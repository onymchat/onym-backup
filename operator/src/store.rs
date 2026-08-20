//! SQLite bookkeeping. The bytes live on the filesystem; this holds
//! what the operator is allowed to know about them.
//!
//! `migrate()` is CREATE-IF-NOT-EXISTS plus explicit, idempotent
//! migrations. Schema changes preserve the previous release's rows;
//! startup must never depend on an operator discarding its store.
//!
//! **There is no `access_log` table, and that absence is a design
//! commitment** (§8.3, §15). A per-holder record of who fetched what
//! and when is exactly the metadata diary this seat exists without. An
//! operator adding one has changed what it is.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::error::{Error, Result};

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: &str) -> Result<Store> {
        let connection = Connection::open(path)?;
        let store = Store { connection };
        store.migrate()?;
        Ok(store)
    }

    /// For tests. Same schema, no file.
    pub fn in_memory() -> Result<Store> {
        let connection = Connection::open_in_memory()?;
        let store = Store { connection };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            -- The blob layer syncs files and directory renames before
            -- their rows commit; FULL makes the SQLite side of that
            -- ordering equally explicit across power loss.
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;

            -- A snapshot's identity is the pair (holder, digest), never
            -- the digest alone. Across holders the same digest is not a
            -- collision: sealed bytes are portable verbatim, so a
            -- migration or a re-uploaded export legitimately produces
            -- one. Storage is partitioned by holder and nothing
            -- compares across the partition.
            CREATE TABLE IF NOT EXISTS snapshots (
                holder_handle     TEXT NOT NULL,
                digest            TEXT NOT NULL,
                algorithm         TEXT NOT NULL,
                sealed_byte_size  INTEGER NOT NULL,
                chunk_count       INTEGER NOT NULL,
                accepted_terms_id TEXT NOT NULL,
                supersedes        TEXT,
                retained_at       TEXT NOT NULL,
                retained_until    TEXT,
                erased_at         TEXT,
                PRIMARY KEY (holder_handle, digest)
            );

            CREATE TABLE IF NOT EXISTS uploads (
                upload_id         TEXT PRIMARY KEY,
                holder_handle     TEXT NOT NULL,
                operation_id      TEXT NOT NULL,
                digest            TEXT NOT NULL,
                sealed_byte_size  INTEGER NOT NULL,
                chunk_bytes       INTEGER NOT NULL,
                chunk_count       INTEGER NOT NULL,
                received_mask     BLOB NOT NULL,
                accepted_terms_id TEXT NOT NULL,
                supersedes        TEXT,
                started_at        TEXT NOT NULL,
                expires_at        TEXT NOT NULL
            );
            -- Resuming a grant needs (holder, digest) to be findable.
            CREATE INDEX IF NOT EXISTS uploads_by_digest
                ON uploads (holder_handle, digest);
            CREATE INDEX IF NOT EXISTS uploads_by_holder
                ON uploads (holder_handle, expires_at);

            -- Answers /v1/operations/{id} so a lost response is
            -- reconciled rather than relabelled. Bounded, and the bound
            -- is declared: keeping an operation id IS the per-holder
            -- timing trace §15 otherwise forbids, so it is a window
            -- measured in hours rather than an exception.
            -- Keyed on (holder, operation) rather than operation
            -- alone. The operation id is chosen by the client, so a
            -- bare primary key would let one holder pick another's id
            -- and silently replace their outcome row — breaking the
            -- reconciliation this table exists to serve. Namespacing it
            -- per holder makes the id a holder's own business, which is
            -- what it always was.
            CREATE TABLE IF NOT EXISTS operation_outcomes (
                operation_id  TEXT NOT NULL,
                holder_handle TEXT NOT NULL,
                -- What the operation was about: a digest for an upload,
                -- an erasure scope for an erase. Named for what it
                -- holds rather than for the first thing that went in
                -- it — as `digest` it reported "all" for a whole-holder
                -- erasure, which is a scope wearing a digest's name.
                subject       TEXT NOT NULL,
                status        TEXT NOT NULL,
                -- JSON array of receiptIds for an erasure, NULL
                -- otherwise. §9.6 justifies the client-chosen
                -- operationId by saying a lost erase response must not
                -- cost the holder their receipt — which is only true if
                -- reconciling by that id yields something §9.7 can be
                -- asked for.
                receipt_ids   TEXT,
                recorded_at   TEXT NOT NULL,
                PRIMARY KEY (holder_handle, operation_id)
            );

            -- Every terms document this operator has ever published.
            --
            -- §4.1 requires serving them forever, and a retained
            -- snapshot pins one — so a document that lived only in the
            -- process that minted it would leave a holder, after a
            -- restart under new terms, holding a `termsId` whose
            -- preimage is gone. That is a pin pointing at nothing:
            -- no way to check what retention, jurisdiction or erasure
            -- scope the snapshot was accepted under. §12 needs the same
            -- bytes for the export container.
            CREATE TABLE IF NOT EXISTS terms_documents (
                terms_id    TEXT PRIMARY KEY,
                raw         BLOB NOT NULL,
                signature   BLOB NOT NULL,
                first_seen  TEXT NOT NULL
            );

            -- Kept because §12 exports them and a holder may need to
            -- re-present one. `excludedScope` is the reason: what an
            -- erasure did not reach outlives the snapshot it describes.
            CREATE TABLE IF NOT EXISTS erasure_receipts (
                receipt_id    TEXT PRIMARY KEY,
                holder_handle TEXT NOT NULL,
                scope         TEXT NOT NULL,
                terms_id      TEXT NOT NULL,
                raw           BLOB NOT NULL,
                issued_at     TEXT NOT NULL
            );

            -- Which references each receipt covers.
            --
            -- Scope strings are not comparable: a receipt minted for
            -- `all` covers digests that a later single-digest erase
            -- names directly, and matching on the string alone would
            -- tell that holder their evidence had aged out while it sat
            -- fetchable by id. Coverage is the thing that actually
            -- relates a receipt to a snapshot, so it is stored as such.
            CREATE TABLE IF NOT EXISTS receipt_snapshots (
                receipt_id TEXT NOT NULL,
                digest     TEXT NOT NULL,
                PRIMARY KEY (receipt_id, digest)
            );
            CREATE INDEX IF NOT EXISTS receipt_snapshots_by_digest
                ON receipt_snapshots (digest);

            CREATE TABLE IF NOT EXISTS holder_entitlements (
                entitlement_id TEXT PRIMARY KEY,
                holder_handle  TEXT NOT NULL,
                offer_id       TEXT NOT NULL,
                not_before     TEXT NOT NULL,
                expires_at     TEXT NOT NULL,
                quota_units    INTEGER,
                quota_unit     TEXT,
                quota_consumed INTEGER NOT NULL DEFAULT 0,
                raw            BLOB NOT NULL,
                registered_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS entitlements_by_holder
                ON holder_entitlements (holder_handle, expires_at);

            -- Single-use request nonces. Retained for at least twice the
            -- freshness window: the window is two-sided, so a signature
            -- timestamped `max_skew` ahead stays acceptable until
            -- `now + max_skew` and is live for up to 2x from first
            -- sight. Sweeping at 1x would drop it while still valid and
            -- reopen the replay this table closes.
            CREATE TABLE IF NOT EXISTS seen_nonces (
                holder_handle TEXT NOT NULL,
                nonce         TEXT NOT NULL,
                seen_at       TEXT NOT NULL,
                PRIMARY KEY (holder_handle, nonce)
            );

            -- There is no `lapse_state` table, and that absence is
            -- deliberate. Lapse is *derived* — from the newest
            -- unrevoked entitlement's expiry, and then per snapshot
            -- from the `endOfPayment` clause of its own pinned terms
            -- (§10.3). A cached copy would be a per-holder payment
            -- record that nothing reads and §15 would have to declare,
            -- and it can only ever disagree with the derivation.
            -- Earlier schemas created one; it was never written to.
            DROP TABLE IF EXISTS lapse_state;

            CREATE TABLE IF NOT EXISTS revocation_cache (
                epoch      INTEGER PRIMARY KEY,
                fetched_at TEXT NOT NULL,
                document   BLOB NOT NULL
            );
            "#,
        )?;

        self.migrate_operation_outcomes()?;
        Ok(())
    }

    /// `main` called an outcome's subject `digest` and had no place
    /// to record erasure receipt ids. Renaming a NOT NULL column cannot
    /// be expressed as a pair of ADD COLUMNs: old inserts would still
    /// owe `digest`, and new reads need `subject`. Rebuild the table
    /// transactionally and copy every existing outcome.
    fn migrate_operation_outcomes(&self) -> Result<()> {
        let columns: Vec<String> = self
            .connection
            .prepare("PRAGMA table_info(operation_outcomes)")?
            .query_map([], |row| row.get(1))?
            .collect::<std::result::Result<_, _>>()?;
        let has_subject = columns.iter().any(|column| column == "subject");
        let has_digest = columns.iter().any(|column| column == "digest");
        let has_receipt_ids = columns.iter().any(|column| column == "receipt_ids");

        if !has_subject && has_digest {
            let transaction = self.connection.unchecked_transaction()?;
            transaction.execute_batch(
                r#"
                CREATE TABLE operation_outcomes_v2 (
                    operation_id  TEXT NOT NULL,
                    holder_handle TEXT NOT NULL,
                    subject       TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    receipt_ids   TEXT,
                    recorded_at   TEXT NOT NULL,
                    PRIMARY KEY (holder_handle, operation_id)
                );
                INSERT INTO operation_outcomes_v2
                    (operation_id, holder_handle, subject, status, receipt_ids, recorded_at)
                SELECT operation_id, holder_handle, digest, status, NULL, recorded_at
                  FROM operation_outcomes;
                DROP TABLE operation_outcomes;
                ALTER TABLE operation_outcomes_v2 RENAME TO operation_outcomes;
                "#,
            )?;
            transaction.commit()?;
        } else if has_subject && !has_receipt_ids {
            // Supports development stores created after the rename but
            // before erase outcomes gained receipt ids.
            self.connection
                .execute("ALTER TABLE operation_outcomes ADD COLUMN receipt_ids TEXT", [])?;
        }
        // Earlier pre-release builds used the abstract UI state
        // `erased` for an operator acknowledgement. The profile now
        // reserves that word for the client's later, deadline-based
        // destruction judgement.
        self.connection.execute(
            "UPDATE operation_outcomes
             SET status = 'erasure_acknowledged'
             WHERE status = 'erased'",
            [],
        )?;
        Ok(())
    }

    /// Record a nonce, refusing a repeat.
    ///
    /// Returns `false` when it has been seen — the caller refuses the
    /// request. Scoped to the holder: two holders choosing the same
    /// random nonce is not a replay, and colliding their namespaces
    /// would let one holder deny service to another.
    pub fn record_nonce(&self, handle: &str, nonce: &str, now: &str) -> Result<bool> {
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO seen_nonces (holder_handle, nonce, seen_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![handle, nonce, now],
        )?;
        Ok(inserted == 1)
    }

    /// Drop nonces older than the retention bound.
    pub fn sweep_nonces(&self, older_than: &str) -> Result<usize> {
        Ok(self.connection.execute(
            "DELETE FROM seen_nonces WHERE julianday(seen_at) < julianday(?1)",
            [older_than],
        )?)
    }

    /// What this holder has retained, newest first.
    pub fn snapshots(&self, handle: &str) -> Result<Vec<RetainedRow>> {
        self.listed(handle, true)
    }

    /// Everything the holder has ever had here, erased rows included.
    ///
    /// `list` reports those as `erased` rather than omitting them.
    /// §5.7 makes `erased` a distinct status for a reason: a holder who
    /// asks about a digest they erased is owed that answer, not a
    /// silence that reads the same as never having stored it.
    pub fn snapshots_including_erased(&self, handle: &str) -> Result<Vec<RetainedRow>> {
        self.listed(handle, false)
    }

    fn listed(&self, handle: &str, live_only: bool) -> Result<Vec<RetainedRow>> {
        let mut statement = self.connection.prepare(if live_only {
            "SELECT digest, algorithm, sealed_byte_size, chunk_count, accepted_terms_id, supersedes,
                    retained_at, retained_until, erased_at
             FROM snapshots
             WHERE holder_handle = ?1
               AND erased_at IS NULL
               AND retained_until IS NULL
             ORDER BY julianday(retained_at) DESC"
        } else {
            "SELECT digest, algorithm, sealed_byte_size, chunk_count, accepted_terms_id, supersedes,
                    retained_at, retained_until, erased_at
             FROM snapshots
             WHERE holder_handle = ?1
             ORDER BY julianday(retained_at) DESC"
        })?;
        let rows = statement
            .query_map([handle], |row| {
                Ok(RetainedRow {
                    digest: row.get(0)?,
                    algorithm: row.get(1)?,
                    sealed_byte_size: row.get(2)?,
                    chunk_count: row.get(3)?,
                    accepted_terms_id: row.get(4)?,
                    supersedes: row.get(5)?,
                    retained_at: row.get(6)?,
                    retained_until: row.get(7)?,
                    erased_at: row.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Retained count and bytes, for the quota check.
    pub fn usage(&self, handle: &str) -> Result<(i64, i64)> {
        self.connection
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(sealed_byte_size), 0)
                 FROM snapshots
                 WHERE holder_handle = ?1
                   AND erased_at IS NULL
                   AND retained_until IS NULL",
                [handle],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_upload(
        &self,
        upload_id: &str,
        handle: &str,
        operation_id: &str,
        digest: &str,
        sealed_byte_size: i64,
        chunk_bytes: i64,
        chunk_count: i64,
        accepted_terms_id: &str,
        supersedes: Option<&str>,
        started_at: &str,
        expires_at: &str,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO uploads (upload_id, holder_handle, operation_id, digest,
                sealed_byte_size, chunk_bytes, chunk_count, received_mask,
                accepted_terms_id, supersedes, started_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, X'', ?8, ?9, ?10, ?11)",
            rusqlite::params![
                upload_id, handle, operation_id, digest, sealed_byte_size,
                chunk_bytes, chunk_count, accepted_terms_id, supersedes,
                started_at, expires_at
            ],
        )?;
        Ok(())
    }

    pub fn upload(&self, upload_id: &str) -> Result<Option<UploadRow>> {
        let mut statement = self.connection.prepare(
            "SELECT upload_id, holder_handle, operation_id, digest, sealed_byte_size,
                    chunk_bytes, chunk_count, accepted_terms_id, supersedes, expires_at
             FROM uploads WHERE upload_id = ?1",
        )?;
        let mut rows = statement.query_map([upload_id], |row| {
            Ok(UploadRow {
                upload_id: row.get(0)?,
                holder_handle: row.get(1)?,
                operation_id: row.get(2)?,
                digest: row.get(3)?,
                sealed_byte_size: row.get(4)?,
                chunk_bytes: row.get(5)?,
                chunk_count: row.get(6)?,
                accepted_terms_id: row.get(7)?,
                supersedes: row.get(8)?,
                expires_at: row.get(9)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn drop_upload(&self, upload_id: &str) -> Result<()> {
        self.connection
            .execute("DELETE FROM uploads WHERE upload_id = ?1", [upload_id])?;
        Ok(())
    }

    /// Record a committed snapshot.
    ///
    /// An upsert, not `INSERT OR IGNORE`. A row survives its bytes —
    /// erasure marks rather than deletes, so `list` can report `erased`
    /// — and that row keeps the `(holder, digest)` primary key. With
    /// `INSERT OR IGNORE`, re-uploading a digest the holder had erased
    /// was silently dropped while the operator answered `retained`:
    /// the bytes landed, `erased_at` stayed set, the download 404'd,
    /// and the sweep then deleted the freshly committed bytes as
    /// orphans. That is the migration flow §12 advertises — the same
    /// sealed bytes under the same reference — failing while claiming
    /// to work.
    ///
    /// So the conflict clears `erased_at` and refreshes what the new
    /// upload pinned. A *live* row is still left alone: committing a
    /// digest already held is `already_retained`, not an overwrite of
    /// bytes that are addressed by their own digest.
    pub fn retain(&self, upload: &UploadRow, retained_at: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO snapshots (holder_handle, digest, algorithm,
                sealed_byte_size, chunk_count, accepted_terms_id, supersedes, retained_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (holder_handle, digest) DO UPDATE SET
                 erased_at         = NULL,
                 retained_until    = NULL,
                 retained_at       = excluded.retained_at,
                 accepted_terms_id = excluded.accepted_terms_id,
                 supersedes        = excluded.supersedes,
                 sealed_byte_size  = excluded.sealed_byte_size,
                 chunk_count       = excluded.chunk_count
             WHERE snapshots.erased_at IS NOT NULL
                OR snapshots.retained_until IS NOT NULL",
            rusqlite::params![
                upload.holder_handle,
                upload.digest,
                crate::documents::DIGEST_SUITE,
                upload.sealed_byte_size,
                upload.chunk_count,
                upload.accepted_terms_id,
                upload.supersedes,
                retained_at
            ],
        )?;
        Ok(())
    }

    /// Answer `/v1/operations/{id}` so a lost response is reconciled
    /// rather than relabelled.
    pub fn record_outcome(
        &self,
        operation_id: &str,
        handle: &str,
        subject: &str,
        status: &str,
        receipt_ids: Option<String>,
        recorded_at: &str,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO operation_outcomes
                (operation_id, holder_handle, subject, status, receipt_ids, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![operation_id, handle, subject, status, receipt_ids, recorded_at],
        )?;
        Ok(())
    }

    /// Grants this holder has open and has not let expire.
    ///
    /// Counted alongside retained snapshots at preflight. Quota checked
    /// against retained rows alone is checked against a number that has
    /// not moved yet: a holder one below the limit could preflight N
    /// uploads, each seeing the same count, then commit all N. The
    /// commit-time re-check is the authoritative gate; counting grants
    /// here is what keeps the refusal *cheap*, which is the entire
    /// reason preflight exists.
    pub fn open_grants(&self, handle: &str, now: &str) -> Result<(i64, i64)> {
        self.connection
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(sealed_byte_size), 0) FROM uploads
                 WHERE holder_handle = ?1
                   AND julianday(expires_at) > julianday(?2)",
                rusqlite::params![handle, now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(Into::into)
    }

    /// Record a verified entitlement against a holder.
    ///
    /// Idempotent by `entitlementId` (§9.1), and the same call serves
    /// the header path: a credential presented on a request is
    /// registered exactly as one posted to §9.1's route would be.
    /// Remembering it is not bookkeeping for its own sake — lapse
    /// (§10.3) is derived from entitlement expiry, and an operator that
    /// verified a credential and then forgot it has no way to know a
    /// holder ever had one.
    ///
    /// `INSERT OR REPLACE` rather than `OR IGNORE`: a broker may
    /// re-issue the same `entitlementId` with a later `expiresAt` on
    /// renewal, and keeping the first copy would lapse a holder who
    /// paid.
    pub fn register_entitlement(
        &self,
        handle: &str,
        entitlement: &crate::entitlements::VerifiedEntitlement,
        now: &str,
    ) -> Result<()> {
        let stamp = |at: OffsetDateTime| -> Result<String> {
            at.format(&Rfc3339)
                .map_err(|e| Error::Internal(format!("format timestamp: {e}")))
        };
        self.connection.execute(
            "INSERT OR REPLACE INTO holder_entitlements
                (entitlement_id, holder_handle, offer_id, not_before, expires_at,
                 quota_units, quota_unit, quota_consumed, raw, registered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 0, ?6, ?7)",
            rusqlite::params![
                entitlement.entitlement_id,
                handle,
                entitlement.offer_id,
                stamp(entitlement.not_before)?,
                stamp(entitlement.expires_at)?,
                entitlement.raw,
                now,
            ],
        )?;
        Ok(())
    }

    /// The latest `expiresAt` among this holder's registered
    /// entitlements, revoked ids excluded.
    ///
    /// The *latest*, not the first found: a holder who renewed early
    /// holds two credentials at once, and lapsing them on the older
    /// one's expiry would cut off someone who has already paid for the
    /// next period.
    ///
    /// Revocation is applied here as well as at presentation because
    /// this is what lapse reads. A refunded entitlement that still sat
    /// in the table would hold lapse off indefinitely — the holder
    /// would stop being able to upload (presentation refuses the
    /// credential) while never entering grace, which is the worst of
    /// both.
    pub fn entitlement_horizon(
        &self,
        handle: &str,
        revoked: &HashSet<String>,
    ) -> Result<Option<String>> {
        let mut statement = self.connection.prepare(
            "SELECT entitlement_id, expires_at FROM holder_entitlements
             WHERE holder_handle = ?1",
        )?;
        let rows = statement.query_map([handle], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut horizon: Option<(OffsetDateTime, String)> = None;
        for row in rows {
            let (id, expires_at) = row?;
            if revoked.contains(&id) {
                continue;
            }
            let Ok(at) = OffsetDateTime::parse(&expires_at, &Rfc3339) else {
                continue;
            };
            if horizon.as_ref().is_none_or(|(held, _)| at > *held) {
                horizon = Some((at, expires_at));
            }
        }
        Ok(horizon.map(|(_, text)| text))
    }

    /// Whether this holder has ever registered an entitlement.
    ///
    /// Distinguishes "never paid" from "paid and lapsed", which are
    /// different refusals: the first is a `402` that starts the payment
    /// loop, the second is grace under terms already agreed.
    pub fn has_entitlement_record(&self, handle: &str) -> Result<bool> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM holder_entitlements WHERE holder_handle = ?1)",
                [handle],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count == 1)
            .map_err(Into::into)
    }

    /// Discard entitlement records past the declared window.
    ///
    /// `metadataRetention.entitlementRecords` declares "to expiry plus
    /// one revocation-epoch interval", and the caller computes that
    /// floor. The epoch interval is in there because an entitlement
    /// revoked just before it expired must stay recognisable for at
    /// least as long as it takes the next epoch to say so.
    pub fn sweep_entitlements(&self, older_than: &str) -> Result<usize> {
        Ok(self.connection.execute(
            "DELETE FROM holder_entitlements WHERE julianday(expires_at) < julianday(?1)",
            [older_than],
        )?)
    }

    /// Holders with at least one live snapshot.
    ///
    /// The sweep's starting point for post-grace expiry. Deriving lapse
    /// from here rather than from `lapse_state` alone is deliberate: a
    /// holder who stopped paying and never came back never triggers a
    /// request-time evaluation, and an operator that only expired the
    /// holders who kept knocking would hold the abandoned ones forever.
    pub fn holders_with_snapshots(&self) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT holder_handle FROM snapshots
             WHERE erased_at IS NULL AND retained_until IS NULL",
        )?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<_, _>>().map_err(Into::into)
    }




    /// Persist the epoch in force, so a restart during a broker outage
    /// comes back with the revocations it had rather than with none.
    pub fn cache_epoch(&self, epoch: i64, fetched_at: &str, document: &[u8]) -> Result<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO revocation_cache (epoch, fetched_at, document)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![epoch, fetched_at, document],
        )?;
        // Only the newest is useful; older epochs are a list of
        // revocations that have since been restated or expired.
        self.connection.execute(
            "DELETE FROM revocation_cache WHERE epoch < ?1",
            [epoch],
        )?;
        Ok(())
    }

    /// The newest cached epoch, with when it was fetched.
    pub fn latest_epoch(&self) -> Result<Option<(Vec<u8>, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT document, fetched_at FROM revocation_cache ORDER BY epoch DESC LIMIT 1",
        )?;
        let mut rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.next().transpose()?)
    }

    /// Record a terms document, if it is not already known.
    ///
    /// Called at boot with the current terms. Idempotent: the same
    /// document across restarts is one row, and a *different* one adds
    /// a row rather than replacing — which is the entire point.
    pub fn remember_terms(&self, terms_id: &str, raw: &[u8], signature: &[u8], now: &str) -> Result<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO terms_documents (terms_id, raw, signature, first_seen)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![terms_id, raw, signature, now],
        )?;
        Ok(())
    }

    /// A published terms document by id, with its detached signature.
    pub fn terms_document(&self, terms_id: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut statement = self
            .connection
            .prepare("SELECT raw, signature FROM terms_documents WHERE terms_id = ?1")?;
        let mut rows = statement.query_map([terms_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.next().transpose()?)
    }

    /// Snapshots in an erasure's scope: one digest, or all of them.
    pub fn snapshots_in_scope(&self, handle: &str, scope: &str) -> Result<Vec<RetainedRow>> {
        if scope == "all" {
            return self.snapshots(handle);
        }
        Ok(self
            .snapshots(handle)?
            .into_iter()
            .filter(|row| row.digest == scope)
            .collect())
    }

    /// One snapshot record in any state, for distinguishing an
    /// unavailable snapshot from one this holder never stored.
    pub fn snapshot_record(&self, handle: &str, digest: &str) -> Result<Option<RetainedRow>> {
        let mut statement = self.connection.prepare(
            "SELECT digest, algorithm, sealed_byte_size, chunk_count, accepted_terms_id,
                    supersedes, retained_at, retained_until, erased_at
             FROM snapshots WHERE holder_handle = ?1 AND digest = ?2",
        )?;
        let mut rows = statement.query_map(rusqlite::params![handle, digest], |row| {
            Ok(RetainedRow {
                digest: row.get(0)?,
                algorithm: row.get(1)?,
                sealed_byte_size: row.get(2)?,
                chunk_count: row.get(3)?,
                accepted_terms_id: row.get(4)?,
                supersedes: row.get(5)?,
                retained_at: row.get(6)?,
                retained_until: row.get(7)?,
                erased_at: row.get(8)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Every row the operator currently claims has bytes, with the
    /// holder partition needed to inspect its directory at startup.
    pub fn all_live_snapshots(&self) -> Result<Vec<(String, RetainedRow)>> {
        let mut statement = self.connection.prepare(
            "SELECT holder_handle, digest, algorithm, sealed_byte_size, chunk_count,
                    accepted_terms_id, supersedes, retained_at, retained_until, erased_at
             FROM snapshots
             WHERE erased_at IS NULL AND retained_until IS NULL",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get(0)?,
                RetainedRow {
                    digest: row.get(1)?,
                    algorithm: row.get(2)?,
                    sealed_byte_size: row.get(3)?,
                    chunk_count: row.get(4)?,
                    accepted_terms_id: row.get(5)?,
                    supersedes: row.get(6)?,
                    retained_at: row.get(7)?,
                    retained_until: row.get(8)?,
                    erased_at: row.get(9)?,
                },
            ))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Stop claiming bytes are retained after the blob layer proves
    /// they are absent or incomplete. The row remains so list and a
    /// later erase can report `retention_expired` rather than pretend
    /// the snapshot was never stored.
    pub fn mark_unavailable(&self, handle: &str, digest: &str, at: &str) -> Result<usize> {
        Ok(self.connection.execute(
            "UPDATE snapshots SET retained_until = ?3
             WHERE holder_handle = ?1 AND digest = ?2
               AND erased_at IS NULL AND retained_until IS NULL",
            rusqlite::params![handle, digest, at],
        )?)
    }

    pub fn scope_is_unavailable(&self, handle: &str, scope: &str) -> Result<bool> {
        let count: i64 = if scope == "all" {
            self.connection.query_row(
                "SELECT COUNT(*) FROM snapshots
                 WHERE holder_handle = ?1 AND erased_at IS NULL
                   AND retained_until IS NOT NULL",
                [handle],
                |row| row.get(0),
            )?
        } else {
            self.connection.query_row(
                "SELECT COUNT(*) FROM snapshots
                 WHERE holder_handle = ?1 AND digest = ?2
                   AND erased_at IS NULL AND retained_until IS NOT NULL",
                rusqlite::params![handle, scope],
                |row| row.get(0),
            )?
        };
        Ok(count > 0)
    }

    /// Mark erased, record the receipts, record the outcome — all or
    /// nothing.
    ///
    /// One transaction because the three are one fact. Written
    /// separately, a failure between them left bytes gone, rows still
    /// saying `retained`, and no receipt — so `list` reported
    /// `retained` about bytes that no longer existed, and a retry
    /// answered `receipt_expired` about a receipt that was never
    /// minted. Both are the operator asserting something false.
    ///
    /// The bytes are unlinked *after* this commits, which is the safe
    /// direction: a crash in between leaves rows marked erased with
    /// their bytes still on disk, and the sweep collects those as
    /// orphans because it lists only live rows. The reverse — unlink
    /// first — leaves a live row whose bytes are gone, which nothing
    /// repairs and which `list` misreports forever.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_erasure(
        &mut self,
        handle: &str,
        scope: &str,
        digests: &[String],
        receipts: &[(String, String, Vec<u8>, Vec<String>)],
        operation_id: &str,
        stamp: &str,
    ) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for digest in digests {
            transaction.execute(
                "UPDATE snapshots SET erased_at = ?3
                 WHERE holder_handle = ?1 AND digest = ?2 AND erased_at IS NULL",
                rusqlite::params![handle, digest, stamp],
            )?;
        }
        for (receipt_id, terms_id, raw, covers) in receipts {
            transaction.execute(
                "INSERT OR REPLACE INTO erasure_receipts
                    (receipt_id, holder_handle, scope, terms_id, raw, issued_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![receipt_id, handle, scope, terms_id, raw, stamp],
            )?;
            for digest in covers {
                transaction.execute(
                    "INSERT OR IGNORE INTO receipt_snapshots (receipt_id, digest)
                     VALUES (?1, ?2)",
                    rusqlite::params![receipt_id, digest],
                )?;
            }
        }
        let ids: Vec<&str> = receipts.iter().map(|(id, ..)| id.as_str()).collect();
        transaction.execute(
            "INSERT OR REPLACE INTO operation_outcomes
                (operation_id, holder_handle, subject, status, receipt_ids, recorded_at)
             VALUES (?1, ?2, ?3, 'erasure_acknowledged', ?4, ?5)",
            rusqlite::params![
                operation_id,
                handle,
                scope,
                serde_json::to_string(&ids).unwrap_or_default(),
                stamp
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// The newest live receipt set relevant to this erased scope.
    ///
    /// Both the original scope and stored coverage matter. A digest can
    /// be erased, uploaded again, and later covered by `all`; replaying
    /// the older exact-scope receipt would describe the wrong storage
    /// lifecycle. Conversely, a receipt minted for one digest is still
    /// relevant when a later retry names `all`.
    ///
    /// One erasure can mint several receipts for distinct pinned terms,
    /// so recency is selected by `issued_at` and every receipt sharing
    /// that timestamp is returned as one set.
    pub fn latest_receipts_for_erased_scope(
        &self,
        handle: &str,
        scope: &str,
        digests: &[String],
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let digests: HashSet<&str> = digests.iter().map(String::as_str).collect();
        let mut statement = self.connection.prepare(
            "SELECT r.receipt_id, r.raw, r.issued_at, r.terms_id, r.scope, c.digest
               FROM erasure_receipts r
               LEFT JOIN receipt_snapshots c ON c.receipt_id = r.receipt_id
              WHERE r.holder_handle = ?1",
        )?;
        let rows = statement.query_map([handle], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;

        let mut candidates: HashMap<String, (Vec<u8>, OffsetDateTime, String)> = HashMap::new();
        for row in rows {
            let (id, raw, issued_at, terms_id, receipt_scope, covered_digest) = row?;
            let covers_requested = covered_digest
                .as_deref()
                .is_some_and(|digest| digests.contains(digest));
            if receipt_scope == scope || covers_requested {
                let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
                    .map_err(|error| Error::Internal(format!("stored receipt timestamp: {error}")))?;
                candidates.entry(id).or_insert((raw, issued_at, terms_id));
            }
        }
        let Some(newest) = candidates.values().map(|(_, issued_at, _)| *issued_at).max() else {
            return Ok(Vec::new());
        };
        let mut newest_set: Vec<(String, Vec<u8>, String)> = candidates
            .into_iter()
            .filter(|(_, (_, issued_at, _))| *issued_at == newest)
            .map(|(id, (raw, _, terms_id))| (id, raw, terms_id))
            .collect();
        newest_set.sort_by(|left, right| left.2.cmp(&right.2).then(left.0.cmp(&right.0)));
        Ok(newest_set
            .into_iter()
            .map(|(id, raw, _)| (id, raw))
            .collect())
    }

    /// References this holder has erased, within a scope.
    pub fn erased_digests(&self, handle: &str, scope: &str) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare(if scope == "all" {
            "SELECT digest FROM snapshots
             WHERE holder_handle = ?1 AND erased_at IS NOT NULL"
        } else {
            "SELECT digest FROM snapshots
             WHERE holder_handle = ?1 AND digest = ?2 AND erased_at IS NOT NULL"
        })?;
        let rows = if scope == "all" {
            statement.query_map(rusqlite::params![handle], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<String>, _>>()?
        } else {
            statement.query_map(rusqlite::params![handle, scope], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<String>, _>>()?
        };
        Ok(rows)
    }

    /// The terms ids cited by this holder's receipts.
    ///
    /// Union'd into the export container's terms list. A receipt pins
    /// the terms of a snapshot that is *erased*, so collecting terms
    /// from live snapshots alone can ship a receipt citing a document
    /// the container does not carry — the same pin-whose-preimage-is-
    /// gone the container exists to prevent, arriving by the one route
    /// nobody was watching.
    pub fn receipt_terms_ids(&self, handle: &str) -> Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT terms_id FROM erasure_receipts WHERE holder_handle = ?1")?;
        let rows = statement.query_map([handle], |row| row.get(0))?;
        Ok(rows.collect::<std::result::Result<Vec<String>, _>>()?)
    }

    /// One receipt by id, scoped to its holder.
    pub fn receipt(&self, handle: &str, receipt_id: &str) -> Result<Option<Vec<u8>>> {
        let mut statement = self.connection.prepare(
            "SELECT raw FROM erasure_receipts WHERE holder_handle = ?1 AND receipt_id = ?2",
        )?;
        let mut rows = statement.query_map(rusqlite::params![handle, receipt_id], |row| row.get(0))?;
        Ok(rows.next().transpose()?)
    }

    /// This holder's receipts, for §12's container.
    pub fn receipts(&self, handle: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let mut statement = self.connection.prepare(
            "SELECT receipt_id, raw FROM erasure_receipts
             WHERE holder_handle = ?1 ORDER BY julianday(issued_at)",
        )?;
        let rows = statement.query_map([handle], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The outcome recorded for one holder's operation, if any.
    #[allow(clippy::type_complexity)]
    pub fn outcome(
        &self,
        handle: &str,
        operation_id: &str,
    ) -> Result<Option<(String, String, Option<String>, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT subject, status, receipt_ids, recorded_at FROM operation_outcomes
             WHERE holder_handle = ?1 AND operation_id = ?2",
        )?;
        let mut rows = statement.query_map(rusqlite::params![handle, operation_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Forget references erased longer ago than the declared window.
    ///
    /// The row is what lets `list` say `erased` and `/v1/erasures` say
    /// `receipt_expired`; kept without limit it is a permanent list of
    /// everything this holder has ever erased, which is a more complete
    /// history than the backups themselves. So it is bounded, and both
    /// of those answers end with it.
    pub fn sweep_erased_references(&self, older_than: &str) -> Result<usize> {
        Ok(self.connection.execute(
            "DELETE FROM snapshots
             WHERE erased_at IS NOT NULL
               AND julianday(erased_at) < julianday(?1)",
            [older_than],
        )?)
    }

    /// Drop outcome records and receipts past their declared windows.
    ///
    /// Upload outcomes use the short `operationOutcomes` window.
    /// Erase outcomes name receipt ids, so the profile binds them to
    /// `erasureReceipts` instead: they must neither predecease nor
    /// outlive the receipts they name.
    ///
    /// Coverage, receipts, and erase outcomes cross that boundary in
    /// one transaction. A crash or concurrent reconciliation must not
    /// observe a receipt fetchable by id after its coverage disappeared,
    /// or a receipt without the erase outcome retained alongside it.
    pub fn sweep_outcomes_and_receipts(
        &mut self,
        uploads_before: &str,
        receipts_before: &str,
    ) -> Result<(usize, usize)> {
        let transaction = self.connection.transaction()?;
        let outcomes = transaction.execute(
            "DELETE FROM operation_outcomes
             WHERE (status <> 'erasure_acknowledged' AND julianday(recorded_at) < julianday(?1))
                OR (status =  'erasure_acknowledged' AND julianday(recorded_at) < julianday(?2))",
            rusqlite::params![uploads_before, receipts_before],
        )?;
        // Coverage first, while the receipts it points at still exist
        // to be selected. The transaction makes "first" invisible to
        // readers until the receipt rows have gone too.
        transaction.execute(
            "DELETE FROM receipt_snapshots WHERE receipt_id IN (
                 SELECT receipt_id FROM erasure_receipts
                  WHERE julianday(issued_at) < julianday(?1)
             )",
            [receipts_before],
        )?;
        let receipts = transaction.execute(
            "DELETE FROM erasure_receipts
             WHERE julianday(issued_at) < julianday(?1)",
            [receipts_before],
        )?;
        transaction.commit()?;
        Ok((outcomes, receipts))
    }

    /// A grant this holder already holds for this digest, if one is
    /// still live.
    ///
    /// Preflight returns it rather than minting a second. Without this
    /// a holder whose grant response was lost re-preflights, is told
    /// `quota_exceeded` by their own orphaned grant, and can do nothing
    /// but wait for it to expire — the same reconciliation failure
    /// `already_retained` avoids for the committed case, one step
    /// earlier.
    pub fn open_grant_for(
        &self,
        handle: &str,
        digest: &str,
        now: &str,
    ) -> Result<Option<UploadRow>> {
        let mut statement = self.connection.prepare(
            "SELECT upload_id, holder_handle, operation_id, digest, sealed_byte_size,
                    chunk_bytes, chunk_count, accepted_terms_id, supersedes, expires_at
             FROM uploads
             WHERE holder_handle = ?1 AND digest = ?2
               AND julianday(expires_at) > julianday(?3)
             ORDER BY julianday(expires_at) DESC",
        )?;
        let mut rows = statement.query_map(rusqlite::params![handle, digest, now], |row| {
            Ok(UploadRow {
                upload_id: row.get(0)?,
                holder_handle: row.get(1)?,
                operation_id: row.get(2)?,
                digest: row.get(3)?,
                sealed_byte_size: row.get(4)?,
                chunk_bytes: row.get(5)?,
                chunk_count: row.get(6)?,
                accepted_terms_id: row.get(7)?,
                supersedes: row.get(8)?,
                expires_at: row.get(9)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Upload ids whose grants have run out.
    pub fn expired_uploads(&self, now: &str) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT upload_id FROM uploads
                 WHERE julianday(expires_at) <= julianday(?1)",
        )?;
        let rows = statement.query_map([now], |row| row.get(0))?;
        Ok(rows.collect::<std::result::Result<Vec<String>, _>>()?)
    }

    /// Every live snapshot as `(holder_handle, digest-hex)` — the shape
    /// the blob layer names them by, so the sweep can compare directly.
    pub fn all_retained_keys(&self) -> Result<Vec<(String, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT holder_handle, digest FROM snapshots
                 WHERE erased_at IS NULL AND retained_until IS NULL",
        )?;
        let rows = statement.query_map([], |row| {
            let handle: String = row.get(0)?;
            let digest: String = row.get(1)?;
            Ok((
                handle,
                digest.strip_prefix("sha256:").unwrap_or(&digest).to_string(),
            ))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The raw connection, for tests that assert on table shape rather
    /// than on behaviour — the primary key of `operation_outcomes` is
    /// not observable through any method, and it is a property worth
    /// asserting directly.
    #[cfg(test)]
    pub fn connection_for_tests(&self) -> &rusqlite::Connection {
        &self.connection
    }

    pub fn snapshot_exists(&self, handle: &str, digest: &str) -> Result<bool> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM snapshots
                 WHERE holder_handle = ?1 AND digest = ?2
                   AND erased_at IS NULL AND retained_until IS NULL",
            rusqlite::params![handle, digest],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}

/// An upload in flight.
pub struct UploadRow {
    pub upload_id: String,
    pub holder_handle: String,
    pub operation_id: String,
    pub digest: String,
    pub sealed_byte_size: i64,
    pub chunk_bytes: i64,
    pub chunk_count: i64,
    pub accepted_terms_id: String,
    pub supersedes: Option<String>,
    pub expires_at: String,
}

pub struct RetainedRow {
    pub digest: String,
    pub algorithm: String,
    pub sealed_byte_size: i64,
    pub chunk_count: i64,
    pub accepted_terms_id: String,
    pub supersedes: Option<String>,
    pub retained_at: String,
    pub retained_until: Option<String>,
    pub erased_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_is_idempotent() {
        let store = Store::in_memory().unwrap();
        // Running it twice is what a restart does.
        store.migrate().unwrap();
        store.migrate().unwrap();
    }

    #[test]
    fn migrate_preserves_outcomes_from_the_previous_schema() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE operation_outcomes (
                    operation_id  TEXT NOT NULL,
                    holder_handle TEXT NOT NULL,
                    digest        TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    recorded_at   TEXT NOT NULL,
                    PRIMARY KEY (holder_handle, operation_id)
                );
                INSERT INTO operation_outcomes
                    (operation_id, holder_handle, digest, status, recorded_at)
                VALUES
                    ('op-old', 'holder', 'sha256:old', 'retained',
                     '2026-08-20T10:00:00Z'),
                    ('op-old-erase', 'holder', 'all', 'erased',
                     '2026-08-20T10:30:00Z');
                "#,
            )
            .unwrap();

        let store = Store { connection };
        store.migrate().unwrap();
        store.migrate().unwrap();

        let outcome = store.outcome("holder", "op-old").unwrap().unwrap();
        assert_eq!(outcome.0, "sha256:old");
        assert_eq!(outcome.1, "retained");
        assert_eq!(outcome.2, None);

        let old_erasure = store.outcome("holder", "op-old-erase").unwrap().unwrap();
        assert_eq!(old_erasure.0, "all");
        assert_eq!(old_erasure.1, "erasure_acknowledged");

        store
            .record_outcome(
                "op-erase",
                "holder",
                "all",
                "erasure_acknowledged",
                Some(r#"["receipt"]"#.into()),
                "2026-08-20T11:00:00Z",
            )
            .unwrap();
        let erased = store.outcome("holder", "op-erase").unwrap().unwrap();
        assert_eq!(erased.0, "all");
        assert_eq!(erased.2.as_deref(), Some(r#"["receipt"]"#));

        let columns: Vec<String> = store
            .connection
            .prepare("PRAGMA table_info(operation_outcomes)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert!(columns.iter().any(|column| column == "subject"));
        assert!(columns.iter().any(|column| column == "receipt_ids"));
        assert!(!columns.iter().any(|column| column == "digest"));
    }

    #[test]
    fn outcome_and_receipt_sweep_rolls_back_as_one_unit() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_outcome(
                "op-erase",
                "holder",
                "sha256:old",
                "erasure_acknowledged",
                Some(r#"["receipt"]"#.into()),
                "2026-01-01T00:00:00Z",
            )
            .unwrap();
        store
            .connection
            .execute_batch(
                r#"
                INSERT INTO erasure_receipts
                    (receipt_id, holder_handle, scope, terms_id, raw, issued_at)
                VALUES
                    ('receipt', 'holder', 'sha256:old', 'terms',
                     '{"receiptId":"receipt"}', '2026-01-01T00:00:00Z');
                INSERT INTO receipt_snapshots (receipt_id, digest)
                VALUES ('receipt', 'sha256:old');
                "#,
            )
            .unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER refuse_receipt_delete
                 BEFORE DELETE ON erasure_receipts
                 BEGIN SELECT RAISE(ABORT, 'refuse delete'); END;",
            )
            .unwrap();

        assert!(
            store
                .sweep_outcomes_and_receipts("2027-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
                .is_err()
        );
        for table in [
            "operation_outcomes",
            "erasure_receipts",
            "receipt_snapshots",
        ] {
            let count: i64 = store
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1, "{table} escaped the rollback");
        }
    }

    /// The absence is the design. A table here would make this a
    /// different seat, so it is asserted rather than described.
    ///
    /// A tripwire, not a proof: it catches a table named for what it is
    /// and would miss one called `fetch_history`. What actually keeps
    /// the property is that nothing writes such a table — this exists
    /// so adding the obvious one is noisy.
    #[test]
    fn there_is_no_access_log_table() {
        let store = Store::in_memory().unwrap();
        let names: Vec<String> = store
            .connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        for name in &names {
            assert!(
                !name.contains("access") && !name.contains("audit"),
                "an access log appeared: {name}"
            );
        }
    }

    #[test]
    fn a_repeated_nonce_is_refused() {
        let store = Store::in_memory().unwrap();
        assert!(
            store
                .record_nonce("h1", "n1", "2026-08-20T10:00:00Z")
                .unwrap()
        );
        assert!(
            !store
                .record_nonce("h1", "n1", "2026-08-20T10:00:01Z")
                .unwrap()
        );
    }

    /// Nonce namespaces are per holder. Sharing one would let any
    /// holder deny service to another by guessing.
    #[test]
    fn nonces_do_not_collide_across_holders() {
        let store = Store::in_memory().unwrap();
        assert!(
            store
                .record_nonce("h1", "same", "2026-08-20T10:00:00Z")
                .unwrap()
        );
        assert!(
            store
                .record_nonce("h2", "same", "2026-08-20T10:00:00Z")
                .unwrap()
        );
    }

    #[test]
    fn sweeping_only_drops_what_is_old() {
        let store = Store::in_memory().unwrap();
        store.record_nonce("h1", "old", "2026-08-20T09:00:00Z").unwrap();
        store.record_nonce("h1", "new", "2026-08-20T11:00:00Z").unwrap();
        assert_eq!(store.sweep_nonces("2026-08-20T10:00:00Z").unwrap(), 1);
        // The swept one is accepted again; the retained one is not.
        assert!(
            store
                .record_nonce("h1", "old", "2026-08-20T11:00:01Z")
                .unwrap()
        );
        assert!(
            !store
                .record_nonce("h1", "new", "2026-08-20T11:00:01Z")
                .unwrap()
        );
    }

    #[test]
    fn timestamp_ordering_is_chronological_not_lexical() {
        let mut store = Store::in_memory().unwrap();
        store
            .begin_upload(
                "u1",
                "holder",
                "op",
                "sha256:aa",
                3,
                3,
                1,
                "terms",
                None,
                "2026-08-20T10:00:00Z",
                "2026-08-20T10:00:20Z",
            )
            .unwrap();
        assert_eq!(
            store
                .open_grants("holder", "2026-08-20T10:00:20.5Z")
                .unwrap(),
            (0, 0),
            "20Z sorted after the later 20.5Z"
        );
        assert_eq!(
            store.expired_uploads("2026-08-20T10:00:20.5Z").unwrap(),
            vec!["u1".to_string()]
        );

        store
            .record_outcome(
                "op",
                "holder",
                "sha256:aa",
                "retained",
                None,
                "2026-08-20T10:00:20Z",
            )
            .unwrap();
        let (outcomes, _) = store
            .sweep_outcomes_and_receipts("2026-08-20T10:00:20.5Z", "2000-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(outcomes, 1);
    }

    #[test]
    fn usage_counts_only_live_snapshots_for_one_holder() {
        let store = Store::in_memory().unwrap();
        let insert = |handle: &str, digest: &str, size: i64, erased: Option<&str>| {
            store
                .connection
                .execute(
                    "INSERT INTO snapshots (holder_handle, digest, algorithm, sealed_byte_size,
                        chunk_count, accepted_terms_id, retained_at, erased_at)
                     VALUES (?1, ?2, 'sha-256/lowercase-hex', ?3, 1, 'sha256:t', '2026-08-20T10:00:00Z', ?4)",
                    rusqlite::params![handle, digest, size, erased],
                )
                .unwrap();
        };
        insert("h1", "sha256:a", 100, None);
        insert("h1", "sha256:b", 200, Some("2026-08-20T11:00:00Z"));
        insert("h2", "sha256:c", 400, None);

        assert_eq!(store.usage("h1").unwrap(), (1, 100));
        assert_eq!(store.usage("h2").unwrap(), (1, 400));
        assert!(store.snapshot_exists("h1", "sha256:a").unwrap());
        assert!(!store.snapshot_exists("h1", "sha256:b").unwrap(), "an erased snapshot counted as held");
        assert!(!store.snapshot_exists("h1", "sha256:c").unwrap(), "another holder's snapshot was visible");
    }
}
