//! SQLite bookkeeping. The bytes live on the filesystem; this holds
//! what the operator is allowed to know about them.
//!
//! `migrate()` is CREATE-IF-NOT-EXISTS plus an explicit ALTER list —
//! the shape `onym-moderation` uses. The ALTER list is empty at first
//! release and exists anyway, because adding a column later without a
//! place to put it is how a store ends up wiped in the field.
//!
//! **There is no `access_log` table, and that absence is a design
//! commitment** (§8.3, §15). A per-holder record of who fetched what
//! and when is exactly the metadata diary this seat exists without. An
//! operator adding one has changed what it is.

use rusqlite::Connection;

use crate::error::Result;

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
                recorded_at   TEXT NOT NULL,
                PRIMARY KEY (holder_handle, operation_id)
            );

            -- Kept because §12 exports them and a holder may need to
            -- re-present one. `excluded_scope` is the reason: what an
            -- erasure did not reach outlives the snapshot it describes.
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

            CREATE TABLE IF NOT EXISTS erasure_receipts (
                receipt_id    TEXT PRIMARY KEY,
                holder_handle TEXT NOT NULL,
                scope         TEXT NOT NULL,
                terms_id      TEXT NOT NULL,
                raw           BLOB NOT NULL,
                issued_at     TEXT NOT NULL
            );

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

            -- Derived from entitlement expiry, never from a charge
            -- failure — this operator is not the seller and has no
            -- charge to fail.
            CREATE TABLE IF NOT EXISTS lapse_state (
                holder_handle     TEXT PRIMARY KEY,
                lapsed_at         TEXT NOT NULL,
                grace_expires_at  TEXT NOT NULL,
                post_grace_action TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revocation_cache (
                epoch      INTEGER PRIMARY KEY,
                fetched_at TEXT NOT NULL,
                document   BLOB NOT NULL
            );
            "#,
        )?;

        // Added columns go here, one tuple each. Empty at first release
        // and deliberately present: SQLite has no IF NOT EXISTS for
        // ADD COLUMN, so without a place to express this, the tempting
        // alternative is dropping the table.
        let additions: [(&str, &str, &str); 0] = [];
        for (table, column, definition) in additions {
            let already = self
                .connection
                .prepare(&format!("PRAGMA table_info({table})"))?
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(std::result::Result::ok)
                .any(|existing| existing == column);
            if !already {
                self.connection
                    .execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"), [])?;
            }
        }
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
        Ok(self
            .connection
            .execute("DELETE FROM seen_nonces WHERE seen_at < ?1", [older_than])?)
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
            "SELECT digest, algorithm, sealed_byte_size, accepted_terms_id, supersedes,
                    retained_at, retained_until, erased_at
             FROM snapshots
             WHERE holder_handle = ?1 AND erased_at IS NULL
             ORDER BY retained_at DESC"
        } else {
            "SELECT digest, algorithm, sealed_byte_size, accepted_terms_id, supersedes,
                    retained_at, retained_until, erased_at
             FROM snapshots
             WHERE holder_handle = ?1
             ORDER BY retained_at DESC"
        })?;
        let rows = statement
            .query_map([handle], |row| {
                Ok(RetainedRow {
                    digest: row.get(0)?,
                    algorithm: row.get(1)?,
                    sealed_byte_size: row.get(2)?,
                    accepted_terms_id: row.get(3)?,
                    supersedes: row.get(4)?,
                    retained_at: row.get(5)?,
                    retained_until: row.get(6)?,
                    erased_at: row.get(7)?,
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
                 FROM snapshots WHERE holder_handle = ?1 AND erased_at IS NULL",
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
                 retained_at       = excluded.retained_at,
                 accepted_terms_id = excluded.accepted_terms_id,
                 supersedes        = excluded.supersedes,
                 sealed_byte_size  = excluded.sealed_byte_size,
                 chunk_count       = excluded.chunk_count
             WHERE snapshots.erased_at IS NOT NULL",
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
        recorded_at: &str,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO operation_outcomes
                (operation_id, holder_handle, subject, status, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![operation_id, handle, subject, status, recorded_at],
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
                 WHERE holder_handle = ?1 AND expires_at > ?2",
                rusqlite::params![handle, now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(Into::into)
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
        let all = self.snapshots(handle)?;
        if scope == "all" {
            return Ok(all);
        }
        Ok(all.into_iter().filter(|row| row.digest == scope).collect())
    }

    /// Mark a snapshot erased. The row survives its bytes: `list` must
    /// be able to answer `erased` rather than forgetting, and a holder
    /// who asks about a digest they erased deserves better than a 404
    /// that reads like it never existed.
    pub fn mark_erased(&self, handle: &str, digest: &str, erased_at: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE snapshots SET erased_at = ?3
             WHERE holder_handle = ?1 AND digest = ?2 AND erased_at IS NULL",
            rusqlite::params![handle, digest, erased_at],
        )?;
        Ok(())
    }

    pub fn record_receipt(
        &self,
        receipt_id: &str,
        handle: &str,
        scope: &str,
        terms_id: &str,
        raw: &[u8],
        issued_at: &str,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO erasure_receipts
                (receipt_id, holder_handle, scope, terms_id, raw, issued_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![receipt_id, handle, scope, terms_id, raw, issued_at],
        )?;
        Ok(())
    }

    /// Receipts already issued for exactly this scope.
    ///
    /// What makes a retried erase idempotent: the snapshots are gone,
    /// so there is nothing to erase, but the holder asking again is
    /// owed the receipt rather than a 404 — which would be the same
    /// "silence indistinguishable from never having stored it" that
    /// `list` avoids by reporting `erased`.
    pub fn receipts_for_scope(&self, handle: &str, scope: &str) -> Result<Vec<Vec<u8>>> {
        let mut statement = self.connection.prepare(
            "SELECT raw FROM erasure_receipts
             WHERE holder_handle = ?1 AND scope = ?2 ORDER BY issued_at",
        )?;
        let rows = statement.query_map(rusqlite::params![handle, scope], |row| row.get(0))?;
        Ok(rows.collect::<std::result::Result<Vec<Vec<u8>>, _>>()?)
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

    /// A receipt already issued for this scope under these terms.
    ///
    /// Erasure re-checks this under the lock before minting. The lock
    /// is deliberately dropped for the blob work, so two erases of one
    /// scope can both find live targets; without this each mints a
    /// fresh receipt and a later retry returns both.
    pub fn receipt_for(&self, handle: &str, scope: &str, terms_id: &str) -> Result<Option<Vec<u8>>> {
        let mut statement = self.connection.prepare(
            "SELECT raw FROM erasure_receipts
             WHERE holder_handle = ?1 AND scope = ?2 AND terms_id = ?3",
        )?;
        let mut rows =
            statement.query_map(rusqlite::params![handle, scope, terms_id], |row| row.get(0))?;
        Ok(rows.next().transpose()?)
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
             WHERE holder_handle = ?1 ORDER BY issued_at",
        )?;
        let rows = statement.query_map([handle], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The outcome recorded for one holder's operation, if any.
    pub fn outcome(&self, handle: &str, operation_id: &str) -> Result<Option<(String, String, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT subject, status, recorded_at FROM operation_outcomes
             WHERE holder_handle = ?1 AND operation_id = ?2",
        )?;
        let mut rows = statement.query_map(rusqlite::params![handle, operation_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Drop outcome records past the declared window.
    ///
    /// The window is short on purpose: keeping an operation id is the
    /// per-holder timing trace §15 otherwise forbids, so it is a
    /// declared few hours rather than an exception.
    pub fn sweep_outcomes(&self, older_than: &str) -> Result<usize> {
        Ok(self.connection.execute(
            "DELETE FROM operation_outcomes WHERE recorded_at < ?1",
            [older_than],
        )?)
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
             WHERE holder_handle = ?1 AND digest = ?2 AND expires_at > ?3
             ORDER BY expires_at DESC",
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
        let mut statement = self
            .connection
            .prepare("SELECT upload_id FROM uploads WHERE expires_at <= ?1")?;
        let rows = statement.query_map([now], |row| row.get(0))?;
        Ok(rows.collect::<std::result::Result<Vec<String>, _>>()?)
    }

    pub fn all_upload_ids(&self) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare("SELECT upload_id FROM uploads")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<std::result::Result<Vec<String>, _>>()?)
    }

    /// Every live snapshot as `(holder_handle, digest-hex)` — the shape
    /// the blob layer names them by, so the sweep can compare directly.
    pub fn all_retained_keys(&self) -> Result<Vec<(String, String)>> {
        let mut statement = self
            .connection
            .prepare("SELECT holder_handle, digest FROM snapshots WHERE erased_at IS NULL")?;
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
             WHERE holder_handle = ?1 AND digest = ?2 AND erased_at IS NULL",
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
        assert!(store.record_nonce("h1", "n1", "2026-08-20T10:00:00Z").unwrap());
        assert!(!store.record_nonce("h1", "n1", "2026-08-20T10:00:01Z").unwrap());
    }

    /// Nonce namespaces are per holder. Sharing one would let any
    /// holder deny service to another by guessing.
    #[test]
    fn nonces_do_not_collide_across_holders() {
        let store = Store::in_memory().unwrap();
        assert!(store.record_nonce("h1", "same", "2026-08-20T10:00:00Z").unwrap());
        assert!(store.record_nonce("h2", "same", "2026-08-20T10:00:00Z").unwrap());
    }

    #[test]
    fn sweeping_only_drops_what_is_old() {
        let store = Store::in_memory().unwrap();
        store.record_nonce("h1", "old", "2026-08-20T09:00:00Z").unwrap();
        store.record_nonce("h1", "new", "2026-08-20T11:00:00Z").unwrap();
        assert_eq!(store.sweep_nonces("2026-08-20T10:00:00Z").unwrap(), 1);
        // The swept one is accepted again; the retained one is not.
        assert!(store.record_nonce("h1", "old", "2026-08-20T11:00:01Z").unwrap());
        assert!(!store.record_nonce("h1", "new", "2026-08-20T11:00:01Z").unwrap());
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
