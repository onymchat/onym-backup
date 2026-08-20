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
                started_at        TEXT NOT NULL,
                expires_at        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS uploads_by_holder
                ON uploads (holder_handle, expires_at);

            -- Answers /v1/operations/{id} so a lost response is
            -- reconciled rather than relabelled. Bounded, and the bound
            -- is declared: keeping an operation id IS the per-holder
            -- timing trace §15 otherwise forbids, so it is a window
            -- measured in hours rather than an exception.
            CREATE TABLE IF NOT EXISTS operation_outcomes (
                operation_id  TEXT PRIMARY KEY,
                holder_handle TEXT NOT NULL,
                digest        TEXT NOT NULL,
                status        TEXT NOT NULL,
                recorded_at   TEXT NOT NULL
            );

            -- Kept because §12 exports them and a holder may need to
            -- re-present one. `excluded_scope` is the reason: what an
            -- erasure did not reach outlives the snapshot it describes.
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
        let mut statement = self.connection.prepare(
            "SELECT digest, algorithm, sealed_byte_size, accepted_terms_id, supersedes,
                    retained_at, retained_until
             FROM snapshots
             WHERE holder_handle = ?1 AND erased_at IS NULL
             ORDER BY retained_at DESC",
        )?;
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

pub struct RetainedRow {
    pub digest: String,
    pub algorithm: String,
    pub sealed_byte_size: i64,
    pub accepted_terms_id: String,
    pub supersedes: Option<String>,
    pub retained_at: String,
    pub retained_until: Option<String>,
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
