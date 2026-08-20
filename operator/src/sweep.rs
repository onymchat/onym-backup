//! Reconciling the filesystem against the bookkeeping.
//!
//! Bytes and rows are written in two steps, so a crash between them
//! leaves one without the other. This resolves that in one direction
//! only: **bytes with no row are deleted; a row is never invented for
//! bytes that were found.** The reverse would let a truncated or
//! unverified upload become a snapshot the operator claims to hold, and
//! `retained` is a word this operator must never say without having
//! recomputed the digest.
//!
//! It also collects abandoned uploads. A grant that expired is disk
//! nobody is coming back for, and without this the only bound on
//! `incoming/` would be the goodwill of clients that finish what they
//! start.

use std::collections::HashSet;

use crate::blobs::Blobs;
use crate::store::Store;

pub struct Swept {
    pub expired_grants: usize,
    pub orphan_incoming: usize,
    pub orphan_snapshots: usize,
}

/// Runs at boot and then on a timer. Failures are logged, not fatal: an
/// operator that will not serve because it could not tidy up is worse
/// than one carrying some dead bytes.
pub fn reconcile(store: &Store, blobs: &Blobs, now: &str) -> Swept {
    let mut swept = Swept {
        expired_grants: 0,
        orphan_incoming: 0,
        orphan_snapshots: 0,
    };

    // (1) Grants that ran out. The bytes go first: if the row survives
    // a crash here the next sweep finds it again, whereas a row deleted
    // before its bytes leaves an orphan nothing points at.
    match store.expired_uploads(now) {
        Ok(ids) => {
            for id in ids {
                blobs.discard_upload(&id);
                if let Err(error) = store.drop_upload(&id) {
                    tracing::warn!(%error, "could not drop expired upload row");
                    continue;
                }
                swept.expired_grants += 1;
            }
        }
        Err(error) => tracing::warn!(%error, "could not list expired uploads"),
    }

    // (2) `incoming/` directories with no grant behind them.
    match store.all_upload_ids() {
        Ok(live) => {
            let live: HashSet<String> = live.into_iter().collect();
            for id in blobs.incoming_on_disk() {
                if !live.contains(&id) {
                    blobs.discard_upload(&id);
                    swept.orphan_incoming += 1;
                }
            }
        }
        Err(error) => tracing::warn!(%error, "could not list uploads"),
    }

    // (3) Snapshot directories with no row — the crash-between-rename-
    // and-insert case. Deleted, never adopted.
    match store.all_retained_keys() {
        Ok(rows) => {
            let rows: HashSet<(String, String)> = rows.into_iter().collect();
            for (handle, digest) in blobs.retained_on_disk() {
                if !rows.contains(&(handle.clone(), digest.clone())) {
                    if let Err(error) = blobs.erase(&handle, &digest) {
                        tracing::warn!(%error, "could not erase orphan snapshot");
                        continue;
                    }
                    swept.orphan_snapshots += 1;
                }
            }
        }
        Err(error) => tracing::warn!(%error, "could not list snapshots"),
    }

    swept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::UploadRow;

    fn upload_row(id: &str, handle: &str, digest: &str) -> UploadRow {
        UploadRow {
            upload_id: id.into(),
            holder_handle: handle.into(),
            operation_id: "op".into(),
            digest: digest.into(),
            sealed_byte_size: 3,
            chunk_bytes: 8,
            chunk_count: 1,
            accepted_terms_id: "terms".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
        }
    }

    const HANDLE: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn an_expired_grant_gives_its_disk_back() {
        let store = Store::in_memory().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        store
            .begin_upload(
                "u1", HANDLE, "op", "sha256:aa", 3, 8, 1, "terms",
                "2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z",
            )
            .unwrap();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-01T00:00:00Z");
        assert_eq!(swept.expired_grants, 1);
        assert!(store.upload("u1").unwrap().is_none());
        assert!(blobs.incoming_on_disk().is_empty());
    }

    #[test]
    fn a_live_grant_is_left_alone() {
        let store = Store::in_memory().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        store
            .begin_upload(
                "u1", HANDLE, "op", "sha256:aa", 3, 8, 1, "terms",
                "2026-01-01T00:00:00Z", "2999-01-01T00:00:00Z",
            )
            .unwrap();
        blobs.begin_upload("u1").unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-02T00:00:00Z");
        assert_eq!(swept.expired_grants, 0);
        assert_eq!(swept.orphan_incoming, 0);
        assert!(store.upload("u1").unwrap().is_some());
    }

    /// The crash-between-rename-and-insert case.
    #[test]
    fn bytes_with_no_row_are_deleted_not_adopted() {
        let store = Store::in_memory().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.commit("u1", HANDLE, "aa").unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-01T00:00:00Z");
        assert_eq!(swept.orphan_snapshots, 1);
        assert!(blobs.read_snapshot(HANDLE, "aa").is_err());
        // And nothing was invented: the operator does not now claim to
        // hold a snapshot whose digest it never checked.
        assert!(store.all_retained_keys().unwrap().is_empty());
    }

    #[test]
    fn a_snapshot_with_a_row_survives() {
        let store = Store::in_memory().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.commit("u1", HANDLE, "aa").unwrap();
        store
            .retain(&upload_row("u1", HANDLE, "sha256:aa"), "2026-01-01T00:00:00Z")
            .unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-01T00:00:00Z");
        assert_eq!(swept.orphan_snapshots, 0);
        assert_eq!(blobs.read_snapshot(HANDLE, "aa").unwrap(), b"abc");
    }
}
