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
//! It also collects abandoned uploads and spent nonces. A grant that
//! expired is disk nobody is coming back for, and without this the only
//! bound on `incoming/` would be the goodwill of clients that finish
//! what they start.
//!
//! **The store lock is taken in short bursts, never across the disk
//! walk.** Listing every holder and digest under a large blob root is
//! not something to do while holding the one mutex every request needs
//! — an hourly stall is still a stall. The walk runs unlocked, and
//! every deletion re-checks the bookkeeping under the lock immediately
//! before it happens: preflight and commit both hold the lock across
//! their write-bytes-then-write-row pairs, so a row that is absent at
//! that moment is absent for good.

use std::collections::HashSet;

use tokio::sync::Mutex;

use crate::blobs::Blobs;
use crate::store::Store;

pub struct Swept {
    pub expired_grants: usize,
    pub orphan_incoming: usize,
    pub orphan_snapshots: usize,
    pub spent_nonces: usize,
}

/// Runs at boot and then on a timer, on the blocking pool. Failures are
/// logged, not fatal: an operator that will not serve because it could
/// not tidy up is worse than one carrying some dead bytes.
///
/// Synchronous by design — it does blocking disk work, so it belongs on
/// a blocking thread, and `blocking_lock` is the right way to take the
/// store from one.
pub fn reconcile(store: &Mutex<Store>, blobs: &Blobs, now: &str, nonce_floor: &str) -> Swept {
    let mut swept = Swept {
        expired_grants: 0,
        orphan_incoming: 0,
        orphan_snapshots: 0,
        spent_nonces: 0,
    };

    // (1) Grants that ran out. The bytes go first: if the row survives
    // a crash here the next sweep finds it again, whereas a row deleted
    // before its bytes leaves an orphan nothing points at.
    let expired = match store.blocking_lock().expired_uploads(now) {
        Ok(ids) => ids,
        Err(error) => {
            tracing::warn!(%error, "could not list expired uploads");
            Vec::new()
        }
    };
    for id in expired {
        blobs.discard_upload(&id);
        if let Err(error) = store.blocking_lock().drop_upload(&id) {
            tracing::warn!(%error, "could not drop expired upload row");
            continue;
        }
        swept.expired_grants += 1;
    }

    // (2) `incoming/` directories with no grant behind them. The walk
    // is unlocked; the check that decides is not.
    for id in blobs.incoming_on_disk() {
        let known = match store.blocking_lock().upload(&id) {
            Ok(row) => row.is_some(),
            Err(error) => {
                tracing::warn!(%error, "could not check upload row");
                continue;
            }
        };
        if !known {
            blobs.discard_upload(&id);
            swept.orphan_incoming += 1;
        }
    }

    // (3) Snapshot directories with no row — the crash-between-rename-
    // and-insert case. Deleted, never adopted.
    //
    // The live set is read once, unlocked work happens against it, and
    // each deletion re-checks. Commit holds the lock across the rename
    // and the insert, so a digest absent from a fresh read is a digest
    // no commit is midway through.
    let live: HashSet<(String, String)> = match store.blocking_lock().all_retained_keys() {
        Ok(rows) => rows.into_iter().collect(),
        Err(error) => {
            tracing::warn!(%error, "could not list snapshots");
            return swept;
        }
    };
    for (handle, digest) in blobs.retained_on_disk() {
        if live.contains(&(handle.clone(), digest.clone())) {
            continue;
        }
        let still_absent = match store
            .blocking_lock()
            .snapshot_exists(&handle, &format!("sha256:{digest}"))
        {
            Ok(exists) => !exists,
            Err(error) => {
                tracing::warn!(%error, "could not re-check snapshot row");
                continue;
            }
        };
        if !still_absent {
            continue;
        }
        if let Err(error) = blobs.erase(&handle, &digest) {
            tracing::warn!(%error, "could not erase orphan snapshot");
            continue;
        }
        swept.orphan_snapshots += 1;
    }

    // (4) Spent nonces. The table is the replay defence, and it is the
    // one piece of per-holder state that grows with traffic rather than
    // with what is stored — leaving it unbounded would make the replay
    // window's own bookkeeping the largest thing the operator keeps
    // about a holder, which §15 is precisely about not doing.
    match store.blocking_lock().sweep_nonces(nonce_floor) {
        Ok(count) => swept.spent_nonces = count,
        Err(error) => tracing::warn!(%error, "could not sweep nonces"),
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
            supersedes: None,
            expires_at: "2999-01-01T00:00:00Z".into(),
        }
    }

    const HANDLE: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn an_expired_grant_gives_its_disk_back() {
        let store = Mutex::new(Store::in_memory().unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        store
            .blocking_lock()
            .begin_upload(
                "u1", HANDLE, "op", "sha256:aa", 3, 8, 1, "terms", None,
                "2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z",
            )
            .unwrap();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
        assert_eq!(swept.expired_grants, 1);
        assert!(store.blocking_lock().upload("u1").unwrap().is_none());
        assert!(blobs.incoming_on_disk().is_empty());
    }

    #[test]
    fn a_live_grant_is_left_alone() {
        let store = Mutex::new(Store::in_memory().unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        store
            .blocking_lock()
            .begin_upload(
                "u1", HANDLE, "op", "sha256:aa", 3, 8, 1, "terms", None,
                "2026-01-01T00:00:00Z", "2999-01-01T00:00:00Z",
            )
            .unwrap();
        blobs.begin_upload("u1").unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z");
        assert_eq!(swept.expired_grants, 0);
        assert_eq!(swept.orphan_incoming, 0);
        assert!(store.blocking_lock().upload("u1").unwrap().is_some());
    }

    /// The crash-between-rename-and-insert case.
    #[test]
    fn bytes_with_no_row_are_deleted_not_adopted() {
        let store = Mutex::new(Store::in_memory().unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.commit("u1", HANDLE, "aa").unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
        assert_eq!(swept.orphan_snapshots, 1);
        assert!(blobs.read_snapshot(HANDLE, "aa").is_err());
        // And nothing was invented: the operator does not now claim to
        // hold a snapshot whose digest it never checked.
        assert!(store.blocking_lock().all_retained_keys().unwrap().is_empty());
    }

    #[test]
    fn a_snapshot_with_a_row_survives() {
        let store = Mutex::new(Store::in_memory().unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.commit("u1", HANDLE, "aa").unwrap();
        store
            .blocking_lock()
            .retain(&upload_row("u1", HANDLE, "sha256:aa"), "2026-01-01T00:00:00Z")
            .unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
        assert_eq!(swept.orphan_snapshots, 0);
        assert_eq!(blobs.read_snapshot(HANDLE, "aa").unwrap(), b"abc");
    }

    /// The replay table is the one piece of per-holder state that grows
    /// with traffic rather than with what is stored. Leaving it
    /// unbounded would make the replay window's own bookkeeping the
    /// largest thing the operator keeps about a holder.
    #[test]
    fn spent_nonces_are_collected() {
        let store = Mutex::new(Store::in_memory().unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        store
            .blocking_lock()
            .record_nonce(HANDLE, "old", "2026-01-01T00:00:00Z")
            .unwrap();
        store
            .blocking_lock()
            .record_nonce(HANDLE, "fresh", "2026-01-01T12:00:00Z")
            .unwrap();

        let swept = reconcile(&store, &blobs, "2026-01-01T12:00:00Z", "2026-01-01T06:00:00Z");
        assert_eq!(swept.spent_nonces, 1);

        // The one still inside the window is still refused, which is
        // the property the table exists for.
        assert!(
            !store
                .blocking_lock()
                .record_nonce(HANDLE, "fresh", "2026-01-01T12:00:01Z")
                .unwrap(),
            "a live nonce was swept and could be replayed"
        );
    }
}
