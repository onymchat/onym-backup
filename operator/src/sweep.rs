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
    pub post_grace_snapshots: usize,
    pub aged_entitlements: usize,
    pub forgotten_lapse_state: usize,
    pub expired_grants: usize,
    pub orphan_incoming: usize,
    pub orphan_snapshots: usize,
    pub unavailable_snapshots: usize,
    pub spent_nonces: usize,
    pub aged_outcomes: usize,
    pub aged_receipts: usize,
    pub forgotten_references: usize,
}

pub struct Cutoffs<'a> {
    pub now: &'a str,
    pub nonce: &'a str,
    pub outcome: &'a str,
    pub receipt: &'a str,
    pub erased_reference: &'a str,
    /// Entitlement records past `expiresAt` plus one revocation-epoch
    /// interval — §15's normative bound, and what
    /// `metadataRetention.entitlementRecords` declares.
    pub entitlement: &'a str,
}

/// Runs at boot and then on a timer, on the blocking pool. Failures are
/// logged, not fatal: an operator that will not serve because it could
/// not tidy up is worse than one carrying some dead bytes.
///
/// Synchronous by design — it does blocking disk work, so it belongs on
/// a blocking thread, and `blocking_lock` is the right way to take the
/// store from one.
pub fn reconcile(
    store: &Mutex<Store>,
    blob_mutations: &Mutex<()>,
    blobs: &Blobs,
    revoked: &HashSet<String>,
    now_at: time::OffsetDateTime,
    cutoffs: Cutoffs<'_>,
) -> Swept {
    let Cutoffs {
        now,
        nonce: nonce_floor,
        outcome: outcome_floor,
        receipt: receipt_floor,
        erased_reference: erased_floor,
        entitlement: entitlement_floor,
    } = cutoffs;
    let mut swept = Swept {
        post_grace_snapshots: 0,
        aged_entitlements: 0,
        forgotten_lapse_state: 0,
        expired_grants: 0,
        orphan_incoming: 0,
        orphan_snapshots: 0,
        unavailable_snapshots: 0,
        spent_nonces: 0,
        aged_outcomes: 0,
        aged_receipts: 0,
        forgotten_references: 0,
    };

    // (0) Snapshots whose own grace window closed.
    //
    // First, because marking one `retention_expired` drops it out of
    // the live set and step (4) then collects its bytes as an orphan in
    // the same pass — one deletion path rather than two.
    //
    // **Reported as retention expiry, not as erasure.** The holder did
    // not erase it; its retention ran out, which is what the terms they
    // accepted said would happen. No receipt is minted: §11 receipts
    // answer a holder's erase request, and signing one nobody asked for
    // would be evidence of a decision the holder did not make.
    let holders = match store.blocking_lock().holders_with_snapshots() {
        Ok(holders) => holders,
        Err(error) => {
            tracing::warn!(%error, "could not list holders");
            Vec::new()
        }
    };
    for handle in holders {
        let due = match crate::lapse::post_grace_due(
            &store.blocking_lock(),
            &handle,
            revoked,
            now_at,
        ) {
            Ok(due) => due,
            Err(error) => {
                tracing::warn!(%error, "could not evaluate post-grace state");
                continue;
            }
        };
        for (digest, after_grace) in due {
            // Only `erase` is implemented. A terms document declaring a
            // cold state is promising something this operator does not
            // do, and the safe reading of an unimplemented clause is to
            // keep the bytes and say so — deleting on a clause we
            // cannot honour would be the one irreversible way to be
            // wrong about it.
            if after_grace != "erase" {
                tracing::warn!(
                    %after_grace,
                    "terms declare a post-grace state this operator does not implement; keeping the snapshot"
                );
                continue;
            }
            let _mutation = blob_mutations.blocking_lock();
            match store.blocking_lock().mark_unavailable(&handle, &digest, now) {
                Ok(changed) => swept.post_grace_snapshots += changed,
                Err(error) => tracing::warn!(%error, "could not expire a post-grace snapshot"),
            }
        }
    }

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
        if let Err(error) = blobs.discard_upload(&id) {
            tracing::warn!(%error, "could not discard expired upload bytes");
            continue;
        }
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
            match blobs.discard_upload(&id) {
                Ok(()) => swept.orphan_incoming += 1,
                Err(error) => tracing::warn!(%error, "could not discard orphan upload"),
            }
        }
    }

    // (3) Rows whose committed bytes are absent or incomplete. The
    // profile is explicit: such a row is marked unavailable and is
    // never reported as retained.
    let claimed = match store.blocking_lock().all_live_snapshots() {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "could not list live snapshots");
            Vec::new()
        }
    };
    for (handle, row) in claimed {
        let _mutation = blob_mutations.blocking_lock();
        let still_live = match store.blocking_lock().snapshot_exists(&handle, &row.digest) {
            Ok(live) => live,
            Err(error) => {
                tracing::warn!(%error, "could not re-check live snapshot");
                continue;
            }
        };
        if !still_live {
            continue;
        }
        let digest = match crate::blobs::digest_hex(&row.digest) {
            Ok(digest) => digest,
            Err(error) => {
                tracing::warn!(%error, "stored snapshot has an invalid digest");
                continue;
            }
        };
        match blobs.chunk_paths(&handle, &digest, row.chunk_count, row.sealed_byte_size) {
            Ok(_) => {}
            Err(crate::error::Error::RetentionExpired) => {
                match store
                    .blocking_lock()
                    .mark_unavailable(&handle, &row.digest, now)
                {
                    Ok(changed) => swept.unavailable_snapshots += changed,
                    Err(error) => {
                        tracing::warn!(%error, "could not mark snapshot unavailable")
                    }
                }
            }
            Err(error) => tracing::warn!(%error, "could not inspect retained snapshot"),
        }
    }

    // (3b) Entitlement records past §15's bound — `expiresAt` plus one
    // revocation-epoch interval — and the derived lifecycle state that
    // takes over from them. A window nothing enforces is a window in
    // name only, and this is the one whose bound is normative rather
    // than self-declared.
    //
    // Derive first, then delete. The record is what lapse is read from,
    // and §15's bound falls due long before the grace it opened runs
    // out, so something must carry the horizon across: four fields
    // saying when the holder lapsed and when the last window they were
    // promised ends. Not the credential, not the `entitlementId`, not
    // the offer or the issuer — see `store::LapseState`.
    //
    // Per holder rather than one statement over the table, so a
    // derivation that fails leaves that holder's records in place
    // rather than dropping them with nothing behind them.
    //
    // **The step order no longer carries anything.** It used to: the
    // old floor was the last grace window plus one poll interval, so
    // the pass that first found a record deletable was the same pass
    // that had to act on it, and a transient failure in step (0)
    // orphaned the snapshot permanently. Now the horizon outlives the
    // record by construction, and the derived row is retired in (3c)
    // only once nothing is due from it.
    let losing = match store
        .blocking_lock()
        .holders_losing_entitlements(entitlement_floor)
    {
        Ok(holders) => holders,
        Err(error) => {
            tracing::warn!(%error, "could not list holders losing entitlement records");
            Vec::new()
        }
    };
    for handle in losing {
        let store = store.blocking_lock();
        let derived = match crate::lapse::derive_lapse_state(&store, &handle, revoked) {
            // Nothing retained, so nothing is owed a window: the record
            // goes and leaves no successor, which is the point of
            // holding lifecycle state only for holders who have
            // something to lose.
            Ok(None) => true,
            Ok(Some(state)) => match store.record_lapse_state(&handle, &state) {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(%error, "could not persist derived lapse state");
                    false
                }
            },
            Err(error) => {
                tracing::warn!(%error, "could not derive lapse state");
                false
            }
        };
        if !derived {
            continue;
        }
        match store.sweep_entitlements(&handle, entitlement_floor) {
            Ok(count) => swept.aged_entitlements += count,
            Err(error) => tracing::warn!(%error, "could not sweep entitlement records"),
        }
    }

    // (3c) Derived lifecycle state that has outlived its purpose.
    //
    // Retired only when the last window it records has closed *and*
    // nothing is still due from it. The second condition is what makes
    // a transient failure in step (0) survivable: a `mark_unavailable`
    // that failed leaves the snapshot in `post_grace_due`, so the row
    // stays and the next pass tries again. The row's real bound is
    // "once it has been acted on", which is the only bound that cannot
    // strand a snapshot.
    //
    // A `post_grace_action` this operator does not implement keeps the
    // row too, for the reason step (0) keeps the bytes: the promise it
    // records has not been honoured, and forgetting it would be the
    // operator tidying away the evidence of that.
    let lapsed = match store.blocking_lock().lapsed_holders() {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "could not list derived lapse state");
            Vec::new()
        }
    };
    for (handle, state) in lapsed {
        let closed = time::OffsetDateTime::parse(
            &state.grace_expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok_and(|ends| now_at >= ends);
        if !closed || state.post_grace_action != "erase" {
            continue;
        }
        let store = store.blocking_lock();
        match crate::lapse::post_grace_due(&store, &handle, revoked, now_at) {
            Ok(due) if due.is_empty() => match store.forget_lapse_state(&handle) {
                Ok(count) => swept.forgotten_lapse_state += count,
                Err(error) => tracing::warn!(%error, "could not forget derived lapse state"),
            },
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "could not re-check post-grace state"),
        }
    }

    // (4) Snapshot directories with no row — the crash-between-rename-
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
        // Commit and erase take this before the store lock too. Keep
        // the fresh row check and the unlink in the same mutation
        // critical section so a re-upload cannot revive the row
        // between them and then lose its newly committed bytes.
        let _mutation = blob_mutations.blocking_lock();
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

    // (5) Spent nonces. The table is the replay defence, and it is the
    // one piece of per-holder state that grows with traffic rather than
    // with what is stored — leaving it unbounded would make the replay
    // window's own bookkeeping the largest thing the operator keeps
    // about a holder, which §15 is precisely about not doing.
    match store.blocking_lock().sweep_nonces(nonce_floor) {
        Ok(count) => swept.spent_nonces = count,
        Err(error) => tracing::warn!(%error, "could not sweep nonces"),
    }

    // (6–7) Outcomes, receipts, and receipt coverage. Upload outcomes
    // use the short declared window; erase outcomes use the receipt
    // window. The latter and the receipts they name cross their bound
    // atomically, as do receipt rows and their coverage.
    let metadata = store
        .blocking_lock()
        .sweep_outcomes_and_receipts(outcome_floor, receipt_floor);
    match metadata {
        Ok((outcomes, receipts)) => {
            swept.aged_outcomes = outcomes;
            swept.aged_receipts = receipts;
        }
        Err(error) => tracing::warn!(%error, "could not sweep outcomes and receipts"),
    }

    // (8) Erased references past their window. Every promise that
    // rides on the row ends here too: `list` stops reporting `erased`
    // and `/v1/erasures` stops answering `receipt_expired`, because the
    // operator has genuinely forgotten rather than chosen to be coy.
    match store.blocking_lock().sweep_erased_references(erased_floor) {
        Ok(count) => swept.forgotten_references = count,
        Err(error) => tracing::warn!(%error, "could not sweep erased references"),
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

    fn cutoffs<'a>(
        now: &'a str,
        nonce: &'a str,
        outcome: &'a str,
        receipt: &'a str,
        erased_reference: &'a str,
    ) -> Cutoffs<'a> {
        Cutoffs {
            now,
            nonce,
            outcome,
            receipt,
            erased_reference,
            entitlement: "2000-01-01T00:00:00Z",
        }
    }

    /// These tests are about bytes and rows, not payment. A free
    /// operator holds no entitlements, so an empty revoked set and a
    /// fixed clock are the whole of what post-grace expiry needs to
    /// find nothing to do.
    fn unpaid() -> (HashSet<String>, time::OffsetDateTime) {
        (
            HashSet::new(),
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        )
    }

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

        let swept = reconcile(
            &store,
            &Mutex::new(()),
            &blobs,
            &unpaid().0,
            unpaid().1,
            cutoffs(
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
            ),
        );
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

        let swept = reconcile(
            &store,
            &Mutex::new(()),
            &blobs,
            &unpaid().0,
            unpaid().1,
            cutoffs(
                "2026-01-02T00:00:00Z",
                "2026-01-02T00:00:00Z",
                "2026-01-02T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
            ),
        );
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
        blobs.commit("u1", HANDLE, "aa", 1, 3).unwrap();

        let swept = reconcile(
            &store,
            &Mutex::new(()),
            &blobs,
            &unpaid().0,
            unpaid().1,
            cutoffs(
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
            ),
        );
        assert_eq!(swept.orphan_snapshots, 1);
        assert!(blobs.read_snapshot(HANDLE, "aa").is_err());
        // And nothing was invented: the operator does not now claim to
        // hold a snapshot whose digest it never checked.
        assert!(
            store
                .blocking_lock()
                .all_retained_keys()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_snapshot_with_a_row_survives() {
        let store = Mutex::new(Store::in_memory().unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.commit("u1", HANDLE, "aa", 1, 3).unwrap();
        store
            .blocking_lock()
            .retain(&upload_row("u1", HANDLE, "sha256:aa"), "2026-01-01T00:00:00Z")
            .unwrap();

        let swept = reconcile(
            &store,
            &Mutex::new(()),
            &blobs,
            &unpaid().0,
            unpaid().1,
            cutoffs(
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
            ),
        );
        assert_eq!(swept.orphan_snapshots, 0);
        assert_eq!(blobs.read_snapshot(HANDLE, "aa").unwrap(), b"abc");
    }

    #[test]
    fn a_row_without_complete_bytes_is_marked_unavailable() {
        let store = Mutex::new(Store::in_memory().unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let blobs = Blobs::new(dir.path());
        let digest = format!("sha256:{}", "aa".repeat(32));
        store
            .blocking_lock()
            .retain(&upload_row("u1", HANDLE, &digest), "2026-01-01T00:00:00Z")
            .unwrap();

        let swept = reconcile(
            &store,
            &Mutex::new(()),
            &blobs,
            &unpaid().0,
            unpaid().1,
            cutoffs(
                "2026-01-02T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
            ),
        );
        assert_eq!(swept.unavailable_snapshots, 1);
        assert!(
            !store
                .blocking_lock()
                .snapshot_exists(HANDLE, &digest)
                .unwrap()
        );
        let row = store
            .blocking_lock()
            .snapshot_record(HANDLE, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(row.retained_until.as_deref(), Some("2026-01-02T00:00:00Z"));
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

        let swept = reconcile(
            &store,
            &Mutex::new(()),
            &blobs,
            &unpaid().0,
            unpaid().1,
            cutoffs(
                "2026-01-01T12:00:00Z",
                "2026-01-01T06:00:00Z",
                "2026-01-01T12:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
            ),
        );
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
