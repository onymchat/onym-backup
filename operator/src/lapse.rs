//! Lapse, grace, and the explicit allowlist that decides what a lapsed
//! holder can still do.
//!
//! **Lapse is derived from entitlement expiry, never from a failed
//! charge.** This operator is not the seller and has no charge to fail
//! (§10.3). What it knows is when the last credential it was shown
//! stops being valid.
//!
//! Two rules from §10.3 shape everything here, and both cut against the
//! obvious implementation:
//!
//! 1. **Each retained snapshot is governed by its own pinned terms.**
//!    Not by the operator's current terms, and not by one account-wide
//!    clause. Forward-only binding means a client refuses to upload
//!    under terms weaker than those a retained snapshot already pins,
//!    so across a holder's snapshots the terms *strengthen* with age —
//!    the oldest pins the least protective set. An operator reaching
//!    for "the holder's terms" and finding the oldest would hand every
//!    newer snapshot a shorter notice and a shorter grace than the
//!    person consented to.
//!
//! 2. **What stays open is the union across snapshots.** A route is
//!    either open or closed, so that one thing must be decided
//!    holder-wide; and an operation any snapshot's `duringGrace`
//!    promises stays available while that snapshot is in grace.
//!    Refusing wholesale what the holder is owed on one snapshot is the
//!    same under-delivery in another form.
//!
//! And the allowlist below is a table rather than a scattering of
//! checks because §10.3 requires exactly that: "an explicit allowlist
//! in the authorization path, not an emergent property of which routes
//! happen to check an entitlement."

use std::collections::HashSet;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::api::AppState;
use crate::auth::Holder;
use crate::documents::duration_seconds;
use crate::error::{Error, Result};
use crate::store::Store;

/// Every §9 operation, and the only place their lapse behaviour is
/// written down.
///
/// `Export`, `Upload` and `Commit` are never constructed outside the
/// tests below, and that is the design rather than an oversight.
///
/// §9.7 requires the export path to be one that never *consults*
/// entitlement state, not one that consults it and allows — and a test
/// scans that module for payment symbols to hold it there. §9.2 puts
/// the chunk and commit routes in the same position for a different
/// reason: what authorizes them is the grant, and consulting lapse
/// there could only ever produce a refusal the profile forbids.
///
/// The variants exist so this table can state their answer alongside
/// every other route's. A variant that says "never gated", for a
/// reason, is a decision somebody can read; a route that simply stopped
/// appearing here is one nobody can tell from an omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Operation {
    Register,
    Preflight,
    Upload,
    Commit,
    List,
    Download,
    Erase,
    Export,
    Reconcile,
}

impl Operation {
    /// The `duringGrace` term a terms document would use for this
    /// operation, if any.
    ///
    /// `None` means the operation is not gateable — see
    /// `always_available`. The vocabulary is the terms document's, not
    /// ours: a clause promising `download` must be read as promising
    /// this route.
    fn grace_term(self) -> Option<&'static str> {
        match self {
            Operation::Download => Some("download"),
            Operation::Erase => Some("erase"),
            Operation::Export => Some("export"),
            _ => None,
        }
    }

    /// Operations lapse never closes, and why each one is on the list.
    ///
    /// This is the part that must be explicit. Every entry is a
    /// deliberate decision, not a route that happened to skip a check.
    fn always_available(self) -> bool {
        match self {
            // §9.7 and the `export` module's own guard: export is never
            // gated on payment, by anything, ever. A holder who stopped
            // paying is exactly the holder who needs to get their bytes
            // out.
            Operation::Export => true,
            // How a holder stops being lapsed. Gating it would make the
            // lapse permanent.
            Operation::Register => true,
            // A holder who cannot see what they hold cannot decide what
            // to rescue, and grace they cannot navigate is not grace.
            // Listing is also the only way to learn a snapshot is in
            // grace at all.
            Operation::List => true,
            // §9.8 answers "what happened to the operation whose
            // response I lost". Refusing it would strand a holder
            // between two states rather than charge them for anything.
            Operation::Reconcile => true,
            // Never gated — and this entry exists so that is a stated
            // decision rather than a route that quietly stopped asking.
            //
            // §9.2: "A grant is an obligation the operator already
            // accepted: the entitlement was checked when it was minted,
            // and some of the bytes are already on the operator's
            // disk... Finishing an upload the operator agreed to take
            // is the smaller commitment." A holder whose seat lapses
            // mid-upload would otherwise hold a grant they can neither
            // finish nor abandon, consuming quota until it expires,
            // while download, export and erase keep working around it.
            //
            // It cannot become a way to store snapshots unpaid: neither
            // route can exist without a live grant, the grant's own
            // `expiresAt` bounds it and is never extended, and
            // `Preflight` — the only route that mints one — is gated.
            // A lapsed holder finishes what was in flight and gets
            // nothing further.
            Operation::Upload | Operation::Commit => true,
            // Everything else is decided by the terms.
            _ => false,
        }
    }

    /// Whether a lapse closes this operation for the whole holder even
    /// while a snapshot is still in grace.
    ///
    /// §10.3: "`preflight` and upload refuse for the whole holder,
    /// because a lapsed holder is not owed new retention by any
    /// snapshot's terms." Grace protects what is already stored; it
    /// does not buy room for more.
    ///
    /// Read against §9.2, that sentence bounds the *creation* of a
    /// grant, not the use of one already issued: `Preflight` is the
    /// only route that mints an `uploadId`, so gating it is what closes
    /// the upload path holder-wide. `Upload` and `Commit` are
    /// `always_available` above and never reach this table — the check
    /// they carry is the grant itself, which the operator issued while
    /// the holder was entitled and which expires on its own clock.
    fn refused_holder_wide(self) -> bool {
        matches!(self, Operation::Preflight)
    }
}

/// What a holder's payment state permits right now.
pub enum Access {
    /// A live entitlement, or a free operator — nothing is gated.
    Entitled,
    /// Never presented a credential this operator could verify. The
    /// `402` that starts the payment loop.
    Unpaid,
    /// Lapsed, with at least one snapshot still inside its own terms'
    /// notice-plus-grace window.
    Grace {
        /// The union of `duringGrace` across snapshots still in grace.
        allowed: HashSet<String>,
    },
    /// Lapsed, and every snapshot is past its grace.
    Lapsed,
}

/// Decide a holder's payment state.
///
/// Order matters. A credential presented on this request is believed
/// first — a holder who just renewed should not be told they lapsed
/// because the store has not caught up — and registering it here is
/// what lets the *next* request know, including the ones that carry no
/// header.
pub fn evaluate(
    state: &AppState,
    store: &Store,
    holder: &Holder,
    headers: &axum::http::HeaderMap,
    now: OffsetDateTime,
) -> Result<Access> {
    if !state.config.requires_entitlement() {
        return Ok(Access::Entitled);
    }

    if let Some(verified) = crate::entitlements::presented(headers, state, &holder.reference, now)? {
        let stamp = now
            .format(&Rfc3339)
            .map_err(|e| Error::Internal(format!("format timestamp: {e}")))?;
        // Registering it is what un-lapses them: the next evaluation
        // reads a newer horizon, and the sweep derives from the same
        // one. There is no lapse flag to clear, which is the point of
        // deriving rather than storing.
        store.register_entitlement(&holder.handle, &verified, &stamp)?;
        return Ok(Access::Entitled);
    }

    let revoked = state.revocation.revoked();
    let Some((horizon, horizon_revoked)) = store.entitlement_horizon(&holder.handle, &revoked)?
    else {
        // No record at all. Either they never paid, or their records
        // aged out of `entitlementRecords` — which is well past every
        // grace window either way.
        return Ok(if store.has_entitlement_record(&holder.handle)? {
            Access::Lapsed
        } else {
            Access::Unpaid
        });
    };

    let expires_at = OffsetDateTime::parse(&horizon, &Rfc3339)
        .map_err(|e| Error::Internal(format!("stored entitlement expiry: {e}")))?;
    if !horizon_revoked && now < expires_at {
        // Registered, unexpired, just not attached to this request.
        return Ok(Access::Entitled);
    }

    // Revoked and not yet at its own `expiresAt`: still blocked from new
    // paid work — the shortcut above is what grants `Entitled`, and it
    // was skipped — but the terms a snapshot was accepted under still
    // govern it, so grace is derived from the same `expiresAt` the
    // credential itself declared rather than from the moment revocation
    // was noticed.
    grace_from(store, holder, expires_at, now)
}

/// The union of what each snapshot's own terms still promise.
fn grace_from(
    store: &Store,
    holder: &Holder,
    lapsed_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<Access> {
    let mut allowed: HashSet<String> = HashSet::new();
    let mut any_in_grace = false;

    for row in store.snapshots(&holder.handle)? {
        let Some(clause) = end_of_payment(store, &row.accepted_terms_id)? else {
            continue;
        };
        let Some(ends) = clause.window_end(lapsed_at) else {
            continue;
        };
        if now >= ends {
            continue;
        }
        any_in_grace = true;
        allowed.extend(clause.during_grace.iter().cloned());
    }

    Ok(if any_in_grace {
        Access::Grace { allowed }
    } else {
        Access::Lapsed
    })
}

/// One snapshot's `endOfPayment` clause.
struct EndOfPayment {
    notice_secs: i64,
    grace_secs: i64,
    during_grace: Vec<String>,
    after_grace: String,
}

impl EndOfPayment {
    /// When protection actually ends: notice, then grace, both counted
    /// from the lapse. Reading them as alternatives rather than as a
    /// sequence would halve what the holder was promised.
    fn window_end(&self, lapsed_at: OffsetDateTime) -> Option<OffsetDateTime> {
        let total = self.notice_secs.checked_add(self.grace_secs)?;
        lapsed_at.checked_add(time::Duration::seconds(total))
    }
}

/// Read the clause out of a snapshot's *own* pinned terms.
///
/// The document is fetched by `termsId` from the store rather than
/// taken from `state.documents`, because the whole point of §10.3 is
/// that a snapshot is governed by what it was accepted under — which,
/// after any terms change, is not what this operator publishes today.
fn end_of_payment(store: &Store, terms_id: &str) -> Result<Option<EndOfPayment>> {
    let Some((raw, _)) = store.terms_document(terms_id)? else {
        // A pin with no preimage. §4.1 forbids this and `remember_terms`
        // prevents it, so it means the store was edited underneath us.
        // Treating it as "no grace" would be the operator quietly
        // shortening a window it can no longer read, so it contributes
        // nothing to the union and is said out loud instead.
        tracing::error!(%terms_id, "a retained snapshot pins terms this operator cannot produce");
        return Ok(None);
    };
    let document: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| Error::Internal(format!("stored terms are not JSON: {e}")))?;
    let Some(clause) = document.get("endOfPayment") else {
        return Ok(None);
    };
    let string = |key: &str| clause.get(key).and_then(serde_json::Value::as_str);

    let (Some(notice), Some(grace)) = (string("notice"), string("grace")) else {
        return Ok(None);
    };
    let (Some(notice_secs), Some(grace_secs)) = (duration_seconds(notice), duration_seconds(grace))
    else {
        tracing::error!(%terms_id, "endOfPayment declares an unreadable duration");
        return Ok(None);
    };

    Ok(Some(EndOfPayment {
        notice_secs,
        grace_secs,
        during_grace: clause
            .get("duringGrace")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        after_grace: string("afterGrace").unwrap_or("erase").to_string(),
    }))
}

/// Snapshots whose own grace window has closed, and what their terms
/// say happens next.
///
/// Evaluated **per snapshot, not per holder**. §10.3 governs each
/// snapshot by its own pinned terms, and a holder's snapshots do not
/// share a window — an older one pinning a shorter grace runs out while
/// a newer one is still protected. Collapsing this to the holder would
/// either delete the protected snapshot early or hold the expired one
/// past what was promised.
///
/// Returns `(digest, afterGrace)` pairs. The caller decides what to do
/// with the clause; this only says the window is over.
pub fn post_grace_due(
    store: &Store,
    handle: &str,
    revoked: &HashSet<String>,
    now: OffsetDateTime,
) -> Result<Vec<(String, String)>> {
    let Some((horizon, _)) = store.entitlement_horizon(handle, revoked)? else {
        // Nothing to lapse from. A holder with no entitlement record on
        // a charging operator is one whose records aged out — and
        // acting on that would make `entitlementRecords` expiry into a
        // deletion trigger, which is not what a retention bound is.
        return Ok(Vec::new());
    };
    let lapsed_at = OffsetDateTime::parse(&horizon, &Rfc3339)
        .map_err(|e| Error::Internal(format!("stored entitlement expiry: {e}")))?;
    if now < lapsed_at {
        return Ok(Vec::new());
    }

    let mut due = Vec::new();
    for row in store.snapshots(handle)? {
        let Some(clause) = end_of_payment(store, &row.accepted_terms_id)? else {
            continue;
        };
        let Some(ends) = clause.window_end(lapsed_at) else {
            continue;
        };
        if now >= ends {
            due.push((row.digest, clause.after_grace.clone()));
        }
    }
    Ok(due)
}

/// How long an entitlement record must outlive its own `expiresAt`,
/// and the cutoff `sweep_entitlements` deletes below.
///
/// This is the whole of finding: **the record is what lapse is derived
/// from.** `evaluate` reads `expires_at` to decide whether a holder is
/// in grace, and `post_grace_due` reads the same field to decide when
/// the snapshot's own window has closed. A row swept at expiry plus the
/// poll interval takes both derivations with it: the holder is
/// classified `Unpaid` rather than `Grace` — closing the download and
/// erase their terms promised for another six weeks — and
/// `post_grace_due` returns empty forever, so the bytes are never
/// expired at all. Deleting a record early is not a cheaper version of
/// deleting it on time; it is deleting the evidence of an obligation
/// while the obligation is still running.
///
/// So the floor is expiry, plus the longest `notice + grace` any terms
/// document this operator has published declares, plus one
/// revocation-epoch interval. The first term covers the derivation, the
/// second covers a revocation landing just before expiry.
///
/// The longest across *all* published terms rather than the current
/// ones, because a snapshot keeps the terms it was accepted under
/// (§5.4): the document governing the oldest retained snapshot may
/// promise a longer window than the one this operator publishes today,
/// and it is that promise the record has to outlive.
///
/// One record class, not two. The alternative — sweeping on time and
/// caching the derived lapse elsewhere — replaces a record §15 already
/// declares with a per-holder payment flag that would need declaring
/// too, and that can only ever disagree with the derivation it stands
/// in for. Holding one row a while longer and saying so is the smaller
/// claim.
pub fn record_floor(
    store: &Store,
    revocation_poll_secs: i64,
    now: OffsetDateTime,
) -> Result<OffsetDateTime> {
    let mut longest = 0i64;
    for terms_id in store.published_terms_ids()? {
        let Some(clause) = end_of_payment(store, &terms_id)? else {
            continue;
        };
        // Unreadable or absent clauses contribute nothing rather than
        // shortening the floor: `end_of_payment` has already said so
        // out loud, and the failure mode of keeping a row too long is
        // one an operator can declare.
        longest = longest.max(clause.notice_secs.saturating_add(clause.grace_secs));
    }
    now.checked_sub(time::Duration::seconds(
        longest.saturating_add(revocation_poll_secs),
    ))
    .ok_or_else(|| Error::Internal("entitlement record floor is out of range".into()))
}

/// The gate every §9 route passes through.
///
/// One function, one table, so that adding a route means answering the
/// question rather than inheriting an answer by omission.
pub fn require(
    state: &AppState,
    store: &Store,
    holder: &Holder,
    headers: &axum::http::HeaderMap,
    operation: Operation,
    now: OffsetDateTime,
) -> Result<()> {
    if operation.always_available() || !state.config.requires_entitlement() {
        return Ok(());
    }

    let payment_required = || Error::PaymentRequired {
        component_id: state.config.component_id.clone(),
        offers: state.config.offers.clone(),
        entitlement_issuers: state.config.entitlement_issuers.clone(),
        manifest_url: state.config.manifest_url(),
    };

    match evaluate(state, store, holder, headers, now)? {
        Access::Entitled => Ok(()),
        Access::Unpaid | Access::Lapsed => Err(payment_required()),
        Access::Grace { allowed } => {
            if operation.refused_holder_wide() {
                return Err(payment_required());
            }
            match operation.grace_term() {
                Some(term) if allowed.contains(term) => Ok(()),
                _ => Err(payment_required()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uploads::tests::Harness;

    use axum::http::StatusCode;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    /// A charging operator, a holder who has paid, and one snapshot
    /// retained under the default terms — `notice: P14D`,
    /// `grace: P30D`, `duringGrace: [download, export, erase]`.
    async fn holder_with_a_snapshot() -> (Harness, Vec<u8>, String) {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let issuer = format!(
            "onym:key:{}",
            hex::encode(signing.verifying_key().as_bytes())
        );
        let holder = SigningKey::from_bytes(&[5u8; 32]);
        let subject = format!(
            "onym:seat-key:{}",
            hex::encode(holder.verifying_key().as_bytes())
        );
        let now = OffsetDateTime::now_utc();
        let stamp = |at: OffsetDateTime| at.format(&Rfc3339).unwrap();

        let mut document = json!({
            "version": 1,
            "type": "SeatEntitlement",
            "issuer": issuer,
            "audience": "onym:component:test",
            "subject": subject,
            "offerId": "backup-monthly-v1",
            "entitlementId": "ent-1",
            "notBefore": stamp(now - time::Duration::days(1)),
            "expiresAt": stamp(now + time::Duration::days(30)),
            "quota": serde_json::Value::Null,
            "status": "https://broker.example/v1/revocations/current",
        });
        let signed = crate::documents::canonical_bytes(&document, &["signature"]).unwrap();
        document["signature"] = json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing.sign(&signed).to_bytes(),
        ));

        let harness = Harness::new(vec![issuer]);
        let credential = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&document).unwrap(),
        );
        harness.holding(Some(credential.clone()));

        let snapshot: Vec<u8> = (0..20u8).collect();
        let (status, body) = harness.store_snapshot(&snapshot).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        // Stop carrying the credential. From here the operator knows
        // only what it registered.
        harness.holding(None);
        (harness, snapshot, credential)
    }

    /// Move the registered entitlement's expiry into the past, which is
    /// the only thing lapse is ever derived from.
    async fn lapsed_days_ago(harness: &Harness, days: i64) {
        let at = (OffsetDateTime::now_utc() - time::Duration::days(days))
            .format(&Rfc3339)
            .unwrap();
        harness
            .state
            .store
            .lock()
            .await
            .connection_for_tests()
            .execute(
                "UPDATE holder_entitlements SET expires_at = ?1",
                [at],
            )
            .unwrap();
    }

    /// §10.3, both halves at once: what the terms promise during grace
    /// stays open, and the upload path does not — because a lapsed
    /// holder is not owed new retention by any snapshot's terms.
    #[tokio::test]
    async fn grace_keeps_what_the_terms_promised_and_no_more() {
        let (harness, snapshot, _) = holder_with_a_snapshot().await;
        // One day past expiry: well inside notice (P14D) plus grace
        // (P30D).
        lapsed_days_ago(&harness, 1).await;

        let hex_digest = hex::encode(Sha256::digest(&snapshot));
        let (status, _) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "grace refused a download the terms promise"
        );

        // Listing stays open too, or grace cannot be navigated.
        let (status, _) = harness.send("GET", "/v1/snapshots", vec![]).await;
        assert_eq!(status, StatusCode::OK);

        // But nothing new comes in.
        let terms = harness.terms_id();
        let fresh: Vec<u8> = (100..120u8).collect();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&fresh, &terms))
            .await;
        assert_eq!(
            status,
            StatusCode::PAYMENT_REQUIRED,
            "grace bought room for a new snapshot"
        );
    }

    /// §9.2: a grant the operator issued while the holder was entitled
    /// is finishable after the lapse — every remaining chunk and the
    /// commit — because the entitlement was checked when it was minted
    /// and some of the bytes are already on the operator's disk.
    ///
    /// The whole sequence, because the halves pass separately and the
    /// bug lives between them: re-preflight resuming a grant proves
    /// nothing about the routes that actually move the bytes.
    #[tokio::test]
    async fn a_lapse_mid_upload_still_lets_the_grant_finish() {
        let (harness, _, credential) = holder_with_a_snapshot().await;

        // Preflight while entitled. This is the check §9.2 says the
        // grant carries forward.
        harness.holding(Some(credential));
        let terms = harness.terms_id();
        let fresh: Vec<u8> = (100..120u8).collect();
        let (status, body) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&fresh, &terms))
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let grant: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();
        let chunk_bytes = grant["chunkBytes"].as_u64().unwrap() as usize;
        let chunk_count = grant["chunkCount"].as_u64().unwrap() as usize;
        assert!(chunk_count > 1, "the test needs chunks either side of the lapse");

        let chunk = |index: usize| {
            let start = index * chunk_bytes;
            fresh[start..usize::min(start + chunk_bytes, fresh.len())].to_vec()
        };
        let (status, _) = harness
            .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/0"), chunk(0))
            .await;
        assert_eq!(status, StatusCode::OK);

        // The seat lapses with the transfer half done.
        harness.holding(None);
        lapsed_days_ago(&harness, 1).await;

        for index in 1..chunk_count {
            let (status, body) = harness
                .send(
                    "PUT",
                    &format!("/v1/uploads/{upload_id}/chunks/{index}"),
                    chunk(index),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "chunk {index} was refused after the lapse: {}",
                String::from_utf8_lossy(&body)
            );
        }

        let (status, body) = harness
            .send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![])
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the operator took the bytes and then refused to finish: {}",
            String::from_utf8_lossy(&body)
        );
        let outcome: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(outcome["outcome"]["status"], "retained");

        // Readable, not merely recorded: a commit that reported success
        // and left nothing fetchable would pass every assertion above.
        let hex_digest = hex::encode(Sha256::digest(&fresh));
        let (status, bytes) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, fresh);

        // And nothing further is granted. The lapsed holder finished
        // what was in flight; the next preflight reaches the payment
        // check and stops there.
        let another: Vec<u8> = (200..220u8).collect();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&another, &terms))
            .await;
        assert_eq!(
            status,
            StatusCode::PAYMENT_REQUIRED,
            "finishing a grant bought a new one"
        );
    }

    /// Past notice plus grace, the promises are over and the gated
    /// routes close.
    #[tokio::test]
    async fn past_grace_the_gated_routes_close() {
        let (harness, snapshot, _) = holder_with_a_snapshot().await;
        // P14D + P30D = 44 days.
        lapsed_days_ago(&harness, 50).await;

        let hex_digest = hex::encode(Sha256::digest(&snapshot));
        let (status, _) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);

        // Export still works. It is never gated, at any point, by
        // anything — §9.7, and the whole reason a lapsed holder is not
        // trapped.
        let (status, _) = harness.send("GET", "/v1/exports", vec![]).await;
        assert_eq!(status, StatusCode::OK, "export closed with grace");
    }

    /// Presenting a live credential again ends the lapse. There is no
    /// flag to clear, which is the point of deriving rather than
    /// storing.
    #[tokio::test]
    async fn renewing_ends_the_lapse() {
        let (harness, _, credential) = holder_with_a_snapshot().await;
        lapsed_days_ago(&harness, 50).await;

        let terms = harness.terms_id();
        let fresh: Vec<u8> = (100..120u8).collect();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&fresh, &terms))
            .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);

        // Present a live credential again. Registering it moves the
        // horizon forward, and the very next request is entitled — no
        // flag was set, so none has to be cleared.
        harness.holding(Some(credential));
        let (status, body) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&fresh, &terms))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "renewing did not end the lapse: {}",
            String::from_utf8_lossy(&body)
        );
    }

    /// The sweep reports a post-grace snapshot as retention expiry, not
    /// as erasure. The holder did not erase it; its retention ran out,
    /// which is what the terms they accepted said would happen — and no
    /// receipt is minted, because §11 receipts answer a holder's
    /// request rather than an operator's timer.
    #[tokio::test(flavor = "multi_thread")]
    async fn past_grace_the_sweep_expires_the_snapshot() {
        let (harness, snapshot, _) = holder_with_a_snapshot().await;
        lapsed_days_ago(&harness, 50).await;

        let swept = tokio::task::block_in_place(|| {
            crate::sweep::reconcile(
                &harness.state.store,
                &harness.state.blob_mutations,
                &harness.state.blobs,
                &HashSet::new(),
                OffsetDateTime::now_utc(),
                crate::sweep::Cutoffs {
                    now: &OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
                    nonce: "2000-01-01T00:00:00Z",
                    outcome: "2000-01-01T00:00:00Z",
                    receipt: "2000-01-01T00:00:00Z",
                    erased_reference: "2000-01-01T00:00:00Z",
                    entitlement: "2000-01-01T00:00:00Z",
                },
            )
        });
        assert_eq!(swept.post_grace_snapshots, 1);

        // Reported as expiry, and not as something the holder did.
        let (_, body) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let rows: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows[0]["status"], json!("retention_expired"));
        assert!(rows[0]["erasedAt"].is_null(), "expiry was recorded as an erasure");

        // And the bytes are gone with it.
        let hex_digest = hex::encode(Sha256::digest(&snapshot));
        assert!(
            !harness
                .state
                .blobs
                .retained_on_disk()
                .into_iter()
                .any(|(_, digest)| digest == hex_digest),
            "the bytes outlived the retention that justified holding them"
        );
    }

    /// The sweep must not delete the record its own next decision
    /// depends on.
    ///
    /// Two passes against the real sweep, because the failure is
    /// invisible in either one alone. `expires_at` is the moment the
    /// holder lapsed — the grace window and the post-grace expiry are
    /// both computed from it — so a record swept an hour after expiry
    /// takes both with it: the download the terms promise for another
    /// six weeks closes immediately, and nothing is ever expired
    /// afterwards, which is the operator holding the bytes forever
    /// while believing it tidied up.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_record_outlives_the_grace_it_is_derived_from() {
        let (harness, snapshot, _) = holder_with_a_snapshot().await;
        let hex_digest = hex::encode(Sha256::digest(&snapshot));

        // The default poll interval, which is the only term of the
        // floor that would be there if the record were not what lapse
        // is read from.
        let poll = crate::config::Config::for_tests("onym:component:test", vec![])
            .revocation_poll_secs as i64;
        let sweep_now = |harness: &Harness| {
            let at = OffsetDateTime::now_utc();
            tokio::task::block_in_place(|| {
                let floor = record_floor(&harness.state.store.blocking_lock(), poll, at)
                    .unwrap()
                    .format(&Rfc3339)
                    .unwrap();
                crate::sweep::reconcile(
                    &harness.state.store,
                    &harness.state.blob_mutations,
                    &harness.state.blobs,
                    &HashSet::new(),
                    at,
                    crate::sweep::Cutoffs {
                        now: &at.format(&Rfc3339).unwrap(),
                        nonce: "2000-01-01T00:00:00Z",
                        outcome: "2000-01-01T00:00:00Z",
                        receipt: "2000-01-01T00:00:00Z",
                        erased_reference: "2000-01-01T00:00:00Z",
                        entitlement: &floor,
                    },
                )
            })
        };

        // (1) An hour past expiry — the point at which the first sweep
        // after a lapse runs. The record must survive it.
        lapsed_days_ago(&harness, 1).await;
        let swept = sweep_now(&harness);
        assert_eq!(swept.aged_entitlements, 0, "the record lapse is derived from was swept mid-grace");
        assert_eq!(swept.post_grace_snapshots, 0);

        // Which is the same thing as saying grace still works: the
        // holder is in `Grace`, not `Unpaid`, and downloads what their
        // terms promised.
        let (status, _) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK, "the sweep ended a grace window 43 days early");

        // (2) Past notice plus grace. Now the window really is over,
        // and the snapshot is expired *from that same record* — the
        // half that goes silent rather than loud when the record is
        // gone, because an empty `post_grace_due` looks exactly like
        // nothing being due.
        lapsed_days_ago(&harness, 50).await;
        let swept = sweep_now(&harness);
        assert_eq!(swept.post_grace_snapshots, 1, "the post-grace expiry never fired");

        let (_, body) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let rows: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows[0]["status"], json!("retention_expired"));

        assert!(
            !harness
                .state
                .blobs
                .retained_on_disk()
                .into_iter()
                .any(|(_, digest)| digest == hex_digest),
            "the bytes outlived the retention that justified holding them"
        );

        // And only now, in the pass that acted on it, does the record
        // itself go — 50 days is past 44 plus a poll interval.
        assert_eq!(swept.aged_entitlements, 1, "the record was kept past every window it could open");
    }

    /// Revocation must not erase the timestamp the rest of lapse is
    /// derived from.
    ///
    /// `entitlement_horizon` used to drop a revoked id from
    /// consideration outright. For a holder with exactly one
    /// entitlement, revoking it made the horizon `None` — `evaluate`
    /// then read that as "no record" and returned `Lapsed` immediately,
    /// skipping the grace the terms had already promised, and
    /// `post_grace_due` had nothing left to derive a due date from and
    /// returned empty forever, so the snapshot was retained past every
    /// window it could open.
    #[tokio::test(flavor = "multi_thread")]
    async fn revocation_blocks_new_work_without_erasing_the_lapse_horizon() {
        let (harness, snapshot, _) = holder_with_a_snapshot().await;
        let hex_digest = hex::encode(Sha256::digest(&snapshot));

        let now = OffsetDateTime::now_utc();
        harness.state.revocation.install(
            crate::revocation::Epoch {
                epoch: 1,
                published_at: now,
                revoked: HashSet::from(["ent-1".to_string()]),
                raw: Vec::new(),
            },
            now,
        );

        // Revoked, well before the credential's own `expiresAt` (30
        // days out). New paid work is refused immediately...
        let terms = harness.terms_id();
        let fresh: Vec<u8> = (100..120u8).collect();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&fresh, &terms))
            .await;
        assert_eq!(
            status,
            StatusCode::PAYMENT_REQUIRED,
            "a revoked-but-unexpired entitlement still granted new work"
        );

        // ...but the snapshot's own terms — pinned at accept time — are
        // still honoured, because the horizon is still the credential's
        // real `expiresAt`, not nothing.
        let (status, _) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "revocation closed a grace window the terms still owed"
        );

        // Move `expiresAt` itself past notice-and-grace (14 + 30 = 44
        // days) so the credential's own window is over. The record must
        // still be there to derive the post-grace expiry from, and the
        // snapshot must actually expire.
        lapsed_days_ago(&harness, 50).await;

        let poll = crate::config::Config::for_tests("onym:component:test", vec![])
            .revocation_poll_secs as i64;
        let sweep_now = |harness: &Harness| {
            let at = OffsetDateTime::now_utc();
            let revoked = harness.state.revocation.revoked();
            tokio::task::block_in_place(|| {
                let floor = record_floor(&harness.state.store.blocking_lock(), poll, at)
                    .unwrap()
                    .format(&Rfc3339)
                    .unwrap();
                crate::sweep::reconcile(
                    &harness.state.store,
                    &harness.state.blob_mutations,
                    &harness.state.blobs,
                    &revoked,
                    at,
                    crate::sweep::Cutoffs {
                        now: &at.format(&Rfc3339).unwrap(),
                        nonce: "2000-01-01T00:00:00Z",
                        outcome: "2000-01-01T00:00:00Z",
                        receipt: "2000-01-01T00:00:00Z",
                        erased_reference: "2000-01-01T00:00:00Z",
                        entitlement: &floor,
                    },
                )
            })
        };

        let swept = sweep_now(&harness);
        assert_eq!(
            swept.post_grace_snapshots, 1,
            "post-grace expiry never fired for a revoked holder's snapshot"
        );

        let (_, body) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let rows: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows[0]["status"], json!("retention_expired"));

        assert!(
            !harness
                .state
                .blobs
                .retained_on_disk()
                .into_iter()
                .any(|(_, digest)| digest == hex_digest),
            "the bytes outlived the retention that justified holding them"
        );
    }

    /// The two rules that are easy to get backwards, asserted directly
    /// on the table rather than through a router.
    #[test]
    fn the_allowlist_says_what_ten_three_says() {
        // Export is never gated. Not "gated and allowed" — never asked.
        assert!(Operation::Export.always_available());
        // A lapsed holder is not owed *new* retention by any snapshot's
        // terms, so grace does not reopen the route that mints a grant.
        assert!(Operation::Preflight.refused_holder_wide());
        assert!(!Operation::Preflight.always_available());
        // But finishing a grant the operator already issued is not new
        // retention — §9.2 — so the two routes that can only run
        // against a live grant are never gated at all. Not gated and
        // refused, not gated and allowed: never asked.
        for operation in [Operation::Upload, Operation::Commit] {
            assert!(operation.always_available());
            assert!(!operation.refused_holder_wide());
        }
        // These are the ones a terms document can promise back.
        assert_eq!(Operation::Download.grace_term(), Some("download"));
        assert_eq!(Operation::Erase.grace_term(), Some("erase"));
        // And these must stay open or grace is unusable.
        assert!(Operation::List.always_available());
        assert!(Operation::Register.always_available());
        assert!(Operation::Reconcile.always_available());
    }

    /// Notice and grace are a sequence, not alternatives. Reading them
    /// as alternatives would halve what was promised.
    #[test]
    fn the_window_is_notice_then_grace() {
        let clause = EndOfPayment {
            notice_secs: 14 * 86_400,
            grace_secs: 30 * 86_400,
            during_grace: vec!["download".into()],
            after_grace: "erase".into(),
        };
        let lapsed = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert_eq!(
            clause.window_end(lapsed).unwrap(),
            lapsed + time::Duration::days(44)
        );
    }

    /// The operator's reader and the clients' must agree, or a holder
    /// is cut off while their screen still shows time remaining.
    #[test]
    fn durations_read_the_way_the_clients_read_them() {
        assert_eq!(duration_seconds("P30D"), Some(30 * 86_400));
        assert_eq!(duration_seconds("PT1H"), Some(3_600));
        assert_eq!(duration_seconds("P1M"), Some(30 * 86_400));
        assert_eq!(duration_seconds("P1Y"), Some(365 * 86_400));
        assert_eq!(duration_seconds("PT5M"), Some(300));
        assert_eq!(duration_seconds("none"), Some(0));
        // Malformed, not a silent zero.
        assert_eq!(duration_seconds("P30"), None);
        assert_eq!(duration_seconds("30D"), None);
        assert_eq!(duration_seconds("until-erased"), None);
    }
}
