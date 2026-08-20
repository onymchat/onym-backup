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
    let Some(horizon) = store.entitlement_horizon(&holder.handle, &revoked)? else {
        // No record. Either they never paid, or the records aged out at
        // §15's bound — in which case the derived lifecycle state is
        // what still knows when the grace they were promised runs out.
        let Some(state) = store.lapse_state(&holder.handle)? else {
            return Ok(if store.has_entitlement_record(&holder.handle)? {
                Access::Lapsed
            } else {
                Access::Unpaid
            });
        };
        let lapsed_at = OffsetDateTime::parse(&state.lapsed_at, &Rfc3339)
            .map_err(|e| Error::Internal(format!("derived lapse timestamp: {e}")))?;
        return grace_from(store, holder, lapsed_at, now);
    };

    // **Access** is the unrevoked answer, and only that. A revoked
    // record contributes nothing here however far its own `expiresAt`
    // still is: revocation blocks new paid work from the moment the
    // epoch says so.
    if let Some(access) = &horizon.access {
        let expires_at = OffsetDateTime::parse(access, &Rfc3339)
            .map_err(|e| Error::Internal(format!("stored entitlement expiry: {e}")))?;
        if now < expires_at {
            // Registered, unexpired, just not attached to this request.
            return Ok(Access::Entitled);
        }
    }

    // **Lifecycle** is the answer across every record, revoked
    // included. The terms a snapshot was accepted under still govern
    // it, so grace is derived from the latest `expiresAt` a credential
    // declared rather than from the moment revocation was noticed — or
    // from an older unrevoked record that happened to be the only one
    // access could see.
    let lapsed_at = OffsetDateTime::parse(&horizon.lifecycle, &Rfc3339)
        .map_err(|e| Error::Internal(format!("stored entitlement expiry: {e}")))?;
    grace_from(store, holder, lapsed_at, now)
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
    let Some(lapsed_at) = lifecycle_horizon(store, handle, revoked)? else {
        // Nothing to lapse from, and nothing derived either. Acting on
        // that would make the expiry of a *retention bound* into a
        // deletion trigger, which is not what a retention bound is.
        return Ok(Vec::new());
    };
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

/// The moment a holder lapsed, from whichever record still knows it.
///
/// The full entitlement record while there is one; the derived
/// `LapseState` after §15's bound has taken it. Both `evaluate` and
/// `post_grace_due` go through here so the two cannot drift — a
/// fallback that only one of them takes is how a holder ends up in
/// grace on the request path and expired by the sweep in the same hour.
///
/// The record wins where both exist. The derived row is a summary
/// written at sweep time; the record is the credential itself, and a
/// renewal lands there first.
fn lifecycle_horizon(
    store: &Store,
    handle: &str,
    revoked: &HashSet<String>,
) -> Result<Option<OffsetDateTime>> {
    let text = match store.entitlement_horizon(handle, revoked)? {
        Some(horizon) => horizon.lifecycle,
        None => match store.lapse_state(handle)? {
            Some(state) => state.lapsed_at,
            None => return Ok(None),
        },
    };
    OffsetDateTime::parse(&text, &Rfc3339)
        .map(Some)
        .map_err(|e| Error::Internal(format!("stored lapse horizon: {e}")))
}

/// §15's bound on an entitlement record: `expiresAt` plus one
/// revocation-epoch interval, and the cutoff `sweep_entitlements`
/// deletes below.
///
/// The interval is the only term, and it is there for the one reason
/// §10.4 gives: an entitlement revoked just before it expired must stay
/// recognisable for at least as long as it takes the next epoch to say
/// so.
///
/// **This used to add the longest notice-and-grace this operator had
/// ever published**, so that the record would still be there for
/// `evaluate` and `post_grace_due` to derive from. The problem it
/// solved is real — a record swept mid-grace closes a download the
/// terms promise for another six weeks and leaves `post_grace_due` with
/// nothing, so the bytes are held forever — but the remedy exceeded a
/// normative bound and then declared its way out of it. §15's table is
/// not advisory, and `metadataRetention` is a disclosure, not a
/// licence. What the derivation needs is a timestamp; what that
/// implementation kept was a signed credential naming an offer, an
/// issuer and a purchase, for six weeks after it stopped being usable.
///
/// The horizon now moves into `store::LapseState` before the record is
/// dropped — see `derive_lapse_state`. Four fields instead of a
/// credential, and this floor goes back to the table.
///
/// Takes no store: the floor no longer depends on anything published,
/// which is most of the point.
pub fn record_floor(revocation_poll_secs: i64, now: OffsetDateTime) -> Result<OffsetDateTime> {
    now.checked_sub(time::Duration::seconds(revocation_poll_secs))
        .ok_or_else(|| Error::Internal("entitlement record floor is out of range".into()))
}

/// Reduce a lapsed holder's entitlement records to the minimum needed
/// to finish honouring §10.3, ahead of dropping them.
///
/// Returns `None` for a holder with nothing to protect. That is the
/// common case and it matters: a holder with no live snapshot is owed
/// no notice, no grace and no post-grace action, so there is nothing
/// for a row to carry and none is written. Retention state for someone
/// the operator holds nothing about is just a record of a person.
///
/// `grace_expires_at` is the latest window end across their snapshots
/// and bounds the row itself — it is not what any decision is made
/// from. Each snapshot's own window is recomputed from its own pinned
/// terms every time, before and after the record goes, because §10.3
/// governs each snapshot by the terms it was accepted under and a
/// holder-wide date would hand the older ones a window they never
/// agreed to in one direction or the other.
pub fn derive_lapse_state(
    store: &Store,
    handle: &str,
    revoked: &HashSet<String>,
) -> Result<Option<crate::store::LapseState>> {
    let Some(lapsed_at) = lifecycle_horizon(store, handle, revoked)? else {
        return Ok(None);
    };

    let mut latest: Option<(OffsetDateTime, String)> = None;
    for row in store.snapshots(handle)? {
        let Some(clause) = end_of_payment(store, &row.accepted_terms_id)? else {
            continue;
        };
        let Some(ends) = clause.window_end(lapsed_at) else {
            continue;
        };
        if latest.as_ref().is_none_or(|(held, _)| ends > *held) {
            latest = Some((ends, clause.after_grace.clone()));
        }
    }
    let Some((ends, after_grace)) = latest else {
        return Ok(None);
    };

    let stamp = |at: OffsetDateTime| {
        at.format(&Rfc3339)
            .map_err(|e| Error::Internal(format!("format timestamp: {e}")))
    };
    Ok(Some(crate::store::LapseState {
        lapsed_at: stamp(lapsed_at)?,
        grace_expires_at: stamp(ends)?,
        post_grace_action: after_grace,
    }))
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

    /// Move the lapse horizon into the past.
    ///
    /// Both tables, because after §15's bound has taken the credential
    /// the derived row is the horizon — a helper that moved only the
    /// records would silently stop moving anything, and a test asserting
    /// on a clock that never advanced passes for the wrong reason.
    /// `grace_expires_at` moves with it at the default terms' 14 + 30.
    async fn lapsed_days_ago(harness: &Harness, days: i64) {
        let lapsed = OffsetDateTime::now_utc() - time::Duration::days(days);
        let at = lapsed.format(&Rfc3339).unwrap();
        let ends = (lapsed + time::Duration::days(44)).format(&Rfc3339).unwrap();
        let store = harness.state.store.lock().await;
        store
            .connection_for_tests()
            .execute("UPDATE holder_entitlements SET expires_at = ?1", [&at])
            .unwrap();
        store
            .connection_for_tests()
            .execute(
                "UPDATE lapse_state SET lapsed_at = ?1, grace_expires_at = ?2",
                rusqlite::params![&at, &ends],
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

    /// The record goes at §15's bound; the *horizon* survives it.
    ///
    /// Two passes against the real sweep, because the failure is
    /// invisible in either one alone. `expires_at` is the moment the
    /// holder lapsed — the grace window and the post-grace expiry are
    /// both computed from it — so a record dropped an hour after expiry
    /// with nothing behind it takes both with it: the download the
    /// terms promise for another six weeks closes immediately, and
    /// nothing is ever expired afterwards, which is the operator
    /// holding the bytes forever while believing it tidied up.
    ///
    /// The earlier fix kept the whole credential for the length of the
    /// window. This one keeps four fields, so the assertions run in
    /// both directions: the record must be *gone* at §15's bound, and
    /// everything derived from it must still work for six weeks after.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_horizon_outlives_the_record_it_came_from() {
        let (harness, snapshot, _) = holder_with_a_snapshot().await;
        let hex_digest = hex::encode(Sha256::digest(&snapshot));

        // The poll interval is now the whole of the floor, which is
        // what §15's table says it should be.
        let poll = crate::config::Config::for_tests("onym:component:test", vec![])
            .revocation_poll_secs as i64;
        let sweep_now = |harness: &Harness| {
            let at = OffsetDateTime::now_utc();
            tokio::task::block_in_place(|| {
                let floor = record_floor(poll, at)
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

        // (1) An hour past expiry — the first sweep after a lapse, and
        // past `expiresAt` plus the poll interval. The credential goes
        // here, on time, and its `entitlementId`, `offerId`, issuer and
        // raw bytes go with it.
        lapsed_days_ago(&harness, 1).await;
        let swept = sweep_now(&harness);
        assert_eq!(
            swept.aged_entitlements, 1,
            "the credential was held past §15's bound"
        );
        assert!(
            !harness
                .state
                .store
                .lock()
                .await
                .has_entitlement_record(&harness.handle())
                .unwrap(),
            "an entitlement record survived its normative bound"
        );
        assert_eq!(swept.post_grace_snapshots, 0);

        // And the window it opened is still running: the holder is in
        // `Grace`, not `Unpaid`, and downloads what their terms
        // promised — from four derived fields rather than from a
        // credential.
        let derived = harness
            .state
            .store
            .lock()
            .await
            .lapse_state(&harness.handle())
            .unwrap()
            .expect("the horizon went with the record");
        assert_eq!(derived.post_grace_action, "erase");
        let (status, _) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK, "the sweep ended a grace window 43 days early");

        // (2) Past notice plus grace. The window really is over, and
        // the snapshot is expired from the derived state — the half
        // that goes silent rather than loud when the horizon is lost,
        // because an empty `post_grace_due` looks exactly like nothing
        // being due.
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

        // (3) And the derived row does not outlive its purpose either.
        // It is retired in the same pass that acted on it, because
        // retirement is conditioned on nothing being due rather than on
        // a clock — which is also what makes a transient failure in the
        // expiry step recoverable rather than permanent: a snapshot
        // that was not expired is still due, so the row would stay.
        assert_eq!(
            swept.forgotten_lapse_state, 1,
            "the derived lapse state outlived the window it recorded"
        );
        assert!(
            harness
                .state
                .store
                .lock()
                .await
                .lapse_state(&harness.handle())
                .unwrap()
                .is_none()
        );
    }

    /// Access and lifecycle are two questions, and the store used to
    /// answer both with whichever record won the first one.
    ///
    /// An unrevoked credential expiring at t1, and a revoked renewal
    /// expiring at t2 > t1. The unrevoked answer won outright, so t2 was
    /// discarded and every window ran from t1 — expiring the snapshot up
    /// to `t2 - t1` early, and contradicting the rule that a revoked
    /// record still contributes its declared `expiresAt` to the
    /// lifecycle of the snapshots accepted under it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_revoked_renewal_still_sets_the_lifecycle_horizon() {
        let (harness, snapshot, _) = holder_with_a_snapshot().await;
        let hex_digest = hex::encode(Sha256::digest(&snapshot));

        // `ent-1` is the unrevoked original. Age it out — it expired
        // yesterday, so it can grant nothing.
        lapsed_days_ago(&harness, 1).await;
        // `ent-2` is a renewal that was refunded: revoked, and declaring
        // an `expiresAt` twenty days out.
        let renewal_expiry = (OffsetDateTime::now_utc() + time::Duration::days(20))
            .format(&Rfc3339)
            .unwrap();
        harness
            .state
            .store
            .lock()
            .await
            .connection_for_tests()
            .execute(
                "INSERT INTO holder_entitlements
                    (entitlement_id, holder_handle, offer_id, not_before, expires_at,
                     quota_units, quota_unit, quota_consumed, raw, registered_at)
                 VALUES ('ent-2', ?1, 'backup-monthly-v1', '2020-01-01T00:00:00Z', ?2,
                         NULL, NULL, 0, X'00', '2020-01-01T00:00:00Z')",
                rusqlite::params![harness.handle(), renewal_expiry],
            )
            .unwrap();
        let now = OffsetDateTime::now_utc();
        harness.state.revocation.install(
            crate::revocation::Epoch {
                epoch: 1,
                published_at: now,
                revoked: HashSet::from(["ent-2".to_string()]),
                raw: Vec::new(),
            },
            now,
        );

        // **Access** is refused. The only unrevoked record expired
        // yesterday, and the revoked renewal grants nothing however far
        // out its own `expiresAt` still is.
        let terms = harness.terms_id();
        let fresh: Vec<u8> = (100..120u8).collect();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&fresh, &terms))
            .await;
        assert_eq!(
            status,
            StatusCode::PAYMENT_REQUIRED,
            "a revoked renewal bought new paid work"
        );

        // **Lifecycle** runs from the renewal. Grace is 20 days out
        // plus notice-and-grace, so at 50 days past the *original*
        // expiry — long past 44 — the snapshot is still protected and
        // nothing is due.
        let revoked = harness.state.revocation.revoked();
        let due = tokio::task::block_in_place(|| {
            post_grace_due(
                &harness.state.store.blocking_lock(),
                &harness.handle(),
                &revoked,
                OffsetDateTime::now_utc() + time::Duration::days(50),
            )
            .unwrap()
        });
        assert!(
            due.is_empty(),
            "post-grace expiry ran from the older unrevoked record and fired 20 days early"
        );

        // Still downloadable today, for the same reason.
        let (status, _) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "grace ran from the older record and closed early"
        );

        // And past the renewal's own window — 20 days out plus 44 — it
        // is finally due. Same call, later clock: the horizon really is
        // t2 and not merely "later than t1".
        let due = tokio::task::block_in_place(|| {
            post_grace_due(
                &harness.state.store.blocking_lock(),
                &harness.handle(),
                &revoked,
                OffsetDateTime::now_utc() + time::Duration::days(70),
            )
            .unwrap()
        });
        assert_eq!(due.len(), 1, "the snapshot was never due at all");
        assert_eq!(due[0].1, "erase");
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
                let floor = record_floor(poll, at)
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
