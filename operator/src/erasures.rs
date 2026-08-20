//! Erasure, and the receipt that commits to it.
//!
//! A receipt is a **signed commitment measured against pinned terms**,
//! not proof of destruction — §11 says so, and the fields are chosen so
//! a client cannot render it as more than that. `excludedScope` is
//! mandatory and non-empty for the same reason: there is always
//! something an erasure does not reach, at minimum the copies held by
//! the other participants in every conversation the snapshot contained,
//! and an operator that cannot name that has not understood what it is
//! signing.
//!
//! The scopes are copied from **the terms the erased snapshot pinned**,
//! never from current terms and never composed at request time. A
//! holder is owed the promise they accepted, not the one the operator
//! would make today.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::api::AppState;
use crate::auth::authenticate;
use crate::error::{Error, Resource, Result};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EraseRequest {
    /// Client-chosen, like every other operation's. §14.9
    /// reconciliation is keyed on an id the *client* knows: an
    /// operator-invented one cannot be asked about, so a lost erase
    /// response would leave the holder with no way to find out whether
    /// their erasure happened.
    pub operation_id: String,
    pub scope: String,
}

/// `POST /v1/erasures`.
///
/// Returns an array of receipts, one per distinct pinned `termsId` in
/// scope. §11's receipt carries a single `termsId`, so a `scope: "all"`
/// spanning snapshots accepted under different terms cannot honestly be
/// one document — and the alternative, citing whichever terms happened
/// to be current, would sign a promise the holder never accepted. The
/// erasure itself always covers the whole scope regardless; only the
/// number of receipts varies.
pub async fn erase(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let stamp = now
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(e.to_string()))?;
    // Commit and erase both take this before the store lock. It closes
    // the mark-erased → unlink window in which a re-upload could revive
    // the row and then lose its newly committed directory.
    let _blob_mutation = state.blob_mutations.lock().await;

    // Filled inside the locked section, used after it: the bytes are
    // unlinked once the bookkeeping has committed.
    let (receipts, who, doomed_hex) = {
        let mut receipts = Vec::new();
        let mut store = state.store.lock().await;
        let holder = authenticate(
            &headers,
            "POST",
            "/v1/erasures",
            &body,
            &state.config,
            &store,
            now,
        )?;
        crate::lapse::require(
            &state,
            &store,
            &holder,
            &headers,
            crate::lapse::Operation::Erase,
            now,
        )?;
        let request: EraseRequest = serde_json::from_slice(&body)
            .map_err(|e| Error::BadRequest(format!("erasure body: {e}")))?;
        if request.operation_id.trim().is_empty() {
            return Err(Error::BadRequest("operationId is required".into()));
        }
        if request.scope != "all" {
            crate::blobs::digest_hex(&request.scope)?;
        }

        let targets = store.snapshots_in_scope(&holder.handle, &request.scope)?;
        if targets.is_empty() {
            if store.scope_is_unavailable(&holder.handle, &request.scope)? {
                return Err(Error::RetentionExpired);
            }
            // Nothing live in scope. If these references were erased
            // before, the holder is owed the newest receipt set that
            // covers them. Scope equality alone is insufficient: the
            // same digest may have been uploaded again and erased later
            // under `all`, making an older exact-scope receipt stale.
            let erased = store.erased_digests(&holder.handle, &request.scope)?;
            let existing = store.latest_receipts_for_erased_scope(
                &holder.handle,
                &request.scope,
                &erased,
            )?;
            if !existing.is_empty() {
                let ids: Vec<&str> = existing.iter().map(|(id, _)| id.as_str()).collect();
                // The retry's own operation id is recorded too, so a
                // client that retries with a fresh id and loses *that*
                // response can still reconcile it. Otherwise the retry
                // path is the one operation §9.8 cannot answer for.
                store.record_outcome(
                    &request.operation_id,
                    &holder.handle,
                    &request.scope,
                    "erasure_acknowledged",
                    Some(serde_json::to_string(&ids).unwrap_or_default()),
                    &stamp,
                )?;
                return Ok(axum::Json(decode_receipts(existing)?).into_response());
            }
            // Erased, and no receipt survives. The snapshot rows
            // outlive the receipts, so the operator knows this happened
            // and says so rather than answering "no such snapshot"
            // about an erasure the holder requested themselves.
            if !erased.is_empty() {
                return Err(Error::ReceiptExpired);
            }
            // Never held, so there is nothing to commit to. A receipt
            // for an empty scope would be a signed statement about
            // nothing.
            return Err(Error::NotFound(Resource::Snapshot));
        }
        // Everything that can leave the erasure undecided runs before
        // anything is destroyed. Composing a receipt reads the pinned
        // terms and can refuse —
        // terms with no completion deadline, for one — and doing that
        // after the bytes were gone left the holder erased, with no
        // receipt, and a retry answering `receipt_expired` about a
        // receipt that never existed.
        let mut pinned: Vec<String> = targets
            .iter()
            .map(|row| row.accepted_terms_id.clone())
            .collect();
        pinned.sort();
        pinned.dedup();

        let mut minted: Vec<(String, String, Vec<u8>, Vec<String>)> = Vec::new();
        for terms_id in pinned {
            let (raw, _) = store
                .terms_document(&terms_id)?
                .ok_or(Error::NotFound(Resource::Terms))?;
            let terms: Value = serde_json::from_slice(&raw)
                .map_err(|e| Error::Internal(format!("stored terms: {e}")))?;
            // The references this receipt covers. Every receipt for a
            // `scope: "all"` echoes the same scope string and differs
            // only in termsId, so without this a holder holding three
            // of them cannot tell which bytes each commitment is
            // about — and coveredScope/excludedScope would describe a
            // set nobody can enumerate.
            let covered: Vec<String> = targets
                .iter()
                .filter(|row| row.accepted_terms_id == terms_id)
                .map(|row| row.digest.clone())
                .collect();
            let receipt =
                compose(&state, &terms, &terms_id, &request.scope, &covered, &stamp)?;
            let receipt_id = receipt["receiptId"]
                .as_str()
                .ok_or_else(|| Error::Internal("receipt has no id".into()))?
                .to_string();
            let (document, signed) = crate::documents::sign_receipt(receipt, &state.signing)?;
            minted.push((receipt_id, terms_id, signed, covered));
            receipts.push(document);
        }

        // Rows, receipts and outcome in one transaction: they are one
        // fact, and a failure between them is the operator asserting
        // something false.
        let doomed: Vec<String> = targets.iter().map(|row| row.digest.clone()).collect();
        store.commit_erasure(
            &holder.handle,
            &request.scope,
            &doomed,
            &minted,
            &request.operation_id,
            &stamp,
        )?;

        let who = holder.handle.clone();
        let doomed_hex = targets
            .iter()
            .map(|row| crate::blobs::digest_hex(&row.digest))
            .collect::<Result<Vec<_>>>()?;
        (receipts, who, doomed_hex)
    };

    // Bytes last, and deliberately. A crash here leaves rows marked
    // erased with their bytes still on disk, which the sweep collects
    // as orphans because it lists only live rows — the safe direction,
    // converging on what the holder was told. Unlinking first would
    // leave a live row whose bytes are gone: nothing repairs that, and
    // `list` would report `retained` about them forever.
    //
    // Off the runtime thread. `remove_dir_all` over every chunk of
    // every snapshot is blocking I/O, and doing it on a runtime thread
    // stalls the executor. Cleanup is best-effort after the committed
    // acknowledgement: failures are logged and retried by the orphan
    // sweep, never turned into a false "operation failed" response.
    crate::uploads::blocking(&state, move |state| {
        for digest_hex in &doomed_hex {
            if let Err(error) = state.blobs.erase(&who, digest_hex) {
                // The signed receipt and erased row are already
                // committed. Returning 500 now would make a decided
                // operation look unknown, and stopping would strand
                // every later digest in an `all` scope. Continue; the
                // orphan sweep retries any bytes that remain.
                tracing::error!(
                    %error,
                    holder = %who,
                    digest = %digest_hex,
                    "could not unlink committed erasure"
                );
            }
        }
        Ok(())
    })
    .await?;

    Ok(axum::Json(receipts).into_response())
}

fn decode_receipts(raw: Vec<(String, Vec<u8>)>) -> Result<Vec<Value>> {
    raw.iter()
        .map(|(_, bytes)| {
            serde_json::from_slice(bytes)
                .map_err(|e| Error::Internal(format!("stored receipt: {e}")))
        })
        .collect()
}

/// One receipt, against one pinned terms document.
#[allow(clippy::too_many_arguments)]
fn compose(
    state: &Arc<AppState>,
    terms: &Value,
    terms_id: &str,
    scope: &str,
    snapshots: &[String],
    acknowledged_at: &str,
) -> Result<Value> {
    let erasure = &terms["erasure"];
    let excluded = erasure["excluded"].as_str().unwrap_or_default();
    if excluded.trim().is_empty() {
        // Malformed rather than generous: §11 is explicit that a
        // receipt with an empty exclusion is not a stronger promise,
        // it is a broken document.
        return Err(Error::Internal(
            "pinned terms declare no erasure exclusions".into(),
        ));
    }
    let covered = erasure["scope"].as_str().unwrap_or_default();
    if covered.trim().is_empty() {
        return Err(Error::Internal("pinned terms declare no erasure scope".into()));
    }

    // Not defaulted. The module's rule is that a receipt cites the
    // pinned terms and composes nothing at request time, and a default
    // deadline is exactly a composed one — a commitment the holder
    // never accepted, signed by this operator, indistinguishable
    // afterwards from one they did.
    let deadline = erasure["completionDeadline"].as_str().ok_or_else(|| {
        Error::Internal("pinned terms declare no erasure completion deadline".into())
    })?;
    let acknowledged = OffsetDateTime::parse(acknowledged_at, &Rfc3339)
        .map_err(|e| Error::Internal(format!("unparseable stamp: {e}")))?;
    let committed_by = acknowledged
        .checked_add(iso8601_days(deadline)?)
        .ok_or_else(|| Error::Internal("erasure completion deadline is out of range".into()))?
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(json!({
        "receiptVersion": 1,
        "receiptId": hex::encode(uuid::Uuid::new_v4().as_bytes()),
        "operator": state.documents.operator_key,
        "scope": scope,
        "snapshots": snapshots,
        "acknowledgedAt": acknowledged_at,
        "completionCommittedBy": committed_by,
        "coveredScope": covered,
        "excludedScope": excluded,
        "termsId": terms_id,
    }))
}

/// `P<n>D` → a duration.
///
/// Deliberately narrow: the terms this operator publishes declare a
/// completion deadline in whole days, and a receipt is the wrong place
/// to discover that a general ISO 8601 parser disagrees with the terms
/// about what `P1M` means.
fn iso8601_days(period: &str) -> Result<time::Duration> {
    let days = period
        .strip_prefix('P')
        .and_then(|rest| rest.strip_suffix('D'))
        .and_then(|days| days.parse::<i64>().ok())
        .ok_or_else(|| {
            Error::Internal(format!(
                "completion deadline {period} is not a whole number of days"
            ))
        })?;
    if days <= 0 {
        return Err(Error::Internal(format!(
            "completion deadline {period} must be positive"
        )));
    }
    let seconds = days
        .checked_mul(24 * 60 * 60)
        .ok_or_else(|| Error::Internal(format!("completion deadline {period} is too large")))?;
    Ok(time::Duration::seconds(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uploads::tests::Harness;

    use axum::http::StatusCode;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    #[test]
    fn completion_deadlines_are_positive_and_bounded() {
        assert!(iso8601_days("P-1D").is_err());
        assert!(iso8601_days("P9223372036854775807D").is_err());

        let large = iso8601_days("P100000000D").unwrap();
        assert!(
            OffsetDateTime::now_utc().checked_add(large).is_none(),
            "the fixture no longer reaches the checked-add boundary"
        );
    }

    async fn erase(harness: &Harness, scope: &str) -> (StatusCode, Value) {
        erase_as(harness, scope, &uuid::Uuid::new_v4().to_string()).await
    }

    async fn erase_as(
        harness: &Harness,
        scope: &str,
        operation_id: &str,
    ) -> (StatusCode, Value) {
        let body = serde_json::to_vec(
            &json!({"version": 1, "operationId": operation_id, "scope": scope}),
        )
        .unwrap();
        let (status, bytes) = harness.send("POST", "/v1/erasures", body).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The bytes go, the record stays, and the receipt verifies against
    /// the operator key a holder already has from the manifest.
    #[tokio::test]
    async fn erasing_a_snapshot_yields_a_verifiable_receipt() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));

        let (status, receipts) = erase(&harness, &digest).await;
        assert_eq!(status, StatusCode::OK);
        let receipt = &receipts.as_array().unwrap()[0];
        assert_eq!(receipt["scope"], json!(digest));
        assert_eq!(receipt["termsId"], json!(harness.terms_id()));

        // Verified the way a holder would: canonical bytes minus the
        // signature, against the operator key from the manifest.
        let signed = crate::documents::canonical_bytes(receipt, &["signature"]).unwrap();
        let key_hex = harness
            .state
            .documents
            .operator_key
            .strip_prefix("onym:key:")
            .unwrap();
        let key = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(hex::decode(key_hex).unwrap()).unwrap(),
        )
        .unwrap();
        let signature = ed25519_dalek::Signature::from_slice(
            &base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                receipt["signature"].as_str().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        key.verify(&signed, &signature)
            .expect("the receipt does not verify against the operator key");

        // The bytes are gone.
        let hex_digest = hex::encode(Sha256::digest(&snapshot));
        let (status, _) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// §11: a receipt with an empty exclusion is malformed rather than
    /// generous. There is always something an erasure does not reach.
    #[tokio::test]
    async fn a_receipt_names_what_the_erasure_does_not_reach() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));

        let (_, receipts) = erase(&harness, &digest).await;
        let receipt = &receipts.as_array().unwrap()[0];
        let excluded = receipt["excludedScope"].as_str().unwrap();
        assert!(!excluded.trim().is_empty(), "the receipt excludes nothing");
        assert!(
            !receipt["coveredScope"].as_str().unwrap().trim().is_empty(),
            "the receipt covers nothing"
        );
        // And it is a commitment with a deadline, not a claim of
        // completion.
        assert!(receipt["completionCommittedBy"].as_str().unwrap()
            > receipt["acknowledgedAt"].as_str().unwrap());
    }

    /// `erased` is a distinct status. A holder who asks about a digest
    /// they erased is owed that answer, not a silence indistinguishable
    /// from never having stored it.
    #[tokio::test]
    async fn an_erased_snapshot_is_listed_as_erased() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        erase(&harness, &digest).await;

        let (_, listed) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let listed: Value = serde_json::from_slice(&listed).unwrap();
        let row = &listed.as_array().unwrap()[0];
        assert_eq!(row["status"], "erased");
        assert_eq!(row["snapshotReference"]["digest"], json!(digest));
    }

    /// Erasing frees the quota it was consuming.
    #[tokio::test]
    async fn erasing_returns_the_quota() {
        let harness = Harness::new(vec![]);
        let first: Vec<u8> = (0..20u8).collect();
        let second: Vec<u8> = (50..70u8).collect();
        harness.store_snapshot(&first).await;
        harness.store_snapshot(&second).await;

        let terms = harness.terms_id();
        let third: Vec<u8> = (100..120u8).collect();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&third, &terms))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "quota was not full");

        erase(&harness, &format!("sha256:{}", hex::encode(Sha256::digest(&first)))).await;
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&third, &terms))
            .await;
        assert_eq!(status, StatusCode::OK, "erasing did not return the quota");
    }

    /// One holder's erasure must not reach another's bytes, even at the
    /// same digest — and `scope: "all"` is the sharpest form of that.
    #[tokio::test]
    async fn an_erasure_stops_at_the_holder_boundary() {
        let harness = Harness::new(vec![]);
        let mut stranger = Harness::new(vec![]);
        stranger.state = harness.state.clone();
        stranger.signing = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);

        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        stranger.store_snapshot(&snapshot).await;

        let (status, _) = erase(&stranger, "all").await;
        assert_eq!(status, StatusCode::OK);

        // The first holder's copy is untouched. Two holders storing
        // byte-identical snapshots keep two copies precisely so that
        // one erasure cannot reach the other.
        let hex_digest = hex::encode(Sha256::digest(&snapshot));
        let (status, bytes) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK, "a stranger's erasure reached these bytes");
        assert_eq!(bytes, snapshot);
    }

    /// A receipt for a scope with nothing in it would be a signed
    /// statement about nothing.
    #[tokio::test]
    async fn there_is_no_receipt_for_an_empty_scope() {
        let harness = Harness::new(vec![]);
        let (status, _) = erase(&harness, "all").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Erasure without a usable operation id cannot be reconciled, so
    /// it is refused rather than accepted and made unaskable.
    ///
    /// Both shapes, because they are refused by different code and only
    /// one of them is mine: a missing field is serde's, and an empty
    /// string sails past serde into a receipt nobody can ever ask
    /// about. The first version of this test asserted only the missing
    /// field and passed with the empty-string guard deleted.
    #[tokio::test]
    async fn an_erasure_must_carry_a_usable_operation_id() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;

        let missing = serde_json::to_vec(&json!({"version": 1, "scope": "all"})).unwrap();
        let (status, _) = harness.send("POST", "/v1/erasures", missing).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "no operationId at all");

        let (status, _) = erase_as(&harness, "all", "   ").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a blank operationId");

        // And the snapshot is still there — a refused erasure erases
        // nothing.
        let (_, listed) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let listed: Value = serde_json::from_slice(&listed).unwrap();
        assert_eq!(listed.as_array().unwrap()[0]["status"], "retained");
    }

    /// A lost erase response is reconciled by asking, like every other
    /// operation — which is only possible because the id is the
    /// client's.
    #[tokio::test]
    async fn a_lost_erase_response_can_be_reconciled() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));

        let (status, _) = erase_as(&harness, &digest, "op-erase-1").await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = harness
            .send("GET", "/v1/operations/op-erase-1", vec![])
            .await;
        assert_eq!(status, StatusCode::OK, "the erasure could not be reconciled");
        let outcome: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            outcome["outcome"]["status"],
            "erasure_acknowledged"
        );
    }

    /// Retrying an erase returns the receipt already earned. A 404
    /// would be the same silence `list` avoids by reporting `erased`.
    #[tokio::test]
    async fn erasing_twice_returns_the_same_receipt() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));

        let (_, first) = erase(&harness, &digest).await;
        let (status, again) = erase(&harness, &digest).await;
        assert_eq!(status, StatusCode::OK, "a retried erase was refused");
        assert_eq!(
            again[0]["receiptId"], first[0]["receiptId"],
            "the retry minted a second receipt"
        );
        assert_eq!(again[0]["signature"], first[0]["signature"]);
    }

    /// The receipt outlives the response that carried it. A holder
    /// whose erase response was lost still has the only evidence they
    /// hold that the erasure was acknowledged.
    #[tokio::test]
    async fn a_receipt_can_be_fetched_again_by_id() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        let (_, receipts) = erase(&harness, &digest).await;
        let id = receipts[0]["receiptId"].as_str().unwrap().to_string();

        let (status, body) = harness
            .send("GET", &format!("/v1/exports/receipts/{id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK, "an issued receipt is unfetchable");
        let fetched: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched["signature"], receipts[0]["signature"]);

        // And it is holder-scoped like everything else.
        let mut stranger = Harness::new(vec![]);
        stranger.state = harness.state.clone();
        stranger.signing = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let (status, _) = stranger
            .send("GET", &format!("/v1/exports/receipts/{id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Every path the export manifest names must be fetchable, or the
    /// manifest describes a container nobody can assemble.
    #[tokio::test]
    async fn every_container_member_the_manifest_names_is_fetchable() {
        let harness = Harness::new(vec![]);
        let first: Vec<u8> = (0..20u8).collect();
        let second: Vec<u8> = (50..70u8).collect();
        harness.store_snapshot(&first).await;
        harness.store_snapshot(&second).await;
        erase(&harness, &format!("sha256:{}", hex::encode(Sha256::digest(&first)))).await;

        let (_, body) = harness.send("GET", "/v1/exports", vec![]).await;
        let manifest: Value = serde_json::from_slice(&body).unwrap();

        for entry in manifest["snapshots"].as_array().unwrap() {
            let file = entry["file"].as_str().unwrap();
            let hex = file.trim_start_matches("snapshots/").trim_end_matches(".seal");
            let (status, _) = harness.send("GET", &format!("/v1/exports/{hex}"), vec![]).await;
            assert_eq!(status, StatusCode::OK, "{file} is unfetchable");
        }
        for entry in manifest["receipts"].as_array().unwrap() {
            let file = entry.as_str().unwrap();
            let id = file.trim_start_matches("receipts/").trim_end_matches(".json");
            let (status, _) = harness
                .send("GET", &format!("/v1/exports/receipts/{id}"), vec![])
                .await;
            assert_eq!(status, StatusCode::OK, "{file} is unfetchable");
        }
        // Terms come from `/terms/`, which is where the snapshot
        // entry's `termsUrl` points. The container outlives the
        // operator; the route only has to outlive the assembly.
        for entry in manifest["terms"].as_array().unwrap() {
            let hex = entry["file"]
                .as_str()
                .unwrap()
                .trim_start_matches("terms/")
                .trim_end_matches(".json");
            for path in [format!("/terms/{hex}.json"), format!("/terms/{hex}.json.sig")] {
                let response = crate::api::router(harness.state.clone())
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(&path)
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{path} is unfetchable");
            }
        }

        assert!(
            !manifest["receipts"].as_array().unwrap().is_empty(),
            "the fixture proves nothing without a receipt in it"
        );
        assert!(!manifest["terms"].as_array().unwrap().is_empty());
    }

    /// A receipt must not invent a deadline the pinned terms never
    /// made. Terms without one are a broken document, not a licence to
    /// choose a number and sign it.
    #[tokio::test]
    async fn terms_without_a_completion_deadline_produce_no_receipt() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));

        // Replace the stored terms with a document that declares scope
        // and exclusions but no deadline.
        {
            let store = harness.state.store.lock().await;
            let (raw, _) = store.terms_document(&harness.terms_id()).unwrap().unwrap();
            let mut terms: Value = serde_json::from_slice(&raw).unwrap();
            terms["erasure"]
                .as_object_mut()
                .unwrap()
                .remove("completionDeadline");
            store
                .connection_for_tests()
                .execute(
                    "UPDATE terms_documents SET raw = ?2 WHERE terms_id = ?1",
                    ::rusqlite::params![harness.terms_id(), serde_json::to_vec(&terms).unwrap()],
                )
                .unwrap();
        }

        let (status, _) = erase(&harness, &digest).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a deadline was invented for terms that declare none"
        );
    }

    use tower::ServiceExt;

    /// Erase, then store the same snapshot again.
    ///
    /// This is the migration flow `export.rs` advertises — the same
    /// sealed bytes re-uploaded under the same reference — and it is
    /// also just a holder changing their mind. The erased row keeps the
    /// `(holder, digest)` primary key, so a re-upload must revive it
    /// rather than being silently ignored by `INSERT OR IGNORE` while
    /// the operator answers `retained`.
    #[tokio::test]
    async fn a_snapshot_can_be_stored_again_after_being_erased() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        let hex_digest = hex::encode(Sha256::digest(&snapshot));
        erase(&harness, &digest).await;

        let (status, body) = harness.store_snapshot(&snapshot).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let outcome: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(outcome["outcome"]["status"], "retained");

        // The word has to be true. Reporting `retained` for bytes that
        // cannot be read back is worse than refusing the upload.
        let (status, bytes) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK, "the operator said retained and stored nothing");
        assert_eq!(bytes, snapshot);

        let (_, listed) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let listed: Value = serde_json::from_slice(&listed).unwrap();
        assert_eq!(listed.as_array().unwrap()[0]["status"], "retained");
    }

    /// And the sweep must not then delete what was just committed.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_sweep_keeps_a_snapshot_restored_after_erasure() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        erase(&harness, &digest).await;
        harness.store_snapshot(&snapshot).await;

        let swept = tokio::task::block_in_place(|| {
            crate::sweep::reconcile(
                &harness.state.store,
                &harness.state.blob_mutations,
                &harness.state.blobs,
                &std::collections::HashSet::new(),
                false,
                time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
                crate::sweep::Cutoffs {
                    now: "2099-01-01T00:00:00Z",
                    nonce: "2000-01-01T00:00:00Z",
                    outcome: "2000-01-01T00:00:00Z",
                    receipt: "2000-01-01T00:00:00Z",
                    entitlement: "2000-01-01T00:00:00Z",
                    erased_reference: "2000-01-01T00:00:00Z",
                },
            )
        });
        assert_eq!(swept.orphan_snapshots, 0, "the sweep deleted a live snapshot");

        let hex_digest = hex::encode(Sha256::digest(&snapshot));
        let (status, _) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A whole-holder erasure's outcome is a scope, not a digest.
    /// Reporting `"digest": "all"` would be a scope wearing a digest's
    /// name, which a client parsing the field would take literally.
    #[tokio::test]
    async fn an_erasure_outcome_reports_a_scope() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        erase_as(&harness, "all", "op-all").await;

        let (status, body) = harness.send("GET", "/v1/operations/op-all", vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let outcome: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(outcome["outcome"]["scope"], "all");
        assert!(
            outcome["outcome"]["digest"].is_null(),
            "an erasure scope was reported as a digest"
        );
    }

    /// A retry with a fresh operation id must be reconcilable too —
    /// otherwise the retry path is the one operation §9.8 cannot
    /// answer for, which is the path most likely to need it.
    #[tokio::test]
    async fn a_retried_erasure_records_its_own_operation_id() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));

        erase_as(&harness, &digest, "op-first").await;
        let (status, _) = erase_as(&harness, &digest, "op-retry").await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = harness.send("GET", "/v1/operations/op-retry", vec![]).await;
        assert_eq!(status, StatusCode::OK, "the retry could not be reconciled");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["outcome"]["status"],
            "erasure_acknowledged"
        );
    }

    /// A receipt cites the terms of a snapshot that is gone, so the
    /// container has to carry those terms even when no live snapshot
    /// pins them. Otherwise the container ships a receipt whose pin has
    /// no preimage — by the one route the module doc was not watching.
    #[tokio::test]
    async fn the_container_carries_the_terms_a_receipt_pins() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        erase(&harness, "all").await;

        let (_, body) = harness.send("GET", "/v1/exports", vec![]).await;
        let manifest: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            manifest["snapshots"].as_array().unwrap().is_empty(),
            "nothing is live, which is the case that breaks"
        );
        assert_eq!(manifest["receipts"].as_array().unwrap().len(), 1);
        assert_eq!(
            manifest["terms"].as_array().unwrap().len(),
            1,
            "the receipt's terms are not in the container"
        );
        assert_eq!(
            manifest["terms"][0]["termsId"],
            json!(harness.terms_id())
        );
    }

    /// `scope: "all"` means "all, now" — it is evaluated at request
    /// time, so erasing it again after new snapshots were retained is a
    /// new erasure of new bytes. Replaying the first receipt would
    /// misdate the commitment: `acknowledgedAt` and
    /// `completionCommittedBy` are about the erasure that produced it.
    #[tokio::test]
    async fn erasing_all_again_covers_what_arrived_since() {
        let harness = Harness::new(vec![]);
        let first: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&first).await;
        let (_, original) = erase(&harness, "all").await;
        let original_id = original[0]["receiptId"].as_str().unwrap().to_string();

        // A new snapshot arrives, and "all" is asked for again.
        let second: Vec<u8> = (50..70u8).collect();
        harness.store_snapshot(&second).await;
        let (status, again) = erase(&harness, "all").await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(
            again[0]["receiptId"].as_str().unwrap(),
            original_id,
            "the second erasure replayed the first receipt"
        );

        // Both remain fetchable by id — the earlier one is not reissued
        // but it is not destroyed either.
        for id in [original_id.as_str(), again[0]["receiptId"].as_str().unwrap()] {
            let (status, _) = harness
                .send("GET", &format!("/v1/exports/receipts/{id}"), vec![])
                .await;
            assert_eq!(status, StatusCode::OK, "receipt {id} is gone");
        }

        // And the new snapshot really was erased.
        let (_, listed) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let listed: Value = serde_json::from_slice(&listed).unwrap();
        for row in listed.as_array().unwrap() {
            assert_eq!(row["status"], "erased");
        }
    }

    /// Once the receipts age out, the erasure is still a fact the
    /// operator knows. `receipt_expired`, not a 404 that reads like the
    /// snapshot never existed — and not `retention_expired`, which a
    /// client maps to a sentence about a snapshot.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_aged_out_receipt_is_not_a_missing_snapshot() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        erase(&harness, &digest).await;

        tokio::task::block_in_place(|| {
            crate::sweep::reconcile(
                &harness.state.store,
                &harness.state.blob_mutations,
                &harness.state.blobs,
                &std::collections::HashSet::new(),
                false,
                time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
                crate::sweep::Cutoffs {
                    now: "2099-01-01T00:00:00Z",
                    nonce: "2000-01-01T00:00:00Z",
                    outcome: "2000-01-01T00:00:00Z",
                    // Every receipt is now past its window.
                    receipt: "2099-01-01T00:00:00Z",
                    erased_reference: "2000-01-01T00:00:00Z",
                    entitlement: "2000-01-01T00:00:00Z",
                },
            )
        });

        let (status, body) = erase(&harness, &digest).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(body["error"], "receipt_expired");

        // A scope that was never held is still a 404: the difference is
        // whether the operator knows an erasure happened.
        let (status, _) = erase(&harness, &format!("sha256:{}", "cc".repeat(32))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// §9.7's routes must all be reachable without an entitlement, and
    /// the receipt route is the one a holder reaches in exactly the
    /// state where a check would be tempting: after erasing everything,
    /// or after lapsing. Evidence conditioned on payment is not
    /// evidence.
    #[tokio::test]
    async fn a_receipt_is_fetchable_without_an_entitlement() {
        let harness = Harness::new(vec![format!("onym:key:{}", "aa".repeat(32))]);
        assert!(harness.state.config.requires_entitlement());

        // Seed a receipt directly: this operator charges, so the upload
        // path is closed and the fixture is about the read path.
        let receipt = serde_json::to_vec(&json!({"receiptVersion": 1, "receiptId": "r1"})).unwrap();
        harness
            .state
            .store
            .lock()
            .await
            .connection_for_tests()
            .execute(
                "INSERT INTO erasure_receipts
                    (receipt_id, holder_handle, scope, terms_id, raw, issued_at)
                 VALUES ('r1', ?1, 'all', 'sha256:aa', ?2, '2026-01-01T00:00:00Z')",
                rusqlite::params![harness.handle(), receipt],
            )
            .unwrap();

        let (status, _) = harness.send("GET", "/v1/exports/receipts/r1", vec![]).await;
        assert_eq!(status, StatusCode::OK, "a receipt was withheld from an unpaid holder");
    }

    /// Every receipt for a `scope: "all"` echoes the same scope string
    /// and differs only in `termsId`, so without `snapshots` a holder
    /// cannot tell which bytes each signed commitment is about.
    #[tokio::test]
    async fn a_receipt_names_the_snapshots_it_covers() {
        let harness = Harness::new(vec![]);
        let first: Vec<u8> = (0..20u8).collect();
        let second: Vec<u8> = (50..70u8).collect();
        harness.store_snapshot(&first).await;
        harness.store_snapshot(&second).await;

        let (_, receipts) = erase(&harness, "all").await;
        let receipt = &receipts.as_array().unwrap()[0];
        let covered: Vec<&str> = receipt["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for snapshot in [&first, &second] {
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(snapshot)));
            assert!(covered.contains(&digest.as_str()), "{digest} is not named");
        }

        assert_eq!(receipts.as_array().unwrap().len(), 1, "one terms document, one receipt");
    }

    /// §9.6 justifies the client-chosen operationId by saying a lost
    /// erase response must not cost the holder their receipt — which is
    /// only true if reconciling by that id yields something §9.7 can be
    /// asked for. This is the whole path a holder walks after losing
    /// the response.
    #[tokio::test]
    async fn a_lost_erase_response_leads_back_to_the_receipt() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        erase_as(&harness, &digest, "op-lost").await;

        // The response never arrived. All the holder has is the id.
        let (status, body) = harness.send("GET", "/v1/operations/op-lost", vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let outcome: Value = serde_json::from_slice(&body).unwrap();
        let ids = outcome["outcome"]["receiptIds"].as_array().unwrap();
        assert_eq!(ids.len(), 1, "the outcome does not name the receipts");

        let id = ids[0].as_str().unwrap();
        let (status, body) = harness
            .send("GET", &format!("/v1/exports/receipts/{id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK, "the named receipt is unfetchable");
        let receipt: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(receipt["scope"], json!(digest));
    }

    /// Replay returns the most recent set, not every receipt ever
    /// issued for the string — which would grow without bound and mix
    /// commitments about different bytes made on different days.
    #[tokio::test]
    async fn replay_returns_only_the_latest_set() {
        let harness = Harness::new(vec![]);
        harness.store_snapshot(&(0..20u8).collect::<Vec<u8>>()).await;
        let (_, first) = erase(&harness, "all").await;
        let first_id = first[0]["receiptId"].as_str().unwrap().to_string();

        harness.store_snapshot(&(50..70u8).collect::<Vec<u8>>()).await;
        let (_, second) = erase(&harness, "all").await;
        let second_id = second[0]["receiptId"].as_str().unwrap().to_string();

        let (status, replay) = erase(&harness, "all").await;
        assert_eq!(status, StatusCode::OK);
        let replay = replay.as_array().unwrap();
        assert_eq!(replay.len(), 1, "the replay accumulated receipts");
        assert_eq!(replay[0]["receiptId"], json!(second_id));
        assert_ne!(replay[0]["receiptId"], json!(first_id));

        // The earlier one is not reissued, but nothing is lost.
        let (status, _) = harness
            .send("GET", &format!("/v1/exports/receipts/{first_id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Scope strings are not comparable, and a holder must not be told
    /// their evidence aged out while it sits fetchable by id.
    ///
    /// Both directions: a receipt minted for `all` covers digests a
    /// later single-digest retry names directly, and a receipt minted
    /// for one digest is part of what a later `all` retry asks about.
    #[tokio::test]
    async fn a_retry_under_a_different_scope_still_finds_the_receipt() {
        // all → digest
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        let (_, minted) = erase(&harness, "all").await;
        let minted_id = minted[0]["receiptId"].as_str().unwrap().to_string();

        let (status, body) = erase(&harness, &digest).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a live receipt was reported as expired: {body}"
        );
        assert_eq!(body[0]["receiptId"], json!(minted_id));

        // digest → all
        let other = Harness::new(vec![]);
        let second: Vec<u8> = (50..70u8).collect();
        other.store_snapshot(&second).await;
        let second_digest = format!("sha256:{}", hex::encode(Sha256::digest(&second)));
        let (_, first) = erase(&other, &second_digest).await;
        let first_id = first[0]["receiptId"].as_str().unwrap().to_string();

        let (status, body) = erase(&other, "all").await;
        assert_eq!(status, StatusCode::OK, "a live receipt was reported as expired");
        assert_eq!(body[0]["receiptId"], json!(first_id));
    }

    /// §9.6 justifies the client-chosen operationId by saying a lost
    /// erase response must not cost the holder their receipt. That
    /// stops being true the moment the outcome is swept on the short
    /// upload window — the holder would be left holding a receiptId
    /// they can no longer learn. Erase outcomes ride the receipt
    /// window instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_erase_outcome_outlives_the_upload_outcome_window() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        erase_as(&harness, &digest, "op-erase-window").await;

        // Every upload outcome is past its window; no receipt is.
        tokio::task::block_in_place(|| {
            crate::sweep::reconcile(
                &harness.state.store,
                &harness.state.blob_mutations,
                &harness.state.blobs,
                &std::collections::HashSet::new(),
                false,
                time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
                crate::sweep::Cutoffs {
                    now: "2099-01-01T00:00:00Z",
                    nonce: "2000-01-01T00:00:00Z",
                    outcome: "2099-01-01T00:00:00Z",
                    receipt: "2000-01-01T00:00:00Z",
                    entitlement: "2000-01-01T00:00:00Z",
                    erased_reference: "2000-01-01T00:00:00Z",
                },
            )
        });

        let (status, body) = harness
            .send("GET", "/v1/operations/op-erase-window", vec![])
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the erase outcome was swept on the upload window"
        );
        let outcome: Value = serde_json::from_slice(&body).unwrap();
        let id = outcome["outcome"]["receiptIds"][0].as_str().unwrap();
        let (status, _) = harness
            .send("GET", &format!("/v1/exports/receipts/{id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A scope that was never held is a 404 — the one empty-scope case
    /// that is not a replay. Three distinct answers, and a client that
    /// conflated them would retry an erasure that can never succeed.
    #[tokio::test]
    async fn the_three_empty_scope_answers_are_distinct() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let held = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        let never = format!("sha256:{}", "cc".repeat(32));

        // Never held.
        let (status, _) = erase(&harness, &never).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "never held");

        // Erased, receipt live.
        erase(&harness, &held).await;
        let (status, _) = erase(&harness, &held).await;
        assert_eq!(status, StatusCode::OK, "erased with a live receipt");

        // Erased, receipt expired, reference still remembered.
        harness
            .state
            .store
            .lock()
            .await
            .sweep_outcomes_and_receipts("2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z")
            .unwrap();
        let (status, _) = erase(&harness, &held).await;
        assert_eq!(status, StatusCode::GONE, "erased with an expired receipt");
    }

    /// One request is acknowledged at one moment.
    ///
    /// Replay groups by `acknowledgedAt`, so an operator stamping each
    /// receipt as it signs it would split one erasure across two
    /// timestamps and replay a subset of its own commitment. This needs
    /// a scope spanning *two* pinned terms documents to mean anything —
    /// with one, the set is trivially of size one and the assertion
    /// cannot fail, which is what the first version of it did.
    #[tokio::test]
    async fn one_erasure_is_acknowledged_at_one_moment() {
        let harness = Harness::new(vec![]);
        let first: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&first).await;

        // A second snapshot pinned to superseded terms, which is the
        // only way a scope spans two terms documents.
        let older = br#"{"termsVersion":1,"erasure":{"scope":"the primary copy","excluded":"copies held by other participants","completionDeadline":"P3D"}}"#;
        let older_id = crate::documents::digest(older);
        {
            let store = harness.state.store.lock().await;
            store
                .remember_terms(&older_id, older, b"c2ln", "2026-01-01T00:00:00Z")
                .unwrap();
            store
                .retain(
                    &crate::store::UploadRow {
                        upload_id: "u-old".into(),
                        holder_handle: harness.handle(),
                        operation_id: "op-old".into(),
                        digest: format!("sha256:{}", "ab".repeat(32)),
                        sealed_byte_size: 8,
                        chunk_bytes: 8,
                        chunk_count: 1,
                        accepted_terms_id: older_id.clone(),
                        supersedes: None,
                        expires_at: "2999-01-01T00:00:00Z".into(),
                    },
                    "2026-01-02T00:00:00Z",
                )
                .unwrap();
        }

        let (status, receipts) = erase(&harness, "all").await;
        assert_eq!(status, StatusCode::OK);
        let receipts = receipts.as_array().unwrap();
        assert_eq!(receipts.len(), 2, "two pinned terms should yield two receipts");

        let stamps: std::collections::HashSet<&str> = receipts
            .iter()
            .map(|r| r["acknowledgedAt"].as_str().unwrap())
            .collect();
        assert_eq!(stamps.len(), 1, "one erasure produced two acknowledgedAt values");

        // And each cites its own pinned terms, not whichever were
        // current — the whole reason there are two.
        let cited: std::collections::HashSet<&str> = receipts
            .iter()
            .map(|r| r["termsId"].as_str().unwrap())
            .collect();
        assert!(cited.contains(older_id.as_str()), "superseded terms were not cited");
        assert!(cited.contains(harness.terms_id().as_str()));

        // Replay returns both, since they share an acknowledgedAt.
        let (_, replay) = erase(&harness, "all").await;
        assert_eq!(replay.as_array().unwrap().len(), 2, "replay dropped half the erasure");
    }

    /// A failure while minting must leave nothing half-done.
    ///
    /// Composing a receipt reads the pinned terms and can refuse. When
    /// that happened *after* the bytes were unlinked, the holder was
    /// erased with no receipt, `list` still said `retained`, and a
    /// retry answered `receipt_expired` about a receipt that never
    /// existed — three false statements from one failed request.
    #[tokio::test]
    async fn a_refused_receipt_erases_nothing() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));

        // Terms that cannot produce a receipt: no completion deadline.
        {
            let store = harness.state.store.lock().await;
            let (raw, _) = store.terms_document(&harness.terms_id()).unwrap().unwrap();
            let mut terms: Value = serde_json::from_slice(&raw).unwrap();
            terms["erasure"].as_object_mut().unwrap().remove("completionDeadline");
            store
                .connection_for_tests()
                .execute(
                    "UPDATE terms_documents SET raw = ?2 WHERE terms_id = ?1",
                    ::rusqlite::params![harness.terms_id(), serde_json::to_vec(&terms).unwrap()],
                )
                .unwrap();
        }

        let (status, _) = erase(&harness, &digest).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        // Nothing was destroyed and nothing was claimed.
        let (_, listed) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let listed: Value = serde_json::from_slice(&listed).unwrap();
        assert_eq!(listed.as_array().unwrap()[0]["status"], "retained");
        let hex_digest = hex::encode(Sha256::digest(&snapshot));
        let (status, bytes) = harness
            .send("GET", &format!("/v1/snapshots/{hex_digest}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK, "the bytes were erased for a refused receipt");
        assert_eq!(bytes, snapshot);
    }

    #[tokio::test]
    async fn unlink_failure_does_not_stop_the_rest_of_an_all_erasure() {
        let harness = Harness::new(vec![]);
        harness
            .store_snapshot(&(0..20u8).collect::<Vec<u8>>())
            .await;
        harness
            .store_snapshot(&(50..70u8).collect::<Vec<u8>>())
            .await;

        let targets = harness
            .state
            .store
            .lock()
            .await
            .snapshots(&harness.handle())
            .unwrap();
        assert_eq!(targets.len(), 2);
        let first_hex = crate::blobs::digest_hex(&targets[0].digest).unwrap();
        let second_hex = crate::blobs::digest_hex(&targets[1].digest).unwrap();
        let holder_root = harness
            .state
            .blobs
            .root()
            .join(&harness.handle()[..2])
            .join(harness.handle());
        let first_path = holder_root.join(first_hex);
        std::fs::remove_dir_all(&first_path).unwrap();
        std::fs::write(&first_path, b"cannot remove this with remove_dir_all").unwrap();

        let (status, _) = erase(&harness, "all").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a committed erasure was relabeled as failed"
        );
        assert!(
            !holder_root.join(second_hex).exists(),
            "the first unlink failure stopped later snapshots"
        );
    }

    /// The sweep takes a receipt's coverage with it.
    ///
    /// Coverage rows name digests a holder erased. Left behind they
    /// outlive the `erasureReceipts` window the terms declare, which is
    /// a §15 retention problem rather than only a leak.
    #[tokio::test(flavor = "multi_thread")]
    async fn sweeping_a_receipt_takes_its_coverage() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        erase(&harness, "all").await;

        let count = |harness: &Harness| {
            let store = harness.state.store.blocking_lock();
            store
                .connection_for_tests()
                .query_row("SELECT COUNT(*) FROM receipt_snapshots", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert!(tokio::task::block_in_place(|| count(&harness)) > 0);

        tokio::task::block_in_place(|| {
            crate::sweep::reconcile(
                &harness.state.store,
                &harness.state.blob_mutations,
                &harness.state.blobs,
                &std::collections::HashSet::new(),
                false,
                time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
                crate::sweep::Cutoffs {
                    now: "2099-01-01T00:00:00Z",
                    nonce: "2000-01-01T00:00:00Z",
                    outcome: "2000-01-01T00:00:00Z",
                    receipt: "2099-01-01T00:00:00Z",
                    erased_reference: "2000-01-01T00:00:00Z",
                    entitlement: "2000-01-01T00:00:00Z",
                },
            )
        });
        assert_eq!(
            tokio::task::block_in_place(|| count(&harness)),
            0,
            "coverage rows outlived the receipts they belong to"
        );
    }

    /// Every promise that rides on the erased reference ends with it.
    ///
    /// The row is what lets `list` say `erased` and a re-erase say
    /// `receipt_expired`. Kept without limit it is a permanent list of
    /// everything this holder has erased — a more complete history than
    /// the backups. So it is bounded, and past the bound the operator
    /// has genuinely forgotten rather than chosen to be coy.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_forgotten_erasure_stops_being_reported() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        erase(&harness, &digest).await;

        // Receipts and the reference are both past their windows.
        tokio::task::block_in_place(|| {
            crate::sweep::reconcile(
                &harness.state.store,
                &harness.state.blob_mutations,
                &harness.state.blobs,
                &std::collections::HashSet::new(),
                false,
                time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
                crate::sweep::Cutoffs {
                    now: "2099-01-01T00:00:00Z",
                    nonce: "2000-01-01T00:00:00Z",
                    outcome: "2000-01-01T00:00:00Z",
                    receipt: "2099-01-01T00:00:00Z",
                    erased_reference: "2099-01-01T00:00:00Z",
                    entitlement: "2000-01-01T00:00:00Z",
                },
            )
        });

        // Not `receipt_expired`: the operator no longer knows there was
        // an erasure, and saying so would require the record it just
        // discarded.
        let (status, _) = erase(&harness, &digest).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // And `list` no longer carries the row either.
        let (_, listed) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let listed: Value = serde_json::from_slice(&listed).unwrap();
        assert!(listed.as_array().unwrap().is_empty());
    }

    /// While the reference survives, the erasure is still reported.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_remembered_erasure_is_still_receipt_expired() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        erase(&harness, &digest).await;

        // Receipts gone; the reference kept.
        tokio::task::block_in_place(|| {
            crate::sweep::reconcile(
                &harness.state.store,
                &harness.state.blob_mutations,
                &harness.state.blobs,
                &std::collections::HashSet::new(),
                false,
                time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
                crate::sweep::Cutoffs {
                    now: "2099-01-01T00:00:00Z",
                    nonce: "2000-01-01T00:00:00Z",
                    outcome: "2000-01-01T00:00:00Z",
                    receipt: "2099-01-01T00:00:00Z",
                    erased_reference: "2000-01-01T00:00:00Z",
                    entitlement: "2000-01-01T00:00:00Z",
                },
            )
        });

        let (status, body) = erase(&harness, &digest).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(body["error"], "receipt_expired");
    }

    #[tokio::test]
    async fn replay_uses_the_latest_covering_erasure_not_an_older_exact_scope() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));

        let (_, first) = erase(&harness, &digest).await;
        let first_id = first[0]["receiptId"].as_str().unwrap().to_string();

        harness.store_snapshot(&snapshot).await;
        let (_, latest) = erase(&harness, "all").await;
        let latest_id = latest[0]["receiptId"].as_str().unwrap().to_string();
        assert_ne!(first_id, latest_id);

        let (status, replay) = erase(&harness, &digest).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            replay[0]["receiptId"],
            json!(latest_id),
            "replay returned an older exact-scope receipt"
        );
    }
}
