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
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

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

    let mut receipts = Vec::new();
    {
        let store = state.store.lock().await;
        let holder = authenticate(
            &headers,
            "POST",
            "/v1/erasures",
            &body,
            &state.config,
            &store,
            now,
        )?;
        let request: EraseRequest = serde_json::from_slice(&body)
            .map_err(|e| Error::BadRequest(format!("erasure body: {e}")))?;
        if request.operation_id.trim().is_empty() {
            return Err(Error::BadRequest("operationId is required".into()));
        }
        if request.scope != "all" {
            crate::uploads::digest_hex(&request.scope)?;
        }

        let targets = store.snapshots_in_scope(&holder.handle, &request.scope)?;
        if targets.is_empty() {
            // Nothing live in scope. If this scope was erased before,
            // the holder is retrying and is owed the receipt they
            // already earned — a 404 here would be the same silence
            // `list` avoids by reporting `erased`.
            let existing = store.receipts_for_scope(&holder.handle, &request.scope)?;
            if !existing.is_empty() {
                // The retry's own operation id is recorded too, so a
                // client that retries with a fresh id and loses *that*
                // response can still reconcile it. Otherwise the retry
                // path is the one operation §9.8 cannot answer for.
                store.record_outcome(
                    &request.operation_id,
                    &holder.handle,
                    &request.scope,
                    "erased",
                    &stamp,
                )?;
                return Ok(axum::Json(decode_receipts(existing)?).into_response());
            }
            // Erased, but the receipts have aged out. The snapshot
            // rows outlive them, so the operator knows this happened
            // and says so rather than answering "no such snapshot"
            // about an erasure the holder requested themselves.
            if store.scope_was_erased(&holder.handle, &request.scope)? {
                return Err(Error::ReceiptExpired);
            }
            // Never held, so there is nothing to commit to. A receipt
            // for an empty scope would be a signed statement about
            // nothing.
            return Err(Error::NotFound(Resource::Snapshot));
        }
        // The lock is held from target selection through to the
        // receipts, unlike upload's commit. Two erases of one scope
        // would otherwise both find live targets and each mint a
        // receipt, making the receipt count a record of concurrency
        // rather than of erasures. The reason it is affordable here and
        // not there: erasing is `unlink` per chunk, bounded by file
        // count, where commit hashes every byte.
        //
        // Bytes first, then the rows. A crash between them leaves a
        // record whose bytes are gone, which the sweep resolves and
        // which `list` reports as erased — the safe direction. The
        // reverse would leave bytes the holder believes are gone.
        for row in &targets {
            let digest_hex = crate::uploads::digest_hex(&row.digest)?;
            state.blobs.erase(&holder.handle, &digest_hex)?;
        }

        for row in &targets {
            store.mark_erased(&holder.handle, &row.digest, &stamp)?;
        }

        let mut pinned: Vec<String> = targets
            .iter()
            .map(|row| row.accepted_terms_id.clone())
            .collect();
        pinned.sort();
        pinned.dedup();

        for terms_id in pinned {
            // A fresh receipt every time something was actually erased.
            // `scope: "all"` is evaluated at request time, so erasing
            // "all" again after new snapshots were retained is a new
            // erasure of new bytes — handing back the earlier receipt
            // would misdate the commitment, since `acknowledgedAt` and
            // `completionCommittedBy` are about the erasure that
            // produced it. Replay belongs to the empty-scope path
            // above, and only there.
            let (raw, _) = store
                .terms_document(&terms_id)?
                .ok_or(Error::NotFound(Resource::Terms))?;
            let terms: Value = serde_json::from_slice(&raw)
                .map_err(|e| Error::Internal(format!("stored terms: {e}")))?;
            let receipt = compose(&state, &terms, &terms_id, &request.scope, &stamp)?;
            let receipt_id = receipt["receiptId"]
                .as_str()
                .ok_or_else(|| Error::Internal("receipt has no id".into()))?
                .to_string();
            let (document, signed) = crate::documents::sign_receipt(receipt, &state.signing)?;
            store.record_receipt(
                &receipt_id,
                &holder.handle,
                &request.scope,
                &terms_id,
                &signed,
                &stamp,
            )?;
            receipts.push(document);
        }

        store.record_outcome(
            &request.operation_id,
            &holder.handle,
            &request.scope,
            "erased",
            &stamp,
        )?;
    }

    Ok(axum::Json(receipts).into_response())
}

fn decode_receipts(raw: Vec<Vec<u8>>) -> Result<Vec<Value>> {
    raw.iter()
        .map(|bytes| {
            serde_json::from_slice(bytes)
                .map_err(|e| Error::Internal(format!("stored receipt: {e}")))
        })
        .collect()
}

/// One receipt, against one pinned terms document.
fn compose(
    state: &Arc<AppState>,
    terms: &Value,
    terms_id: &str,
    scope: &str,
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
    let committed_by = (acknowledged + iso8601_days(deadline)?)
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(json!({
        "receiptVersion": 1,
        "receiptId": hex::encode(uuid::Uuid::new_v4().as_bytes()),
        "operator": state.documents.operator_key,
        "scope": scope,
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
    Ok(time::Duration::days(days))
}

#[cfg(test)]
mod tests {
    use crate::uploads::tests::Harness;
    use axum::http::StatusCode;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

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
        assert_eq!(outcome["outcome"]["status"], "erased");
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
                    rusqlite::params![harness.terms_id(), serde_json::to_vec(&terms).unwrap()],
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
                &harness.state.blobs,
                "2099-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
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
            "erased"
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
                &harness.state.blobs,
                "2099-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",
                // Every receipt is now past its window.
                "2099-01-01T00:00:00Z",
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
            .record_receipt("r1", &harness.handle(), "all", "sha256:aa", &receipt, "2026-01-01T00:00:00Z")
            .unwrap();

        let (status, _) = harness.send("GET", "/v1/exports/receipts/r1", vec![]).await;
        assert_eq!(status, StatusCode::OK, "a receipt was withheld from an unpaid holder");
    }
}
