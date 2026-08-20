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
pub struct EraseRequest {
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

    let (holder, targets) = {
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
        if request.scope != "all" {
            crate::uploads::digest_hex(&request.scope)?;
        }

        let targets = store.snapshots_in_scope(&holder.handle, &request.scope)?;
        if targets.is_empty() {
            // Nothing to erase and nothing to commit to. A receipt for
            // an empty scope would be a signed statement about nothing.
            return Err(Error::NotFound(Resource::Snapshot));
        }
        (holder, (request.scope, targets))
    };
    let (scope, targets) = targets;

    // Bytes first, then the rows. A crash between them leaves a record
    // whose bytes are gone, which the sweep resolves and which `list`
    // reports as erased — the safe direction. The reverse would leave
    // bytes the holder believes are gone.
    for row in &targets {
        let digest_hex = crate::uploads::digest_hex(&row.digest)?;
        let handle = holder.handle.clone();
        crate::uploads::blocking(&state, move |state| state.blobs.erase(&handle, &digest_hex))
            .await?;
    }

    let mut receipts = Vec::new();
    {
        let store = state.store.lock().await;
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
            let (raw, _) = store
                .terms_document(&terms_id)?
                .ok_or(Error::NotFound(Resource::Terms))?;
            let terms: Value = serde_json::from_slice(&raw)
                .map_err(|e| Error::Internal(format!("stored terms: {e}")))?;
            let receipt = compose(&state, &terms, &terms_id, &scope, &stamp)?;
            let signed = crate::documents::sign_receipt(receipt, &state.signing)?;
            let receipt_id = serde_json::from_slice::<Value>(&signed)
                .map_err(|e| Error::Internal(e.to_string()))?["receiptId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            store.record_receipt(
                &receipt_id,
                &holder.handle,
                &scope,
                &terms_id,
                &signed,
                &stamp,
            )?;
            receipts.push(
                serde_json::from_slice::<Value>(&signed)
                    .map_err(|e| Error::Internal(e.to_string()))?,
            );
        }

        store.record_outcome(
            &format!("erase:{scope}"),
            &holder.handle,
            &scope,
            "erased",
            &stamp,
        )?;
    }

    Ok(axum::Json(receipts).into_response())
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

    let deadline = erasure["completionDeadline"].as_str().unwrap_or("P7D");
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
        let body = serde_json::to_vec(&json!({"version": 1, "scope": scope})).unwrap();
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
}
