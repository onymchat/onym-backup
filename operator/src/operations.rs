//! `GET /v1/operations/{operationId}` — reconciling a lost response.
//!
//! §14.9's rule is the whole point: **`unknown` is preserved as
//! `unknown`.** A client that lost a response asks here rather than
//! guessing, and an operator that answered "retained" for an operation
//! it has no record of would turn a client's uncertainty into a false
//! certainty — which is worse than the uncertainty.
//!
//! A `404` is therefore not evidence the operation failed. The window
//! is short on purpose (§15: keeping an operation id is a per-holder
//! timing trace), and a client that has aged past it reconciles by
//! reference through `listSnapshots` instead.

use std::sync::Arc;

use axum::extract::{OriginalUri, Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::OffsetDateTime;

use crate::api::AppState;
use crate::auth::authenticate;
use crate::error::{Error, Resource, Result};

pub async fn query(
    State(state): State<Arc<AppState>>,
    Path(operation_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    // Authenticate the request target the holder actually signed.
    // Axum percent-decodes `Path`, which is correct for the database
    // key but not for reconstructing a signature target such as
    // `/v1/operations/op%201`.
    let path = uri.path();

    let store = state.store.lock().await;
    let holder = authenticate(&headers, "GET", path, b"", &state.config, &store, now)?;
    // Always available. Reconciling a lost response is not a service a
    // holder can be behind on paying for — refusing it would strand
    // them between two states rather than charge them for anything.
    crate::lapse::require(
        &state,
        &store,
        &holder,
        &headers,
        crate::lapse::Operation::Reconcile,
        now,
    )?;

    // Scoped to the asking holder. The id is client-chosen, so an
    // unscoped lookup would let one holder read another's outcome by
    // guessing — and the ids are only as unguessable as the client
    // that minted them.
    let (subject, status, receipt_ids, recorded_at) = store
        .outcome(&holder.handle, &operation_id)?
        .ok_or(Error::NotFound(Resource::Operation))?;

    // Named for what the operation was about. An upload's subject is a
    // digest; an erasure's is its scope, which may be "all" — and a
    // field called `digest` reporting "all" is a scope wearing a
    // digest's name.
    let subject_field = if status == "erasure_acknowledged" {
        "scope"
    } else {
        "digest"
    };
    let mut outcome = json!({
        "componentId": state.config.component_id,
        "operationId": operation_id,
        "status": status,
        subject_field: subject,
        "recordedAt": recorded_at,
    });
    // §9.6 justifies the client-chosen operationId by saying a lost
    // erase response must not cost the holder their receipt — which is
    // only true if reconciling by that id yields something §9.7 can be
    // asked for. Without this the holder recovers the fact of the
    // erasure and still cannot name the receipt.
    if let Some(ids) = receipt_ids {
        let ids: Vec<String> = serde_json::from_str(&ids).unwrap_or_default();
        outcome["receiptIds"] = json!(ids);
    }
    Ok(axum::Json(json!({ "outcome": outcome })).into_response())
}

#[cfg(test)]
mod tests {
    use crate::uploads::tests::Harness;
    use axum::http::StatusCode;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    /// The §14.9 case: a lost commit response is reconciled by asking,
    /// not by guessing.
    #[tokio::test]
    async fn a_committed_operation_can_be_reconciled() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let body = harness.preflight_body(&snapshot, &terms);
        let operation_id = serde_json::from_slice::<Value>(&body).unwrap()["operationId"]
            .as_str()
            .unwrap()
            .to_string();

        let (_, grant) = harness.send("POST", "/v1/preflight", body).await;
        let grant: Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();
        for index in 0..3usize {
            let end = usize::min(index * 8 + 8, snapshot.len());
            harness
                .send(
                    "PUT",
                    &format!("/v1/uploads/{upload_id}/chunks/{index}"),
                    snapshot[index * 8..end].to_vec(),
                )
                .await;
        }
        harness
            .send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![])
            .await;

        let (status, body) = harness
            .send("GET", &format!("/v1/operations/{operation_id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK);
        let outcome: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(outcome["outcome"]["status"], "retained");
        assert_eq!(
            outcome["outcome"]["digest"],
            serde_json::json!(format!("sha256:{}", hex::encode(Sha256::digest(&snapshot))))
        );
    }

    /// An operation the operator has no record of is a 404, and a 404
    /// is not "it failed". §14.9 keeps `unknown` as `unknown`; the
    /// operator's part of that is never inventing an outcome.
    #[tokio::test]
    async fn an_unknown_operation_is_not_an_outcome() {
        let harness = Harness::new(vec![]);
        let (status, body) = harness
            .send("GET", "/v1/operations/never-happened", vec![])
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "operation_not_found");
    }

    #[tokio::test]
    async fn a_percent_encoded_operation_id_can_be_reconciled() {
        let harness = Harness::new(vec![]);
        for (operation_id, encoded) in [("op 1", "op%201"), ("op/1", "op%2F1")] {
            harness
                .state
                .store
                .lock()
                .await
                .record_outcome(
                    operation_id,
                    &harness.handle(),
                    "sha256:aa",
                    "retained",
                    None,
                    "2026-01-01T00:00:00Z",
                )
                .unwrap();

            let (status, body) = harness
                .send("GET", &format!("/v1/operations/{encoded}"), vec![])
                .await;
            assert_eq!(status, StatusCode::OK, "{operation_id}");
            let outcome: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(outcome["outcome"]["operationId"], operation_id);
        }
    }

    /// The id is client-chosen, so an unscoped lookup would let one
    /// holder read another's outcome by guessing.
    #[tokio::test]
    async fn one_holder_cannot_read_anothers_outcome() {
        let harness = Harness::new(vec![]);
        let mut stranger = Harness::new(vec![]);
        stranger.state = harness.state.clone();
        stranger.signing = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);

        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let body = harness.preflight_body(&snapshot, &terms);
        let operation_id = serde_json::from_slice::<Value>(&body).unwrap()["operationId"]
            .as_str()
            .unwrap()
            .to_string();
        let (_, grant) = harness.send("POST", "/v1/preflight", body).await;
        let grant: Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();
        for index in 0..3usize {
            let end = usize::min(index * 8 + 8, snapshot.len());
            harness
                .send(
                    "PUT",
                    &format!("/v1/uploads/{upload_id}/chunks/{index}"),
                    snapshot[index * 8..end].to_vec(),
                )
                .await;
        }
        harness
            .send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![])
            .await;

        let (status, _) = stranger
            .send("GET", &format!("/v1/operations/{operation_id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
