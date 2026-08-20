//! Preflight, chunked upload, commit, list, download.
//!
//! The ordering inside preflight is the substance and it is not
//! arbitrary — see `preflight` below.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::api::AppState;
use crate::auth::{authenticate, Holder};
use crate::error::{Error, Resource, Result};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotReference {
    pub algorithm: String,
    pub digest: String,
    pub sealed_byte_size: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightRequest {
    pub operation_id: String,
    pub snapshot_reference: SnapshotReference,
    pub accepted_terms_id: String,
    #[serde(default)]
    pub supersedes: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadGrant {
    pub upload_id: String,
    pub chunk_bytes: i64,
    pub chunk_count: i64,
    pub expires_at: String,
}

/// The cheap refusal point.
///
/// **A 402 must cost one small request, not a completed
/// multi-hundred-megabyte upload** — that is the entire reason this
/// route exists, and an operator that skips it does not conform.
///
/// The order of the checks matters and two of them are counterintuitive:
///
/// 1. `terms_changed` — nothing may be pinned to terms nobody agreed to.
/// 2. `payment_required` — before any bytes move.
/// 3. `already_retained` — **before** the size and quota checks.
///    Re-preflighting a digest we already hold adds no bytes, so a
///    holder at their limit reconciling a lost response must get
///    `already_retained` rather than `quota_exceeded`. Idempotent
///    reconciliation has to keep working *at* the limit, which is
///    exactly where it gets used.
/// 4. `snapshot_too_large`, then 5. `quota_exceeded` — the two checks
///    that bound accepting *new* bytes, and therefore both after (3).
pub async fn preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let store = state.store.lock().await;
    let holder = authenticate(
        &headers,
        "POST",
        "/v1/preflight",
        &body,
        &state.config,
        &store,
        now,
    )?;

    let request: PreflightRequest = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(format!("preflight body: {e}")))?;
    let reference = &request.snapshot_reference;

    if reference.algorithm != crate::documents::DIGEST_SUITE {
        return Err(Error::BadRequest("unsupported digest algorithm".into()));
    }
    let digest_hex = digest_hex(&reference.digest)?;
    if reference.sealed_byte_size <= 0 {
        return Err(Error::BadRequest("sealedByteSize must be positive".into()));
    }

    // (1) Terms.
    if request.accepted_terms_id != state.documents.terms.0 {
        return Err(Error::TermsChanged {
            current_terms_id: state.documents.terms.0.clone(),
        });
    }

    // (2) Payment. Free operators never reach this.
    if state.config.requires_entitlement() {
        return Err(Error::PaymentRequired {
            component_id: state.config.component_id.clone(),
            offers: vec![],
            entitlement_issuers: state.config.entitlement_issuers.clone(),
        });
    }

    // (3) Already held — before the bounds, deliberately.
    if store.snapshot_exists(&holder.handle, &reference.digest)? {
        return Ok(axum::Json(json!({
            "outcome": {
                "componentId": state.config.component_id,
                "status": "already_retained",
                "snapshotReference": {
                    "referenceVersion": 1,
                    "algorithm": reference.algorithm,
                    "digest": reference.digest,
                    "sealedByteSize": reference.sealed_byte_size,
                },
                "termsId": state.documents.terms.0,
            }
        }))
        .into_response());
    }

    // (4) Size.
    if reference.sealed_byte_size > state.config.maximum_sealed_snapshot_bytes {
        return Err(Error::SnapshotTooLarge {
            maximum_sealed_snapshot_bytes: state.config.maximum_sealed_snapshot_bytes,
        });
    }

    // (5) Quota. Never resolved by dropping an older snapshot — that is
    // the holder's call, not ours.
    let (retained, retained_bytes) = store.usage(&holder.handle)?;
    if retained >= state.config.maximum_retained_snapshots {
        return Err(Error::QuotaExceeded {
            retained_snapshots: retained,
            maximum_retained_snapshots: state.config.maximum_retained_snapshots,
            retained_bytes,
            limit_bytes: state.config.maximum_sealed_snapshot_bytes
                * state.config.maximum_retained_snapshots,
        });
    }

    let chunk_bytes = state.config.chunk_bytes;
    let chunk_count = (reference.sealed_byte_size + chunk_bytes - 1) / chunk_bytes;
    let upload_id = uuid::Uuid::new_v4().to_string();
    let expires_at = (now + time::Duration::seconds(state.config.upload_expiry_secs))
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(e.to_string()))?;

    state.blobs.begin_upload(&upload_id)?;
    store.begin_upload(
        &upload_id,
        &holder.handle,
        &request.operation_id,
        &reference.digest,
        reference.sealed_byte_size,
        chunk_bytes,
        chunk_count,
        &request.accepted_terms_id,
        &now.format(&Rfc3339).map_err(|e| Error::Internal(e.to_string()))?,
        &expires_at,
    )?;
    let _ = digest_hex;

    Ok(axum::Json(UploadGrant {
        upload_id,
        chunk_bytes,
        chunk_count,
        expires_at,
    })
    .into_response())
}

/// One transfer chunk.
///
/// Transfer framing only — unrelated to the AEAD chunking inside the
/// sealed container, which this operator cannot see and does not need
/// to.
pub async fn put_chunk(
    State(state): State<Arc<AppState>>,
    Path((upload_id, index)): Path<(String, i64)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let store = state.store.lock().await;
    let path = format!("/v1/uploads/{upload_id}/chunks/{index}");
    let holder = authenticate(&headers, "PUT", &path, &body, &state.config, &store, now)?;

    let upload = store
        .upload(&upload_id)?
        .ok_or(Error::NotFound(Resource::Upload))?;
    // Scoped to the holder who started it. Without this, anyone who
    // learned an upload id could write into someone else's snapshot.
    if upload.holder_handle != holder.handle {
        return Err(Error::NotFound(Resource::Upload));
    }
    if index < 0 || index >= upload.chunk_count {
        return Err(Error::BadRequest("chunk index outside the grant".into()));
    }

    let expected = if index == upload.chunk_count - 1 {
        upload.sealed_byte_size - upload.chunk_bytes * (upload.chunk_count - 1)
    } else {
        upload.chunk_bytes
    };
    if body.len() as i64 != expected {
        return Err(Error::BadRequest(format!(
            "chunk {index} must be {expected} bytes"
        )));
    }

    state.blobs.write_chunk(&upload_id, index, &body)?;
    Ok(StatusCode::OK.into_response())
}

/// Finish an upload: count, size, digest, then move into place.
///
/// The digest is recomputed over the bytes actually received. A client
/// asserting a reference is not evidence — the recomputation is.
pub async fn commit(
    State(state): State<Arc<AppState>>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let store = state.store.lock().await;
    let path = format!("/v1/uploads/{upload_id}/commit");
    let holder = authenticate(&headers, "POST", &path, &body, &state.config, &store, now)?;

    let upload = store
        .upload(&upload_id)?
        .ok_or(Error::NotFound(Resource::Upload))?;
    if upload.holder_handle != holder.handle {
        return Err(Error::NotFound(Resource::Upload));
    }

    let received = state.blobs.received_bytes(&upload_id, upload.chunk_count)?;
    if received != upload.sealed_byte_size {
        // Cheap check first: a truncated upload should not cost a hash
        // of everything that did arrive.
        state.blobs.discard_upload(&upload_id);
        store.drop_upload(&upload_id)?;
        return Err(Error::DigestMismatch);
    }

    let digest = state.blobs.digest_of(&upload_id, upload.chunk_count)?;
    if digest != upload.digest {
        state.blobs.discard_upload(&upload_id);
        store.drop_upload(&upload_id)?;
        return Err(Error::DigestMismatch);
    }

    let digest_hex = digest_hex(&digest)?;
    state.blobs.commit(&upload_id, &holder.handle, &digest_hex)?;
    let retained_at = now
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(e.to_string()))?;
    store.retain(&upload, &retained_at)?;
    store.drop_upload(&upload_id)?;
    store.record_outcome(
        &upload.operation_id,
        &holder.handle,
        &upload.digest,
        "retained",
        &retained_at,
    )?;

    Ok(axum::Json(json!({
        "outcome": {
            "componentId": state.config.component_id,
            "status": "retained",
            "snapshotReference": {
                "referenceVersion": 1,
                "algorithm": crate::documents::DIGEST_SUITE,
                "digest": upload.digest,
                "sealedByteSize": upload.sealed_byte_size,
            },
            "termsId": upload.accepted_terms_id,
        }
    }))
    .into_response())
}

/// Everything this holder's key can enumerate. There is no parameter
/// that widens it.
pub async fn list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let store = state.store.lock().await;
    let holder = authenticate(
        &headers,
        "GET",
        "/v1/snapshots",
        b"",
        &state.config,
        &store,
        now,
    )?;

    let rows = store.snapshots(&holder.handle)?;
    let body: Vec<_> = rows
        .into_iter()
        .map(|row| {
            json!({
                "snapshotReference": {
                    "referenceVersion": 1,
                    "algorithm": row.algorithm,
                    "digest": row.digest,
                    "sealedByteSize": row.sealed_byte_size,
                },
                "acceptedTermsId": row.accepted_terms_id,
                "retainedAt": row.retained_at,
                "retainedUntil": row.retained_until,
                "supersedes": row.supersedes,
                "status": "retained",
            })
        })
        .collect();
    Ok(axum::Json(body).into_response())
}

pub async fn download(
    State(state): State<Arc<AppState>>,
    Path(digest_path): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let store = state.store.lock().await;
    let path = format!("/v1/snapshots/{digest_path}");
    let holder = authenticate(&headers, "GET", &path, b"", &state.config, &store, now)?;

    let digest = format!("sha256:{digest_path}");
    if !store.snapshot_exists(&holder.handle, &digest)? {
        // Not "this holder cannot see it" versus "it does not exist" —
        // the same answer either way, because distinguishing them would
        // tell one holder whether another holds a given digest.
        return Err(Error::NotFound(Resource::Snapshot));
    }
    let bytes = state.blobs.read_snapshot(&holder.handle, &digest_path)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    )
        .into_response())
}

/// `sha256:<64 lowercase hex>` → the hex, or a refusal.
fn digest_hex(digest: &str) -> Result<String> {
    let hex_value = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::BadRequest("digest must be sha256:<hex>".into()))?;
    if hex_value.len() != 64
        || !hex_value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::BadRequest(
            "digest must be 64 lowercase hex characters".into(),
        ));
    }
    Ok(hex_value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{router, AppState};
    use crate::auth;
    use crate::config::Config;
    use crate::documents::Documents;
    use crate::payload;
    use crate::store::Store;
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    struct Harness {
        state: Arc<AppState>,
        signing: SigningKey,
        _dir: tempdir::TempDir,
    }

    impl Harness {
        fn new(issuers: Vec<String>) -> Harness {
            let dir = tempdir::TempDir::new("onym-uploads").unwrap();
            let mut config = Config::for_tests("onym:component:test", issuers);
            config.chunk_bytes = 8;
            config.maximum_retained_snapshots = 2;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&config.signing_seed);
            let documents = Documents::build(&config, &signing_key).unwrap();
            Harness {
                state: Arc::new(AppState {
                    config,
                    documents,
                    store: tokio::sync::Mutex::new(Store::in_memory().unwrap()),
                    blobs: crate::blobs::Blobs::new(dir.path()),
                }),
                signing: SigningKey::from_bytes(&[5u8; 32]),
                _dir: dir,
            }
        }

        fn terms_id(&self) -> String {
            self.state.documents.terms.0.clone()
        }

        async fn send(&self, method: &str, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
            let reference = format!(
                "onym:seat-key:{}",
                hex::encode(self.signing.verifying_key().as_bytes())
            );
            let stamp = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
            let nonce = uuid::Uuid::new_v4().to_string();
            let signature = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                self.signing
                    .sign(&payload::signing_bytes(method, path, &reference, &stamp, &nonce, &body))
                    .to_bytes(),
            );

            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(auth::HOLDER, reference)
                .header(auth::TIMESTAMP, stamp)
                .header(auth::NONCE, nonce)
                .header(auth::SIGNATURE, signature)
                .body(Body::from(body))
                .unwrap();
            let response = router(self.state.clone()).oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            (status, bytes)
        }

        fn preflight_body(&self, snapshot: &[u8], terms: &str) -> Vec<u8> {
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(snapshot)));
            serde_json::to_vec(&json!({
                "version": 1,
                "operationId": uuid::Uuid::new_v4().to_string(),
                "snapshotReference": {
                    "referenceVersion": 1,
                    "algorithm": crate::documents::DIGEST_SUITE,
                    "digest": digest,
                    "sealedByteSize": snapshot.len(),
                },
                "acceptedTermsId": terms,
            }))
            .unwrap()
        }

        /// Preflight, upload every chunk, commit.
        async fn store_snapshot(&self, snapshot: &[u8]) -> (StatusCode, Vec<u8>) {
            let terms = self.terms_id();
            let (status, body) = self.send("POST", "/v1/preflight", self.preflight_body(snapshot, &terms)).await;
            assert_eq!(status, StatusCode::OK, "preflight: {}", String::from_utf8_lossy(&body));
            let grant: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let upload_id = grant["uploadId"].as_str().unwrap().to_string();
            let chunk_bytes = grant["chunkBytes"].as_u64().unwrap() as usize;
            let chunk_count = grant["chunkCount"].as_u64().unwrap() as usize;

            for index in 0..chunk_count {
                let start = index * chunk_bytes;
                let end = usize::min(start + chunk_bytes, snapshot.len());
                let (status, body) = self
                    .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/{index}"), snapshot[start..end].to_vec())
                    .await;
                assert_eq!(status, StatusCode::OK, "chunk {index}: {}", String::from_utf8_lossy(&body));
            }
            self.send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![]).await
        }
    }

    /// The whole path, against the real router.
    #[tokio::test]
    async fn a_snapshot_round_trips() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..37u8).collect();

        let (status, body) = harness.store_snapshot(&snapshot).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let outcome: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(outcome["outcome"]["status"], "retained");

        let (status, body) = harness.send("GET", "/v1/snapshots", vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 1);

        let digest_hex = hex::encode(Sha256::digest(&snapshot));
        let (status, bytes) = harness.send("GET", &format!("/v1/snapshots/{digest_hex}"), vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, snapshot, "the bytes came back changed");
    }

    /// The digest is recomputed over what arrived. A client asserting a
    /// reference is not evidence.
    #[tokio::test]
    async fn a_snapshot_whose_bytes_do_not_match_its_digest_is_refused() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = vec![1u8; 20];
        let terms = harness.terms_id();
        // Claim one digest, send different bytes of the same length.
        let body = harness.preflight_body(&snapshot, &terms);
        let (_, grant) = harness.send("POST", "/v1/preflight", body).await;
        let grant: serde_json::Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();

        let lie: Vec<u8> = vec![2u8; 20];
        for index in 0..3 {
            let start = index * 8;
            let end = usize::min(start + 8, lie.len());
            harness
                .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/{index}"), lie[start..end].to_vec())
                .await;
        }
        let (status, _) = harness.send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![]).await;
        assert_eq!(status, StatusCode::CONFLICT, "mismatched bytes were retained");
    }

    /// Re-preflighting a held digest is `already_retained` — and this
    /// is checked *before* size and quota, so reconciliation keeps
    /// working at the limit.
    #[tokio::test]
    async fn a_held_digest_is_already_retained_even_at_quota() {
        let harness = Harness::new(vec![]);
        // Fill the quota (2) with two distinct snapshots.
        let first: Vec<u8> = (0..20u8).collect();
        let second: Vec<u8> = (50..70u8).collect();
        harness.store_snapshot(&first).await;
        harness.store_snapshot(&second).await;

        // At quota, a *new* snapshot is refused...
        let third: Vec<u8> = (100..120u8).collect();
        let terms = harness.terms_id();
        let (status, _) = harness.send("POST", "/v1/preflight", harness.preflight_body(&third, &terms)).await;
        assert_eq!(status, StatusCode::CONFLICT, "quota was not enforced");

        // ...but re-preflighting one we already hold is not, because it
        // would add no bytes. This is the ordering that makes a lost
        // response recoverable at the limit.
        let (status, body) = harness.send("POST", "/v1/preflight", harness.preflight_body(&first, &terms)).await;
        assert_eq!(status, StatusCode::OK, "already_retained lost to the quota check");
        let outcome: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(outcome["outcome"]["status"], "already_retained");
    }

    /// Terms outrank everything: nothing is pinned to terms nobody
    /// agreed to.
    #[tokio::test]
    async fn stale_terms_stop_the_upload() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = vec![7u8; 16];
        let stale = format!("sha256:{}", "0".repeat(64));
        let (status, body) = harness.send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &stale)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "terms_changed");
        // And it says which terms to read, or the client is stuck.
        assert_eq!(error["currentTermsId"], harness.terms_id());
    }

    /// A paid operator refuses before any bytes move, and names the
    /// issuers — but never a price, which belongs to the frontend's
    /// channel agreement rather than to this refusal.
    #[tokio::test]
    async fn a_paid_operator_refuses_at_preflight() {
        let issuer = format!("onym:key:{}", hex::encode([3u8; 32]));
        let harness = Harness::new(vec![issuer.clone()]);
        let snapshot: Vec<u8> = vec![7u8; 16];
        let terms = harness.terms_id();
        let (status, body) = harness.send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms)).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "payment_required");
        assert_eq!(error["paymentRequired"]["entitlementIssuers"][0], issuer);
        assert!(error["paymentRequired"].get("price").is_none(), "a price appeared in a refusal");
    }

    /// One holder must not be able to write into another's upload, even
    /// knowing the id.
    #[tokio::test]
    async fn an_upload_belongs_to_the_holder_who_started_it() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = vec![4u8; 16];
        let terms = harness.terms_id();
        let (_, grant) = harness.send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms)).await;
        let grant: serde_json::Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();

        let mut stranger = Harness::new(vec![]);
        stranger.state = harness.state.clone();
        stranger.signing = SigningKey::from_bytes(&[6u8; 32]);
        let (status, _) = stranger
            .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/0"), vec![9u8; 8])
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a stranger wrote into someone else's upload");
    }

    /// And must not be able to read another's snapshot, even knowing
    /// the digest.
    #[tokio::test]
    async fn a_snapshot_is_not_readable_by_another_holder() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..24u8).collect();
        harness.store_snapshot(&snapshot).await;
        let digest_hex = hex::encode(Sha256::digest(&snapshot));

        let mut stranger = Harness::new(vec![]);
        stranger.state = harness.state.clone();
        stranger.signing = SigningKey::from_bytes(&[6u8; 32]);
        let (status, _) = stranger.send("GET", &format!("/v1/snapshots/{digest_hex}"), vec![]).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
