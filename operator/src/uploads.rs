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
use crate::auth::authenticate;
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
    /// What has not arrived, as inclusive `[first, last]` ranges.
    ///
    /// Present on a fresh grant too, as one range covering everything,
    /// so a resuming client needs no special case. Without it the only
    /// way to learn progress is a commit expected to fail — which
    /// works, and which every implementer would discover separately
    /// and none would write down.
    pub missing_chunks: Vec<(i64, i64)>,
}

/// The cheap refusal point.
///
/// **A 402 must cost one small request, not a completed
/// multi-hundred-megabyte upload** — that is the entire reason this
/// route exists, and an operator that skips it does not conform.
///
/// The order of the checks matters and three of them are
/// counterintuitive:
///
/// 1. **grant resume — ahead of the terms check.** A holder halfway
///    through an upload when the operator publishes new terms would
///    otherwise be refused at (2) and never reach resume, stranding
///    their grant against the quota until it expires. The grant is
///    itself the record of consent to the terms it was minted under,
///    and the request must carry *those* terms to resume it.
/// 2. `terms_changed` — nothing new may be pinned to terms nobody
///    agreed to.
/// 3. `payment_required` — before any bytes move.
/// 4. `already_retained` — **before** the size and quota checks.
///    Re-preflighting a digest we already hold adds no bytes, so a
///    holder at their limit reconciling a lost response must get
///    `already_retained` rather than `quota_exceeded`. Idempotent
///    reconciliation has to keep working *at* the limit, which is
///    exactly where it gets used.
/// 5. `snapshot_too_large`, then 6. `quota_exceeded` — the two checks
///    that bound accepting *new* bytes, and therefore both after (4).
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
    // Validated for shape here even though preflight has no use for
    // the hex itself — a reference we would refuse at commit should not
    // be granted an upload first.
    digest_hex(&reference.digest)?;
    if reference.sealed_byte_size <= 0 {
        return Err(Error::BadRequest("sealedByteSize must be positive".into()));
    }
    // Validated and then *stored*. §14's record table declares
    // `supersedes` as state the profile's own operations require, and
    // `listSnapshots` reports it — accepting the field and dropping it
    // would make that column report a value no client ever set.
    if let Some(previous) = request.supersedes.as_deref() {
        digest_hex(previous)?;
        if previous == reference.digest {
            return Err(Error::BadRequest(
                "a snapshot cannot supersede itself".into(),
            ));
        }
    }

    let now_stamp = now
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(e.to_string()))?;

    // (1) A grant this holder already has for this digest, resumed.
    //
    // Ahead of the terms check, not after it. A holder halfway through
    // an upload when the operator publishes new terms would otherwise
    // be refused at (2) and never reach resume: their grant strands
    // against the quota until it expires, which is the harm resume
    // exists to prevent, arriving by the one route that cannot be
    // retried out of. The grant is itself the record of consent to the
    // terms it was minted under, and terms bind forward — a snapshot
    // accepted under T1 keeps T1 — so finishing that upload under T1 is
    // what the pinning already promises.
    //
    // The `accepted_terms_id` condition is what keeps this narrow: the
    // request must carry the *grant's* terms, so this resumes an agreed
    // upload and is never a route around consent.
    if let Some(open) = store.open_grant_for(&holder.handle, &reference.digest, &now_stamp)? {
        if open.accepted_terms_id == request.accepted_terms_id {
            // Two byte counts for one digest is a contradiction, and
            // choosing between them is not the operator's job.
            // `supersedes` is different: the grant keeps what it was
            // minted with, since refusing would strand the holder until
            // expiry holding quota headroom they cannot release.
            if open.sealed_byte_size != reference.sealed_byte_size {
                return Err(Error::BadRequest(
                    "sealedByteSize disagrees with the open grant for this digest".into(),
                ));
            }
            let (_, missing) = state.blobs.arrival(&open.upload_id, open.chunk_count)?;
            return Ok(axum::Json(UploadGrant {
                upload_id: open.upload_id,
                chunk_bytes: open.chunk_bytes,
                chunk_count: open.chunk_count,
                expires_at: open.expires_at,
                missing_chunks: missing,
            })
            .into_response());
        }
    }

    // (2) Terms.
    if request.accepted_terms_id != state.documents.terms.0 {
        return Err(Error::TermsChanged {
            current_terms_id: state.documents.terms.0.clone(),
        });
    }

    // (3) Payment. Free operators never reach this.
    if state.config.requires_entitlement() {
        return Err(Error::PaymentRequired {
            component_id: state.config.component_id.clone(),
            offers: vec![],
            entitlement_issuers: state.config.entitlement_issuers.clone(),
        });
    }

    // (4) Already held — before the bounds, deliberately.
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

    // (5) Size.
    if reference.sealed_byte_size > state.config.maximum_sealed_snapshot_bytes {
        return Err(Error::SnapshotTooLarge {
            maximum_sealed_snapshot_bytes: state.config.maximum_sealed_snapshot_bytes,
        });
    }

    // (6) Quota. Never resolved by dropping an older snapshot — that is
    // the holder's call, not ours.
    //
    // Open grants count. Retained rows alone are a number that has not
    // moved yet: a holder one below the limit could preflight N
    // uploads, each seeing the same count, and commit them all. Commit
    // re-checks and is the authoritative gate; counting grants here is
    // what keeps the refusal cheap, which is why preflight exists.
    let (retained, retained_bytes) = store.usage(&holder.handle)?;
    let (open_grants, open_grant_bytes) = store.open_grants(&holder.handle, &now_stamp)?;
    if retained + open_grants >= state.config.maximum_retained_snapshots {
        return Err(Error::QuotaExceeded {
            retained_snapshots: retained,
            maximum_retained_snapshots: state.config.maximum_retained_snapshots,
            retained_bytes,
            limit_bytes: state.config.maximum_sealed_snapshot_bytes
                * state.config.maximum_retained_snapshots,
            open_grants,
            open_grant_bytes,
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
        request.supersedes.as_deref(),
        &now_stamp,
        &expires_at,
    )?;

    Ok(axum::Json(UploadGrant {
        upload_id,
        chunk_bytes,
        chunk_count,
        expires_at,
        // Nothing has arrived, so one range covers it — the same shape
        // a resume returns, so a client branches on neither.
        missing_chunks: vec![(0, chunk_count - 1)],
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
    let path = format!("/v1/uploads/{upload_id}/chunks/{index}");

    // The row check needs the lock; the write does not. This is the
    // hot path — every chunk of every upload — and the idempotency
    // read-back alone can be tens of megabytes, so holding the one
    // global mutex across it would stall every other holder's request
    // behind each chunk of each upload.
    let upload = {
        let store = state.store.lock().await;
        let holder = authenticate(&headers, "PUT", &path, &body, &state.config, &store, now)?;
        let upload = store
            .upload(&upload_id)?
            .ok_or(Error::NotFound(Resource::Upload))?;
        // Scoped to the holder who started it. Without this, anyone who
        // learned an upload id could write into someone else's
        // snapshot.
        if upload.holder_handle != holder.handle {
            return Err(Error::NotFound(Resource::Upload));
        }
        if has_expired(&upload.expires_at, now)? {
            return Err(Error::UploadExpired);
        }
        upload
    };

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

    blocking(&state, {
        let id = upload_id.clone();
        move |state| state.blobs.write_chunk(&id, index, &body)
    })
    .await?;
    Ok(StatusCode::OK.into_response())
}

/// Finish an upload: count, size, digest, quota, then move into place.
///
/// The digest is recomputed over the bytes actually received. A client
/// asserting a reference is not evidence — the recomputation is.
///
/// The store lock is deliberately *not* held across the hashing. It is
/// one global mutex, so hashing a few hundred megabytes under it would
/// stall every other holder's request — including the cheap ones — on
/// the async runtime thread. Blob work runs on the blocking pool, and
/// the lock is taken only for the bookkeeping either side of it.
pub async fn commit(
    State(state): State<Arc<AppState>>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let path = format!("/v1/uploads/{upload_id}/commit");

    let upload = {
        let store = state.store.lock().await;
        let holder = authenticate(&headers, "POST", &path, &body, &state.config, &store, now)?;
        let upload = store
            .upload(&upload_id)?
            .ok_or(Error::NotFound(Resource::Upload))?;
        if upload.holder_handle != holder.handle {
            return Err(Error::NotFound(Resource::Upload));
        }
        if has_expired(&upload.expires_at, now)? {
            return Err(Error::UploadExpired);
        }
        upload
    };

    // Cheap check first: a truncated upload should not cost a hash of
    // everything that did arrive.
    //
    // And an incomplete upload is *kept*, not discarded. A commit sent
    // one chunk early — a lost chunk response is enough — would
    // otherwise destroy every byte already received and call it a
    // digest mismatch, making the client re-send hundreds of megabytes
    // to recover from one missing chunk. It is told which indices are
    // missing and the grant stays open.
    let (received, missing) = blocking(&state, {
        let id = upload_id.clone();
        let count = upload.chunk_count;
        move |state| state.blobs.arrival(&id, count)
    })
    .await?;
    if !missing.is_empty() {
        return Err(Error::UploadIncomplete {
            missing_chunks: missing,
            chunk_count: upload.chunk_count,
        });
    }
    if received != upload.sealed_byte_size {
        // Every chunk is present and the total is still wrong, which
        // no retry fixes: the grant was minted for a different size.
        abandon(&state, &upload_id).await?;
        return Err(Error::DigestMismatch);
    }

    let digest = blocking(&state, {
        let id = upload_id.clone();
        let count = upload.chunk_count;
        move |state| state.blobs.digest_of(&id, count)
    })
    .await?;
    if digest != upload.digest {
        abandon(&state, &upload_id).await?;
        return Err(Error::DigestMismatch);
    }
    let digest_hex = digest_hex(&digest)?;

    let retained_at = now
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(e.to_string()))?;
    {
        // Quota is re-checked here, under the lock, with the rename
        // inside it. The preflight check is against a count that had
        // not moved yet; this one is against the count that decides.
        // A rename is O(1), not O(bytes), so holding the lock across it
        // costs nothing and makes check-and-place atomic.
        let store = state.store.lock().await;
        let already_held = store.snapshot_exists(&upload.holder_handle, &upload.digest)?;
        if !already_held {
            let (retained, retained_bytes) = store.usage(&upload.holder_handle)?;
            // The holder's *other* open grants — this one is being
            // committed, so it is no longer headroom anybody waits on,
            // but the rest still are and are what a refused client
            // needs named.
            let now_stamp = now
                .format(&Rfc3339)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let (open_grants, open_grant_bytes) =
                store.open_grants(&upload.holder_handle, &now_stamp)?;
            let open_grants = (open_grants - 1).max(0);
            let open_grant_bytes = (open_grant_bytes - upload.sealed_byte_size).max(0);
            if retained >= state.config.maximum_retained_snapshots {
                state.blobs.discard_upload(&upload_id);
                store.drop_upload(&upload_id)?;
                return Err(Error::QuotaExceeded {
                    retained_snapshots: retained,
                    maximum_retained_snapshots: state.config.maximum_retained_snapshots,
                    retained_bytes,
                    limit_bytes: state.config.maximum_sealed_snapshot_bytes
                        * state.config.maximum_retained_snapshots,
                    open_grants,
                    open_grant_bytes,
                });
            }
        }
        state
            .blobs
            .commit(&upload_id, &upload.holder_handle, &digest_hex)?;
        store.retain(&upload, &retained_at)?;
        store.drop_upload(&upload_id)?;
        store.record_outcome(
            &upload.operation_id,
            &upload.holder_handle,
            &upload.digest,
            "retained",
            // An upload produces no receipts.
            None,
            &retained_at,
        )?;
    }

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

/// Run blob work on the blocking pool, off the store lock.
pub async fn blocking<T, F>(state: &Arc<AppState>, work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&AppState) -> Result<T> + Send + 'static,
{
    let state = state.clone();
    tokio::task::spawn_blocking(move || work(&state))
        .await
        .map_err(|e| Error::Internal(format!("blob task: {e}")))?
}

/// Give up on an upload: bytes first, then the row.
async fn abandon(state: &Arc<AppState>, upload_id: &str) -> Result<()> {
    state.blobs.discard_upload(upload_id);
    state.store.lock().await.drop_upload(upload_id)
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

    // Erased rows included, reported as `erased`. §5.7 makes that a
    // distinct status because a holder asking about a digest they
    // erased is owed that answer rather than a silence indistinguishable
    // from never having stored it.
    let rows = store.snapshots_including_erased(&holder.handle)?;
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
                "erasedAt": row.erased_at,
                "status": if row.erased_at.is_some() { "erased" } else { "retained" },
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
    let path = format!("/v1/snapshots/{digest_path}");
    let digest = format!("sha256:{digest_path}");

    let holder = {
        let store = state.store.lock().await;
        let holder = authenticate(&headers, "GET", &path, b"", &state.config, &store, now)?;
        // Shape-checked as well as looked up. The database lookup would
        // refuse a malformed digest today because nothing matches it,
        // but the path segment reaches the filesystem and should not
        // depend on that for its safety.
        digest_hex(&digest)?;
        if !store.snapshot_exists(&holder.handle, &digest)? {
            // Not "this holder cannot see it" versus "it does not
            // exist" — the same answer either way, because
            // distinguishing them would tell one holder whether another
            // holds a given digest.
            return Err(Error::NotFound(Resource::Snapshot));
        }
        holder
    };

    // Streamed, not buffered. A snapshot is routinely hundreds of
    // megabytes; reading one into a `Vec` per concurrent download would
    // make a handful of readers enough to exhaust memory.
    let paths = state.blobs.chunk_paths(&holder.handle, &digest_path)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        axum::body::Body::from_stream(snapshot_stream(paths)),
    )
        .into_response())
}

/// The snapshot's bytes, chunk by chunk, a bounded buffer at a time.
pub fn snapshot_stream(
    paths: Vec<std::path::PathBuf>,
) -> impl futures_core::Stream<Item = std::io::Result<Bytes>> {
    async_stream::try_stream! {
        for path in paths {
            let mut file = tokio::fs::File::open(&path).await?;
            let mut buffer = vec![0u8; 256 * 1024];
            loop {
                let read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
                if read == 0 {
                    break;
                }
                yield Bytes::copy_from_slice(&buffer[..read]);
            }
        }
    }
}

/// Has a grant run out?
///
/// Parsed and compared as instants rather than as strings. Both sides
/// are RFC 3339 written by us, so a lexicographic compare would almost
/// always agree — "almost always" is not a property worth relying on
/// for the check that decides whether bytes are still accepted.
fn has_expired(expires_at: &str, now: OffsetDateTime) -> Result<bool> {
    let expiry = OffsetDateTime::parse(expires_at, &Rfc3339)
        .map_err(|e| Error::Internal(format!("unparseable grant expiry: {e}")))?;
    Ok(expiry <= now)
}

/// `sha256:<64 lowercase hex>` → the hex, or a refusal.
pub fn digest_hex(digest: &str) -> Result<String> {
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
pub mod tests {
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

    pub struct Harness {
        pub state: Arc<AppState>,
        pub signing: SigningKey,
        _dir: tempfile::TempDir,
    }

    impl Harness {
        pub fn new(issuers: Vec<String>) -> Harness {
            let dir = tempfile::TempDir::new().unwrap();
            let mut config = Config::for_tests("onym:component:test", issuers);
            config.chunk_bytes = 8;
            config.maximum_retained_snapshots = 2;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&config.signing_seed);
            let documents = Documents::build(&config, &signing_key).unwrap();
            Harness {
                state: Arc::new(
                    AppState::new(
                        config,
                        documents,
                        Store::in_memory().unwrap(),
                        crate::blobs::Blobs::new(dir.path()),
                        signing_key.clone(),
                        "2026-01-01T00:00:00Z",
                    )
                    .unwrap(),
                ),
                signing: SigningKey::from_bytes(&[5u8; 32]),
                _dir: dir,
            }
        }

        /// The blinded handle the operator knows this holder by.
        pub fn handle(&self) -> String {
            payload::holder_handle(&self.signing.verifying_key())
        }

        pub fn terms_id(&self) -> String {
            self.state.documents.terms.0.clone()
        }

        pub async fn send(&self, method: &str, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
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

        pub fn preflight_body(&self, snapshot: &[u8], terms: &str) -> Vec<u8> {
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
        pub async fn store_snapshot(&self, snapshot: &[u8]) -> (StatusCode, Vec<u8>) {
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

    /// Preflight counts open grants, not just retained rows.
    ///
    /// Without this a holder one below the limit could preflight N
    /// uploads — each seeing the same unmoved count — and commit them
    /// all, walking straight past the quota.
    #[tokio::test]
    async fn open_grants_count_against_the_quota() {
        let harness = Harness::new(vec![]);
        let terms = harness.terms_id();
        // Limit is 2. Two grants, nothing committed yet.
        for seed in [0u8, 50] {
            let snapshot: Vec<u8> = (seed..seed + 20).collect();
            let (status, _) = harness
                .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
                .await;
            assert_eq!(status, StatusCode::OK);
        }
        let third: Vec<u8> = (100..120u8).collect();
        let (status, body) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&third, &terms))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "a third grant was issued at a limit of two");
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "quota_exceeded");
    }

    /// Commit re-checks, and is the gate that actually decides.
    ///
    /// Preflight's count is against a number that has not moved yet, so
    /// commit must not trust it. The sequence here is ordinary rather
    /// than contrived: a grant is issued while there is room, and the
    /// operator's limit is lowered before it is committed.
    #[tokio::test]
    async fn commit_refuses_a_grant_that_no_longer_fits() {
        let mut harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let (_, grant) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        let grant: serde_json::Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();
        for index in 0..3usize {
            let end = usize::min(index * 8 + 8, snapshot.len());
            harness
                .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/{index}"), snapshot[index * 8..end].to_vec())
                .await;
        }

        // The operator's limit drops to zero — a config change, not a
        // race, and commit is the only thing standing between the open
        // grant and a snapshot over the limit.
        Arc::get_mut(&mut harness.state).unwrap().config.maximum_retained_snapshots = 0;

        let (status, body) = harness
            .send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![])
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "commit accepted a snapshot over the quota");
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "quota_exceeded");

        // And it did not leave the bytes lying around.
        assert!(harness.state.blobs.incoming_on_disk().is_empty());
    }

    /// A grant that ran out stops accepting bytes.
    ///
    /// `upload_expired`, not `upload_not_found`: the holder was right
    /// about the upload, they were just too late, and a client told
    /// "not found" by a row that still exists learns the wrong thing.
    #[tokio::test]
    async fn an_expired_grant_accepts_nothing() {
        let harness = Harness::new(vec![]);
        let upload_id = "expired-grant";
        {
            let store = harness.state.store.lock().await;
            store
                .begin_upload(
                    upload_id,
                    &harness.handle(),
                    "op-expired",
                    "sha256:{}",
                    8,
                    8,
                    1,
                    &harness.terms_id(),
                    None,
                    "2020-01-01T00:00:00Z",
                    "2020-01-02T00:00:00Z",
                )
                .unwrap();
        }
        harness.state.blobs.begin_upload(upload_id).unwrap();

        let (status, body) = harness
            .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/0"), vec![7u8; 8])
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "an expired grant took a chunk");
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "upload_expired");

        let (status, _) = harness
            .send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![])
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "an expired grant was committed");
    }

    /// The operation id is chosen by the client, so one holder must not
    /// be able to pick another's and overwrite the outcome they will
    /// later reconcile against.
    #[tokio::test]
    async fn one_holders_operation_id_does_not_displace_anothers() {
        let harness = Harness::new(vec![]);
        let mut stranger = Harness::new(vec![]);
        stranger.state = harness.state.clone();
        stranger.signing = SigningKey::from_bytes(&[6u8; 32]);

        let shared_operation = "op-collision";
        {
            let store = harness.state.store.lock().await;
            store
                .record_outcome(shared_operation, &harness.handle(), "sha256:aa", "retained", None, "2026-01-01T00:00:00Z")
                .unwrap();
            store
                .record_outcome(shared_operation, &stranger.handle(), "sha256:bb", "retained", None, "2026-01-02T00:00:00Z")
                .unwrap();

            // Both rows survive, each under its own holder.
            let count: i64 = store
                .connection_for_tests()
                .query_row("SELECT COUNT(*) FROM operation_outcomes", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 2, "one holder's outcome replaced another's");
            let digest: String = store
                .connection_for_tests()
                .query_row(
                    "SELECT subject FROM operation_outcomes WHERE holder_handle = ?1",
                    [&harness.handle()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(digest, "sha256:aa");
        }
    }

    /// Bigger than one buffer of the download stream, so the response
    /// is assembled from more than one read and more than one chunk
    /// file. A `Vec`-returning read would have passed this too — what
    /// it guards is that streaming did not reorder or drop anything.
    #[tokio::test]
    async fn a_multi_chunk_snapshot_streams_back_in_order() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..250u8).cycle().take(4096).collect();
        let (status, body) = harness.store_snapshot(&snapshot).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        let digest_hex = hex::encode(Sha256::digest(&snapshot));
        let (status, bytes) = harness.send("GET", &format!("/v1/snapshots/{digest_hex}"), vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes.len(), snapshot.len());
        assert_eq!(bytes, snapshot, "the streamed bytes came back changed");
    }

    /// A refusal a client cannot act on is a refusal that will be
    /// retried forever. The count that decides is `retained +
    /// openGrants`, so both terms are in the body — otherwise a holder
    /// sees usage below the maximum and a 409 beside it.
    #[tokio::test]
    async fn a_quota_refusal_names_the_grants_holding_the_headroom() {
        let harness = Harness::new(vec![]);
        let terms = harness.terms_id();
        for seed in [0u8, 50] {
            let snapshot: Vec<u8> = (seed..seed + 20).collect();
            harness
                .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
                .await;
        }
        let third: Vec<u8> = (100..120u8).collect();
        let (status, body) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&third, &terms))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["retainedSnapshots"], json!(0), "nothing is retained yet");
        assert_eq!(error["openGrants"], json!(2), "the grants are invisible");
        assert_eq!(
            error["openGrantBytes"], json!(40),
            "a holder refused on bytes cannot see what consumed them"
        );
        assert_eq!(error["maximumRetainedSnapshots"], json!(2));
    }

    /// One interrupted run is one range, however long — which is the
    /// case ranges exist for.
    #[tokio::test]
    async fn a_long_contiguous_gap_is_one_range() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..80u8).collect();
        let terms = harness.terms_id();
        let (_, grant) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        let grant: serde_json::Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();
        assert_eq!(grant["chunkCount"], json!(10));

        // Only the first chunk lands; the connection dies after it.
        harness
            .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/0"), snapshot[..8].to_vec())
            .await;
        let (status, body) = harness
            .send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![])
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            error["missingChunks"],
            json!([[1, 9]]),
            "nine missing chunks were not collapsed into one range"
        );
    }

    /// The digest reaches the filesystem as a path segment. The
    /// database lookup would refuse a malformed one today because
    /// nothing matches it — that is a reason to validate anyway, not a
    /// reason to skip it.
    #[tokio::test]
    async fn a_malformed_digest_is_refused_before_it_reaches_the_disk() {
        let harness = Harness::new(vec![]);
        for segment in ["..", "AAAA", &"f".repeat(63)] {
            let (status, _) = harness.send("GET", &format!("/v1/snapshots/{segment}"), vec![]).await;
            assert!(
                status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
                "{segment} produced {status}"
            );
        }
    }

    /// Accepted, stored, and reported back. `list` reads the column, so
    /// dropping the field would have made it report a value no client
    /// ever set.
    #[tokio::test]
    async fn supersedes_survives_the_upload() {
        let harness = Harness::new(vec![]);
        let first: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&first).await;
        let first_digest = format!("sha256:{}", hex::encode(Sha256::digest(&first)));

        let second: Vec<u8> = (50..70u8).collect();
        let terms = harness.terms_id();
        let mut body: serde_json::Value =
            serde_json::from_slice(&harness.preflight_body(&second, &terms)).unwrap();
        body["supersedes"] = json!(first_digest);
        let (status, grant) = harness
            .send("POST", "/v1/preflight", serde_json::to_vec(&body).unwrap())
            .await;
        assert_eq!(status, StatusCode::OK);
        let grant: serde_json::Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();
        for index in 0..3usize {
            let end = usize::min(index * 8 + 8, second.len());
            harness
                .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/{index}"), second[index * 8..end].to_vec())
                .await;
        }
        let (status, _) = harness.send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![]).await;
        assert_eq!(status, StatusCode::OK);

        let (_, listed) = harness.send("GET", "/v1/snapshots", vec![]).await;
        let listed: serde_json::Value = serde_json::from_slice(&listed).unwrap();
        let second_digest = format!("sha256:{}", hex::encode(Sha256::digest(&second)));
        let row = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["snapshotReference"]["digest"] == second_digest)
            .expect("the second snapshot was not listed");
        assert_eq!(row["supersedes"], json!(first_digest), "supersedes was dropped");
    }

    /// A claim the operator cannot check is not one it should store.
    #[tokio::test]
    async fn a_malformed_supersedes_is_refused() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
        for value in [json!("not-a-digest"), json!(digest)] {
            let mut body: serde_json::Value =
                serde_json::from_slice(&harness.preflight_body(&snapshot, &terms)).unwrap();
            body["supersedes"] = value.clone();
            let (status, _) = harness
                .send("POST", "/v1/preflight", serde_json::to_vec(&body).unwrap())
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted supersedes {value}");
        }
    }

    /// A lost grant response must not cost the holder their quota.
    ///
    /// Re-preflighting returns the grant they already have rather than
    /// minting a second one that competes with it — the same
    /// reconciliation `already_retained` gives the committed case, one
    /// step earlier.
    #[tokio::test]
    async fn a_lost_grant_response_is_recovered_not_duplicated() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let (_, first) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        let first: serde_json::Value = serde_json::from_slice(&first).unwrap();

        // The client never saw that response. It asks again.
        let (status, second) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        assert_eq!(status, StatusCode::OK, "a re-preflight was refused");
        let second: serde_json::Value = serde_json::from_slice(&second).unwrap();
        assert_eq!(second["uploadId"], first["uploadId"], "a second grant was minted");
        assert_eq!(second["expiresAt"], first["expiresAt"], "the deadline was extended");

        // And the quota was not spent twice: with a limit of two, a
        // different snapshot still fits.
        let other: Vec<u8> = (50..70u8).collect();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&other, &terms))
            .await;
        assert_eq!(status, StatusCode::OK, "the duplicate grant consumed the quota");
    }

    /// A resumed grant says what has arrived, so the client does not
    /// have to learn it by sending a commit it expects to fail.
    #[tokio::test]
    async fn a_resumed_grant_reports_what_is_missing() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let (_, first) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        let first: serde_json::Value = serde_json::from_slice(&first).unwrap();
        // A fresh grant reports everything missing, as one range, so a
        // client needs no special case for the two paths.
        assert_eq!(first["missingChunks"], json!([[0, 2]]));
        let upload_id = first["uploadId"].as_str().unwrap().to_string();

        harness
            .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/0"), snapshot[..8].to_vec())
            .await;
        let (_, resumed) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        let resumed: serde_json::Value = serde_json::from_slice(&resumed).unwrap();
        assert_eq!(resumed["uploadId"], json!(upload_id));
        assert_eq!(
            resumed["missingChunks"],
            json!([[1, 2]]),
            "the resumed grant does not say what arrived"
        );
    }

    /// A grant is resumable across a terms change, because the grant
    /// is itself the record of consent to the terms it was minted
    /// under. Refusing at the terms step would strand it against the
    /// quota until expiry — the harm resume exists to prevent, by the
    /// one route that cannot be retried out of.
    #[tokio::test]
    async fn a_grant_survives_the_terms_changing_under_it() {
        let mut harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let minted_under = harness.terms_id();
        let (_, grant) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &minted_under))
            .await;
        let grant: serde_json::Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();
        harness
            .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/0"), snapshot[..8].to_vec())
            .await;

        // The operator publishes new terms mid-upload.
        let mut config = Config::for_tests("onym:component:test", vec![]);
        config.chunk_bytes = 8;
        // A different declared limit, so the terms document — which
        // carries `snapshotsRetained` — really does hash differently.
        config.maximum_retained_snapshots = 7;
        let signing = ed25519_dalek::SigningKey::from_bytes(&config.signing_seed);
        let fresh = Documents::build(&config, &signing).unwrap();
        assert_ne!(fresh.terms.0, minted_under, "the fixture did not change the terms");
        {
            let state = Arc::get_mut(&mut harness.state).unwrap();
            state.documents = fresh;
        }

        // The grant resumes, carrying the terms it was minted under.
        let (status, resumed) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &minted_under))
            .await;
        assert_eq!(status, StatusCode::OK, "the grant was stranded by a terms change");
        let resumed: serde_json::Value = serde_json::from_slice(&resumed).unwrap();
        assert_eq!(resumed["uploadId"], json!(upload_id));
        assert_eq!(resumed["missingChunks"], json!([[1, 2]]));

        // A *new* snapshot under stale terms is still refused: this is
        // a resumption, not a route around consent.
        let other: Vec<u8> = (50..70u8).collect();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&other, &minted_under))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    /// Two byte counts for one digest is a contradiction, and choosing
    /// between them is not the operator's job.
    #[tokio::test]
    async fn a_resume_with_a_different_size_is_refused() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;

        let mut body: serde_json::Value =
            serde_json::from_slice(&harness.preflight_body(&snapshot, &terms)).unwrap();
        body["snapshotReference"]["sealedByteSize"] = json!(999);
        let (status, _) = harness
            .send("POST", "/v1/preflight", serde_json::to_vec(&body).unwrap())
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// A commit sent one chunk early costs one chunk, not the snapshot.
    #[tokio::test]
    async fn an_early_commit_keeps_the_bytes_already_sent() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let (_, grant) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        let grant: serde_json::Value = serde_json::from_slice(&grant).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();

        // Chunk 1's response is lost, so the client never sends it and
        // commits believing it is done.
        for index in [0usize, 2] {
            let end = usize::min(index * 8 + 8, snapshot.len());
            harness
                .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/{index}"), snapshot[index * 8..end].to_vec())
                .await;
        }
        let (status, body) = harness.send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![]).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "upload_incomplete");
        // Inclusive ranges, not indices: one contiguous gap is one
        // range however long it is.
        assert_eq!(error["missingChunks"], json!([[1, 1]]), "the gap was not named");
        assert_eq!(error["chunkCount"], json!(3));

        // The grant survives, so recovery is one chunk.
        let (status, _) = harness
            .send("PUT", &format!("/v1/uploads/{upload_id}/chunks/1"), snapshot[8..16].to_vec())
            .await;
        assert_eq!(status, StatusCode::OK, "the grant was destroyed by a premature commit");
        let (status, body) = harness.send("POST", &format!("/v1/uploads/{upload_id}/commit"), vec![]).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }
}
