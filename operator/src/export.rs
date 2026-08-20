//! The portable export container (§12).
//!
//! **This module must never consult entitlement state.** Not "consult
//! and allow" — not consult. §14.15 makes export unconditional, and
//! §9.7 is explicit that the only way that survives future edits is for
//! the code path to have no access to the state that could condition
//! it. A test in `api.rs` scans this file for entitlement, payment and
//! lapse symbols, and a conformance test asserts export succeeds for a
//! holder with no entitlement at all.
//!
//! The container carries the **terms bytes**, not just their digest.
//! §4.1 obliges an operator to serve historical terms forever, but only
//! for as long as the operator exists — and the whole point of export
//! is that it outlives the operator. A container carrying a `termsId`
//! and a URL would leave a holder, after shutdown, with sealed bytes
//! they can verify and a pin whose preimage is gone: no way to check
//! what retention, jurisdiction or erasure scope the snapshot was
//! accepted under. Pinning that survives as an unresolvable reference
//! is not pinning.
//!
//! The `.seal` files are the sealed bytes verbatim, so migration to
//! another conforming operator is an upload of the same bytes under the
//! same reference — no re-sealing, and no cooperation from the operator
//! being left (§18.3).
//!
//! **The operator serves the members; the client assembles the
//! container.** `manifest.json` names in-container paths, and every one
//! of them has to be fetchable while the operator lives or the manifest
//! describes a container nobody can build:
//!
//! | Container path | Served at |
//! |---|---|
//! | `snapshots/<hex>.seal` | `GET /v1/exports/<hex>` |
//! | `receipts/<id>.json` | `GET /v1/exports/receipts/<id>` |
//! | `terms/<hex>.json` | the terms entry's `termsUrl` |
//! | `terms/<hex>.json.sig` | `termsUrl` + `.sig` |
//!
//! That the terms come from `/terms/` rather than from under
//! `/v1/exports/` is not a contradiction of the paragraph above: the
//! container is assembled while the operator is alive, and it is the
//! container — not the route — that has to outlive it.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::api::AppState;
use crate::auth::authenticate;
use crate::blobs::{digest_hex, snapshot_stream};
use crate::error::{Error, Resource, Result};

/// `GET /v1/exports` — the container manifest.
pub async fn manifest(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let (snapshots, receipts, receipt_terms) = {
        let store = state.store.lock().await;
        let holder = authenticate(&headers, "GET", "/v1/exports", b"", &state.config, &store, now)?;
        (
            store.snapshots(&holder.handle)?,
            store.receipts(&holder.handle)?,
            store.receipt_terms_ids(&holder.handle)?,
        )
    };

    // Live snapshots *and* the receipts' terms. A receipt pins the
    // terms of a snapshot that is gone, so collecting from live
    // snapshots alone ships a receipt citing a document the container
    // does not carry.
    let mut terms_ids: Vec<String> = snapshots
        .iter()
        .map(|row| row.accepted_terms_id.clone())
        .chain(receipt_terms)
        .collect();
    terms_ids.sort();
    terms_ids.dedup();

    Ok(axum::Json(json!({
        "exportVersion": 1,
        "exportedAt": now.format(&Rfc3339).map_err(|e| Error::Internal(e.to_string()))?,
        "operator": state.documents.operator_key,
        "snapshots": snapshots.iter().map(|row| json!({
            "snapshotReference": {
                "referenceVersion": 1,
                "algorithm": row.algorithm,
                "digest": row.digest,
                "sealedByteSize": row.sealed_byte_size,
            },
            "acceptedTermsId": row.accepted_terms_id,
            "termsUrl": terms_url(&state, &row.accepted_terms_id),
            "retainedAt": row.retained_at,
            "file": format!("snapshots/{}.seal", hex_of(&row.digest)),
        })).collect::<Vec<_>>(),
        "receipts": receipts.iter()
            .map(|(id, _)| format!("receipts/{id}.json"))
            .collect::<Vec<_>>(),
        "terms": terms_ids.iter().map(|id| json!({
            "termsId": id,
            "termsUrl": terms_url(&state, id),
            "file": format!("terms/{}.json", hex_of(id)),
            "signature": format!("terms/{}.json.sig", hex_of(id)),
        })).collect::<Vec<_>>(),
    }))
    .into_response())
}

/// `GET /v1/exports/{digest}` — one snapshot's sealed bytes, verbatim.
///
/// Byte-identical to what was uploaded, digest unchanged. This is what
/// makes migration possible without the operator's cooperation.
pub async fn snapshot(
    State(state): State<Arc<AppState>>,
    Path(digest_path): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let path = format!("/v1/exports/{digest_path}");
    let digest = format!("sha256:{digest_path}");

    let (holder, row) = {
        let store = state.store.lock().await;
        let holder = authenticate(&headers, "GET", &path, b"", &state.config, &store, now)?;
        digest_hex(&digest)?;
        let row = store
            .snapshot_record(&holder.handle, &digest)?
            .ok_or(Error::NotFound(Resource::Snapshot))?;
        if row.erased_at.is_some() {
            return Err(Error::NotFound(Resource::Snapshot));
        }
        if row.retained_until.is_some() {
            return Err(Error::RetentionExpired);
        }
        (holder, row)
    };

    let paths = match state.blobs.chunk_paths(
        &holder.handle,
        &digest_path,
        row.chunk_count,
        row.sealed_byte_size,
    ) {
        Ok(paths) => paths,
        Err(Error::RetentionExpired) => {
            let unavailable_at = now
                .format(&Rfc3339)
                .map_err(|e| Error::Internal(e.to_string()))?;
            state
                .store
                .lock()
                .await
                .mark_unavailable(&holder.handle, &digest, &unavailable_at)?;
            return Err(Error::RetentionExpired);
        }
        Err(error) => return Err(error),
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, row.sealed_byte_size.to_string()),
        ],
        axum::body::Body::from_stream(snapshot_stream(paths)),
    )
        .into_response())
}

/// `GET /v1/exports/receipts/{receiptId}` — one signed receipt.
///
/// Receipts are container members (§12), so they have to be fetchable
/// or the manifest lists a file the holder cannot obtain. It also
/// closes a worse hole: a holder whose erase response was lost had no
/// way to ever see the receipt they earned, and a receipt is the only
/// evidence they hold that the erasure was ever acknowledged.
///
/// On the export branch, so it is as unconditional as the rest of it.
pub async fn receipt(
    State(state): State<Arc<AppState>>,
    Path(receipt_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let path = format!("/v1/exports/receipts/{receipt_id}");

    let store = state.store.lock().await;
    let holder = authenticate(&headers, "GET", &path, b"", &state.config, &store, now)?;
    let raw = store
        .receipt(&holder.handle, &receipt_id)?
        .ok_or(Error::NotFound(Resource::Receipt))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        raw,
    )
        .into_response())
}

fn terms_url(state: &Arc<AppState>, terms_id: &str) -> String {
    format!(
        "{}/terms/{}.json",
        state.config.public_url.trim_end_matches('/'),
        hex_of(terms_id)
    )
}

fn hex_of(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

#[cfg(test)]
mod tests {
    use crate::uploads::tests::Harness;
    use axum::http::StatusCode;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    /// The container carries the terms **bytes**, not just a digest —
    /// and after shutdown the digest alone would be a pin whose
    /// preimage is gone.
    #[tokio::test]
    async fn the_export_manifest_carries_every_pinned_terms_document() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;

        let (status, body) = harness.send("GET", "/v1/exports", vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let manifest: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(manifest["exportVersion"], 1);

        let terms = manifest["terms"].as_array().unwrap();
        assert_eq!(terms.len(), 1, "the pinned terms are not in the container");
        assert_eq!(terms[0]["termsId"], json!(harness.terms_id()));

        // The document and its detached signature are both fetchable,
        // which is what makes the pin checkable rather than decorative.
        let terms_url = terms[0]["termsUrl"]
            .as_str()
            .expect("the manifest did not provide a terms URL");
        let path = terms_url
            .strip_prefix(harness.state.config.public_url.as_str())
            .expect("termsUrl is outside the operator origin");
        for path in [path.to_string(), format!("{path}.sig")] {
            let response = crate::api::router(harness.state.clone())
                .oneshot(
                    axum::http::Request::builder()
                        .uri(&path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn a_receipt_only_export_still_locates_its_terms() {
        let harness = Harness::new(vec![]);
        harness
            .store_snapshot(&(0..20u8).collect::<Vec<u8>>())
            .await;
        let erase = serde_json::to_vec(&json!({
            "version": 1,
            "operationId": hex::encode(uuid::Uuid::new_v4().as_bytes()),
            "scope": "all"
        }))
        .unwrap();
        let (status, _) = harness.send("POST", "/v1/erasures", erase).await;
        assert_eq!(status, StatusCode::OK);

        let (_, body) = harness.send("GET", "/v1/exports", vec![]).await;
        let manifest: Value = serde_json::from_slice(&body).unwrap();
        assert!(manifest["snapshots"].as_array().unwrap().is_empty());
        assert!(!manifest["receipts"].as_array().unwrap().is_empty());
        assert!(
            manifest["terms"][0]["termsUrl"]
                .as_str()
                .unwrap()
                .starts_with("https://"),
            "receipt-only terms have no fetch location"
        );
    }

    /// The `.seal` bytes are what was uploaded, byte for byte. This is
    /// what makes migration an upload of the same bytes under the same
    /// reference — no re-sealing, no cooperation from the operator
    /// being left (§18.3).
    #[tokio::test]
    async fn exported_bytes_are_the_sealed_bytes_verbatim() {
        let harness = Harness::new(vec![]);
        let snapshot: Vec<u8> = (0..250u8).cycle().take(4096).collect();
        harness.store_snapshot(&snapshot).await;

        let hex = hex::encode(Sha256::digest(&snapshot));
        let (status, bytes) = harness.send("GET", &format!("/v1/exports/{hex}"), vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, snapshot, "the exported bytes are not what was uploaded");
        // The digest is unchanged, so the same reference re-uploads.
        assert_eq!(hex::encode(Sha256::digest(&bytes)), hex);
    }

    /// Export is holder-scoped like everything else.
    #[tokio::test]
    async fn a_stranger_cannot_export_another_holders_snapshot() {
        let harness = Harness::new(vec![]);
        let mut stranger = Harness::new(vec![]);
        stranger.state = harness.state.clone();
        stranger.signing = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);

        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        let hex = hex::encode(Sha256::digest(&snapshot));

        let (status, _) = stranger.send("GET", &format!("/v1/exports/{hex}"), vec![]).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// §4.1's real requirement: terms this boot did **not** mint are
    /// still served, forever, at their content-addressed path.
    ///
    /// Serving only the current terms passes every test that asks for
    /// the current terms — which is why this one asks for a document
    /// the running process never published. A holder whose snapshot
    /// pins superseded terms has a pin pointing at nothing otherwise.
    #[tokio::test]
    async fn superseded_terms_are_still_served() {
        let harness = Harness::new(vec![]);
        let old = br#"{"termsVersion":1,"note":"superseded"}"#;
        let old_id = crate::documents::digest(old);
        let old_hex = old_id.strip_prefix("sha256:").unwrap().to_string();
        harness
            .state
            .store
            .lock()
            .await
            .remember_terms(&old_id, old, b"c2ln", "2026-01-01T00:00:00Z")
            .unwrap();

        for (path, expected) in [
            (format!("/terms/{old_hex}.json"), old.to_vec()),
            (format!("/terms/{old_hex}.json.sig"), b"c2ln".to_vec()),
        ] {
            let response = crate::api::router(harness.state.clone())
                .oneshot(
                    axum::http::Request::builder()
                        .uri(&path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            assert_eq!(body, expected, "{path} served the wrong bytes");
        }
    }

    use tower::ServiceExt;
}
