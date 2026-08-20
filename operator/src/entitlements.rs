//! Verifying a broker's `SeatEntitlement`, and the two ways one
//! arrives.
//!
//! §10.4 is the whole of the check and it is entirely local: canonical
//! bytes, a signature from an issuer pinned at boot, `audience`,
//! `subject`, the validity window, and absence from the cached
//! revocation epoch. The operator never asks the broker about a
//! specific holder — that is the correlation WHITEPAPER §17.8 forbids,
//! and it is why revocation is an epoch document rather than a status
//! endpoint.
//!
//! **Two presentation paths, one verifier.** §9.1 specifies
//! `POST /v1/entitlements`, which registers a credential against the
//! presenting holder. Both shipped clients instead attach
//! `X-Onym-Entitlement` to every authenticated request and never call
//! that route — see `ObjectHttpBackupClient.kt` and
//! `URLSessionBackupClient+Transport.swift`. Refusing the header would
//! break both; dropping the route would leave §9.1 unimplemented. So
//! both exist and both land in `verify`, and the header path registers
//! what it verified for exactly the same reason the route does: lapse
//! (§10.3) is derived from entitlement expiry, which the operator can
//! only know if it remembers the last credential it was shown.
//!
//! **Every failure is one error.** A caller learns "this entitlement is
//! not usable" and the issuers it could have come from, never which of
//! the six checks failed. The distinctions are all things a forger
//! would like an oracle for.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::api::AppState;
use crate::auth::authenticate;
use crate::config::Config;
use crate::documents::canonical_bytes;
use crate::error::{Error, Result};

/// The header both clients attach to every authenticated request, and
/// deliberately omit on `/v1/exports`.
///
/// Carries base64 of the credential's exact bytes — not a re-encoding.
/// A re-serialised document would canonicalise to the same bytes only
/// if the client's JSON writer happened to agree with ours, and the
/// signature is over canonical bytes precisely so nobody has to hope.
pub const HEADER: &str = "x-onym-entitlement";

/// A credential that passed every check in §10.4.
pub struct VerifiedEntitlement {
    pub entitlement_id: String,
    pub offer_id: String,
    pub not_before: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    /// The exact bytes presented, kept so the record can be re-checked
    /// against a later epoch without trusting a re-encoding.
    pub raw: Vec<u8>,
}

/// §10.4, in the order the profile gives — signature before any field
/// is believed, because an unsigned document's `audience` is not
/// evidence of anything.
///
/// `revoked` is passed in rather than fetched. A stale epoch is the
/// caller's policy decision (§10.4: keep serving on the last good one
/// rather than refusing everyone during a broker outage), and this
/// function should not quietly make it.
pub fn verify(
    raw: &[u8],
    config: &Config,
    holder_reference: &str,
    revoked: &HashSet<String>,
    now: OffsetDateTime,
) -> Result<VerifiedEntitlement> {
    let refused = || Error::InvalidEntitlement {
        entitlement_issuers: config.entitlement_issuers.clone(),
    };

    let document: Value = serde_json::from_slice(raw).map_err(|_| refused())?;
    let object = document.as_object().ok_or_else(refused)?;
    let string = |key: &str| -> Result<String> {
        object
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(refused)
    };

    if object.get("version").and_then(Value::as_i64) != Some(1) {
        return Err(refused());
    }
    if string("type")? != "SeatEntitlement" {
        return Err(refused());
    }

    // (2) An issuer pinned at boot and published in the manifest —
    // never a key from the document. `issuer_keys` is keyed by the
    // exact `onym:key:<hex>` reference, so an unpinned issuer simply
    // has no entry and there is no comparison to get wrong.
    let issuer = string("issuer")?;
    let keys = crate::config::issuer_keys(&config.entitlement_issuers);
    let key = keys.get(&issuer).ok_or_else(refused)?;

    // (1) Canonical bytes omitting `signature`, and the signature over
    // them. Same rule as the manifest, the terms and every receipt.
    let signature = {
        use base64::Engine;
        let encoded = string("signature")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| refused())?;
        let bytes: [u8; 64] = bytes.try_into().map_err(|_| refused())?;
        ed25519_dalek::Signature::from_bytes(&bytes)
    };
    let signed = canonical_bytes(&document, &["signature"]).map_err(|_| refused())?;
    {
        use ed25519_dalek::Verifier;
        key.verify(&signed, &signature).map_err(|_| refused())?;
    }

    // (3) and (4). Both are exact string comparisons, prefix included.
    // §10.4 is explicit that there is no normalization step, and an
    // implementation that needs one has a spelling mismatch to fix
    // rather than a comparison to loosen.
    if string("audience")? != config.component_id {
        return Err(refused());
    }
    if string("subject")? != holder_reference {
        return Err(refused());
    }

    // (5) The window. Upper bound is strict, matching
    // `SeatEntitlementVerifier.verify` — an entitlement is not valid at
    // the instant it expires, and the two sides disagreeing about that
    // instant is a bug nobody would find.
    let stamp = |key: &str| -> Result<OffsetDateTime> {
        OffsetDateTime::parse(&string(key)?, &Rfc3339).map_err(|_| refused())
    };
    let not_before = stamp("notBefore")?;
    let expires_at = stamp("expiresAt")?;
    if now < not_before || now >= expires_at {
        return Err(refused());
    }

    // (6) The cached epoch.
    let entitlement_id = string("entitlementId")?;
    if revoked.contains(&entitlement_id) {
        return Err(refused());
    }

    // `quota` is a string-or-null — never a float, which has no
    // canonical decimal form across platforms and which both clients
    // reject as malformed.
    //
    // A non-null quota is a purchased balance the broker expects to be
    // decremented, and this operator does not keep one. Refusing is the
    // honest answer: storing a balance and never spending it would be
    // claiming to honour terms it has not implemented. A subscription —
    // `quota: null` — is the shape this seat actually sells.
    match object.get("quota") {
        None | Some(Value::Null) => {}
        _ => return Err(refused()),
    }

    Ok(VerifiedEntitlement {
        entitlement_id,
        offer_id: string("offerId")?,
        not_before,
        expires_at,
        raw: raw.to_vec(),
    })
}

/// Read and verify the `X-Onym-Entitlement` header, if one is present.
///
/// `Ok(None)` means no header — which is not an error anywhere. A free
/// operator ignores it, and on a charging operator the absence is what
/// produces the `402` that starts the payment loop. A header that *is*
/// present and does not verify is refused: having been shown a bad
/// credential is different from having been shown none, and treating
/// them alike would turn every forgery into a purchase prompt.
pub fn presented(
    headers: &HeaderMap,
    state: &AppState,
    holder_reference: &str,
    now: OffsetDateTime,
) -> Result<Option<VerifiedEntitlement>> {
    if !state.config.requires_entitlement() {
        return Ok(None);
    }
    let Some(value) = headers.get(HEADER).and_then(|value| value.to_str().ok()) else {
        return Ok(None);
    };
    let refused = || Error::InvalidEntitlement {
        entitlement_issuers: state.config.entitlement_issuers.clone(),
    };
    let raw = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .map_err(|_| refused())?
    };
    let revoked = state.revocation.revoked();
    verify(&raw, &state.config, holder_reference, &revoked, now).map(Some)
}

/// §9.1 — register an entitlement against the presenting holder.
///
/// Idempotent by `entitlementId`: re-registering the same credential
/// answers the same way and does not mint a second record.
pub async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let store = state.store.lock().await;
    let holder = authenticate(
        &headers,
        "POST",
        "/v1/entitlements",
        &body,
        &state.config,
        &store,
        now,
    )?;

    // Every §9 route passes the gate, including this one — so that
    // "registering is always available" is an entry in the allowlist
    // rather than a route that happened to skip the check. It is a
    // no-op here by construction; gating it would make a lapse
    // permanent, since this is how a holder ends one.
    crate::lapse::require(
        &state,
        &store,
        &holder,
        &headers,
        crate::lapse::Operation::Register,
        now,
    )?;

    // A free operator has no issuers to verify against, so there is
    // nothing this route could honestly do with a credential. Saying so
    // is better than storing one it will never consult.
    if !state.config.requires_entitlement() {
        return Err(Error::BadRequest(
            "this operator declares no entitlement issuers and never consults an entitlement".into(),
        ));
    }

    let request: Value = serde_json::from_slice(&body)
        .map_err(|_| Error::BadRequest("body is not JSON".into()))?;
    if request.get("version").and_then(Value::as_i64) != Some(1) {
        return Err(Error::BadRequest("version must be 1".into()));
    }
    let entitlement = request
        .get("entitlement")
        .ok_or_else(|| Error::BadRequest("entitlement is required".into()))?;

    // Re-serialised through our own canonical writer rather than sliced
    // out of the request body. The signature is over canonical bytes,
    // so this is lossless for anything that could verify — and it means
    // the route does not need a second JSON parser positioned to find
    // the original span.
    let raw = canonical_bytes(entitlement, &[])?;
    let verified = verify(
        &raw,
        &state.config,
        &holder.reference,
        &state.revocation.revoked(),
        now,
    )?;

    let stamp = now
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(format!("format timestamp: {e}")))?;
    store.register_entitlement(&holder.handle, &verified, &stamp)?;

    Ok(axum::Json(json!({
        "registered": true,
        "entitlementId": verified.entitlement_id,
        "expiresAt": verified.expires_at.format(&Rfc3339)
            .map_err(|e| Error::Internal(format!("format timestamp: {e}")))?,
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uploads::tests::Harness;

    use axum::http::StatusCode;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    /// A broker, and the issuer reference an operator would pin.
    fn broker() -> (SigningKey, String) {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let issuer = format!(
            "onym:key:{}",
            hex::encode(signing.verifying_key().as_bytes())
        );
        (signing, issuer)
    }

    /// Mint a credential the way a broker would, then hand back the
    /// base64 a client would put on the header.
    fn credential(signing: &SigningKey, overrides: Value) -> String {
        let holder = SigningKey::from_bytes(&[5u8; 32]);
        let subject = format!(
            "onym:seat-key:{}",
            hex::encode(holder.verifying_key().as_bytes())
        );
        let issuer = format!(
            "onym:key:{}",
            hex::encode(signing.verifying_key().as_bytes())
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
            "quota": Value::Null,
            "status": "https://broker.example/v1/revocations/current",
        });
        for (key, value) in overrides.as_object().unwrap() {
            document[key] = value.clone();
        }

        let signed = canonical_bytes(&document, &["signature"]).unwrap();
        document["signature"] = json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing.sign(&signed).to_bytes(),
        ));
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&document).unwrap(),
        )
    }

    /// Everything after this one is a variation on it: a credential
    /// that should work, working.
    #[tokio::test]
    async fn a_valid_entitlement_opens_the_upload_path() {
        let (signing, issuer) = broker();
        let harness = Harness::new(vec![issuer]);
        harness.holding(Some(credential(&signing, json!({}))));

        let snapshot: Vec<u8> = (0..20u8).collect();
        let (status, body) = harness.store_snapshot(&snapshot).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a valid entitlement was refused: {}",
            String::from_utf8_lossy(&body)
        );
    }

    /// §18.11. Forged issuer, mutated field, expired window, wrong
    /// audience, wrong subject, revoked id — each refused, and none of
    /// them distinguishable from the others in the response.
    #[tokio::test]
    async fn every_bad_entitlement_is_refused() {
        let (signing, issuer) = broker();
        let impostor = SigningKey::from_bytes(&[4u8; 32]);
        let now = OffsetDateTime::now_utc();
        let stamp = |at: OffsetDateTime| json!(at.format(&Rfc3339).unwrap());

        let cases: Vec<(&str, String)> = vec![
            // Signed by a key this operator does not pin. The issuer
            // field names the real broker, so only the signature check
            // catches it.
            (
                "forged issuer",
                credential(&impostor, json!({ "issuer": issuer.clone() })),
            ),
            // Signed by an unpinned issuer that names itself.
            ("unpinned issuer", credential(&impostor, json!({}))),
            ("wrong audience", credential(&signing, json!({ "audience": "onym:component:someone-else" }))),
            ("wrong subject", credential(&signing, json!({ "subject": "onym:seat-key:00" }))),
            ("expired", credential(&signing, json!({
                "notBefore": stamp(now - time::Duration::days(60)),
                "expiresAt": stamp(now - time::Duration::days(1)),
            }))),
            ("not yet valid", credential(&signing, json!({
                "notBefore": stamp(now + time::Duration::days(1)),
                "expiresAt": stamp(now + time::Duration::days(30)),
            }))),
            // A balance this operator does not keep. Storing one and
            // never spending it would be claiming to honour terms it
            // has not implemented.
            ("consumable quota", credential(&signing, json!({ "quota": "10" }))),
        ];

        for (name, forged) in cases {
            let harness = Harness::new(vec![issuer.clone()]);
            harness.holding(Some(forged));
            let snapshot: Vec<u8> = (0..20u8).collect();
            let terms = harness.terms_id();
            let (status, body) = harness
                .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
                .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{name} was not refused: {}",
                String::from_utf8_lossy(&body)
            );
            let error: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["error"], "invalid_entitlement", "{name}");
            assert_eq!(error["entitlementIssuers"][0], json!(issuer), "{name}");
        }
    }

    /// A mutated field breaks the signature — asserted separately
    /// because it is the check that proves canonical bytes are being
    /// recomputed rather than trusted from the document.
    #[tokio::test]
    async fn a_mutated_field_breaks_the_signature() {
        let (signing, issuer) = broker();
        let valid = credential(&signing, json!({}));
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &valid,
        )
        .unwrap();
        let mut document: Value = serde_json::from_slice(&raw).unwrap();
        // Extend the window without re-signing.
        document["expiresAt"] = json!("2099-01-01T00:00:00Z");
        let mutated = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&document).unwrap(),
        );

        let harness = Harness::new(vec![issuer]);
        harness.holding(Some(mutated));
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// A revoked id is refused even though the credential itself is
    /// perfectly valid and unexpired. This is the refund biting.
    #[tokio::test]
    async fn a_revoked_entitlement_is_refused() {
        let (signing, issuer) = broker();
        let harness = Harness::new(vec![issuer]);
        harness.holding(Some(credential(&signing, json!({ "entitlementId": "ent-refunded" }))));

        let epoch = json!({
            "epoch": 7,
            "publishedAt": "2026-08-01T00:00:00Z",
            "revoked": ["ent-refunded"],
        });
        let signed = canonical_bytes(&epoch, &[]).unwrap();
        let mut epoch = epoch;
        epoch["signature"] = json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing.sign(&signed).to_bytes(),
        ));
        let parsed = crate::revocation::parse(
            &serde_json::to_vec(&epoch).unwrap(),
            &harness.state.config,
        )
        .unwrap();
        harness
            .state
            .revocation
            .install(parsed, OffsetDateTime::now_utc());

        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(&snapshot, &terms))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// §18.12, the payment loop: `402` at preflight, entitlement
    /// obtained, retry with the **same** operationId and the **same**
    /// bytes, `retained`. Re-sealing would mint a new salt and a new
    /// digest, defeating both the retry and `already_retained`.
    #[tokio::test]
    async fn the_payment_loop_preserves_the_bytes() {
        let (signing, issuer) = broker();
        let harness = Harness::new(vec![issuer.clone()]);
        let snapshot: Vec<u8> = (0..20u8).collect();
        let terms = harness.terms_id();
        // One body, reused verbatim across the refusal and the retry.
        let body = harness.preflight_body(&snapshot, &terms);

        let (status, refused) = harness.send("POST", "/v1/preflight", body.clone()).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let error: Value = serde_json::from_slice(&refused).unwrap();
        assert_eq!(error["paymentRequired"]["offers"][0], json!("backup-monthly-v1"));
        assert_eq!(error["paymentRequired"]["entitlementIssuers"][0], json!(issuer));
        assert!(
            error["paymentRequired"]["manifestUrl"].is_string(),
            "the refusal does not say where the signed issuer list is"
        );

        // Buy.
        harness.holding(Some(credential(&signing, json!({}))));

        // The same operationId, the same reference, the same bytes.
        let (status, granted) = harness.send("POST", "/v1/preflight", body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&granted));
        let grant: Value = serde_json::from_slice(&granted).unwrap();
        let upload_id = grant["uploadId"].as_str().unwrap().to_string();
        let chunk_bytes = grant["chunkBytes"].as_u64().unwrap() as usize;
        let chunk_count = grant["chunkCount"].as_u64().unwrap() as usize;
        for index in 0..chunk_count {
            let start = index * chunk_bytes;
            let end = usize::min(start + chunk_bytes, snapshot.len());
            let (status, _) = harness
                .send(
                    "PUT",
                    &format!("/v1/uploads/{upload_id}/chunks/{index}"),
                    snapshot[start..end].to_vec(),
                )
                .await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, committed) = harness
            .send("POST", &format!("/v1/uploads/{upload_id}/commit"), b"{}".to_vec())
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&committed));
        let outcome: Value = serde_json::from_slice(&committed).unwrap();
        assert_eq!(outcome["outcome"]["status"], json!("retained"));
        // And the digest never moved.
        assert_eq!(
            outcome["outcome"]["snapshotReference"]["digest"],
            json!(format!("sha256:{}", hex::encode(Sha256::digest(&snapshot))))
        );
    }

    /// §18.13. Export is never gated on payment, by anything, ever —
    /// against an operator that charges, with a holder who has never
    /// presented a credential.
    #[tokio::test]
    async fn export_succeeds_for_a_holder_with_no_entitlement() {
        let (signing, issuer) = broker();
        let harness = Harness::new(vec![issuer]);

        // Store something while paid, then stop being paid at all.
        harness.holding(Some(credential(&signing, json!({}))));
        let snapshot: Vec<u8> = (0..20u8).collect();
        harness.store_snapshot(&snapshot).await;
        harness.holding(None);

        let (status, body) = harness.send("GET", "/v1/exports", vec![]).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "export was gated on payment: {}",
            String::from_utf8_lossy(&body)
        );
        let manifest: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            !manifest["snapshots"].as_array().unwrap().is_empty(),
            "an unpaid export came back empty"
        );
    }

    /// §9.1's route, for a client that registers rather than attaching
    /// a header. Idempotent by `entitlementId`.
    #[tokio::test]
    async fn registering_an_entitlement_opens_the_upload_path() {
        let (signing, issuer) = broker();
        let harness = Harness::new(vec![issuer]);
        let encoded = credential(&signing, json!({}));
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &encoded,
        )
        .unwrap();
        let document: Value = serde_json::from_slice(&raw).unwrap();
        let body = serde_json::to_vec(&json!({ "version": 1, "entitlement": document })).unwrap();

        let (status, response) = harness.send("POST", "/v1/entitlements", body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&response));
        // Registering twice is registering once.
        let (status, _) = harness.send("POST", "/v1/entitlements", body).await;
        assert_eq!(status, StatusCode::OK);

        // And the upload path is open without a header on the request.
        let snapshot: Vec<u8> = (0..20u8).collect();
        let (status, body) = harness.store_snapshot(&snapshot).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a registered entitlement did not open the upload path: {}",
            String::from_utf8_lossy(&body)
        );
    }
}
