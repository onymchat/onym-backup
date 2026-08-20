//! Turning a request's headers into a verified holder.
//!
//! Three things must all hold, and none of them is optional:
//!
//! 1. the signature verifies over the request we actually received;
//! 2. the timestamp is inside the freshness window;
//! 3. the nonce has not been seen before.
//!
//! (1) and (2) live in `payload`; (3) needs the store, which is why
//! `payload::verify` hands back a `#[must_use] VerifiedProof` carrying
//! the nonce rather than a bare key. This module is the only place that
//! discharges it, so a route cannot accidentally skip the replay check
//! by calling the wrong function.

use axum::http::HeaderMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::payload;
use crate::store::Store;

pub const HOLDER: &str = "x-onym-holder";
pub const TIMESTAMP: &str = "x-onym-timestamp";
pub const NONCE: &str = "x-onym-nonce";
pub const SIGNATURE: &str = "x-onym-signature";

/// A caller who proved possession of their key for this exact request.
pub struct Holder {
    /// `onym:seat-key:<hex>`, exactly as sent — the value a
    /// `SeatEntitlement`'s `subject` must equal.
    pub reference: String,
    /// What we store and shard on.
    pub handle: String,
}

/// Verify a request, and consume its nonce.
pub fn authenticate(
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    config: &Config,
    store: &Store,
    now: OffsetDateTime,
) -> Result<Holder> {
    let header = |name: &str| -> Result<&str> {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or(Error::SignatureInvalid)
    };

    let reference = header(HOLDER)?;
    let timestamp = header(TIMESTAMP)?;
    let nonce = header(NONCE)?;
    let signature = header(SIGNATURE)?;

    let proof = payload::verify(
        reference,
        signature,
        method,
        path,
        timestamp,
        nonce,
        body,
        now,
        config.max_skew_secs,
    )?;

    // Single-use, and recorded under the holder rather than globally so
    // one holder cannot deny service to another by guessing nonces.
    let seen_at = now
        .format(&Rfc3339)
        .map_err(|e| Error::Internal(format!("format timestamp: {e}")))?;
    if !store.record_nonce(&proof.handle, &proof.nonce, &seen_at)? {
        return Err(Error::SignatureInvalid);
    }

    Ok(Holder {
        reference: reference.to_string(),
        handle: proof.handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_headers(
        signing: &SigningKey,
        method: &str,
        path: &str,
        body: &[u8],
        stamp: &str,
        nonce: &str,
    ) -> HeaderMap {
        let reference = format!(
            "onym:seat-key:{}",
            hex::encode(signing.verifying_key().as_bytes())
        );
        let bytes = payload::signing_bytes(method, path, &reference, stamp, nonce, body);
        let signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing.sign(&bytes).to_bytes(),
        );

        let mut headers = HeaderMap::new();
        headers.insert(HOLDER, reference.parse().unwrap());
        headers.insert(TIMESTAMP, stamp.parse().unwrap());
        headers.insert(NONCE, nonce.parse().unwrap());
        headers.insert(SIGNATURE, signature.parse().unwrap());
        headers
    }

    fn fixtures() -> (SigningKey, Config, Store, OffsetDateTime, String) {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let config = Config::for_tests("onym:component:test", vec![]);
        let store = Store::in_memory().unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let stamp = now.format(&Rfc3339).unwrap();
        (signing, config, store, now, stamp)
    }

    #[test]
    fn a_signed_request_authenticates() {
        let (signing, config, store, now, stamp) = fixtures();
        let headers = signed_headers(&signing, "GET", "/v1/snapshots", b"", &stamp, "n1");
        let holder =
            authenticate(&headers, "GET", "/v1/snapshots", b"", &config, &store, now).unwrap();
        assert!(holder.reference.starts_with("onym:seat-key:"));
        assert_eq!(holder.handle.len(), 64);
    }

    /// The whole point of recording the nonce: a captured request
    /// cannot be sent twice.
    #[test]
    fn a_replayed_request_is_refused() {
        let (signing, config, store, now, stamp) = fixtures();
        let headers = signed_headers(&signing, "GET", "/v1/snapshots", b"", &stamp, "n1");
        assert!(authenticate(&headers, "GET", "/v1/snapshots", b"", &config, &store, now).is_ok());
        assert!(
            authenticate(&headers, "GET", "/v1/snapshots", b"", &config, &store, now).is_err(),
            "the same request verified twice"
        );
    }

    /// The signature covers the path, so a proof for one route cannot
    /// be lifted onto another.
    #[test]
    fn a_proof_cannot_be_moved_to_another_route() {
        let (signing, config, store, now, stamp) = fixtures();
        let headers = signed_headers(&signing, "GET", "/v1/snapshots", b"", &stamp, "n1");
        assert!(
            authenticate(&headers, "GET", "/v1/exports", b"", &config, &store, now).is_err(),
            "a proof signed for one path authenticated another"
        );
    }

    /// And it covers the body, so a chunk cannot be swapped under a
    /// signature that was made for different bytes.
    #[test]
    fn a_proof_cannot_be_moved_to_another_body() {
        let (signing, config, store, now, stamp) = fixtures();
        let headers = signed_headers(&signing, "PUT", "/v1/uploads/u/chunks/0", b"aaa", &stamp, "n1");
        assert!(
            authenticate(&headers, "PUT", "/v1/uploads/u/chunks/0", b"bbb", &config, &store, now)
                .is_err(),
            "a proof signed over one body authenticated another"
        );
    }

    #[test]
    fn missing_headers_are_refused_rather_than_defaulted() {
        let (_, config, store, now, _) = fixtures();
        assert!(authenticate(
            &HeaderMap::new(), "GET", "/v1/snapshots", b"", &config, &store, now
        )
        .is_err());
    }
}
