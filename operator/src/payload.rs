//! Proof of possession, reconstructed from the request we actually
//! received (§8).
//!
//! A holder is an Ed25519 public key and nothing else. The signature
//! covers the method, the path with its query, and a digest of the
//! body, so a chunk upload cannot be replayed into a different index, a
//! different upload, or a different operation.
//!
//! Every field is length-prefixed. Without that, a signature over
//! concatenated fields can be reinterpreted by shifting a boundary
//! between two adjacent fields an attacker influences.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub const CONTEXT: &str = "onym-backup-v1";
pub const HOLDER_PREFIX: &str = "onym:seat-key:";

/// The bytes a holder signs, rebuilt on our side.
pub fn signing_bytes(
    method: &str,
    path: &str,
    holder: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    append(&mut out, CONTEXT.as_bytes());
    append(&mut out, method.to_ascii_uppercase().as_bytes());
    append(&mut out, path.as_bytes());
    append(&mut out, holder.as_bytes());
    append(&mut out, timestamp.as_bytes());
    append(&mut out, nonce.as_bytes());
    // The raw digest, not its hex. A body-less request signs the digest
    // of the empty string rather than an empty field, so "no body" and
    // "empty body" are the same value and neither is a shorter payload.
    append(&mut out, &Sha256::digest(body));
    out
}

fn append(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// The 32 raw key bytes behind `onym:seat-key:<64 hex>`.
///
/// The prefix is required, not stripped leniently. It is the one place
/// the wire says *this key is seat-scoped and is not an identity key*,
/// and it is the byte-for-byte value a `SeatEntitlement`'s `subject`
/// must equal.
pub fn holder_key(reference: &str) -> Result<VerifyingKey> {
    let hex_value = reference
        .strip_prefix(HOLDER_PREFIX)
        .ok_or(Error::SignatureInvalid)?;
    if hex_value.len() != 64 || !hex_value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::SignatureInvalid);
    }
    let bytes = hex::decode(hex_value).map_err(|_| Error::SignatureInvalid)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::SignatureInvalid)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::SignatureInvalid)
}

/// What the operator stores and shards on: a digest of the public key,
/// never the key itself. The raw key still arrives in a header — it
/// must, to verify a signature — but nothing persisted or logged is the
/// credential.
pub fn holder_handle(key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"onym-backup-holder-v1");
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify(
    holder: &str,
    signature_b64: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> Result<VerifyingKey> {
    use base64::Engine;

    let key = holder_key(holder)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| Error::SignatureInvalid)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| Error::SignatureInvalid)?;
    let bytes = signing_bytes(method, path, holder, timestamp, nonce, body);
    key.verify(&bytes, &Signature::from_bytes(&signature))
        .map_err(|_| Error::SignatureInvalid)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn holder_of(key: &SigningKey) -> String {
        format!("{HOLDER_PREFIX}{}", hex::encode(key.verifying_key().as_bytes()))
    }

    #[test]
    fn round_trips() {
        let signing = key();
        let holder = holder_of(&signing);
        let bytes = signing_bytes("PUT", "/v1/snapshots", &holder, "2026-08-20T10:00:00Z", "ab", b"x");
        let signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing.sign(&bytes).to_bytes(),
        );
        assert!(verify(
            &holder, &signature, "PUT", "/v1/snapshots", "2026-08-20T10:00:00Z", "ab", b"x"
        )
        .is_ok());
    }

    /// The property the length prefixes exist for: a signature over one
    /// request must not verify against another whose fields concatenate
    /// to the same bytes.
    #[test]
    fn field_boundaries_cannot_shift() {
        let holder = "onym:seat-key:".to_string() + &"a".repeat(64);
        let a = signing_bytes("PUT", "/v1/uploads/u1/chunks/1", &holder, "t", "n", b"");
        let b = signing_bytes("PUT", "/v1/uploads/u1/chunks/11", &holder, "t", "n", b"");
        assert_ne!(a, b);

        let c = signing_bytes("PUT", "/v1/uploads/u/chunks/0", &holder, "t", "n", b"");
        let d = signing_bytes("PUT", "/v1/uploads/u/chunks/", &holder, "0t", "n", b"");
        assert_ne!(c, d, "a boundary shift produced identical signing bytes");
    }

    /// A body-less request and an empty-body request sign the same
    /// value, and neither is an empty field.
    #[test]
    fn empty_body_is_a_digest_not_a_gap() {
        let holder = "onym:seat-key:".to_string() + &"b".repeat(64);
        let bytes = signing_bytes("GET", "/v1/snapshots", &holder, "t", "n", b"");
        assert!(bytes.ends_with(&Sha256::digest(b"")[..]));
    }

    #[test]
    fn holder_reference_must_carry_its_prefix() {
        let signing = key();
        let bare = hex::encode(signing.verifying_key().as_bytes());
        assert!(holder_key(&bare).is_err(), "a bare hex key was accepted");
        assert!(holder_key(&format!("onym:key:{bare}")).is_err(), "an identity-key prefix was accepted");
        assert!(holder_key(&holder_of(&signing)).is_ok());
    }

    /// Uppercase hex is a different string that names the same key;
    /// accepting it would make the holder reference non-canonical, and
    /// the entitlement `subject` comparison is exact.
    #[test]
    fn uppercase_hex_is_refused() {
        let signing = key();
        let upper = hex::encode_upper(signing.verifying_key().as_bytes());
        assert!(holder_key(&format!("{HOLDER_PREFIX}{upper}")).is_err());
    }
}
