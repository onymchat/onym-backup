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
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

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
    // Unreachable with any real field — the longest is a path — but a
    // silent truncation here would collapse two different requests onto
    // one signing payload, which is the failure the prefixes exist to
    // prevent.
    debug_assert!(field.len() <= u32::MAX as usize, "signed field too long to length-prefix");
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

/// A proof that verified, and what the caller still owes.
///
/// Returned rather than a bare key so the nonce is in the caller's
/// hands: §8.2 requires it to be single-use, and single-use is not
/// something this function can enforce — it has no store. Handing back
/// a `VerifyingKey` alone made `verify` look complete, and a route
/// could have shipped calling it and nothing else.
#[must_use = "the nonce must be recorded single-use before the request is honoured"]
pub struct VerifiedProof {
    pub key: VerifyingKey,
    /// Record this and refuse a repeat. Retain for at least **twice**
    /// the freshness window: the window is two-sided, so a signature
    /// timestamped `max_skew` ahead stays acceptable until `now +
    /// max_skew` and is live for up to `2 × max_skew` from first sight.
    pub nonce: String,
    pub handle: String,
}

/// Verify a request's signature and its freshness.
///
/// Freshness is checked here because it needs only a clock. Replay is
/// not, because it needs a store — see `VerifiedProof::nonce`. The
/// split is deliberate and the type makes it visible rather than
/// leaving it to a comment nobody reads at the call site.
pub fn verify(
    holder: &str,
    signature_b64: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
    now: OffsetDateTime,
    max_skew_secs: i64,
) -> Result<VerifiedProof> {
    use base64::Engine;

    let signed_at = OffsetDateTime::parse(timestamp, &Rfc3339)
        .map_err(|_| Error::SignatureInvalid)?;
    // Two-sided: a client clock running fast is ordinary, and refusing
    // every such request would refuse most of them.
    if (now - signed_at).whole_seconds().abs() > max_skew_secs {
        return Err(Error::SignatureInvalid);
    }

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
    Ok(VerifiedProof {
        handle: holder_handle(&key),
        key,
        nonce: nonce.to_string(),
    })
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
        let now = OffsetDateTime::parse("2026-08-20T10:00:00Z", &Rfc3339).unwrap();
        let proof = verify(
            &holder, &signature, "PUT", "/v1/snapshots", "2026-08-20T10:00:00Z", "ab", b"x", now,
            300,
        )
        .expect("a fresh, correctly signed request was refused");
        // The nonce comes back because recording it single-use is the
        // caller's job; the handle, not the key, is what gets stored.
        assert_eq!(proof.nonce, "ab");
        assert_eq!(proof.handle, holder_handle(&signing.verifying_key()));
    }

    /// The property the length prefixes exist for.
    ///
    /// The previous version of this test did not test it. It tried to
    /// shift a byte between `path` and `timestamp`, which are *not*
    /// adjacent — the fixed 78-byte holder sits between them — so both
    /// concatenations differed regardless of framing, and the
    /// assertions still passed with the prefixes removed.
    ///
    /// `timestamp` and `nonce` are adjacent and both attacker-supplied,
    /// so these two inputs concatenate to the identical byte string.
    /// Only the length prefixes separate them: strip `append`'s prefix
    /// and this assertion fires.
    #[test]
    fn adjacent_field_boundaries_cannot_shift() {
        let holder = "onym:seat-key:".to_string() + &"a".repeat(64);
        let a = signing_bytes("PUT", "/x", &holder, "ab", "cd", b"");
        let b = signing_bytes("PUT", "/x", &holder, "abc", "d", b"");

        // The naive concatenation is the same for both — which is the
        // whole point, and is asserted rather than assumed.
        let naive = |t: &str, n: &str| format!("onym-backup-v1PUT/x{holder}{t}{n}").into_bytes();
        assert_eq!(naive("ab", "cd"), naive("abc", "d"));

        assert_ne!(a, b, "a boundary shift produced identical signing bytes");
    }

    /// Freshness is checked; replay is the caller's to record.
    #[test]
    fn stale_and_future_timestamps_are_refused() {
        use ed25519_dalek::Signer;
        let signing = key();
        let holder = holder_of(&signing);
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();

        let sign_at = |stamp: &str| {
            let bytes = signing_bytes("GET", "/v1/snapshots", &holder, stamp, "n", b"");
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                signing.sign(&bytes).to_bytes(),
            )
        };
        let at = |offset: i64| {
            (now + time::Duration::seconds(offset))
                .format(&Rfc3339)
                .unwrap()
        };

        for offset in [0i64, 299, -299] {
            let stamp = at(offset);
            assert!(
                verify(&holder, &sign_at(&stamp), "GET", "/v1/snapshots", &stamp, "n", b"", now, 300)
                    .is_ok(),
                "a signature {offset}s from now was refused"
            );
        }
        for offset in [301i64, -301] {
            let stamp = at(offset);
            assert!(
                verify(&holder, &sign_at(&stamp), "GET", "/v1/snapshots", &stamp, "n", b"", now, 300)
                    .is_err(),
                "a signature {offset}s from now was accepted"
            );
        }
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
