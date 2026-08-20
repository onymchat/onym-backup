//! What this operator publishes about itself: the service manifest, the
//! implementation profile, and the content-addressed terms.
//!
//! All three are served unauthenticated (§4.1), and the terms are
//! **served forever**. A retained snapshot pins a `termsId`, and a
//! holder who cannot fetch the terms their snapshot was accepted under
//! cannot check what they were promised — so dropping a historical
//! terms document breaks the pinning of §5.4 whatever the current terms
//! say.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::error::{Error, Result};

pub const PORTABLE_PROFILE_ID: &str = "onym:backup-profile:sealed-device-archive-v1";
pub const IMPLEMENTATION_PROFILE_ID: &str = "onym:backup-implementation:object-http-v1";
pub const DIGEST_SUITE: &str = "sha-256/lowercase-hex";
pub const SEALING_SUITE: &str = "aes-256-gcm/hkdf-sha256-from-bip39-seed";
pub const INCREMENT_MODEL: &str = "whole-snapshot-transfer-chunked-v1";
pub const AUTHENTICATION: &str = "holder-scoped-capability/ed25519-request-bound-v1";
pub const PAYMENT_REFUSAL: &str = "onym-payment-required-v1";
pub const SEAT: &str = "storage.backup";

/// `sha256:<64 lowercase hex>` over `bytes`, the one digest syntax this
/// system uses for manifests, terms and snapshots alike.
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Canonical bytes: keys sorted by **UTF-8 byte order**, no
/// insignificant whitespace, named fields removed structurally.
///
/// Byte order, not `sort_keys` on strings — they coincide for the
/// all-lowercase-ASCII keys these documents use today, which is exactly
/// why choosing the wrong rule would pass every current test and break
/// on the first uppercase-initial or non-ASCII key.
pub fn canonical_bytes(value: &Value, omitting: &[&str]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        for field in omitting {
            object.remove(*field);
        }
    }
    write_canonical(&value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string(key, out);
                out.push(b':');
                write_canonical(&map[*key], out)?;
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::String(text) => write_json_string(text, out),
        Value::Number(number) => {
            // Floats have no canonical decimal form, so a signed
            // document containing one could not round-trip byte-stably.
            // Refused rather than rendered.
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err(Error::Internal(format!("non-integer number in signed document: {number}")));
            }
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::Bool(flag) => out.extend_from_slice(if *flag { b"true" } else { b"false" }),
        Value::Null => out.extend_from_slice(b"null"),
    }
    Ok(())
}

/// Exactly `"` `\` and U+0000–U+001F escaped, nothing else. No `/`, no
/// non-ASCII, no U+007F.
fn write_json_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// This operator's published documents, signed once at boot.
pub struct Documents {
    pub manifest: Vec<u8>,
    pub profile: Vec<u8>,
    /// Detached Ed25519 over the **exact served bytes** of the
    /// manifest — not over its canonical form. §4.1 says served bytes,
    /// and the difference matters: the embedded `signature` covers the
    /// canonical document minus itself, so a verifier checking the
    /// detached one against canonical bytes would fail on a document
    /// that is perfectly valid.
    pub manifest_signature: String,
    pub terms_signature: String,
    /// `(termsId, bytes)`. Only one set is minted here; historical terms
    /// are served from disk in a later slice, because they must outlive
    /// any single boot.
    pub terms: (String, Vec<u8>),
    pub operator_key: String,
}

impl Documents {
    pub fn build(config: &Config, signing: &SigningKey) -> Result<Documents> {
        let operator_key = format!("onym:key:{}", hex::encode(signing.verifying_key().as_bytes()));

        let terms = sign(default_terms(config, &operator_key), signing, &["termsId", "signature"])?;
        let terms_id = digest(&canonical_bytes(
            &serde_json::from_slice::<Value>(&terms).map_err(|e| Error::Internal(e.to_string()))?,
            &["termsId", "signature"],
        )?);

        let manifest = sign(
            manifest_document(config, &operator_key, &terms_id),
            signing,
            &["signature"],
        )?;

        Ok(Documents {
            manifest_signature: detached(&manifest, signing),
            terms_signature: detached(&terms, signing),
            manifest,
            profile: serde_json::to_vec(&profile_document())
                .map_err(|e| Error::Internal(e.to_string()))?,
            terms: (terms_id, terms),
            operator_key,
        })
    }
}

/// Sign a document over its canonical bytes and fold the signature in.
///
/// The signature is computed over the canonical form with the named
/// fields removed, then written back into the served JSON — so the
/// bytes a client fetches carry their own signature without the
/// signature having covered itself.
fn sign(mut document: Value, signing: &SigningKey, omitting: &[&str]) -> Result<Vec<u8>> {
    use base64::Engine;
    let bytes = canonical_bytes(&document, omitting)?;
    let signature = signing.sign(&bytes);
    let encoded = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    if let Some(object) = document.as_object_mut() {
        if omitting.contains(&"termsId") {
            object.insert("termsId".into(), json!(digest(&bytes)));
        }
        object.insert("signature".into(), json!(encoded));
    }
    serde_json::to_vec(&document).map_err(|e| Error::Internal(e.to_string()))
}

fn manifest_document(config: &Config, operator_key: &str, terms_id: &str) -> Value {
    json!({
        "version": 1,
        "componentId": config.component_id,
        "seat": SEAT,
        "operator": operator_key,
        "backupProfileId": PORTABLE_PROFILE_ID,
        "implementationProfileId": IMPLEMENTATION_PROFILE_ID,
        "endpoints": [{ "uri": config.public_url, "role": "read-write" }],
        "capabilities": ["upload", "list", "download", "erase", "export"],
        "limits": {
            "maximumSealedSnapshotBytes": config.maximum_sealed_snapshot_bytes,
            "maximumRetainedSnapshots": config.maximum_retained_snapshots,
        },
        "declaredTerms": terms_id,
        // Empty in free mode, and that is the declaration: an operator
        // naming no issuers never asks for an entitlement.
        "entitlementIssuers": config.entitlement_issuers,
        // `ServiceManifest.offers` is an array of **objects**
        // (WHITEPAPER §16.1), which is what both clients parse — an
        // array of bare ids decodes lossily to nothing, leaving a
        // charging operator's manifest declaring no offer at all. The
        // §10.1 refusal is the one that carries bare ids, and that
        // asymmetry is in the documents rather than a mistake.
        //
        // `model` is `subscription` because that is what this operator
        // sells: a non-null `quota` is refused, so a consumable offer
        // is not one it could honour. Still no price, no currency and
        // no storefront — those belong to the frontend's channel
        // agreement, not to anything an operator publishes.
        "offers": config.offers.iter().map(|offer| json!({
            "offerId": offer,
            "model": "subscription",
        })).collect::<Vec<_>>(),
    })
}

fn profile_document() -> Value {
    json!({
        "implementationVersion": 1,
        "implementationProfileId": IMPLEMENTATION_PROFILE_ID,
        "backupProfileId": PORTABLE_PROFILE_ID,
        "digestSuite": DIGEST_SUITE,
        "sealingSuite": SEALING_SUITE,
        "incrementModel": INCREMENT_MODEL,
        "authentication": [AUTHENTICATION],
        "paymentRefusal": PAYMENT_REFUSAL,
    })
}

/// A detached signature over exactly these bytes.
fn detached(bytes: &[u8], signing: &SigningKey) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(signing.sign(bytes).to_bytes())
}

/// Sign an erasure receipt over its canonical bytes.
///
/// Public because §11's receipt is minted per request rather than at
/// boot, and it is signed by the same key that signs the manifest and
/// the terms: a holder who can check one can check all three without
/// learning a second key.
pub fn sign_receipt(receipt: Value, signing: &SigningKey) -> Result<(Value, Vec<u8>)> {
    let bytes = sign(receipt, signing, &["signature"])?;
    let document = serde_json::from_slice(&bytes).map_err(|e| Error::Internal(e.to_string()))?;
    Ok((document, bytes))
}

/// The starting terms.
///
/// Deliberately unflattering where the truth is unflattering:
/// `accessLogs` is `none` because §15 forbids the table, `excluded`
/// names what erasure cannot reach, and `afterGrace` says what actually
/// happens rather than the comfortable answer.
fn iso_duration(seconds: i64) -> String {
    if seconds % (24 * 60 * 60) == 0 {
        format!("P{}D", seconds / (24 * 60 * 60))
    } else if seconds % (60 * 60) == 0 {
        format!("PT{}H", seconds / (60 * 60))
    } else if seconds % 60 == 0 {
        format!("PT{}M", seconds / 60)
    } else {
        format!("PT{seconds}S")
    }
}

/// Read a declared duration back into seconds.
///
/// The inverse of `iso_duration`, and deliberately the same reader the
/// clients use — `BackupDuration.seconds` in onym-ios `BackupTerms.swift`
/// and its Kotlin twin. Years and months are approximated at 365 and 30
/// days, which is unfit for calendar arithmetic and exactly right for
/// the one question asked of it: how long is this declared window. The
/// alternative is refusing to compare `P1M` against `P30D` at all.
///
/// **This must not drift from the client's reader.** A grace window the
/// operator computes as shorter than the client displays is the person
/// being cut off while their screen still says they have time.
pub fn duration_seconds(value: &str) -> Option<i64> {
    // A declaration of nothing is a real, comparable window of length
    // zero — the profile requires `accessLogs: "none"`, and reading it
    // as unparseable would make "no log at all" look like a malformed
    // document rather than the strongest possible answer.
    if value == "none" {
        return Some(0);
    }
    let rest = value.strip_prefix('P')?;
    let mut total: i64 = 0;
    let mut number = String::new();
    let mut in_time = false;
    let mut saw_unit = false;
    for character in rest.chars() {
        if character == 'T' {
            in_time = true;
            continue;
        }
        if character.is_ascii_digit() {
            number.push(character);
            continue;
        }
        let magnitude: i64 = number.parse().ok()?;
        number.clear();
        saw_unit = true;
        let seconds = match (character, in_time) {
            ('Y', false) => 365 * 86_400,
            ('M', false) => 30 * 86_400,
            ('W', false) => 7 * 86_400,
            ('D', false) => 86_400,
            ('H', true) => 3_600,
            ('M', true) => 60,
            ('S', true) => 1,
            _ => return None,
        };
        total = total.checked_add(magnitude.checked_mul(seconds)?)?;
    }
    // A trailing number with no unit is malformed, not a silent zero.
    if !number.is_empty() || !saw_unit {
        return None;
    }
    Some(total)
}

fn default_terms(config: &Config, operator_key: &str) -> Value {
    json!({
        "termsVersion": 1,
        "operator": operator_key,
        "retention": {
            "class": "best-effort",
            "maximumRetentionPeriod": "until-erased",
            "snapshotsRetained": config.maximum_retained_snapshots.to_string(),
            "expiryBehavior": "notify-then-erase",
        },
        "erasure": {
            "acknowledgementDeadline": "PT1H",
            "completionDeadline": "P7D",
            "scope": "the primary copy and this operator's own backups of it",
            "excluded": "copies held by the other participants in every conversation this snapshot contains, and any copy you exported yourself",
        },
        "jurisdictions": ["EE"],
        "subProcessors": [],
        "lawfulAccess": {
            "disclosureWhatIsProduced": "sealed-bytes-and-declared-metadata-only",
            "notifyHolderWhenPermitted": true,
            "transparencyReporting": null,
        },
        "breachDisclosure": { "holderNotice": "P3D" },
        "export": { "format": "tar", "availableWhileUnpaid": true },
        "shutdownNotice": "P90D",
        "endOfPayment": {
            "notice": "P14D",
            "grace": "P30D",
            "duringGrace": ["download", "export", "erase"],
            "afterGrace": "erase",
        },
        "metadataRetention": {
            "accessLogs": "none",
            "sizeAndTiming": "while the snapshot is retained",
            "holderIdentifiers": "while any snapshot, receipt, erased reference, or live grant is held",
            "operationOutcomes": iso_duration(config.outcome_retention_secs),
            "erasureReceipts": iso_duration(config.receipt_retention_secs),
            "entitlementRecords": "to expiry plus one revocation-epoch interval",
            // How long the grant *record* outlives `expiresAt` — not
            // how long a grant lives. The partial bytes are never kept
            // past `expiresAt`. This declares the sweep interval
            // honestly rather than claiming PT0S: the record is
            // collected on a timer, so it can answer `upload_expired`
            // for up to that long before becoming
            // `upload_not_found`. Declaring zero and then holding it
            // for an hour would be the comfortable answer rather than
            // the true one.
            "uploadGrants": "PT1H",
            // What is remembered about a snapshot after its bytes are
            // gone: the reference and when it went. Something must
            // outlive the bytes or an erasure is indistinguishable from
            // a snapshot never stored — and it is bounded for the same
            // reason it exists.
            "erasedReferences": iso_duration(config.erased_reference_retention_secs),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn config() -> Config {
        Config::for_tests("onym:component:test", vec![])
    }

    fn documents() -> (Documents, SigningKey) {
        let config = config();
        let signing = SigningKey::from_bytes(&config.signing_seed);
        (Documents::build(&config, &signing).unwrap(), signing)
    }

    /// Keys sort by UTF-8 byte order, which is not the same as
    /// case-insensitive order. Today's documents cannot tell the two
    /// apart — every key is lowercase ASCII — so the fixture uses keys
    /// that can.
    /// The shape both clients parse. `ServiceOffer.decodeLossy` skips
    /// any element that is not an object carrying `offerId` and
    /// `model`, so an array of bare ids leaves a charging operator
    /// declaring no offer at all — and the failure is silent, because
    /// lossy decoding is not an error.
    #[test]
    fn published_offers_are_objects_a_client_can_decode() {
        let config = Config::for_tests("onym:component:test", vec!["onym:key:aa".into()]);
        let manifest = manifest_document(&config, "onym:key:bb", "sha256:cc");
        let offers = manifest["offers"].as_array().unwrap();
        assert_eq!(offers.len(), config.offers.len());
        assert_eq!(offers[0]["offerId"], json!(config.offers[0]));
        assert!(
            offers[0]["model"].as_str().is_some_and(|m| !m.is_empty()),
            "an offer without a model decodes to nothing"
        );
        // §10.1 still holds: nothing about what it costs.
        for key in ["price", "currency", "storefront"] {
            assert!(offers[0].get(key).is_none(), "{key} appeared in an offer");
        }
    }

    #[test]
    fn canonical_keys_sort_by_utf8_byte_order() {
        let value = json!({ "a": 1, "Z": 2, "\u{10400}": 3, "b": 4 });
        let bytes = canonical_bytes(&value, &[]).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        // 'Z' (0x5A) precedes 'a' (0x61) by byte order and follows it
        // case-insensitively; the supplementary-plane key sorts last.
        assert!(text.starts_with("{\"Z\":2,\"a\":1,\"b\":4,"), "got {text}");
        assert!(text.ends_with("\u{10400}\":3}"), "got {text}");
    }

    /// A float has no canonical decimal form, so it cannot appear in a
    /// document whose signature must round-trip byte-stably.
    #[test]
    fn floats_are_refused() {
        assert!(canonical_bytes(&json!({ "price": 1.5 }), &[]).is_err());
        assert!(canonical_bytes(&json!({ "price": 2 }), &[]).is_ok());
    }

    #[test]
    fn manifest_and_terms_verify_against_the_operator_key() {
        let (documents, signing) = documents();
        for (label, bytes, omitting) in [
            ("manifest", &documents.manifest, vec!["signature"]),
            ("terms", &documents.terms.1, vec!["termsId", "signature"]),
        ] {
            let value: Value = serde_json::from_slice(bytes).unwrap();
            let signature = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                value["signature"].as_str().unwrap(),
            )
            .unwrap();
            let signature: [u8; 64] = signature.try_into().unwrap();
            let canonical = canonical_bytes(&value, &omitting).unwrap();
            assert!(
                signing
                    .verifying_key()
                    .verify(&canonical, &ed25519_dalek::Signature::from_bytes(&signature))
                    .is_ok(),
                "{label} did not verify against the operator key"
            );
        }
    }

    /// The manifest's `declaredTerms` must be the digest of the terms
    /// actually served. A mismatch means a client verifies one document
    /// and pins another.
    #[test]
    fn declared_terms_matches_the_served_terms() {
        let (documents, _) = documents();
        let manifest: Value = serde_json::from_slice(&documents.manifest).unwrap();
        assert_eq!(manifest["declaredTerms"].as_str().unwrap(), documents.terms.0);

        let terms: Value = serde_json::from_slice(&documents.terms.1).unwrap();
        let recomputed = digest(&canonical_bytes(&terms, &["termsId", "signature"]).unwrap());
        assert_eq!(recomputed, documents.terms.0, "termsId is not a digest of its own document");
    }

    /// §15 forbids the access-log table, so the terms must not claim to
    /// keep one — the declaration and the schema have to agree.
    #[test]
    fn terms_declare_no_access_logs() {
        let (documents, _) = documents();
        let terms: Value = serde_json::from_slice(&documents.terms.1).unwrap();
        assert_eq!(terms["metadataRetention"]["accessLogs"].as_str().unwrap(), "none");
        // Every record class §15 names is declared; understating is the
        // failure that field exists to prevent.
        for class in ["sizeAndTiming", "holderIdentifiers", "operationOutcomes",
                      "erasureReceipts", "entitlementRecords"] {
            assert!(terms["metadataRetention"][class].is_string(), "{class} is not declared");
        }
    }

    #[test]
    fn terms_declare_the_configured_retention_windows() {
        let mut config = config();
        config.outcome_retention_secs = 90;
        config.receipt_retention_secs = 2 * 24 * 60 * 60;
        config.erased_reference_retention_secs = 3601;
        let signing = SigningKey::from_bytes(&config.signing_seed);
        let documents = Documents::build(&config, &signing).unwrap();
        let terms: Value = serde_json::from_slice(&documents.terms.1).unwrap();
        let retention = &terms["metadataRetention"];

        assert_eq!(retention["operationOutcomes"], "PT90S");
        assert_eq!(retention["erasureReceipts"], "P2D");
        assert_eq!(retention["erasedReferences"], "PT3601S");
        assert_eq!(
            retention["holderIdentifiers"],
            "while any snapshot, receipt, erased reference, or live grant is held"
        );
    }

    /// Erasure must name what it does not reach. An empty exclusion is
    /// not generosity, it is a claim nobody can honour.
    #[test]
    fn erasure_names_what_it_cannot_reach() {
        let (documents, _) = documents();
        let terms: Value = serde_json::from_slice(&documents.terms.1).unwrap();
        let excluded = terms["erasure"]["excluded"].as_str().unwrap();
        assert!(!excluded.trim().is_empty());
        assert!(excluded.contains("other participants"));
    }

    /// §4.1: a detached signature over **the exact served bytes**.
    ///
    /// Not over canonical bytes. The embedded `signature` covers the
    /// canonical document minus itself, so the two are different
    /// signatures over different inputs — and a verifier handed the
    /// detached one, checking it the way it would check the embedded
    /// one, would reject a perfectly valid document.
    #[test]
    fn detached_signatures_cover_the_bytes_that_are_served() {
        let (documents, signing) = documents();
        let key = signing.verifying_key();

        for (name, bytes, detached) in [
            ("manifest", &documents.manifest, &documents.manifest_signature),
            ("terms", &documents.terms.1, &documents.terms_signature),
        ] {
            let raw = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                detached,
            )
            .unwrap();
            let signature = ed25519_dalek::Signature::from_slice(&raw).unwrap();
            key.verify(bytes, &signature)
                .unwrap_or_else(|_| panic!("{name}.sig does not cover the served bytes"));

            // And it is genuinely a different signature from the
            // embedded one, which is the thing that would otherwise go
            // unnoticed.
            let embedded: Value = serde_json::from_slice(bytes).unwrap();
            assert_ne!(
                embedded["signature"].as_str().unwrap(),
                detached.as_str(),
                "{name}.sig is the embedded signature, not a detached one"
            );
        }
    }
}
