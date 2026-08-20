//! The broker's revocation epoch, polled on our own schedule.
//!
//! A revocation epoch is a broker-signed, publicly fetchable list of
//! the `entitlementId` values revoked and not yet expired. The operator
//! polls it; it never asks the broker about a particular holder,
//! because a per-entitlement status endpoint would let the broker
//! observe every seat-to-holder session (WHITEPAPER §17.8) while
//! telling the operator nothing the epoch does not already carry.
//!
//! **A failed poll is not a refusal.** §10.4 is explicit: the operator
//! keeps using the last good epoch. A broker outage must not delete
//! anyone's access, and the failure mode of a stale epoch is a refund
//! honoured late — which the terms' grace and the channel agreement's
//! reserve already absorb. Refusing everyone instead would convert the
//! broker's availability into ours, which is the opposite of what
//! polling an epoch is for.
//!
//! The last good epoch is cached in SQLite, not just in memory, so a
//! restart during an outage comes back with the epoch it had rather
//! than with none. An operator that forgot every revocation on reboot
//! would honour a refund and then un-honour it.

use std::collections::HashSet;
use std::sync::RwLock;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::Config;
use crate::documents::canonical_bytes;
use crate::error::{Error, Result};

/// One published epoch, verified.
#[derive(Clone)]
pub struct Epoch {
    pub epoch: i64,
    pub published_at: OffsetDateTime,
    pub revoked: HashSet<String>,
    pub raw: Vec<u8>,
}

/// The epoch in force, plus when we last managed to fetch one.
///
/// `RwLock` rather than the store mutex: every authenticated request on
/// a charging operator reads this, and making them queue behind
/// bookkeeping writes for a set membership test would be a self-
/// inflicted bottleneck.
pub struct Revocation {
    current: RwLock<Option<(Epoch, OffsetDateTime)>>,
}

impl Revocation {
    pub fn new() -> Revocation {
        Revocation {
            current: RwLock::new(None),
        }
    }

    /// The revoked set in force. Empty when no epoch has ever been
    /// obtained — which is the honest starting position of an operator
    /// that has not yet heard from its broker, and is why
    /// `BACKUP_REVOCATION_URL` is required at boot whenever issuers are
    /// configured.
    pub fn revoked(&self) -> HashSet<String> {
        match self.current.read() {
            Ok(guard) => guard
                .as_ref()
                .map(|(epoch, _)| epoch.revoked.clone())
                .unwrap_or_default(),
            // A poisoned lock means a panic while an epoch was being
            // installed. Failing closed here would refuse every paying
            // holder; failing open would ignore every revocation. The
            // empty set is the latter, so say so loudly rather than
            // letting it pass as normal operation.
            Err(_) => {
                tracing::error!("revocation cache lock poisoned; treating no id as revoked");
                HashSet::new()
            }
        }
    }

    /// Replace the epoch in force. Older epochs are ignored: a
    /// re-published stale document must not un-revoke anything.
    pub fn install(&self, epoch: Epoch, fetched_at: OffsetDateTime) -> bool {
        let Ok(mut guard) = self.current.write() else {
            tracing::error!("revocation cache lock poisoned; epoch not installed");
            return false;
        };
        if let Some((held, _)) = guard.as_ref() {
            if held.epoch > epoch.epoch {
                return false;
            }
        }
        *guard = Some((epoch, fetched_at));
        true
    }

    /// What `/health` publishes: the epoch in force and how old our
    /// copy is. §4.1 requires staleness to be visible, because the
    /// maximum revocation latency an operator can honestly claim is its
    /// poll interval plus the broker's epoch interval — and a stuck
    /// poller silently widens that.
    pub fn health(&self, config: &Config, now: OffsetDateTime) -> Value {
        if !config.requires_entitlement() {
            return Value::Null;
        }
        let guard = match self.current.read() {
            Ok(guard) => guard,
            Err(_) => return serde_json::json!({ "status": "unreadable" }),
        };
        let Some((epoch, fetched_at)) = guard.as_ref() else {
            // Never fetched. Distinct from a stale epoch, and worse:
            // the operator is honouring no revocations at all.
            return serde_json::json!({
                "status": "never_fetched",
                "pollIntervalSeconds": config.revocation_poll_secs,
            });
        };
        let age = (now - *fetched_at).whole_seconds().max(0);
        serde_json::json!({
            // Two intervals, not one: a single missed poll is a retry,
            // not a fault, and alerting on it would train an operator
            // to ignore the signal.
            "status": if age > 2 * config.revocation_poll_secs as i64 { "stale" } else { "current" },
            "epoch": epoch.epoch,
            "publishedAt": epoch.published_at.format(&Rfc3339).unwrap_or_default(),
            "fetchedAt": fetched_at.format(&Rfc3339).unwrap_or_default(),
            "ageSeconds": age,
            "pollIntervalSeconds": config.revocation_poll_secs,
            "revokedCount": epoch.revoked.len(),
        })
    }
}

impl Default for Revocation {
    fn default() -> Revocation {
        Revocation::new()
    }
}

/// Parse and verify a published epoch.
///
/// Verified against the same issuers pinned for entitlements: an epoch
/// signed by anyone else is not this broker's revocation list, and
/// accepting one would let a third party un-revoke — or revoke —
/// whatever it liked. An unverifiable epoch is not an epoch.
pub fn parse(raw: &[u8], config: &Config) -> Result<Epoch> {
    let malformed = || Error::Internal("revocation epoch did not verify".into());

    let document: Value = serde_json::from_slice(raw).map_err(|_| malformed())?;
    let object = document.as_object().ok_or_else(malformed)?;

    let signature = {
        use base64::Engine;
        let encoded = object
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| malformed())?;
        let bytes: [u8; 64] = bytes.try_into().map_err(|_| malformed())?;
        ed25519_dalek::Signature::from_bytes(&bytes)
    };
    let signed = canonical_bytes(&document, &["signature"])?;

    // Any pinned issuer may have signed it. An operator that accepts
    // entitlements from two brokers accepts epochs from both.
    let keys = crate::config::issuer_keys(&config.entitlement_issuers);
    let verified = keys.values().any(|key| {
        use ed25519_dalek::Verifier;
        key.verify(&signed, &signature).is_ok()
    });
    if !verified {
        return Err(malformed());
    }

    let epoch = object
        .get("epoch")
        .and_then(Value::as_i64)
        .ok_or_else(malformed)?;
    let published_at = object
        .get("publishedAt")
        .and_then(Value::as_str)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .ok_or_else(malformed)?;
    let revoked = object
        .get("revoked")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(Epoch {
        epoch,
        published_at,
        revoked,
        raw: raw.to_vec(),
    })
}

/// Fetch the current epoch once.
///
/// Separate from the loop so a caller can poll at boot and report the
/// outcome, and so the loop has nothing in it but timing.
pub async fn fetch(client: &reqwest::Client, url: &str, config: &Config) -> Result<Epoch> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Internal(format!("fetch revocation epoch: {e}")))?;
    if !response.status().is_success() {
        return Err(Error::Internal(format!(
            "revocation epoch: HTTP {}",
            response.status()
        )));
    }
    let raw = response
        .bytes()
        .await
        .map_err(|e| Error::Internal(format!("read revocation epoch: {e}")))?;
    parse(&raw, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn broker() -> (SigningKey, Config) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let issuer = format!(
            "onym:key:{}",
            hex::encode(signing.verifying_key().as_bytes())
        );
        (signing, Config::for_tests("onym:component:test", vec![issuer]))
    }

    fn epoch_bytes(signing: &SigningKey, epoch: i64, revoked: &[&str]) -> Vec<u8> {
        let document = json!({
            "epoch": epoch,
            "publishedAt": "2026-08-01T00:00:00Z",
            "revoked": revoked,
        });
        let signed = canonical_bytes(&document, &[]).unwrap();
        let signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing.sign(&signed).to_bytes(),
        );
        let mut document = document;
        document["signature"] = json!(signature);
        serde_json::to_vec(&document).unwrap()
    }

    #[test]
    fn a_broker_signed_epoch_verifies() {
        let (signing, config) = broker();
        let raw = epoch_bytes(&signing, 4, &["ent-1", "ent-2"]);
        let epoch = parse(&raw, &config).unwrap();
        assert_eq!(epoch.epoch, 4);
        assert!(epoch.revoked.contains("ent-1"));
    }

    /// The check that matters: an epoch is only an epoch if *this*
    /// broker signed it. Otherwise anyone could publish a document that
    /// un-revokes a refunded entitlement.
    #[test]
    fn an_epoch_signed_by_anyone_else_is_refused() {
        let (_, config) = broker();
        let impostor = SigningKey::from_bytes(&[8u8; 32]);
        let raw = epoch_bytes(&impostor, 4, &["ent-1"]);
        assert!(parse(&raw, &config).is_err());
    }

    #[test]
    fn a_mutated_epoch_is_refused() {
        let (signing, config) = broker();
        let raw = epoch_bytes(&signing, 4, &["ent-1"]);
        let mut document: Value = serde_json::from_slice(&raw).unwrap();
        document["revoked"] = json!([]);
        let mutated = serde_json::to_vec(&document).unwrap();
        assert!(
            parse(&mutated, &config).is_err(),
            "a revocation was removed without breaking the signature"
        );
    }

    /// A re-published older epoch must not un-revoke anything.
    #[test]
    fn an_older_epoch_does_not_displace_a_newer_one() {
        let (signing, config) = broker();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let cache = Revocation::new();

        let newer = parse(&epoch_bytes(&signing, 9, &["ent-1"]), &config).unwrap();
        assert!(cache.install(newer, now));
        let older = parse(&epoch_bytes(&signing, 8, &[]), &config).unwrap();
        assert!(!cache.install(older, now));

        assert!(
            cache.revoked().contains("ent-1"),
            "a stale epoch un-revoked an id"
        );
    }

    #[test]
    fn health_reports_staleness_rather_than_hiding_it() {
        let (signing, config) = broker();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let cache = Revocation::new();

        assert_eq!(
            cache.health(&config, now)["status"],
            json!("never_fetched"),
            "an operator that never reached its broker claimed to be current"
        );

        let epoch = parse(&epoch_bytes(&signing, 1, &[]), &config).unwrap();
        cache.install(epoch, now);
        assert_eq!(cache.health(&config, now)["status"], json!("current"));

        let later = now + time::Duration::seconds(3 * config.revocation_poll_secs as i64);
        assert_eq!(cache.health(&config, later)["status"], json!("stale"));
    }

    /// A free operator has no broker, so there is no staleness to
    /// report and reporting one would be an invented dependency.
    #[test]
    fn a_free_operator_reports_no_epoch() {
        let config = Config::for_tests("onym:component:test", vec![]);
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert_eq!(Revocation::new().health(&config, now), Value::Null);
    }
}
