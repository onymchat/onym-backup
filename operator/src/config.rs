//! Environment-driven configuration, validated once at boot with a
//! usage message rather than failing later at first request — the shape
//! `onym-moderation` and `onym-relayer` already use.

use std::collections::BTreeMap;
use std::env;

pub struct Config {
    pub bind_addr: String,
    pub store_path: String,
    /// Where sealed snapshots live. Blobs, not rows: SQLite holds the
    /// bookkeeping and the filesystem holds the bytes.
    pub blob_root: String,
    /// This operator's `onym:component:<id>`.
    pub component_id: String,
    /// Public origin, used to build the endpoint in the served
    /// manifest.
    pub public_url: String,
    /// Ed25519 seed for this operator's signing key, hex. Signs the
    /// manifest, the terms, and every erasure receipt.
    pub signing_seed: [u8; 32],

    /// Broker keys whose `SeatEntitlement` signatures this operator
    /// accepts, as `onym:key:<hex>`.
    ///
    /// **Empty means free mode**: no `402` is ever returned and no
    /// entitlement is ever consulted. That is the self-hosting path the
    /// profile requires (§4.2), and it is the same binary — entitlement
    /// enforcement is a declared capability, not a build flavour.
    pub entitlement_issuers: Vec<String>,
    /// Where the broker publishes revocation epochs.
    pub revocation_url: Option<String>,
    pub revocation_poll_secs: u64,
    /// Offer ids a `402` names, so a client knows what to buy.
    ///
    /// Ids only. §10.1 is explicit that a refusal carries no price, no
    /// currency, no storefront and no product name — pricing belongs to
    /// the frontend's channel agreement, and an operator that puts a
    /// price in a `402` is asserting terms it is not party to.
    pub offers: Vec<String>,

    pub maximum_sealed_snapshot_bytes: i64,
    pub maximum_retained_snapshots: i64,
    /// Transfer framing granted at preflight.
    pub chunk_bytes: i64,
    /// How long an uncommitted upload survives.
    pub upload_expiry_secs: i64,
    /// Freshness window for a holder's signed request, in seconds.
    pub max_skew_secs: i64,
    /// How long an operation outcome is answerable through
    /// `/v1/operations/{id}`.
    ///
    /// Declared, and short. Keeping an operation id *is* the per-holder
    /// timing trace §15 otherwise forbids; the resolution is a bound,
    /// not an exception, and it is measured in hours.
    pub outcome_retention_secs: i64,
    /// How long issued erasure receipts are re-servable. Declared in
    /// `metadataRetention.erasureReceipts`, and swept — a window
    /// nothing enforces is a window in name only.
    pub receipt_retention_secs: i64,
    /// How long an erased snapshot's reference is remembered after its
    /// bytes are gone. `list` reports `erased` and `/v1/erasures`
    /// answers `receipt_expired` only while it survives — past it, both
    /// degrade to "unknown digest", which is the operator having
    /// genuinely forgotten rather than pretending.
    pub erased_reference_retention_secs: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = env::var("BACKUP_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let store_path =
            env::var("BACKUP_STORE_PATH").unwrap_or_else(|_| "/data/backup.sqlite".into());
        let blob_root = env::var("BACKUP_BLOB_ROOT").unwrap_or_else(|_| "/data/blobs".into());

        let component_id = env::var("BACKUP_COMPONENT_ID")
            .map_err(|_| "BACKUP_COMPONENT_ID is required".to_string())?;
        if !component_id.starts_with("onym:component:") {
            return Err("BACKUP_COMPONENT_ID must look like onym:component:<id>".into());
        }

        let public_url =
            env::var("BACKUP_PUBLIC_URL").map_err(|_| "BACKUP_PUBLIC_URL is required".to_string())?;
        if !public_url.starts_with("https://") {
            // The client refuses a non-https endpoint in every build, so
            // publishing one would only produce a manifest nobody can
            // use. Better to fail at boot than to serve it.
            return Err("BACKUP_PUBLIC_URL must be https".into());
        }

        let signing_seed = parse_seed(
            &env::var("BACKUP_SIGNING_SEED")
                .map_err(|_| "BACKUP_SIGNING_SEED is required (64 hex chars)".to_string())?,
        )?;

        let entitlement_issuers = env::var("BACKUP_ENTITLEMENT_ISSUERS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        // Validated exactly as `issuer_keys` will parse it — prefix,
        // length, lowercase-hex charset, and a real curve point.
        //
        // Checking less was worse than not checking: a typo'd issuer
        // passed boot, `issuer_keys` then dropped it silently, and the
        // operator came up in paid mode with an empty trust map. Every
        // broker signature would be refused with nothing at boot having
        // said why — which is precisely what this module's
        // fail-at-boot posture exists to prevent.
        //
        // Lowercase is required for the same reason `payload::holder_key`
        // requires it: a `SeatEntitlement`'s issuer is compared exactly,
        // and a non-canonical spelling of the same key would never match.
        for issuer in &entitlement_issuers {
            issuer_key(issuer).map_err(|reason| {
                format!("BACKUP_ENTITLEMENT_ISSUERS entry {issuer}: {reason}")
            })?;
        }

        let offers: Vec<String> = env::var("BACKUP_OFFERS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect();
        // A charging operator whose refusal names no offer has told the
        // client to buy something without saying what. The payment loop
        // stops there, so it is a boot error rather than a 402 nobody
        // can act on.
        if !entitlement_issuers.is_empty() && offers.is_empty() {
            return Err("BACKUP_OFFERS is required when BACKUP_ENTITLEMENT_ISSUERS is set".into());
        }

        let revocation_url = env::var("BACKUP_REVOCATION_URL").ok().filter(|v| !v.is_empty());
        if !entitlement_issuers.is_empty() && revocation_url.is_none() {
            // Charging without a way to learn about refunds means a
            // refunded entitlement keeps working until it expires.
            return Err(
                "BACKUP_REVOCATION_URL is required when BACKUP_ENTITLEMENT_ISSUERS is set".into(),
            );
        }
        if let Some(url) = &revocation_url {
            if !url.starts_with("https://") {
                return Err("BACKUP_REVOCATION_URL must be https".into());
            }
        }

        Ok(Config {
            bind_addr,
            store_path,
            blob_root,
            component_id,
            public_url: public_url.trim_end_matches('/').to_string(),
            signing_seed,
            entitlement_issuers,
            revocation_url,
            // All positive. A zero poll interval is a busy loop, a zero
            // chunk size is an upload that never advances, and a
            // negative maximum is a limit that refuses everything — none
            // of them is a configuration someone meant.
            revocation_poll_secs: parse_positive_u64("BACKUP_REVOCATION_POLL_SECS", 900)?,
            offers,
            maximum_sealed_snapshot_bytes: parse_positive_i64(
                "BACKUP_MAX_SNAPSHOT_BYTES",
                2 * 1024 * 1024 * 1024,
            )?,
            maximum_retained_snapshots: parse_positive_i64("BACKUP_MAX_SNAPSHOTS", 3)?,
            chunk_bytes: chunk_bytes()?,
            upload_expiry_secs: parse_positive_i64("BACKUP_UPLOAD_EXPIRY_SECS", 24 * 3600)?,
            max_skew_secs: parse_past_window_secs("BACKUP_MAX_SKEW_SECS", 300, 2)?,
            receipt_retention_secs: parse_past_window_secs(
                "BACKUP_RECEIPT_RETENTION_SECS",
                365 * 24 * 3600,
                1,
            )?,
            erased_reference_retention_secs: parse_past_window_secs(
                "BACKUP_ERASED_REFERENCE_RETENTION_SECS",
                365 * 24 * 3600,
                1,
            )?,
            outcome_retention_secs: parse_past_window_secs(
                "BACKUP_OUTCOME_RETENTION_SECS",
                6 * 3600,
                1,
            )?,
        })
    }

    /// A configuration built directly, for tests.
    ///
    /// `from_env` reads process-global state, and Rust runs tests in
    /// parallel threads — so two tests setting different values race,
    /// and the first one to configure issuers can flip `charges` under
    /// another test's feet. Constructing the values is both safer and
    /// clearer about what a given test depends on.
    #[cfg(test)]
    pub fn for_tests(component_id: &str, entitlement_issuers: Vec<String>) -> Config {
        Config {
            bind_addr: "127.0.0.1:0".into(),
            store_path: ":memory:".into(),
            blob_root: "/tmp/onym-backup-tests".into(),
            component_id: component_id.into(),
            public_url: "https://backup.example".into(),
            signing_seed: [0x11; 32],
            entitlement_issuers,
            revocation_url: None,
            revocation_poll_secs: 900,
            offers: vec!["backup-monthly-v1".into()],
            maximum_sealed_snapshot_bytes: 2 * 1024 * 1024 * 1024,
            maximum_retained_snapshots: 3,
            chunk_bytes: 8 * 1024 * 1024,
            upload_expiry_secs: 24 * 3600,
            max_skew_secs: 300,
            receipt_retention_secs: 365 * 24 * 3600,
            erased_reference_retention_secs: 365 * 24 * 3600,
            outcome_retention_secs: 6 * 3600,
        }
    }

    /// True when this operator charges. Free operators never return
    /// `402` and never look at an entitlement.
    pub fn requires_entitlement(&self) -> bool {
        !self.entitlement_issuers.is_empty()
    }

    /// Where §10.1's refusal points a client to check the issuers it
    /// was told about, against a document that is signed.
    pub fn manifest_url(&self) -> String {
        format!("{}/manifest.json", self.public_url)
    }

    pub fn usage() -> &'static str {
        "\
onym-backup-operator

Required:
  BACKUP_COMPONENT_ID           onym:component:<id> for this operator
  BACKUP_PUBLIC_URL             https origin this operator is reached on
  BACKUP_SIGNING_SEED           64 hex chars; signs manifest, terms, receipts

Optional:
  BACKUP_BIND                   default 0.0.0.0:8080
  BACKUP_STORE_PATH             default /data/backup.sqlite
  BACKUP_BLOB_ROOT              default /data/blobs
  BACKUP_ENTITLEMENT_ISSUERS    comma-separated onym:key:<hex>; empty = free mode
  BACKUP_REVOCATION_URL         https; required when issuers are set
  BACKUP_REVOCATION_POLL_SECS   default 900
  BACKUP_OFFERS                 comma-separated offer ids named by a 402
  BACKUP_MAX_SNAPSHOT_BYTES     default 2 GiB
  BACKUP_MAX_SNAPSHOTS          default 3
  BACKUP_CHUNK_BYTES            default 8 MiB
  BACKUP_UPLOAD_EXPIRY_SECS     default 86400
  BACKUP_MAX_SKEW_SECS          default 300
  BACKUP_OUTCOME_RETENTION_SECS default 21600
  BACKUP_RECEIPT_RETENTION_SECS default 31536000
  BACKUP_ERASED_REFERENCE_RETENTION_SECS default 31536000
"
    }
}

fn parse_seed(hex_value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_value.trim())
        .map_err(|_| "BACKUP_SIGNING_SEED must be hex".to_string())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "BACKUP_SIGNING_SEED must be 32 bytes (64 hex chars)".to_string())?;
    Ok(bytes)
}

/// The transfer chunk size, bounded by what a request body may be.
///
/// An operator may raise `BACKUP_CHUNK_BYTES` without editing code —
/// that is the promise `MAX_CHUNK_BODY_BYTES` exists to keep. Above the
/// ceiling every non-final chunk would die at the body limit with a
/// 413, making every grant unfulfillable and the failure look like a
/// client bug. Refused at boot, where the operator can still read the
/// reason.
fn chunk_bytes() -> std::result::Result<i64, String> {
    let bytes = parse_positive_i64("BACKUP_CHUNK_BYTES", 8 * 1024 * 1024)?;
    let ceiling = crate::api::MAX_CHUNK_BODY_BYTES as i64;
    if bytes > ceiling {
        return Err(format!(
            "BACKUP_CHUNK_BYTES is {bytes}, above the {ceiling}-byte request body ceiling; \
             every non-final chunk would be refused at the body limit"
        ));
    }
    Ok(bytes)
}

fn parse_positive_i64(key: &str, default: i64) -> Result<i64, String> {
    let value: i64 = match env::var(key) {
        Err(_) => return Ok(default),
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|_| format!("{key} must be an integer"))?,
    };
    if value <= 0 {
        return Err(format!("{key} must be greater than zero"));
    }
    Ok(value)
}

/// A duration subtracted from the wall clock by the sweep.
///
/// Positivity alone is not enough: `OffsetDateTime - Duration`
/// panics outside its representable range. Refuse that configuration
/// at boot rather than letting the hourly task die and silently stop
/// enforcing every retention window.
fn parse_past_window_secs(key: &str, default: i64, multiplier: i64) -> Result<i64, String> {
    let value = parse_positive_i64(key, default)?;
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("{key} is too large"))?;
    if time::OffsetDateTime::now_utc()
        .checked_sub(time::Duration::seconds(seconds))
        .is_none()
    {
        return Err(format!(
            "{key} is too large for the supported timestamp range"
        ));
    }
    Ok(value)
}

fn parse_positive_u64(key: &str, default: u64) -> Result<u64, String> {
    let value: u64 = match env::var(key) {
        Err(_) => return Ok(default),
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|_| format!("{key} must be an integer"))?,
    };
    if value == 0 {
        return Err(format!("{key} must be greater than zero"));
    }
    Ok(value)
}

/// One `onym:key:<64 lowercase hex>` reference, parsed strictly.
///
/// The single place the rule lives, so boot validation and the trust
/// map can never drift apart — which is the bug this replaced.
pub fn issuer_key(reference: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    let hex_value = reference
        .strip_prefix("onym:key:")
        .ok_or_else(|| "must start with onym:key:".to_string())?;
    if hex_value.len() != 64 {
        return Err("key must be 64 hex characters".into());
    }
    if !hex_value
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("key must be lowercase hex".into());
    }
    let bytes = hex::decode(hex_value).map_err(|_| "key is not hex".to_string())?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| "key must be 32 bytes".to_string())?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "key is not a valid Ed25519 point".to_string())
}

/// Parsed `onym:key:<hex>` references, for verifying entitlements.
pub fn issuer_keys(references: &[String]) -> BTreeMap<String, ed25519_dalek::VerifyingKey> {
    // Every reference here has already passed `issuer_key` at boot, so
    // a failure would mean the two disagreed — which is exactly the bug
    // that made this silent-drop loop dangerous. It cannot happen now,
    // and if it ever does the entry is dropped loudly rather than
    // quietly.
    let mut keys = BTreeMap::new();
    for reference in references {
        match issuer_key(reference) {
            Ok(key) => {
                keys.insert(reference.clone(), key);
            }
            Err(reason) => {
                tracing::error!(%reference, %reason, "configured issuer failed to parse after boot validation");
            }
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MAX_CHUNK_BODY_BYTES` is a promise that an operator can raise
    /// `BACKUP_CHUNK_BYTES` without editing code. Above it, every grant
    /// would be unfulfillable and every non-final chunk would 413.
    #[test]
    fn a_chunk_size_above_the_body_ceiling_is_refused_at_boot() {
        let ceiling = crate::api::MAX_CHUNK_BODY_BYTES;
        std::env::set_var("BACKUP_CHUNK_BYTES", (ceiling + 1).to_string());
        let refused = chunk_bytes();
        std::env::set_var("BACKUP_CHUNK_BYTES", ceiling.to_string());
        let accepted = chunk_bytes();
        std::env::remove_var("BACKUP_CHUNK_BYTES");

        assert!(refused.is_err(), "an unfulfillable chunk size was accepted");
        assert_eq!(accepted.unwrap(), ceiling as i64);
    }

    #[test]
    fn an_unrepresentable_retention_window_is_refused_at_boot() {
        let key = "BACKUP_TEST_RETENTION_WINDOW_SECS";
        std::env::set_var(key, "400000000000");
        let result = parse_past_window_secs(key, 1, 1);
        std::env::remove_var(key);

        assert!(result.is_err(), "a sweep-killing duration was accepted");
        assert!(result.unwrap_err().contains("timestamp range"));
    }

    #[test]
    fn usage_names_every_retention_window() {
        let usage = Config::usage();
        for key in [
            "BACKUP_OUTCOME_RETENTION_SECS",
            "BACKUP_RECEIPT_RETENTION_SECS",
            "BACKUP_ERASED_REFERENCE_RETENTION_SECS",
        ] {
            assert!(usage.contains(key), "{key} is absent from --help");
        }
    }
}
