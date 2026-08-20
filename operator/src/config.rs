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
        for issuer in &entitlement_issuers {
            if !issuer.starts_with("onym:key:") || issuer.len() != "onym:key:".len() + 64 {
                return Err(format!(
                    "BACKUP_ENTITLEMENT_ISSUERS entry is not onym:key:<64 hex>: {issuer}"
                ));
            }
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
            revocation_poll_secs: parse_u64("BACKUP_REVOCATION_POLL_SECS", 900)?,
            maximum_sealed_snapshot_bytes: parse_i64(
                "BACKUP_MAX_SNAPSHOT_BYTES",
                2 * 1024 * 1024 * 1024,
            )?,
            maximum_retained_snapshots: parse_i64("BACKUP_MAX_SNAPSHOTS", 3)?,
            chunk_bytes: parse_i64("BACKUP_CHUNK_BYTES", 8 * 1024 * 1024)?,
            upload_expiry_secs: parse_i64("BACKUP_UPLOAD_EXPIRY_SECS", 24 * 3600)?,
            max_skew_secs: parse_i64("BACKUP_MAX_SKEW_SECS", 300)?,
            outcome_retention_secs: parse_i64("BACKUP_OUTCOME_RETENTION_SECS", 6 * 3600)?,
        })
    }

    /// True when this operator charges. Free operators never return
    /// `402` and never look at an entitlement.
    pub fn requires_entitlement(&self) -> bool {
        !self.entitlement_issuers.is_empty()
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
  BACKUP_MAX_SNAPSHOT_BYTES     default 2 GiB
  BACKUP_MAX_SNAPSHOTS          default 3
  BACKUP_CHUNK_BYTES            default 8 MiB
  BACKUP_UPLOAD_EXPIRY_SECS     default 86400
  BACKUP_MAX_SKEW_SECS          default 300
  BACKUP_OUTCOME_RETENTION_SECS default 21600
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

fn parse_i64(key: &str, default: i64) -> Result<i64, String> {
    match env::var(key) {
        Err(_) => Ok(default),
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|_| format!("{key} must be an integer")),
    }
}

fn parse_u64(key: &str, default: u64) -> Result<u64, String> {
    match env::var(key) {
        Err(_) => Ok(default),
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|_| format!("{key} must be an integer")),
    }
}

/// Parsed `onym:key:<hex>` references, for verifying entitlements.
pub fn issuer_keys(references: &[String]) -> BTreeMap<String, ed25519_dalek::VerifyingKey> {
    let mut keys = BTreeMap::new();
    for reference in references {
        let Some(hex_value) = reference.strip_prefix("onym:key:") else {
            continue;
        };
        let Ok(bytes) = hex::decode(hex_value) else {
            continue;
        };
        let Ok(bytes): std::result::Result<[u8; 32], _> = bytes.try_into() else {
            continue;
        };
        if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&bytes) {
            keys.insert(reference.clone(), key);
        }
    }
    keys
}
