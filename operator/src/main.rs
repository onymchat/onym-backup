//! Retention operator for the Onym device-backup seat.
//!
//! Implements `onym:backup-implementation:object-http-v1`
//! (`onym-system/backup/UI-Backup-Object-HTTP.md`). It authenticates an
//! Ed25519 public key, counts bytes, and can do nothing else with what
//! it holds — every snapshot arrives sealed under a key derived from
//! the holder's recovery phrase, and no code path here has any way to
//! open one.
//!
//! Two properties are structural rather than promised, and both are
//! checked by tests:
//!
//! - **There is no reset path.** A holder is a public key. No account,
//!   no email, no support identifier, no admin route — not even a
//!   token-gated one — and nothing that reassigns a snapshot's holder.
//! - **There is no access log.** Route, status, bytes and duration are
//!   logged; the holder, the digest, the upload id and the operation id
//!   are not, and none of them is aggregated per holder over time.

mod config;
mod error;
mod payload;

use std::process::exit;

use config::Config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(reason) => {
            // Fail at boot with a usage message rather than at the first
            // request with a 500 — the same posture as the moderation
            // service.
            eprintln!("configuration error: {reason}\n\n{}", Config::usage());
            exit(1);
        }
    };

    tracing::info!(
        component = %config.component_id,
        public_url = %config.public_url,
        charges = config.requires_entitlement(),
        "onym-backup-operator starting"
    );

    // Routes land in the next commit; this boots, validates, and says
    // what it is.
    let _ = config;
}
