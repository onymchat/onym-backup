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

mod api;
mod config;
mod documents;
mod error;
mod payload;
mod store;

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

    let signing = ed25519_dalek::SigningKey::from_bytes(&config.signing_seed);
    let documents = match documents::Documents::build(&config, &signing) {
        Ok(documents) => documents,
        Err(error) => {
            eprintln!("could not build published documents: {error}");
            exit(1);
        }
    };
    tracing::info!(
        operator = %documents.operator_key,
        terms = %documents.terms.0,
        "published documents signed"
    );

    let store = match store::Store::open(&config.store_path) {
        Ok(store) => store,
        Err(error) => {
            // Failing here rather than serving: an operator that cannot
            // write its bookkeeping would accept snapshots it has no
            // record of, which is worse than being down.
            eprintln!("could not open {}: {error}", config.store_path);
            exit(1);
        }
    };

    let bind_addr = config.bind_addr.clone();
    let state = std::sync::Arc::new(api::AppState {
        config,
        documents,
        store: tokio::sync::Mutex::new(store),
    });

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("could not bind {bind_addr}: {error}");
            exit(1);
        }
    };
    tracing::info!(%bind_addr, "listening");

    // Bodies are capped here as well as per-route: an unbounded body is
    // memory an unauthenticated caller chooses for us.
    let app = api::router(state).layer(tower_http::limit::RequestBodyLimitLayer::new(
        api::MAX_JSON_BODY_BYTES,
    ));
    if let Err(error) = axum::serve(listener, app).await {
        tracing::error!(%error, "server stopped");
        exit(1);
    }
}
