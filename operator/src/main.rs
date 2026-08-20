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
mod uploads;
mod auth;
mod blobs;
mod config;
mod documents;
mod error;
mod payload;
mod store;
mod sweep;

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
    let blob_root = config.blob_root.clone();
    if let Err(error) = std::fs::create_dir_all(&blob_root) {
        eprintln!("could not create {blob_root}: {error}");
        exit(1);
    }
    let state = std::sync::Arc::new(api::AppState {
        config,
        documents,
        store: tokio::sync::Mutex::new(store),
        blobs: blobs::Blobs::new(blob_root),
    });

    // Reconcile before serving, then hourly. Bytes and rows are
    // written in two steps, so a crash between them leaves one without
    // the other; this deletes bytes with no row and never invents a row
    // for bytes it found. It also collects grants that expired — the
    // only bound on `incoming/` that does not depend on clients
    // finishing what they start — and spent replay nonces.
    //
    // On the blocking pool, not the runtime: it walks every holder and
    // digest under the blob root, and it takes the store lock in short
    // bursts rather than across that walk. An hourly stall of every
    // request is still a stall.
    {
        let state = state.clone();
        let skew = state.config.max_skew_secs;
        tokio::spawn(async move {
            loop {
                let state = state.clone();
                let swept = tokio::task::spawn_blocking(move || {
                    let stamp = |at: time::OffsetDateTime| {
                        at.format(&time::format_description::well_known::Rfc3339)
                    };
                    let at = time::OffsetDateTime::now_utc();
                    // Twice the skew window: it is two-sided, so a
                    // signature stamped `max_skew` ahead stays
                    // acceptable until `now + max_skew` and is live for
                    // up to 2x from first sight. Sweeping at 1x would
                    // drop it while still valid and reopen the replay
                    // the table closes.
                    let floor = at - time::Duration::seconds(skew * 2);
                    match (stamp(at), stamp(floor)) {
                        (Ok(now), Ok(floor)) => {
                            Some(sweep::reconcile(&state.store, &state.blobs, &now, &floor))
                        }
                        _ => None,
                    }
                })
                .await;

                match swept {
                    Ok(Some(swept)) => {
                        if swept.expired_grants
                            + swept.orphan_incoming
                            + swept.orphan_snapshots
                            + swept.spent_nonces
                            > 0
                        {
                            tracing::info!(
                                expired_grants = swept.expired_grants,
                                orphan_incoming = swept.orphan_incoming,
                                orphan_snapshots = swept.orphan_snapshots,
                                spent_nonces = swept.spent_nonces,
                                "swept"
                            );
                        }
                    }
                    Ok(None) => tracing::error!("could not stamp sweep"),
                    Err(error) => tracing::error!(%error, "sweep task failed"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
    }

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("could not bind {bind_addr}: {error}");
            exit(1);
        }
    };
    tracing::info!(%bind_addr, "listening");

    // `DefaultBodyLimit`, not `RequestBodyLimitLayer`. Both cap a body;
    // only the former can be raised on one route. The §9 chunk upload
    // needs its own, larger bound from the grant, and a tower layer
    // wrapping the whole router has no opt-out — the ceiling would have
    // been discovered when uploads landed and looked like a client bug.
    let app = api::router(state).layer(axum::extract::DefaultBodyLimit::max(
        api::MAX_JSON_BODY_BYTES,
    ));
    if let Err(error) = axum::serve(listener, app).await {
        tracing::error!(%error, "server stopped");
        exit(1);
    }
}
