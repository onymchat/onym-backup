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
mod entitlements;
mod erasures;
mod error;
mod export;
mod lapse;
mod operations;
mod payload;
mod revocation;
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
    let now = match time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
    {
        Ok(now) => now,
        Err(error) => {
            eprintln!("could not stamp boot: {error}");
            exit(1);
        }
    };
    let state = match api::AppState::new(
        config,
        documents,
        store,
        blobs::Blobs::new(blob_root),
        signing,
        &now,
    ) {
        Ok(state) => std::sync::Arc::new(state),
        Err(error) => {
            eprintln!("could not assemble operator state: {error}");
            exit(1);
        }
    };

    // The revocation epoch, before serving and then on its own
    // schedule. Two rules from §10.4 shape this:
    //
    // - **A failed poll is not a refusal.** The last good epoch stays
    //   in force. A broker outage must not delete anyone's access, and
    //   the failure mode of a stale epoch is a refund honoured late —
    //   which the terms' grace already absorbs. Staleness is published
    //   in `/health` rather than converted into 402s.
    // - **The cache survives a restart.** An operator that forgot every
    //   revocation on reboot would honour a refund and then un-honour
    //   it, so the epoch in force is read back from SQLite at boot.
    if let Some(url) = state.config.revocation_url.clone() {
        {
            let store = state.store.lock().await;
            match store.latest_epoch() {
                Ok(Some((document, fetched_at))) => {
                    match (
                        revocation::parse(&document, &state.config),
                        time::OffsetDateTime::parse(
                            &fetched_at,
                            &time::format_description::well_known::Rfc3339,
                        ),
                    ) {
                        (Ok(epoch), Ok(at)) => {
                            let number = epoch.epoch;
                            state.revocation.install(epoch, at);
                            tracing::info!(epoch = number, "revocation epoch restored from cache");
                        }
                        _ => tracing::warn!("cached revocation epoch did not verify; ignoring"),
                    }
                }
                Ok(None) => tracing::info!("no cached revocation epoch"),
                Err(error) => tracing::warn!(%error, "could not read cached revocation epoch"),
            }
        }

        let state = state.clone();
        let interval = state.config.revocation_poll_secs;
        tokio::spawn(async move {
            let client = match reqwest::Client::builder()
                // Bounded so a hung broker cannot pin this task
                // forever. Well under the poll interval, so a slow
                // fetch is abandoned rather than overlapping the next.
                .timeout(std::time::Duration::from_secs(30))
                .build()
            {
                Ok(client) => client,
                Err(error) => {
                    tracing::error!(%error, "could not build revocation client");
                    return;
                }
            };
            loop {
                match revocation::fetch(&client, &url, &state.config).await {
                    Ok(epoch) => {
                        let number = epoch.epoch;
                        let revoked = epoch.revoked.len();
                        let at = time::OffsetDateTime::now_utc();
                        let document = epoch.raw.clone();
                        if state.revocation.install(epoch, at) {
                            let stamp = at
                                .format(&time::format_description::well_known::Rfc3339)
                                .unwrap_or_default();
                            let store = state.store.lock().await;
                            if let Err(error) = store.cache_epoch(number, &stamp, &document) {
                                tracing::warn!(%error, "could not cache revocation epoch");
                            }
                            tracing::info!(epoch = number, revoked, "revocation epoch installed");
                        }
                    }
                    // Warn, never refuse. The operator keeps serving on
                    // the epoch it has.
                    Err(error) => tracing::warn!(%error, "revocation poll failed; keeping last good epoch"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        });
    }

    // Reconcile before serving, then hourly. Bytes and rows are
    // written in two steps, so a crash between them leaves one without
    // the other; this deletes bytes with no row and never invents a row
    // for bytes it found. It also collects expired grants — the only
    // bound on `incoming/` that does not depend on clients finishing
    // what they start — spent replay nonces, and aged outcome records.
    //
    // On the blocking pool, not the runtime: it walks every holder and
    // digest under the blob root, and it takes the store lock in short
    // bursts rather than across that walk. An hourly stall of every
    // request is still a stall.
    {
        let state = state.clone();
        let skew = state.config.max_skew_secs;
        let outcome_window = state.config.outcome_retention_secs;
        let receipt_window = state.config.receipt_retention_secs;
        let erased_window = state.config.erased_reference_retention_secs;
        // The entitlement floor is not a constant, so it is computed
        // per sweep by `lapse::record_floor` from the terms this
        // operator has published: expiry, plus the longest declared
        // notice-and-grace, plus this interval. All three terms are in
        // the `metadataRetention.entitlementRecords` declaration, and
        // the reason for the middle one is that the record is what
        // lapse is derived from — see `lapse::record_floor`.
        let poll_interval = state.config.revocation_poll_secs as i64;
        tokio::spawn(async move {
            loop {
                let state = state.clone();
                let swept = tokio::task::spawn_blocking(move || {
                    let stamp = |at: time::OffsetDateTime| {
                        at.format(&time::format_description::well_known::Rfc3339)
                    };
                    let at = time::OffsetDateTime::now_utc();
                    // Reads the published terms, so it needs the lock —
                    // taken and released before `reconcile` takes it
                    // again, the same short-burst discipline the sweep
                    // itself follows.
                    let entitlement_floor = match lapse::record_floor(
                        &state.store.blocking_lock(),
                        poll_interval,
                        at,
                    ) {
                        Ok(floor) => floor,
                        Err(error) => {
                            // Skip the sweep rather than fall back to a
                            // shorter floor: a guessed floor deletes the
                            // records lapse is derived from, and one
                            // missed hour of tidying is recoverable
                            // where that is not.
                            tracing::warn!(%error, "could not compute the entitlement record floor");
                            return None;
                        }
                    };
                    // Twice the skew window: it is two-sided, so a
                    // signature stamped `max_skew` ahead stays
                    // acceptable until `now + max_skew` and is live for
                    // up to 2x from first sight. Sweeping at 1x would
                    // drop it while still valid and reopen the replay
                    // the table closes.
                    let stamped = (|| {
                        let floor =
                            at.checked_sub(time::Duration::seconds(skew.checked_mul(2)?))?;
                        let outcomes = at.checked_sub(time::Duration::seconds(outcome_window))?;
                        let receipts = at.checked_sub(time::Duration::seconds(receipt_window))?;
                        let erased = at.checked_sub(time::Duration::seconds(erased_window))?;
                        Some((
                            stamp(at).ok()?,
                            stamp(floor).ok()?,
                            stamp(outcomes).ok()?,
                            stamp(receipts).ok()?,
                            stamp(erased).ok()?,
                            stamp(entitlement_floor).ok()?,
                        ))
                    })();
                    stamped.map(|(now, floor, outcomes, receipts, erased, entitlements)| {
                        sweep::reconcile(
                            &state.store,
                            &state.blob_mutations,
                            &state.blobs,
                            &state.revocation.revoked(),
                            at,
                            sweep::Cutoffs {
                                now: &now,
                                nonce: &floor,
                                outcome: &outcomes,
                                receipt: &receipts,
                                erased_reference: &erased,
                                entitlement: &entitlements,
                            },
                        )
                    })
                })
                .await;

                match swept {
                    Ok(Some(swept)) => {
                        if swept.post_grace_snapshots
                            + swept.aged_entitlements
                            + swept.expired_grants
                            + swept.orphan_incoming
                            + swept.orphan_snapshots
                            + swept.unavailable_snapshots
                            + swept.spent_nonces
                            + swept.aged_outcomes
                            + swept.aged_receipts
                            + swept.forgotten_references
                            > 0
                        {
                            tracing::info!(
                                post_grace_snapshots = swept.post_grace_snapshots,
                                aged_entitlements = swept.aged_entitlements,
                                expired_grants = swept.expired_grants,
                                orphan_incoming = swept.orphan_incoming,
                                orphan_snapshots = swept.orphan_snapshots,
                                unavailable_snapshots = swept.unavailable_snapshots,
                                spent_nonces = swept.spent_nonces,
                                aged_outcomes = swept.aged_outcomes,
                                aged_receipts = swept.aged_receipts,
                                forgotten_references = swept.forgotten_references,
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
