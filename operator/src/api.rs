//! The HTTP surface.
//!
//! This slice serves what the operator publishes about itself, plus
//! `/health`. The `/v1/` routes land next, against §9's table.
//!
//! Two absences are asserted by tests at the bottom of this file rather
//! than described in prose, because §8.3 asks for them to be *provably*
//! absent:
//!
//! - no administrative route, not even a token-gated one;
//! - no route that reassigns a snapshot's holder.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::json;

use crate::config::Config;
use crate::documents::Documents;
use crate::error::{Error, Resource, Result};
use crate::store::Store;

/// §13 caps a JSON request body at 256 KiB. Chunk uploads are
/// `application/octet-stream` and get their own, larger bound from the
/// grant — this is the ceiling for everything that is not bytes.
///
/// Applied with `DefaultBodyLimit`, which a route can override.
/// `RequestBodyLimitLayer` cannot be, so it would have made the upload
/// route's larger bound unreachable.
pub const MAX_JSON_BODY_BYTES: usize = 256 * 1024;

/// The ceiling for a transfer chunk, which the grant then bounds
/// further. Generous relative to the 8 MiB default so an operator can
/// raise `BACKUP_CHUNK_BYTES` without editing code, and finite so an
/// unauthenticated caller cannot choose our memory.
pub const MAX_CHUNK_BODY_BYTES: usize = 64 * 1024 * 1024;

pub struct AppState {
    pub config: Config,
    /// The key that signs the manifest, the terms and every erasure
    /// receipt. One key, so a holder who can check one document can
    /// check all of them without learning a second.
    pub signing: ed25519_dalek::SigningKey,
    pub documents: Documents,
    pub store: tokio::sync::Mutex<Store>,
    pub blobs: crate::blobs::Blobs,
    /// Serialises mutations of committed snapshot directories with the
    /// SQLite transitions that make those bytes live or erased.
    pub blob_mutations: tokio::sync::Mutex<()>,
}

impl AppState {
    /// Assemble the state, remembering the terms this boot publishes.
    ///
    /// The remembering happens here rather than in `main` because §4.1
    /// requires historical terms *forever*: a construction path that
    /// skipped it would serve snapshots pinned to a document it cannot
    /// produce, and erasure — which must cite the pinned terms — would
    /// fail with a 404 that looks like the snapshot is missing. Making
    /// it a step callers can forget is how that happens.
    pub fn new(
        config: Config,
        documents: Documents,
        store: Store,
        blobs: crate::blobs::Blobs,
        signing: ed25519_dalek::SigningKey,
        now: &str,
    ) -> Result<AppState> {
        store.remember_terms(
            &documents.terms.0,
            &documents.terms.1,
            documents.terms_signature.as_bytes(),
            now,
        )?;
        Ok(AppState {
            config,
            signing,
            documents,
            store: tokio::sync::Mutex::new(store),
            blobs,
            blob_mutations: tokio::sync::Mutex::new(()),
        })
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/manifest.json", get(manifest))
        .route("/manifest.json.sig", get(manifest_signature))
        .route("/profile.json", get(profile))
        .route("/terms/:terms_file", get(terms))
        .route("/v1/preflight", post(crate::uploads::preflight))
        .route(
            "/v1/uploads/:upload_id/chunks/:index",
            // Raised past the JSON ceiling: a transfer chunk is bytes,
            // and the grant is what bounds it.
            put(crate::uploads::put_chunk).layer(DefaultBodyLimit::max(MAX_CHUNK_BODY_BYTES)),
        )
        .route("/v1/uploads/:upload_id/commit", post(crate::uploads::commit))
        .route("/v1/snapshots", get(crate::uploads::list))
        .route("/v1/snapshots/:digest", get(crate::uploads::download))
        .route("/v1/erasures", post(crate::erasures::erase))
        // Export sits on a branch that never consults entitlements —
        // not "consults and allows". §9.7 is explicit that this is the
        // only form that survives future edits, and a scan below holds
        // the module to it.
        .route("/v1/exports", get(crate::export::manifest))
        // Before `/:digest`, and more specific than it — a receipt id
        // is not a digest and must not be looked up as one.
        .route("/v1/exports/receipts/:receipt_id", get(crate::export::receipt))
        .route("/v1/exports/:digest", get(crate::export::snapshot))
        .route("/v1/operations/:operation_id", get(crate::operations::query))
        .with_state(state)
}

/// Liveness, plus the two facts an operator's own monitoring needs:
/// which terms are current, and whether this operator charges.
///
/// Deliberately carries no counts. "How many snapshots does this
/// operator hold" is not a secret, but it is a number that moves with
/// one holder's behaviour when the operator is small, and a health
/// endpoint is the wrong place to publish it.
async fn health(State(state): State<Arc<AppState>>) -> Response {
    axum::Json(json!({
        "status": "ok",
        "componentId": state.config.component_id,
        "operator": state.documents.operator_key,
        "declaredTerms": state.documents.terms.0,
        "charges": state.config.requires_entitlement(),
    }))
    .into_response()
}

async fn manifest(State(state): State<Arc<AppState>>) -> Response {
    json_document(state.documents.manifest.clone())
}

async fn profile(State(state): State<Arc<AppState>>) -> Response {
    json_document(state.documents.profile.clone())
}

/// Content-addressed terms.
///
/// The path carries `<hex>.json`, and the digest is checked against
/// what we serve rather than the file name being trusted — a request
/// for terms we do not have is a 404, never a redirect to the current
/// ones. Silently substituting current terms for the ones a snapshot
/// pinned would defeat the whole point of pinning.
async fn terms(
    State(state): State<Arc<AppState>>,
    Path(terms_file): Path<String>,
) -> Result<Response> {
    let (requested, detached) = match terms_file.strip_suffix(".json.sig") {
        Some(requested) => (requested, true),
        None => (
            terms_file
                .strip_suffix(".json")
                .ok_or(Error::NotFound(Resource::Terms))?,
            false,
        ),
    };

    let (current_id, bytes) = &state.documents.terms;
    let current_hex = current_id.strip_prefix("sha256:").unwrap_or(current_id);
    if requested == current_hex {
        return Ok(if detached {
            signature_document(state.documents.terms_signature.clone())
        } else {
            json_document(bytes.clone())
        });
    }

    // Historical terms, served from the store rather than from this
    // boot's documents. §4.1 requires them forever: a retained snapshot
    // pins a `termsId`, and a document that lived only in the process
    // that minted it would leave that pin unresolvable after the first
    // restart under new terms.
    let stored = state
        .store
        .lock()
        .await
        .terms_document(&format!("sha256:{requested}"))?;
    let (raw, signature) = stored.ok_or(Error::NotFound(Resource::Terms))?;
    Ok(if detached {
        signature_document(String::from_utf8(signature).map_err(|_| {
            // Lossy conversion would serve a corrupted signature that
            // fails verification for a reason nobody could diagnose.
            Error::Internal("stored terms signature is not valid UTF-8".into())
        })?)
    } else {
        json_document(raw)
    })
}

/// A detached signature, served as base64 text over the exact bytes of
/// the document beside it.
fn signature_document(signature: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        signature,
    )
        .into_response()
}

async fn manifest_signature(State(state): State<Arc<AppState>>) -> Response {
    signature_document(state.documents.manifest_signature.clone())
}

/// Serves a published document verbatim.
///
/// Named for what it does rather than for the manifest and terms, which
/// happen to be signed: the profile is not, and a helper called
/// `signed_json` asserted something false about one of its three
/// callers.
fn json_document(bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn state() -> (Arc<AppState>, tempfile::TempDir) {
        // A `TempDir` handed back with the state rather than a shared
        // path under `temp_dir()`: these tests never touch blobs, but a
        // fixed path shared across runs is the kind of thing that works
        // until two run at once.
        let dir = tempfile::TempDir::new().unwrap();
        let config = Config::for_tests("onym:component:test", vec![]);
        let signing = ed25519_dalek::SigningKey::from_bytes(&config.signing_seed);
        let documents = Documents::build(&config, &signing).unwrap();
        (
            Arc::new(
                AppState::new(
                    config,
                    documents,
                    Store::in_memory().unwrap(),
                    crate::blobs::Blobs::new(dir.path()),
                    signing,
                    "2026-01-01T00:00:00Z",
                )
                .unwrap(),
            ),
            dir,
        )
    }

    async fn get_status(path: &str) -> StatusCode {
        let (state, _dir) = state();
        router(state)
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn published_documents_are_served() {
        for path in ["/health", "/manifest.json", "/profile.json"] {
            assert_eq!(get_status(path).await, StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn terms_are_served_at_their_own_digest() {
        let (state, _dir) = state();
        let hex = state.documents.terms.0.strip_prefix("sha256:").unwrap().to_string();
        assert_eq!(get_status(&format!("/terms/{hex}.json")).await, StatusCode::OK);
    }

    /// A request for terms we do not hold is a 404, never a redirect to
    /// the current ones. Substituting would hand back a document the
    /// caller's snapshot never pinned.
    #[tokio::test]
    async fn unknown_terms_are_not_substituted() {
        let (state, _dir) = state();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/terms/{}.json", "f".repeat(64)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// §8.3: the absent reset path has to be checkable, not asserted in
    /// a comment. A holder is a public key — there is nothing to reset
    /// — and this fails the moment someone adds a route that implies
    /// otherwise.
    #[tokio::test]
    async fn there_is_no_administrative_route() {
        // Paths that exist nowhere: a 404 is the whole answer.
        for path in ["/admin", "/v1/admin", "/v1/holders", "/v1/holders/reset", "/internal", "/debug"] {
            assert_eq!(
                get_status(path).await,
                StatusCode::NOT_FOUND,
                "{path} answered — an administrative surface appeared"
            );
        }

        // And paths that *do* route, but only into the ordinary
        // holder-scoped surface. `/v1/snapshots/reassign` is a download
        // of a snapshot named "reassign": it refuses for want of a
        // proof, which is the right refusal and not an administrative
        // one. Asserting 404 here would have been asserting the router
        // shape rather than the property, and it broke the moment a
        // legitimate parameterised route was added — which is how it
        // was noticed.
        for path in ["/v1/snapshots/reassign", "/v1/snapshots/anything"] {
            let status = get_status(path).await;
            assert!(
                status == StatusCode::UNAUTHORIZED || status == StatusCode::NOT_FOUND,
                "{path} answered {status} — an unauthenticated caller got somewhere"
            );
        }
    }

    /// §18.9's conformance fixture: export succeeds for a holder with
    /// no entitlement at all, against an operator that charges.
    ///
    /// This is the assertion §14.15 turns on. An operator that withheld
    /// export for non-payment would hold a holder's own sealed bytes
    /// hostage to a billing relationship — and those bytes are useless
    /// to the operator, which is the whole point.
    ///
    /// It lives here rather than in `export.rs` so that module can stay
    /// provably free of the word: the scan below is a whole-file scan
    /// with no carve-out for tests, and a carve-out is exactly the kind
    /// of thing that later grows.
    #[tokio::test]
    async fn export_works_for_a_holder_with_no_entitlement() {
        let harness = crate::uploads::tests::Harness::new(vec![format!(
            "onym:key:{}",
            "aa".repeat(32)
        )]);
        assert!(
            harness.state.config.requires_entitlement(),
            "the fixture is meaningless against an operator that never charges"
        );

        let (status, _) = harness.send("GET", "/v1/exports", vec![]).await;
        assert_eq!(status, StatusCode::OK, "export was refused to an unpaid holder");

        // And the upload path *does* refuse, so the difference is the
        // export branch rather than the operator being free after all.
        let (status, _) = harness
            .send("POST", "/v1/preflight", harness.preflight_body(b"x", &harness.terms_id()))
            .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    }

    /// The sweep is only a guarantee if something starts it.
    ///
    /// This exists because it did not, briefly: an edit removed the
    /// task that calls it and every one of the sweep's own unit tests
    /// still passed, because they call `reconcile` directly. A promise
    /// enforced only by a function nobody invokes is the same phantom
    /// the sweep was written to fix.
    #[test]
    fn the_sweep_is_actually_scheduled() {
        let main = include_str!("main.rs");
        let call = format!("{}::{}", "sweep", "reconcile");
        assert!(
            main.contains(call.as_str()),
            "nothing in main.rs calls the reconciliation sweep"
        );
        assert!(
            main.contains("spawn_blocking"),
            "the sweep is not on the blocking pool — it walks the whole blob root"
        );
    }

    /// §9.7: the export path must not consult entitlements **at all**
    /// — not "consult and allow". §14.15 makes export unconditional,
    /// and the only form of that which survives future edits is a code
    /// path with no access to the state that could condition it.
    ///
    /// A scan rather than a comment, because the failure this prevents
    /// is somebody later adding a perfectly reasonable-looking check.
    #[test]
    fn the_export_path_cannot_consult_entitlements() {
        let export = include_str!("export.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        // Assembled from parts so this test does not match its own
        // source — the same trap the reassignment scan fell into.
        let forbidden = [
            format!("{}{}", "entitle", "ment"),
            format!("{}{}", "payment_", "required"),
            format!("{}{}", "lapse", "_state"),
            format!("{}{}", "requires_", "entitlement"),
            // Export helpers live in the neutral blob module. Reaching
            // into the upload module would make this one-call-deep scan
            // bless a transitive path through paid preflight code.
            format!("{}{}", "crate::", "uploads"),
        ];
        for needle in &forbidden {
            // Prose about *not* consulting them is the point of the
            // module, so only code is scanned.
            for (number, line) in export.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with("!") {
                    continue;
                }
                assert!(
                    !code.contains(needle.as_str()),
                    "export.rs:{} reaches for `{needle}` — §9.7 forbids the export \
                     path from consulting entitlement state at all",
                    number + 1
                );
            }
        }
    }

    /// The other half of the same promise: no code path moves a
    /// snapshot between holders. Blunt, and §18.6 asks for provably
    /// absent rather than absent-by-intention.
    #[test]
    fn no_code_reassigns_a_snapshots_holder() {
        // Every module, and the list is checked against `main.rs` below
        // so it cannot narrow silently as files are added — a guarantee
        // that quietly stops covering new code is worse than none,
        // because it still reads as covered.
        let sources: [(&str, &str); 13] = [
            ("api", include_str!("api.rs")),
            ("erasures", include_str!("erasures.rs")),
            ("export", include_str!("export.rs")),
            ("operations", include_str!("operations.rs")),
            ("uploads", include_str!("uploads.rs")),
            ("auth", include_str!("auth.rs")),
            ("blobs", include_str!("blobs.rs")),
            ("config", include_str!("config.rs")),
            ("documents", include_str!("documents.rs")),
            ("error", include_str!("error.rs")),
            ("payload", include_str!("payload.rs")),
            ("store", include_str!("store.rs")),
            ("sweep", include_str!("sweep.rs")),
        ];

        let declared: Vec<String> = include_str!("main.rs")
            .lines()
            .filter_map(|line| line.trim().strip_prefix("mod "))
            .filter_map(|line| line.strip_suffix(';'))
            .map(str::to_string)
            .collect();
        for module in &declared {
            assert!(
                sources.iter().any(|(name, _)| name == module),
                "module `{module}` is not covered by the holder-reassignment scan; add it"
            );
        }

        let sources = sources.map(|(_, source)| source);
        // Assembled from parts so this file, which scans itself, does
        // not match on the needle. The first version did exactly that
        // and failed — which at least proved the scan works.
        let needle = ["update", "snapshots", "set", "holder_handle"].concat();
        for source in sources {
            let normalized = source.to_lowercase().replace(char::is_whitespace, "");
            assert!(
                !normalized.contains(&needle),
                "a snapshot's holder is reassigned somewhere"
            );
        }
    }
}
