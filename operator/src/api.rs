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
use axum::routing::get;
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

pub struct AppState {
    pub config: Config,
    pub documents: Documents,
    pub store: tokio::sync::Mutex<Store>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/manifest.json", get(manifest))
        .route("/profile.json", get(profile))
        .route("/terms/:terms_file", get(terms))
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
    let requested = terms_file
        .strip_suffix(".json")
        .ok_or(Error::NotFound(Resource::Terms))?;
    let (current_id, bytes) = &state.documents.terms;
    let current_hex = current_id.strip_prefix("sha256:").unwrap_or(current_id);
    if requested != current_hex {
        // Historical terms are served from disk in a later slice; they
        // must outlive any single boot, because a retained snapshot
        // pins one.
        return Err(Error::NotFound(Resource::Terms));
    }
    Ok(json_document(bytes.clone()))
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

    fn state() -> Arc<AppState> {
        let config = Config::for_tests("onym:component:test", vec![]);
        let signing = ed25519_dalek::SigningKey::from_bytes(&config.signing_seed);
        let documents = Documents::build(&config, &signing).unwrap();
        Arc::new(AppState {
            config,
            documents,
            store: tokio::sync::Mutex::new(Store::in_memory().unwrap()),
        })
    }

    async fn get_status(path: &str) -> StatusCode {
        router(state())
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
        let state = state();
        let hex = state.documents.terms.0.strip_prefix("sha256:").unwrap().to_string();
        assert_eq!(get_status(&format!("/terms/{hex}.json")).await, StatusCode::OK);
    }

    /// A request for terms we do not hold is a 404, never a redirect to
    /// the current ones. Substituting would hand back a document the
    /// caller's snapshot never pinned.
    #[tokio::test]
    async fn unknown_terms_are_not_substituted() {
        let response = router(state())
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
        for path in [
            "/admin",
            "/v1/admin",
            "/v1/holders",
            "/v1/holders/reset",
            "/v1/snapshots/reassign",
            "/internal",
            "/debug",
        ] {
            assert_eq!(
                get_status(path).await,
                StatusCode::NOT_FOUND,
                "{path} answered — an administrative surface appeared"
            );
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
        let sources: [(&str, &str); 6] = [
            ("api", include_str!("api.rs")),
            ("config", include_str!("config.rs")),
            ("documents", include_str!("documents.rs")),
            ("error", include_str!("error.rs")),
            ("payload", include_str!("payload.rs")),
            ("store", include_str!("store.rs")),
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
