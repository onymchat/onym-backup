//! One error type, mapped to the contract vocabulary of
//! `UI-Backup-Object-HTTP.md` §14 and to a status code.
//!
//! The mapping is the API. A client reads `error` and decides what to
//! do; the status code is for proxies and logs. Where §14 pins extra
//! top-level fields for a code, they travel in `detail` — a client
//! cannot act on `terms_changed` without `currentTermsId`, and cannot
//! act on `payment_required` without knowing which offer to buy.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

/// What a 404 is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Snapshot,
    Upload,
    Operation,
    Terms,
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Resource::Snapshot => "snapshot",
            Resource::Upload => "upload",
            Resource::Operation => "operation",
            Resource::Terms => "terms",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// **This text reaches the client.** Unlike `Internal`, a
    /// `BadRequest` message is echoed verbatim, so callers must keep it
    /// holder-safe: a field name and what was wrong with it, never a
    /// path, a query, or another holder's data.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Proof of possession failed, was stale, or was replayed.
    #[error("signature invalid")]
    SignatureInvalid,

    /// The client pinned terms that are no longer current. Carries the
    /// digest it should re-present, because stopping without saying
    /// which terms to read is a dead end.
    #[error("terms changed")]
    TermsChanged { current_terms_id: String },

    /// No valid entitlement. Carries the offer and the issuers, and
    /// deliberately no price — pricing belongs to the frontend's
    /// channel agreement, not to an operator's refusal (§10.1).
    #[error("payment required")]
    PaymentRequired {
        component_id: String,
        offers: Vec<String>,
        entitlement_issuers: Vec<String>,
    },

    /// An entitlement was presented and refused.
    #[error("invalid entitlement")]
    InvalidEntitlement { entitlement_issuers: Vec<String> },

    #[error("snapshot too large")]
    SnapshotTooLarge { maximum_sealed_snapshot_bytes: i64 },

    #[error("quota exceeded")]
    QuotaExceeded {
        retained_snapshots: i64,
        maximum_retained_snapshots: i64,
        retained_bytes: i64,
        limit_bytes: i64,
    },

    /// A chunk index was re-sent with different bytes.
    #[error("chunk mismatch")]
    ChunkMismatch,

    /// Commit recomputed a digest that disagrees with the reference.
    #[error("digest mismatch")]
    DigestMismatch,

    /// Names what was not found. The §9 routes 404 for uploads and
    /// operations as well as snapshots, and a client branching on
    /// `snapshot_not_found` would misread those — worth typing before
    /// the vocabulary is depended on rather than after.
    #[error("{0} not found")]
    NotFound(Resource),

    /// Held once; no longer held.
    #[error("retention expired")]
    RetentionExpired,

    /// `{0}` matters: without it `thiserror` generates a `Display` that
    /// discards the payload, and the log below — which formats with
    /// `%self` — records the literal "internal error" for every
    /// failure. That is the one class where the text is the whole
    /// value: a stringified `rusqlite::Error` naming a constraint, a
    /// path, a filename. It is logged here and never returned.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// The contract code, which is what a client actually branches on.
    pub fn code(&self) -> &'static str {
        match self {
            Error::BadRequest(_) => "bad_request",
            Error::SignatureInvalid => "signature_invalid",
            Error::TermsChanged { .. } => "terms_changed",
            Error::PaymentRequired { .. } => "payment_required",
            Error::InvalidEntitlement { .. } => "invalid_entitlement",
            Error::SnapshotTooLarge { .. } => "snapshot_too_large",
            Error::QuotaExceeded { .. } => "quota_exceeded",
            Error::ChunkMismatch => "chunk_mismatch",
            Error::DigestMismatch => "digest_mismatch",
            Error::NotFound(Resource::Snapshot) => "snapshot_not_found",
            Error::NotFound(Resource::Upload) => "upload_not_found",
            Error::NotFound(Resource::Operation) => "operation_not_found",
            Error::NotFound(Resource::Terms) => "terms_not_found",
            Error::RetentionExpired => "retention_expired",
            Error::Internal(_) => "internal_error",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            Error::SignatureInvalid | Error::InvalidEntitlement { .. } => StatusCode::UNAUTHORIZED,
            Error::TermsChanged { .. }
            | Error::QuotaExceeded { .. }
            | Error::ChunkMismatch
            | Error::DigestMismatch => StatusCode::CONFLICT,
            Error::PaymentRequired { .. } => StatusCode::PAYMENT_REQUIRED,
            Error::SnapshotTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::RetentionExpired => StatusCode::GONE,
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The per-code fields §14 pins, merged into the response body.
    fn detail(&self) -> Value {
        match self {
            Error::TermsChanged { current_terms_id } => json!({
                "currentTermsId": current_terms_id,
            }),
            Error::PaymentRequired {
                component_id,
                offers,
                entitlement_issuers,
            } => json!({
                "paymentRequired": {
                    "version": 1,
                    "componentId": component_id,
                    "offers": offers,
                    "entitlementIssuers": entitlement_issuers,
                }
            }),
            Error::InvalidEntitlement {
                entitlement_issuers,
            } => json!({ "entitlementIssuers": entitlement_issuers }),
            Error::SnapshotTooLarge {
                maximum_sealed_snapshot_bytes,
            } => json!({ "maximumSealedSnapshotBytes": maximum_sealed_snapshot_bytes }),
            Error::QuotaExceeded {
                retained_snapshots,
                maximum_retained_snapshots,
                retained_bytes,
                limit_bytes,
            } => json!({
                "retainedSnapshots": retained_snapshots,
                "maximumRetainedSnapshots": maximum_retained_snapshots,
                "retainedBytes": retained_bytes,
                "limitBytes": limit_bytes,
            }),
            _ => json!({}),
        }
    }

    /// What a client is told. Deliberately not the `Display` text for
    /// internal errors: those can carry a path, a SQL fragment, or a
    /// filename, and none of that is a holder's business.
    fn message(&self) -> String {
        match self {
            Error::Internal(_) => "the operator could not complete the request".into(),
            other => other.to_string(),
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Error::Internal(error.to_string())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            // The operand of the log is the internal text; the response
            // never carries it.
            tracing::error!(code = self.code(), error = %self, "request failed");
        } else {
            tracing::warn!(code = self.code(), "request refused");
        }

        let mut body = json!({ "error": self.code(), "message": self.message() });
        if let (Some(body), Some(detail)) = (body.as_object_mut(), self.detail().as_object()) {
            for (key, value) in detail {
                body.insert(key.clone(), value.clone());
            }
        }
        (status, axum::Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
