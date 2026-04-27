//! Scaffolding shared across `tools.cairn.public.*` handlers (#54).
//! Mirrors [`super::super::admin::common`] but with two differences:
//!
//! 1. **No role lookup.** Public endpoints authorize by self-
//!    identity (the verified `iss` IS the subject); the
//!    `moderators` table is not consulted.
//! 2. **No CORS rejection.** CORS is handled at the router layer
//!    via `tower_http::cors::CorsLayer::allow_origin(Any)` —
//!    public endpoints are browser-safe by design.
//!
//! Error taxonomy is also slimmer because there's no role
//! distinction or admin-style validation surface.

use std::sync::Arc;

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{Pool, Sqlite};

use crate::auth::AuthContext;
use crate::moderation::policy::StrikePolicy;

/// Shared state every public handler receives via `Extension`.
#[derive(Clone)]
pub(super) struct PublicState {
    pub pool: Pool<Sqlite>,
    pub auth: Arc<AuthContext>,
    /// Resolved [strike_policy] (#48); read by the strikes endpoint
    /// for `decay_window_days` etc. Same instance the writer task
    /// + admin router hold.
    pub strike_policy: Arc<StrikePolicy>,
    /// Cairn-mod's labeler DID. Mirrors `Config::service_did` and
    /// `AdminConfig::service_did`. Used by the strikes endpoint
    /// (#65) to scope `labels.src` when computing active_labels.
    pub service_did: String,
}

/// Error taxonomy for `tools.cairn.public.*` handlers. The
/// `IntoResponse` impl produces the XRPC-convention body
/// `{ "error": "<Name>", "message": "<generic>" }`.
#[derive(Debug)]
pub(super) enum PublicError {
    /// 401: the request had no Bearer token, the token failed
    /// verification, or the JWT was malformed.
    AuthenticationRequired,
    /// 404: the calling DID has never been actioned. Declared in
    /// `lexicons/tools/cairn/public/getMyStrikeState.json`.
    SubjectNotFound,
    /// 500: DB error or other internal failure.
    Internal,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: &'static str,
}

impl IntoResponse for PublicError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            PublicError::AuthenticationRequired => (
                StatusCode::UNAUTHORIZED,
                ErrorBody {
                    error: "AuthenticationRequired",
                    message: "authentication required",
                },
            ),
            PublicError::SubjectNotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "SubjectNotFound",
                    message: "no actions recorded for caller",
                },
            ),
            PublicError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "InternalServerError",
                    message: "service temporarily unavailable",
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

/// Verify the ATProto service-auth JWT and return the verified
/// `iss` (the caller's DID). Same JWT verification as
/// [`super::super::admin::common::verify_and_authorize`], minus the
/// CORS-block on `Origin` and minus the role lookup. Public
/// endpoints authorize by self-identity: the caller's `iss` IS
/// the subject, so there's nothing more to check.
pub(super) async fn verify_caller(
    state: &PublicState,
    headers: &HeaderMap,
    lxm: &str,
) -> Result<String, PublicError> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(PublicError::AuthenticationRequired)?;
    let caller = state
        .auth
        .verify_service_auth(token, lxm)
        .await
        .map_err(|_| PublicError::AuthenticationRequired)?;
    Ok(caller.iss)
}
