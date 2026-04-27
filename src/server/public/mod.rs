//! `tools.cairn.public.*` handlers (#54).
//!
//! User-facing read endpoints. Authentication is the same ATProto
//! service-auth flow used for admin endpoints, but authorization is
//! "you can only ask about yourself" — the verified JWT `iss` IS
//! the subject. There is no `subject` parameter on these endpoints
//! by design; if you want to query someone else's state, that's
//! `tools.cairn.admin.*` and requires Mod or Admin role.
//!
//! CORS posture differs from admin: public endpoints are intended
//! for browser-side AppView callers and similar, so allow any
//! origin (mirrors `com.atproto.label.queryLabels` from §F3).
//! Admin endpoints reject any `Origin` header outright.
//!
//! Initial endpoint:
//! - `tools.cairn.public.getMyStrikeState` — returns the calling
//!   DID's strike state, same wire shape as
//!   `tools.cairn.admin.getSubjectStrikes` via the shared
//!   `crate::server::strike_state` projection.
//!
//! Future user-facing endpoints (e.g., `getMyActionHistory` in
//! v1.5+) follow the same pattern.

use std::sync::Arc;

use axum::Extension;
use axum::Router;
use axum::http::Method;
use axum::routing::get;
use sqlx::{Pool, Sqlite};
use tower_http::cors::{Any, CorsLayer};

use crate::auth::AuthContext;

mod common;
mod get_my_strike_state;

use common::PublicState;

/// Build a Router exposing the `tools.cairn.public.*` endpoints.
/// Compose alongside `admin_router` and the public-label routers in
/// `serve::run`.
///
/// `strike_policy` is the resolved v1.4 `[strike_policy]` (#48);
/// the public strikes endpoint consults the threshold + decay
/// window when projecting the wire envelope. Pass the same instance
/// the writer task and admin router hold — `serve::run` resolves
/// once at startup and clones to each router.
pub fn public_router(
    pool: Pool<Sqlite>,
    auth: Arc<AuthContext>,
    strike_policy: crate::moderation::policy::StrikePolicy,
) -> Router {
    let state = PublicState {
        pool,
        auth,
        strike_policy: Arc::new(strike_policy),
    };
    // §F3-style CORS: allow any origin for browser-side callers.
    // Public endpoints are intended for AppView / web-client use;
    // unlike admin (which rejects browsers entirely), public
    // exposes the calling DID's own state and so is browser-safe.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::OPTIONS]);
    Router::new()
        .route(
            "/xrpc/tools.cairn.public.getMyStrikeState",
            get(get_my_strike_state::handler),
        )
        .layer(cors)
        .layer(Extension(state))
}
