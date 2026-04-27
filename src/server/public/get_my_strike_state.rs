//! `tools.cairn.public.getMyStrikeState` handler (#54).
//!
//! Verifies the ATProto service-auth JWT, extracts the verified
//! `iss` (the caller's DID), and returns that subject's strike
//! state via the shared
//! [`crate::server::strike_state::build_strike_state_view`].
//!
//! Authorization is self-identity: the verified `iss` IS the
//! subject. There is no `subject` parameter on this endpoint by
//! design — querying someone else's state requires Mod or Admin
//! role on `tools.cairn.admin.getSubjectStrikes`.
//!
//! Error semantics match the admin endpoint:
//! - 401 `AuthenticationRequired` when the JWT is absent or
//!   invalid.
//! - 404 `SubjectNotFound` when the caller has no actions
//!   recorded — same "exists vs filtered-empty" distinction as
//!   admin's surface.

use std::time::SystemTime;

use axum::Extension;
use axum::Json;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use super::common::{PublicError, PublicState, verify_caller};
use crate::server::strike_state::{build_strike_state_view, subject_has_history};

const LXM: &str = "tools.cairn.public.getMyStrikeState";

pub(super) async fn handler(
    Extension(state): Extension<PublicState>,
    headers: HeaderMap,
) -> Response {
    let caller_did = match verify_caller(&state, &headers, LXM).await {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };

    match subject_has_history(&state.pool, &caller_did).await {
        Ok(true) => {}
        Ok(false) => return PublicError::SubjectNotFound.into_response(),
        Err(_) => return PublicError::Internal.into_response(),
    }

    let view = match build_strike_state_view(
        &state.pool,
        &caller_did,
        &state.strike_policy,
        SystemTime::now(),
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return PublicError::Internal.into_response(),
    };

    Json(view).into_response()
}
