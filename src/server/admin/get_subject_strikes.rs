//! `tools.cairn.admin.getSubjectStrikes` handler (#52 / read-half
//! of #53).
//!
//! Verifies admin auth + role, looks up the subject DID from the
//! query string, then delegates to the shared
//! [`crate::server::strike_state`] module for the actual
//! computation + projection. Public-tier
//! `tools.cairn.public.getMyStrikeState` (#54) shares that same
//! projection so the two endpoints can never drift on field shape.
//!
//! See [`crate::server::strike_state`] for the cache-bypass
//! invariant + `decayWindowRemainingDays` semantics.

use std::time::SystemTime;

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use super::common::{AdminError, AdminState, verify_and_authorize};
use crate::server::strike_state::{build_strike_state_view, subject_has_history};

const LXM: &str = "tools.cairn.admin.getSubjectStrikes";

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(e) = verify_and_authorize(&state, &headers, LXM).await {
        return e.into_response();
    }

    let subject = match parse_subject(query.as_deref().unwrap_or("")) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    match subject_has_history(&state.pool, &subject).await {
        Ok(true) => {}
        Ok(false) => return AdminError::SubjectNotFound.into_response(),
        Err(_) => return AdminError::Internal.into_response(),
    }

    let view = match build_strike_state_view(
        &state.pool,
        &subject,
        &state.config.service_did,
        &state.strike_policy,
        SystemTime::now(),
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(view).into_response()
}

fn parse_subject(raw: &str) -> Result<String, AdminError> {
    let mut subject: Option<String> = None;
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        if k == "subject" && !v.is_empty() {
            subject = Some(v.into_owned());
        }
    }
    let subject = subject.ok_or(AdminError::InvalidRequest("subject is required"))?;
    if !subject.starts_with("did:") {
        return Err(AdminError::InvalidRequest("subject must be a DID"));
    }
    Ok(subject)
}
