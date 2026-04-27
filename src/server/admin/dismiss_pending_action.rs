//! `tools.cairn.admin.dismissPendingAction` handler (§F22 / #75).
//!
//! Submits a [`DismissPendingActionRequest`] to the writer task via
//! the `WriteCommand::DismissPendingAction` variant. The writer
//! handles the atomic flow: pending row load + state-check, UPDATE
//! to `resolution='dismissed'`, hash-chained audit_log append —
//! all in one transaction. No subject_actions row, no label
//! emission, no strike-state change.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::writer::DismissPendingActionRequest;

use super::common::{AdminError, AdminState, verify_and_authorize};

const LXM: &str = "tools.cairn.admin.dismissPendingAction";

#[derive(Debug, Deserialize)]
struct Input {
    #[serde(rename = "pendingId")]
    pending_id: i64,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    #[serde(rename = "pendingId")]
    pending_id: i64,
    #[serde(rename = "resolvedAt")]
    resolved_at: String,
}

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let admin = match verify_and_authorize(&state, &headers, LXM).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let input: Input = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return AdminError::InvalidRequest("malformed request body").into_response(),
    };

    let req = DismissPendingActionRequest {
        pending_id: input.pending_id,
        moderator_did: admin.caller_did,
        reason: input.reason,
    };

    let dismissed = match state.writer.dismiss_pending_action(req).await {
        Ok(r) => r,
        Err(Error::PendingActionNotFound(_)) => {
            return AdminError::PendingActionNotFound.into_response();
        }
        Err(Error::PendingAlreadyResolved(_)) => {
            return AdminError::PendingAlreadyResolved.into_response();
        }
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(Output {
        pending_id: dismissed.pending_id,
        resolved_at: dismissed.resolved_at,
    })
    .into_response()
}
