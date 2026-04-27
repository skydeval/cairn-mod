//! `tools.cairn.admin.confirmPendingAction` handler (§F22 / #74).
//!
//! Submits a [`ConfirmPendingActionRequest`] to the writer task via
//! the `WriteCommand::ConfirmPendingAction` variant. The writer
//! handles the atomic flow: pending row load + state-check,
//! subject_actions INSERT, label emission, pending UPDATE,
//! strike-state recompute, hash-chained audit_log append — all in
//! one transaction.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::writer::ConfirmPendingActionRequest;

use super::common::{AdminError, AdminState, verify_and_authorize};

const LXM: &str = "tools.cairn.admin.confirmPendingAction";

#[derive(Debug, Deserialize)]
struct Input {
    #[serde(rename = "pendingId")]
    pending_id: i64,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    #[serde(rename = "actionId")]
    action_id: i64,
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

    let req = ConfirmPendingActionRequest {
        pending_id: input.pending_id,
        moderator_did: admin.caller_did,
        note: input.note,
    };

    let confirmed = match state.writer.confirm_pending_action(req).await {
        Ok(r) => r,
        Err(Error::PendingActionNotFound(_)) => {
            return AdminError::PendingActionNotFound.into_response();
        }
        Err(Error::PendingAlreadyResolved(_)) => {
            return AdminError::PendingAlreadyResolved.into_response();
        }
        Err(Error::SubjectTakendown(_)) => {
            return AdminError::SubjectTakendown.into_response();
        }
        Err(Error::ReasonNotFound(_)) => return AdminError::InvalidReason.into_response(),
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(Output {
        action_id: confirmed.action_id,
        pending_id: confirmed.pending_id,
        resolved_at: confirmed.resolved_at,
    })
    .into_response()
}
