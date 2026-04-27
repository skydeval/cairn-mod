//! `tools.cairn.admin.revokeAction` handler (§F20 / #51).
//!
//! Submits a [`RevokeActionRequest`] to the writer task via the
//! `WriteCommand::RevokeAction` variant. The writer handles the
//! atomic flow: row lookup + state-check, revoked_* UPDATE,
//! strike_state recompute, hash-chained audit_log append — all
//! in one transaction.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::writer::RevokeActionRequest;

use super::common::{AdminError, AdminState, verify_and_authorize};

const LXM: &str = "tools.cairn.admin.revokeAction";

#[derive(Debug, Deserialize)]
struct Input {
    #[serde(rename = "actionId")]
    action_id: i64,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    #[serde(rename = "actionId")]
    action_id: i64,
    #[serde(rename = "revokedAt")]
    revoked_at: String,
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

    let req = RevokeActionRequest {
        action_id: input.action_id,
        revoked_by_did: admin.caller_did,
        revoked_reason: input.reason,
    };

    let revoked = match state.writer.revoke_action(req).await {
        Ok(r) => r,
        Err(Error::ActionNotFound(_)) => return AdminError::ActionNotFound.into_response(),
        Err(Error::ActionAlreadyRevoked(_)) => {
            return AdminError::ActionAlreadyRevoked.into_response();
        }
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(Output {
        action_id: revoked.action_id,
        revoked_at: revoked.revoked_at,
    })
    .into_response()
}
