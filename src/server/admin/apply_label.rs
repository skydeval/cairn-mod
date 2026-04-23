//! `tools.cairn.admin.applyLabel` handler.
//!
//! Thin shell over [`WriterHandle::apply_label`] (#4). The handler's
//! only added responsibility is:
//!
//! - pre-check (auth + role + CORS) via shared scaffolding,
//! - lexicon-aligned body parse,
//! - `val` allowlist check against operator config (§F12
//!   `InvalidLabelValue`) — message must NOT enumerate the allowed
//!   set.
//!
//! All sequence allocation, cts monotonicity clamping, signing,
//! audit_log writing, and broadcast happen inside the writer task
//! per §F5.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::writer::ApplyLabelRequest;

use super::common::{AdminError, AdminState, verify_and_authorize};

const LXM: &str = "tools.cairn.admin.applyLabel";

#[derive(Debug, Deserialize)]
struct Input {
    uri: String,
    #[serde(default)]
    cid: Option<String>,
    val: String,
    #[serde(default)]
    exp: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    seq: i64,
    cts: String,
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

    // §6.1 schema CHECK enforces val ≤ 128 bytes at INSERT time but
    // it's cheaper to reject before allocating a seq and running
    // through the writer task.
    if input.val.is_empty() || input.val.len() > 128 {
        return AdminError::InvalidRequest("val must be 1..=128 bytes").into_response();
    }
    if !input.uri.starts_with("at://") && !input.uri.starts_with("did:") {
        return AdminError::InvalidRequest("uri must be at:// or did:").into_response();
    }

    // §F12 InvalidLabelValue. When the operator has configured a
    // declared set in AdminConfig.label_values, the value must be
    // in it. When the option is None, accept any val (for ops that
    // haven't restricted their set yet — the restriction is purely
    // additive operational hygiene, not a protocol requirement).
    if let Some(allowed) = &state.config.label_values
        && !allowed.contains(&input.val)
    {
        return AdminError::InvalidLabelValue.into_response();
    }

    let event = match state
        .writer
        .apply_label(ApplyLabelRequest {
            actor_did: admin.caller_did,
            uri: input.uri,
            cid: input.cid,
            val: input.val,
            exp: input.exp,
            moderator_reason: input.reason,
        })
        .await
    {
        Ok(e) => e,
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(Output {
        seq: event.seq,
        cts: event.label.cts,
    })
    .into_response()
}
