//! `tools.cairn.admin.negateLabel` handler.
//!
//! Shell over [`WriterHandle::negate_label`] (#4). Declared custom
//! error `LabelNotFound` (§F6) when no currently-applied label
//! exists for the tuple.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::writer::NegateLabelRequest;

use super::common::{AdminError, AdminState, verify_and_authorize};

const LXM: &str = "tools.cairn.admin.negateLabel";

#[derive(Debug, Deserialize)]
struct Input {
    uri: String,
    val: String,
    #[serde(default)]
    #[allow(dead_code)]
    cid: Option<String>,
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

    if input.val.is_empty() || input.val.len() > 128 {
        return AdminError::InvalidRequest("val must be 1..=128 bytes").into_response();
    }

    let event = match state
        .writer
        .negate_label(NegateLabelRequest {
            actor_did: admin.caller_did,
            uri: input.uri,
            val: input.val,
            moderator_reason: input.reason,
        })
        .await
    {
        Ok(e) => e,
        // §F6: LabelNotFound maps from the writer's LabelNotFound
        // variant; everything else is an internal error surfaced
        // generically.
        Err(Error::LabelNotFound { .. }) => return AdminError::LabelNotFound.into_response(),
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(Output {
        seq: event.seq,
        cts: event.label.cts,
    })
    .into_response()
}
