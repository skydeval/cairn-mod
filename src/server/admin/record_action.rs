//! `tools.cairn.admin.recordAction` handler (§F20 / #51).
//!
//! Submits a [`RecordActionRequest`] to the writer task via the
//! `WriteCommand::RecordAction` variant. The writer handles the
//! atomic flow: input validation, strike calculation via the v1.4
//! calculators (#48/#49/#50/#51), subject_actions INSERT,
//! strike_state UPSERT, and hash-chained audit_log append — all
//! in one transaction.
//!
//! This handler's added responsibilities:
//!
//! - pre-check (auth + role + CORS) via shared scaffolding,
//! - lexicon-aligned body parse,
//! - parse the wire `type` string into [`ActionType`] (lexicon
//!   `knownValues` is advisory; the SQL CHECK is the durable
//!   source of truth and we map through the same Rust enum),
//! - map writer-side errors to lexicon-declared error codes.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::moderation::types::ActionType;
use crate::writer::RecordActionRequest;

use super::common::{AdminError, AdminState, verify_and_authorize};

const LXM: &str = "tools.cairn.admin.recordAction";

#[derive(Debug, Deserialize)]
struct Input {
    subject: String,
    #[serde(rename = "type")]
    action_type: String,
    reasons: Vec<String>,
    #[serde(default)]
    duration: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(rename = "reportIds", default)]
    report_ids: Vec<i64>,
}

#[derive(Debug, Serialize)]
struct Output {
    #[serde(rename = "actionId")]
    action_id: i64,
    #[serde(rename = "strikeValueBase")]
    strike_value_base: u32,
    #[serde(rename = "strikeValueApplied")]
    strike_value_applied: u32,
    #[serde(rename = "wasDampened")]
    was_dampened: bool,
    #[serde(rename = "strikesAtTimeOfAction")]
    strikes_at_time_of_action: u32,
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

    // Surface-level shape validation. Things the writer would
    // fail on but more friendly to reject pre-dispatch with a
    // precise message.
    if input.reasons.is_empty() {
        return AdminError::InvalidRequest("reasons must be non-empty").into_response();
    }
    if !input.subject.starts_with("did:") && !input.subject.starts_with("at://") {
        return AdminError::InvalidRequest("subject must be a DID or at:// URI").into_response();
    }
    let action_type = match ActionType::from_db_str(&input.action_type) {
        Some(t) => t,
        None => return AdminError::InvalidActionType.into_response(),
    };

    let req = RecordActionRequest {
        subject: input.subject,
        actor_did: admin.caller_did,
        action_type,
        reason_codes: input.reasons,
        duration_iso: input.duration,
        notes: input.note,
        report_ids: input.report_ids,
    };

    let recorded = match state.writer.record_action(req).await {
        Ok(r) => r,
        Err(Error::ReasonNotFound(_)) => return AdminError::InvalidReason.into_response(),
        Err(Error::DurationRequiredForTempSuspension) => {
            return AdminError::DurationRequired.into_response();
        }
        Err(Error::DurationOnlyForTempSuspension) => {
            return AdminError::DurationNotAllowed.into_response();
        }
        Err(Error::SubjectUriMismatch) => {
            return AdminError::SubjectUriMismatch.into_response();
        }
        // Generic Signing errors from the writer (route_subject,
        // duration parser, JSON serialization) surface as
        // InvalidRequest so the operator sees what failed without
        // a 500.
        Err(Error::Signing(msg)) => {
            return AdminError::InvalidRequestOwned(msg).into_response();
        }
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(Output {
        action_id: recorded.action_id,
        strike_value_base: recorded.strike_value_base,
        strike_value_applied: recorded.strike_value_applied,
        was_dampened: recorded.was_dampened,
        strikes_at_time_of_action: recorded.strikes_at_time_of_action,
    })
    .into_response()
}
