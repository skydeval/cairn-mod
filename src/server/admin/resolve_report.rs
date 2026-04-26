//! `tools.cairn.admin.resolveReport` handler.
//!
//! Submits a [`ResolveReportRequest`] to the writer task via the
//! new `WriteCommand::ResolveReport` variant. The writer handles
//! the full atomic flow per the resolveReport lexicon's
//! "atomic-transaction requirement" (§F12) — label INSERT +
//! audit(label_applied) + report UPDATE + audit(report_resolved)
//! all commit together or not at all.
//!
//! This handler's only added responsibilities:
//!
//! - pre-check (auth + role + CORS),
//! - body parse,
//! - `applyLabel.val` allowlist check against [`AdminConfig`]
//!   *before* dispatching to the writer — fails fast without
//!   allocating a seq, and keeps the anti-leak error message
//!   local to this handler (same pattern as `applyLabel`),
//! - map [`Error::ReportNotFound`] / [`Error::ReportAlreadyResolved`]
//!   to lexicon-declared errors.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::error::Error;
use crate::writer::{ApplyLabelInline, ResolutionAction, ResolveReportRequest};

use super::common::{AdminError, AdminState, verify_and_authorize};
use super::report_view::{ReportDetail, project_for_fetch};

const LXM: &str = "tools.cairn.admin.resolveReport";

#[derive(Debug, Deserialize)]
struct Input {
    id: i64,
    #[serde(rename = "applyLabel", default)]
    apply_label: Option<InputApplyLabel>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InputApplyLabel {
    uri: String,
    #[serde(default)]
    cid: Option<String>,
    val: String,
    #[serde(default)]
    exp: Option<String>,
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
        Ok(i) => i,
        Err(_) => return AdminError::InvalidRequest("malformed request body").into_response(),
    };

    // Pre-check label-value allowlist BEFORE dispatch. Failing here
    // means we don't even start the writer transaction — no seq
    // allocated, no audit rows written. This is the atomicity
    // guarantee asserted by the tests: validation rejects bad input
    // before any state mutation.
    if let Some(apply) = &input.apply_label {
        if apply.val.is_empty() || apply.val.len() > 128 {
            return AdminError::InvalidRequest("applyLabel.val must be 1..=128 bytes")
                .into_response();
        }
        if !apply.uri.starts_with("at://") && !apply.uri.starts_with("did:") {
            return AdminError::InvalidRequest("applyLabel.uri must be at:// or did:")
                .into_response();
        }
        if let Some(allowed) = &state.config.label_values
            && !allowed.contains(&apply.val)
        {
            return AdminError::InvalidLabelValue.into_response();
        }
    }

    // Wire shape stays `applyLabel: Option<…>`; the typed enum is
    // internal — `None → Dismiss`, `Some(_) → ApplyLabel(_)` (#27).
    let action = match input.apply_label {
        None => ResolutionAction::Dismiss,
        Some(a) => ResolutionAction::ApplyLabel(ApplyLabelInline {
            uri: a.uri,
            cid: a.cid,
            val: a.val,
            exp: a.exp,
        }),
    };
    let writer_req = ResolveReportRequest {
        actor_did: admin.caller_did,
        report_id: input.id,
        action,
        resolution_reason: input.reason,
    };

    let resolved = match state.writer.resolve_report(writer_req).await {
        Ok(r) => r,
        Err(Error::ReportNotFound { .. }) => {
            return AdminError::ReportNotFound.into_response();
        }
        // §A (confirmed last turn): double-resolve → InvalidRequest.
        // Generic message; no timestamps or resolver DID leaked.
        Err(Error::ReportAlreadyResolved { .. }) => {
            return AdminError::InvalidRequest("report already resolved").into_response();
        }
        Err(_) => return AdminError::Internal.into_response(),
    };

    let out: ReportDetail = project_for_fetch(resolved.report);
    Json(out).into_response()
}
