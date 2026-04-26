//! `tools.cairn.admin.retentionSweep` handler (§F4).
//!
//! Operator-initiated retention sweep. Wraps
//! [`WriterHandle::sweep`] so the actual deletes go through the
//! single-writer task (§F5 invariant), then writes one audit_log
//! row with `action = retention_sweep`, `actor_did = JWT iss`,
//! and a JSON `reason` capturing the sweep result. The scheduled-
//! fire path does NOT audit (§F4 + Q6/D2); only this admin path
//! does, so operator-initiated maintenance is reconstruction-
//! friendly.
//!
//! Admin-role-only — `mod` role gets 403 (§F12 role-based
//! authorization). The endpoint takes no input; the cutoff is
//! the writer's configured `retention_days`.

use axum::Extension;
use axum::Json;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::writer::{SweepRequest, build_retention_sweep_audit_reason};

use super::common::{AdminError, AdminState, verify_and_authorize_admin_only};

const LXM: &str = "tools.cairn.admin.retentionSweep";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    rows_deleted: i64,
    batches: u64,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    retention_days_applied: Option<u32>,
}

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
) -> Response {
    let admin = match verify_and_authorize_admin_only(&state, &headers, LXM).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let result = match state.writer.sweep(SweepRequest).await {
        Ok(r) => r,
        Err(_) => return AdminError::Internal.into_response(),
    };

    // Audit row — operator-initiated path only. Scheduled fires
    // skip the audit per Q6/D2; tracing logs cover their
    // observability.
    //
    // Routes through the writer task via WriterHandle::append_audit
    // (#39): the sweep itself ran through the writer above, so its
    // post-sweep audit row goes through the same task to keep all
    // in-process audit appenders consistently routed. Cross-process
    // CLI callers (publish/unpublish-service-record) use
    // append_via_pool instead.
    //
    // `target` is NULL — the sweep doesn't act on a single subject.
    // listAuditLog renders it as such. The reason JSON carries the
    // actionable detail.
    let now_ms = crate::writer::epoch_ms_now();
    let reason = build_retention_sweep_audit_reason(&result);
    if state
        .writer
        .append_audit(crate::audit::append::AuditRowForAppend {
            created_at: now_ms,
            action: "retention_sweep".into(),
            actor_did: admin.caller_did.clone(),
            target: None,
            target_cid: None,
            outcome: "success".into(),
            reason: Some(reason),
        })
        .await
        .is_err()
    {
        return AdminError::Internal.into_response();
    }

    Json(Output {
        rows_deleted: result.rows_deleted,
        batches: result.batches,
        duration_ms: result.duration_ms,
        retention_days_applied: result.retention_days_applied,
    })
    .into_response()
}
