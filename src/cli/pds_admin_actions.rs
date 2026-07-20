//! `cairn pds-admin {accounts, blobs, reports, appeals, emails,
//! subjects}` action subcommands (v1.8.5, v4 §4.6 / chainlink #134).
//!
//! All ten verbs route through v1.8.2's `recordAction` writer
//! convention (R1 LB-G, Path A): the CLI posts
//! `tools.cairn.admin.recordAction` with the verb's `action_type`
//! plus a variant-specific `detail` payload; the writer owns the
//! `subject_actions` INSERT, the post-commit backend dispatch, and
//! the `pds_admin_audit` outcome row (including the v1.8.5
//! `ActionResponse` persistence columns from migration 0010). No
//! `--precipitating-action-id` flag exists — the writer derives it
//! from the row it just wrote.
//!
//! Output: one submission outcome per invocation — the recordAction
//! response, the bridge audit row when the async dispatch has
//! already landed, and the upstream response details
//! (`upstream_audit_entry_id`, `cascading_actions_json`,
//! `snapshots_json`) read back from the audit row's 0010 columns.

use std::path::Path;

use serde_json::json;
use sqlx::{Pool, Sqlite};

use crate::cli::error::CliError;
use crate::cli::moderator_action::{RecordActionInput, RecordResponse, record};
use crate::cli::pds_admin::{PdsAdminAuditView, find_pds_admin_audit_for_action};
use crate::cli::session::SessionFile;

/// Upstream `ActionResponse` details persisted on the audit row
/// (migration 0010 columns). All `None` for failed dispatches and
/// for v1.7/v1.8.2 methods.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UpstreamResponseDetails {
    /// Aurora's audit-chain entry id for the root action.
    pub upstream_audit_entry_id: Option<String>,
    /// JSON-encoded `Vec<String>` of cascaded event ids.
    pub cascading_actions_json: Option<String>,
    /// JSON-encoded snapshot list.
    pub snapshots_json: Option<String>,
}

/// Outcome of one v1.8.5 action subcommand.
#[derive(Debug)]
pub struct PdsAdminActionOutcome {
    /// The recordAction response (local row id + strike echo —
    /// always zero-strike for the backend verbs).
    pub record: RecordResponse,
    /// The bridge dispatch audit row, when the writer's async
    /// post-commit dispatch had already landed at lookup time.
    pub bridge: Option<PdsAdminAuditView>,
    /// v1.8.5 upstream response details from the audit row.
    pub upstream: Option<UpstreamResponseDetails>,
}

/// One v1.8.5 action submission: the verb's wire `action_type`,
/// subject coordinates, and the variant `detail` payload.
pub struct ActionSubmission {
    /// `subject_actions.action_type` value (snake_case).
    pub action_type: &'static str,
    /// Subject: `did:*` or `at://...` (server routes did vs uri).
    pub subject: String,
    /// Blob/record CID when the verb targets one.
    pub cid: Option<String>,
    /// Variant payload for `action_detail` (v1.8.5 wire `detail`).
    pub detail: Option<serde_json::Value>,
    /// Reason identifier from `[moderation_reasons]`.
    pub reason: String,
    /// Optional moderator note (local-only).
    pub notes: Option<String>,
    /// Per-invocation Cairn URL override.
    pub cairn_server_override: Option<String>,
}

/// Submit a v1.8.5 action through the recordAction writer path and
/// read back the bridge outcome.
pub async fn submit(
    pool: &Pool<Sqlite>,
    session: &mut SessionFile,
    session_path: &Path,
    submission: ActionSubmission,
) -> Result<PdsAdminActionOutcome, CliError> {
    let record_resp = record(
        session,
        session_path,
        RecordActionInput {
            subject: submission.subject,
            action_type: submission.action_type.to_string(),
            reasons: vec![submission.reason],
            duration: None,
            note: submission.notes,
            report_ids: Vec::new(),
            cid: submission.cid,
            detail: submission.detail,
            cairn_server_override: submission.cairn_server_override,
        },
    )
    .await?;

    let bridge = find_pds_admin_audit_for_action(pool, record_resp.action_id)
        .await
        .map_err(|e| CliError::Startup(format!("pds_admin_audit lookup: {e}")))?;

    let upstream = match &bridge {
        Some(audit_row) => fetch_upstream_details(pool, audit_row.id)
            .await
            .map_err(|e| CliError::Startup(format!("pds_admin_audit detail lookup: {e}")))?,
        None => None,
    };

    Ok(PdsAdminActionOutcome {
        record: record_resp,
        bridge,
        upstream,
    })
}

/// Read the migration-0010 response-persistence columns for an
/// audit row. Separate query so `PdsAdminAuditRecord` (whose shape
/// participates in the hash-chain walk) stays untouched.
async fn fetch_upstream_details(
    pool: &Pool<Sqlite>,
    audit_id: i64,
) -> crate::error::Result<Option<UpstreamResponseDetails>> {
    let row = sqlx::query!(
        r#"SELECT upstream_audit_entry_id, cascading_actions_json, snapshots_json
           FROM pds_admin_audit WHERE id = ?1"#,
        audit_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| crate::error::Error::Signing(format!("pds_admin_audit detail read: {e}")))?;
    Ok(row.map(|r| UpstreamResponseDetails {
        upstream_audit_entry_id: r.upstream_audit_entry_id,
        cascading_actions_json: r.cascading_actions_json,
        snapshots_json: r.snapshots_json,
    }))
}

/// Pretty-JSON rendering of the full outcome (default output).
pub fn format_action_json(outcome: &PdsAdminActionOutcome) -> String {
    let bridge = outcome.bridge.as_ref().map(|b| {
        json!({
            "auditId": b.id,
            "backendMethod": b.backend_method,
            "outcome": b.outcome,
            "backendActionId": b.backend_action_id,
            "errorCode": b.error_code,
            "errorMessage": b.error_message,
        })
    });
    let upstream = outcome.upstream.as_ref().map(|u| {
        json!({
            "upstreamAuditEntryId": u.upstream_audit_entry_id,
            "cascadingActions": u
                .cascading_actions_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()),
            "snapshots": u
                .snapshots_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()),
        })
    });
    serde_json::to_string_pretty(&json!({
        "actionId": outcome.record.action_id,
        "bridge": bridge,
        "upstream": upstream,
    }))
    .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}"))
}

/// One-line summary (`--summary` flag): action id, dispatch
/// outcome, cascade count.
pub fn format_action_summary(outcome: &PdsAdminActionOutcome) -> String {
    match &outcome.bridge {
        None => format!(
            "Recorded action {}; bridge dispatch pending (re-check with the audit CLI)",
            outcome.record.action_id
        ),
        Some(b) => {
            let cascades = outcome
                .upstream
                .as_ref()
                .and_then(|u| u.cascading_actions_json.as_deref())
                .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                .map(|v| v.len())
                .unwrap_or(0);
            format!(
                "Recorded action {}; backend {} → {}{}{}",
                outcome.record.action_id,
                b.backend_method,
                b.outcome,
                b.backend_action_id
                    .as_ref()
                    .map(|id| format!(" (event {id})"))
                    .unwrap_or_default(),
                if cascades > 0 {
                    format!("; {cascades} cascading action(s)")
                } else {
                    String::new()
                },
            )
        }
    }
}
