//! `cairn moderator pending {list, view, confirm, dismiss}` (#78)
//! — HTTP-routed moderator-tier CLIs that wrap the
//! `tools.cairn.admin.{listPendingActions, getPendingAction,
//! confirmPendingAction, dismissPendingAction}` admin XRPC
//! endpoints from #74 / #75 / #77.
//!
//! Same wire-side pattern as [`super::moderator_action`]: each
//! subcommand loads the moderator session file, mints a fresh
//! service-auth JWT bound to the lexicon method, sends the
//! lexicon-shaped request, and returns a typed response for the
//! dispatcher's human / JSON formatters.

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::auth::acquire_service_auth;
use super::error::CliError;
use super::pds::PdsClient;
use super::session::SessionFile;

const LIST_PENDING_LXM: &str = "tools.cairn.admin.listPendingActions";
const GET_PENDING_LXM: &str = "tools.cairn.admin.getPendingAction";
const CONFIRM_PENDING_LXM: &str = "tools.cairn.admin.confirmPendingAction";
const DISMISS_PENDING_LXM: &str = "tools.cairn.admin.dismissPendingAction";

/// One pending row from a list/get response. Tracks
/// `tools.cairn.admin.defs#pendingAction`. Optional fields use
/// `serde(default)` so deserialization tolerates server-side
/// projections that omit them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PendingActionEntry {
    /// `pending_policy_actions.id` — primary key.
    pub id: i64,
    /// Account DID the proposed action would target.
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    /// AT-URI for record-level proposed actions; absent for
    /// account-level.
    #[serde(
        rename = "subjectUri",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub subject_uri: Option<String>,
    /// Proposed graduated-action category (`warning` / `note` /
    /// `temp_suspension` / `indef_suspension` / `takedown`).
    #[serde(rename = "actionType")]
    pub action_type: String,
    /// ISO-8601 duration (canonical `PT<seconds>S` form). Only
    /// present when `action_type == "temp_suspension"`.
    #[serde(
        rename = "durationIso",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub duration_iso: Option<String>,
    /// Reason identifiers from the operator's `[moderation_reasons]`
    /// vocabulary, frozen at proposal time.
    #[serde(rename = "reasonCodes")]
    pub reason_codes: Vec<String>,
    /// Name of the `[policy_automation.<rule>]` sub-block that
    /// fired and queued this pending.
    #[serde(rename = "triggeredByPolicyRule")]
    pub triggered_by_policy_rule: String,
    /// RFC-3339 wall-clock the rule fired.
    #[serde(rename = "triggeredAt")]
    pub triggered_at: String,
    /// `subject_actions.id` of the precipitating action whose
    /// strike contribution caused the threshold crossing.
    #[serde(rename = "triggeringActionId")]
    pub triggering_action_id: i64,
    /// Always one of `"pending"`, `"confirmed"`, `"dismissed"`.
    pub resolution: String,
    /// RFC-3339 wall-clock the pending was resolved; absent while
    /// resolution is `"pending"`.
    #[serde(
        rename = "resolvedAt",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolved_at: Option<String>,
    /// DID of the moderator (or synthetic policy DID for
    /// takedown-cascade auto-dismissals per #76) that resolved the
    /// pending. Absent while resolution is `"pending"`.
    #[serde(
        rename = "resolvedByDid",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolved_by_did: Option<String>,
    /// `subject_actions.id` of the materialized action created
    /// when this pending was confirmed (#74). Only present when
    /// resolution is `"confirmed"`.
    #[serde(
        rename = "confirmedActionId",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub confirmed_action_id: Option<i64>,
}

// ============================================================
// `cairn moderator pending list` — paginated list (#77).
// ============================================================

/// Input to `cairn moderator pending list`.
#[derive(Debug, Clone, Default)]
pub struct ListPendingInput {
    /// Subject DID filter. Server returns SubjectNotFound (404) if
    /// the subject has never had a pending row.
    pub subject: Option<String>,
    /// Page size. Server caps at 250; default 50.
    pub limit: Option<i64>,
    /// Opaque pagination cursor.
    pub cursor: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Wire-shaped response from `tools.cairn.admin.listPendingActions`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListPendingResponse {
    /// Matched pending rows, newest-first.
    pub actions: Vec<PendingActionEntry>,
    /// Opaque pagination cursor; absent when this is the final
    /// page.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cursor: Option<String>,
}

/// Fetch one page of pending actions. Pagination across pages is
/// the caller's job.
pub async fn list(
    session: &mut SessionFile,
    session_path: &Path,
    input: ListPendingInput,
) -> Result<ListPendingResponse, CliError> {
    if let Some(s) = &input.subject
        && !s.starts_with("did:")
    {
        return Err(CliError::Config(format!(
            "subject must be a DID (`did:...`); got {s:?}"
        )));
    }

    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, LIST_PENDING_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{LIST_PENDING_LXM}");
    let limit_owned = input.limit.map(|n| n.to_string());
    let mut query: Vec<(&str, &str)> = Vec::new();
    if let Some(s) = &input.subject {
        query.push(("subject", s.as_str()));
    }
    if let Some(n) = &limit_owned {
        query.push(("limit", n.as_str()));
    }
    if let Some(c) = &input.cursor {
        query.push(("cursor", c.as_str()));
    }

    let client = build_client();
    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .query(&query)
        .send()
        .await
        .map_err(|source| CliError::Http {
            url: url.clone(),
            source,
        })?;
    cairn_response::<ListPendingResponse>(url, resp).await
}

/// Tabular human renderer for `cairn moderator pending list`.
/// Columns: id | subject_did | action_type | rule_name |
/// triggered_at | days. Empty result renders as a friendly
/// "no pendings" line.
///
/// `today_rfc3339` is the wall-clock to compute the "days since
/// triggered" column against. Passed in (rather than read from
/// `OffsetDateTime::now_utc()` directly) so tests can pin the
/// expected output.
pub fn format_list_human(resp: &ListPendingResponse, today_rfc3339: &str) -> String {
    use std::fmt::Write;
    if resp.actions.is_empty() {
        let mut s = "No pending actions found.".to_string();
        if let Some(c) = &resp.cursor {
            let _ = write!(s, "\nnext cursor: {c}");
        }
        return s;
    }

    // Compute days-since for each entry. Falls back to "-" when
    // either timestamp is unparseable — the wire shape is
    // server-controlled, so a parse failure is unexpected but
    // shouldn't crash the CLI.
    let today_ms = parse_rfc3339_to_ms(today_rfc3339);
    let rows: Vec<[String; 6]> = resp
        .actions
        .iter()
        .map(|e| {
            let days = match (today_ms, parse_rfc3339_to_ms(&e.triggered_at)) {
                (Some(t), Some(when)) => {
                    let delta_days = (t - when).max(0) / 86_400_000;
                    delta_days.to_string()
                }
                _ => "-".to_string(),
            };
            [
                e.id.to_string(),
                e.subject_did.clone(),
                e.action_type.clone(),
                e.triggered_by_policy_rule.clone(),
                e.triggered_at.clone(),
                days,
            ]
        })
        .collect();

    let headers = [
        "ID",
        "SUBJECT",
        "ACTION_TYPE",
        "RULE",
        "TRIGGERED_AT",
        "DAYS",
    ];
    let mut widths = [0usize; 6];
    for (i, h) in headers.iter().enumerate() {
        widths[i] = h.len();
    }
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }

    let mut s = String::new();
    let _ = writeln!(
        s,
        "{h0:<w0$}  {h1:<w1$}  {h2:<w2$}  {h3:<w3$}  {h4:<w4$}  {h5:>w5$}",
        h0 = headers[0],
        h1 = headers[1],
        h2 = headers[2],
        h3 = headers[3],
        h4 = headers[4],
        h5 = headers[5],
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4],
        w5 = widths[5],
    );
    for row in &rows {
        let _ = writeln!(
            s,
            "{c0:<w0$}  {c1:<w1$}  {c2:<w2$}  {c3:<w3$}  {c4:<w4$}  {c5:>w5$}",
            c0 = row[0],
            c1 = row[1],
            c2 = row[2],
            c3 = row[3],
            c4 = row[4],
            c5 = row[5],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4],
            w5 = widths[5],
        );
    }
    if let Some(c) = &resp.cursor {
        let _ = write!(s, "next cursor: {c}");
    } else if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// JSON renderer for `cairn moderator pending list`. The full
/// [`ListPendingResponse`] verbatim.
pub fn format_list_json(resp: &ListPendingResponse) -> String {
    serde_json::to_string_pretty(resp).expect("ListPendingResponse serializes")
}

// ============================================================
// `cairn moderator pending view` — single-id detail (#77).
// ============================================================

/// Input to `cairn moderator pending view`.
#[derive(Debug, Clone)]
pub struct ViewPendingInput {
    /// `pending_policy_actions.id` to fetch.
    pub pending_id: i64,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Fetch a single pending action by id.
pub async fn view(
    session: &mut SessionFile,
    session_path: &Path,
    input: ViewPendingInput,
) -> Result<PendingActionEntry, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, GET_PENDING_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{GET_PENDING_LXM}");
    let pending_id_str = input.pending_id.to_string();
    let client = build_client();
    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .query(&[("pendingId", pending_id_str.as_str())])
        .send()
        .await
        .map_err(|source| CliError::Http {
            url: url.clone(),
            source,
        })?;
    cairn_response::<PendingActionEntry>(url, resp).await
}

/// Multi-line human renderer for `cairn moderator pending view`.
pub fn format_view_human(entry: &PendingActionEntry) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "Pending action {}", entry.id);
    let _ = writeln!(s, "  Subject:           {}", entry.subject_did);
    if let Some(uri) = &entry.subject_uri {
        let _ = writeln!(s, "  Subject URI:       {uri}");
    }
    let _ = writeln!(s, "  Rule:              {}", entry.triggered_by_policy_rule);
    let _ = writeln!(s, "  Action type:       {}", entry.action_type);
    if let Some(d) = &entry.duration_iso {
        let _ = writeln!(s, "  Duration:          {d}");
    }
    let _ = writeln!(s, "  Reason codes:      {}", entry.reason_codes.join(", "));
    let _ = writeln!(s, "  Triggered at:      {}", entry.triggered_at);
    let _ = writeln!(s, "  Triggering action: {}", entry.triggering_action_id);
    let _ = writeln!(s, "  Resolution:        {}", entry.resolution);
    if let Some(t) = &entry.resolved_at {
        let _ = writeln!(s, "  Resolved at:       {t}");
    }
    if let Some(d) = &entry.resolved_by_did {
        let _ = writeln!(s, "  Resolved by:       {d}");
    }
    if let Some(id) = entry.confirmed_action_id {
        let _ = writeln!(s, "  Confirmed action:  {id}");
    }
    if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// JSON renderer for `cairn moderator pending view`.
pub fn format_view_json(entry: &PendingActionEntry) -> String {
    serde_json::to_string_pretty(entry).expect("PendingActionEntry serializes")
}

// ============================================================
// `cairn moderator pending confirm` — promote pending to action (#74).
// ============================================================

/// Input to `cairn moderator pending confirm`.
#[derive(Debug, Clone)]
pub struct ConfirmPendingInput {
    /// `pending_policy_actions.id` to confirm.
    pub pending_id: i64,
    /// Optional moderator-facing rationale. Maps to the
    /// confirmPendingAction lexicon's `note` input field, which
    /// the writer stores on `subject_actions.notes` for the
    /// materialized action.
    pub reason: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Wire-shaped response from `tools.cairn.admin.confirmPendingAction`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfirmPendingResponse {
    /// Inserted subject_actions row id.
    #[serde(rename = "actionId")]
    pub action_id: i64,
    /// The pending row that was just resolved.
    #[serde(rename = "pendingId")]
    pub pending_id: i64,
    /// RFC-3339 wall-clock the confirmation took effect.
    #[serde(rename = "resolvedAt")]
    pub resolved_at: String,
}

/// Submit a confirmPendingAction request.
pub async fn confirm(
    session: &mut SessionFile,
    session_path: &Path,
    input: ConfirmPendingInput,
) -> Result<ConfirmPendingResponse, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, CONFIRM_PENDING_LXM).await?;

    let mut body = json!({"pendingId": input.pending_id});
    // Lexicon field name is `note` (it lands on
    // subject_actions.notes); CLI flag is `--reason` for
    // ergonomic symmetry with dismiss + revoke.
    if let Some(r) = &input.reason {
        body["note"] = json!(r);
    }

    let url = format!("{cairn_server}/xrpc/{CONFIRM_PENDING_LXM}");
    let client = build_client();
    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .map_err(|source| CliError::Http {
            url: url.clone(),
            source,
        })?;
    cairn_response::<ConfirmPendingResponse>(url, resp).await
}

/// Human-readable one-liner for `cairn moderator pending confirm`.
pub fn format_confirm_human(resp: &ConfirmPendingResponse) -> String {
    format!(
        "Confirmed pending {} → action {} recorded.",
        resp.pending_id, resp.action_id
    )
}

/// JSON renderer for `cairn moderator pending confirm`. Full wire
/// envelope (`{actionId, pendingId, resolvedAt}`) — already small;
/// no projection.
pub fn format_confirm_json(resp: &ConfirmPendingResponse) -> String {
    serde_json::to_string_pretty(resp).expect("ConfirmPendingResponse serializes")
}

// ============================================================
// `cairn moderator pending dismiss` — close without action (#75).
// ============================================================

/// Input to `cairn moderator pending dismiss`.
#[derive(Debug, Clone)]
pub struct DismissPendingInput {
    /// `pending_policy_actions.id` to dismiss.
    pub pending_id: i64,
    /// Optional moderator-facing rationale. Lands on the audit
    /// row's `moderator_reason` field per #75 (the pending table
    /// itself has no resolved_reason column).
    pub reason: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Wire-shaped response from `tools.cairn.admin.dismissPendingAction`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DismissPendingResponse {
    /// The pending row that was just resolved.
    #[serde(rename = "pendingId")]
    pub pending_id: i64,
    /// RFC-3339 wall-clock the dismissal took effect.
    #[serde(rename = "resolvedAt")]
    pub resolved_at: String,
}

/// Submit a dismissPendingAction request.
pub async fn dismiss(
    session: &mut SessionFile,
    session_path: &Path,
    input: DismissPendingInput,
) -> Result<DismissPendingResponse, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, DISMISS_PENDING_LXM).await?;

    let mut body = json!({"pendingId": input.pending_id});
    if let Some(r) = &input.reason {
        body["reason"] = json!(r);
    }

    let url = format!("{cairn_server}/xrpc/{DISMISS_PENDING_LXM}");
    let client = build_client();
    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .map_err(|source| CliError::Http {
            url: url.clone(),
            source,
        })?;
    cairn_response::<DismissPendingResponse>(url, resp).await
}

/// Human-readable one-liner for `cairn moderator pending dismiss`.
pub fn format_dismiss_human(resp: &DismissPendingResponse) -> String {
    format!("Dismissed pending {}.", resp.pending_id)
}

/// JSON renderer for `cairn moderator pending dismiss`. Full wire
/// envelope (`{pendingId, resolvedAt}`).
pub fn format_dismiss_json(resp: &DismissPendingResponse) -> String {
    serde_json::to_string_pretty(resp).expect("DismissPendingResponse serializes")
}

// ============================================================
// Shared helpers.
// ============================================================

fn build_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest build")
}

async fn cairn_response<T: serde::de::DeserializeOwned>(
    url: String,
    resp: reqwest::Response,
) -> Result<T, CliError> {
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::CairnStatus { url, status, body });
    }
    let bytes = resp.bytes().await.map_err(|source| CliError::Http {
        url: url.clone(),
        source,
    })?;
    serde_json::from_slice::<T>(&bytes)
        .map_err(|source| CliError::MalformedResponse { url, source })
}

/// Parse an RFC-3339-with-Z timestamp to epoch milliseconds.
/// Returns `None` on parse failure — the formatter falls back to
/// "-" rather than crashing.
fn parse_rfc3339_to_ms(s: &str) -> Option<i64> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .map(|dt| dt.unix_timestamp_nanos() / 1_000_000)
        .and_then(|nanos_ms| i64::try_from(nanos_ms).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unresolved() -> PendingActionEntry {
        PendingActionEntry {
            id: 42,
            subject_did: "did:plc:offender".into(),
            subject_uri: None,
            action_type: "indef_suspension".into(),
            duration_iso: None,
            reason_codes: vec!["spam".into()],
            triggered_by_policy_rule: "indef_at_25".into(),
            triggered_at: "2026-04-25T12:00:00.000Z".into(),
            triggering_action_id: 187,
            resolution: "pending".into(),
            resolved_at: None,
            resolved_by_did: None,
            confirmed_action_id: None,
        }
    }

    fn sample_confirmed() -> PendingActionEntry {
        PendingActionEntry {
            id: 42,
            subject_did: "did:plc:offender".into(),
            subject_uri: None,
            action_type: "indef_suspension".into(),
            duration_iso: None,
            reason_codes: vec!["spam".into()],
            triggered_by_policy_rule: "indef_at_25".into(),
            triggered_at: "2026-04-25T12:00:00.000Z".into(),
            triggering_action_id: 187,
            resolution: "confirmed".into(),
            resolved_at: Some("2026-04-27T09:00:00.000Z".into()),
            resolved_by_did: Some("did:plc:moderator".into()),
            confirmed_action_id: Some(203),
        }
    }

    #[test]
    fn format_list_empty_says_no_pendings() {
        let resp = ListPendingResponse {
            actions: vec![],
            cursor: None,
        };
        let s = format_list_human(&resp, "2026-04-27T12:00:00.000Z");
        assert_eq!(s, "No pending actions found.");
    }

    #[test]
    fn format_list_empty_with_cursor_appends_cursor_line() {
        // Defense-in-depth: an empty page WITH a cursor is
        // structurally unreachable from the server (cursor is set
        // only when `rows.len() > limit`), but the formatter
        // shouldn't lose the cursor if the wire violates that
        // invariant.
        let resp = ListPendingResponse {
            actions: vec![],
            cursor: Some("opaque-cursor".into()),
        };
        let s = format_list_human(&resp, "2026-04-27T12:00:00.000Z");
        assert!(s.contains("No pending actions found."));
        assert!(s.contains("next cursor: opaque-cursor"));
    }

    #[test]
    fn format_list_single_entry_renders_columns() {
        let resp = ListPendingResponse {
            actions: vec![sample_unresolved()],
            cursor: None,
        };
        let s = format_list_human(&resp, "2026-04-27T12:00:00.000Z");
        // Header + one data row.
        assert!(s.contains("ID"));
        assert!(s.contains("SUBJECT"));
        assert!(s.contains("ACTION_TYPE"));
        assert!(s.contains("RULE"));
        assert!(s.contains("TRIGGERED_AT"));
        assert!(s.contains("DAYS"));
        assert!(s.contains("42"));
        assert!(s.contains("did:plc:offender"));
        assert!(s.contains("indef_suspension"));
        assert!(s.contains("indef_at_25"));
        // 2026-04-25 → 2026-04-27 = 2 days.
        let lines: Vec<&str> = s.lines().collect();
        let data_line = lines[1];
        assert!(
            data_line.trim_end().ends_with('2'),
            "data line: {data_line:?}"
        );
    }

    #[test]
    fn format_list_multi_entry_orders_by_input() {
        let mut second = sample_unresolved();
        second.id = 38;
        second.subject_did = "did:plc:badactor".into();
        second.triggered_by_policy_rule = "temp_at_10".into();
        second.action_type = "temp_suspension".into();
        second.triggered_at = "2026-04-26T12:00:00.000Z".into();
        let resp = ListPendingResponse {
            actions: vec![sample_unresolved(), second],
            cursor: None,
        };
        let s = format_list_human(&resp, "2026-04-27T12:00:00.000Z");
        let lines: Vec<&str> = s.lines().collect();
        // Header + 2 data rows.
        assert_eq!(lines.len(), 3);
        // First data row = 42 (input order preserved).
        assert!(lines[1].contains("42"));
        assert!(lines[2].contains("38"));
    }

    #[test]
    fn format_list_with_cursor_appends_next_cursor_line() {
        let resp = ListPendingResponse {
            actions: vec![sample_unresolved()],
            cursor: Some("opaque".into()),
        };
        let s = format_list_human(&resp, "2026-04-27T12:00:00.000Z");
        assert!(s.contains("next cursor: opaque"));
    }

    #[test]
    fn format_list_json_emits_full_envelope() {
        let resp = ListPendingResponse {
            actions: vec![sample_unresolved()],
            cursor: Some("opaque".into()),
        };
        let s = format_list_json(&resp);
        assert!(s.contains("\"actions\""));
        assert!(s.contains("\"cursor\": \"opaque\""));
    }

    #[test]
    fn format_view_unresolved_omits_resolution_lines() {
        let entry = sample_unresolved();
        let s = format_view_human(&entry);
        assert!(s.contains("Pending action 42"));
        assert!(s.contains("Subject:"));
        assert!(s.contains("did:plc:offender"));
        assert!(s.contains("Rule:"));
        assert!(s.contains("indef_at_25"));
        assert!(s.contains("Action type:"));
        assert!(s.contains("indef_suspension"));
        assert!(s.contains("Resolution:"));
        assert!(s.contains("pending"));
        // Unresolved → no resolution-side lines.
        assert!(!s.contains("Resolved at:"));
        assert!(!s.contains("Resolved by:"));
        assert!(!s.contains("Confirmed action:"));
    }

    #[test]
    fn format_view_confirmed_includes_resolution_and_confirmed_action() {
        let entry = sample_confirmed();
        let s = format_view_human(&entry);
        assert!(s.contains("Resolution:"));
        assert!(s.contains("confirmed"));
        assert!(s.contains("Resolved at:"));
        assert!(s.contains("2026-04-27"));
        assert!(s.contains("Resolved by:"));
        assert!(s.contains("did:plc:moderator"));
        assert!(s.contains("Confirmed action:"));
        assert!(s.contains("203"));
    }

    #[test]
    fn format_view_dismissed_omits_confirmed_action_id() {
        let mut entry = sample_confirmed();
        entry.resolution = "dismissed".into();
        entry.confirmed_action_id = None;
        let s = format_view_human(&entry);
        assert!(s.contains("dismissed"));
        assert!(s.contains("Resolved at:"));
        assert!(s.contains("Resolved by:"));
        assert!(!s.contains("Confirmed action:"));
    }

    #[test]
    fn format_view_temp_suspension_renders_duration() {
        let mut entry = sample_unresolved();
        entry.action_type = "temp_suspension".into();
        entry.duration_iso = Some("PT86400S".into());
        let s = format_view_human(&entry);
        assert!(s.contains("Duration:"));
        assert!(s.contains("PT86400S"));
    }

    #[test]
    fn format_view_subject_uri_present_when_record_level() {
        let mut entry = sample_unresolved();
        entry.subject_uri = Some("at://did:plc:offender/app.bsky.feed.post/abc".into());
        let s = format_view_human(&entry);
        assert!(s.contains("Subject URI:"));
        assert!(s.contains("at://did:plc:offender/app.bsky.feed.post/abc"));
    }

    #[test]
    fn format_confirm_human_says_action_recorded() {
        let resp = ConfirmPendingResponse {
            action_id: 203,
            pending_id: 42,
            resolved_at: "2026-04-27T09:00:00.000Z".into(),
        };
        let s = format_confirm_human(&resp);
        assert!(s.contains("42"));
        assert!(s.contains("203"));
        assert!(s.to_lowercase().contains("confirmed"));
    }

    #[test]
    fn format_confirm_json_emits_full_envelope() {
        let resp = ConfirmPendingResponse {
            action_id: 203,
            pending_id: 42,
            resolved_at: "2026-04-27T09:00:00.000Z".into(),
        };
        let s = format_confirm_json(&resp);
        assert!(s.contains("\"actionId\": 203"));
        assert!(s.contains("\"pendingId\": 42"));
        assert!(s.contains("\"resolvedAt\""));
    }

    #[test]
    fn format_dismiss_human_says_dismissed() {
        let resp = DismissPendingResponse {
            pending_id: 42,
            resolved_at: "2026-04-27T09:00:00.000Z".into(),
        };
        let s = format_dismiss_human(&resp);
        assert!(s.contains("42"));
        assert!(s.to_lowercase().contains("dismissed"));
    }

    #[test]
    fn format_dismiss_json_emits_full_envelope() {
        let resp = DismissPendingResponse {
            pending_id: 42,
            resolved_at: "2026-04-27T09:00:00.000Z".into(),
        };
        let s = format_dismiss_json(&resp);
        assert!(s.contains("\"pendingId\": 42"));
        assert!(s.contains("\"resolvedAt\""));
    }

    #[test]
    fn list_input_rejects_non_did_subject() {
        let mut session = SessionFile {
            version: 1,
            pds_url: "https://pds.example".into(),
            moderator_handle: "mod.example".into(),
            moderator_did: "did:plc:m1".into(),
            access_jwt: "x".into(),
            refresh_jwt: "x".into(),
            cairn_server_url: "https://cairn.example".into(),
            cairn_service_did: "did:web:cairn.example".into(),
        };
        let path = std::path::PathBuf::from("/tmp/nonexistent-session");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(list(
                &mut session,
                &path,
                ListPendingInput {
                    subject: Some("not-a-did".into()),
                    ..Default::default()
                },
            ))
            .unwrap_err();
        assert!(matches!(err, CliError::Config(_)));
    }
}
