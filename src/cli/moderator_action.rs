//! `cairn moderator {action, warn, note, revoke}` (#51) — HTTP-routed
//! moderator-tier CLIs that hit `tools.cairn.admin.recordAction` and
//! `tools.cairn.admin.revokeAction`.
//!
//! Same wire-side pattern as `cairn report {flag, resolve}` from
//! v1.2 — each subcommand:
//! 1. Loads the moderator session file.
//! 2. Mints a fresh service-auth JWT bound to the lexicon method,
//!    refreshing on a 401 via the shared `acquire_service_auth`
//!    helper.
//! 3. POSTs the lexicon-shaped body to the running Cairn instance.
//! 4. Returns a typed [`RecordResponse`] / [`RevokeResponse`] for
//!    the dispatcher's human / JSON formatters.
//!
//! Distinct from the v1.1-era `cairn moderator {add, remove, list}`
//! in `cli/moderator.rs` — those are operator-tier (direct-DB,
//! lease-aware). The new write commands here are moderator-tier
//! (HTTP-routed, daemon must be up) — they DO moderation actions,
//! the operator-tier CLI in `cli/moderator.rs` manages WHO can.
//! See the architectural note in MEMORY.md (feedback memory) for
//! the full split.

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::auth::acquire_service_auth;
use super::error::CliError;
use super::pds::PdsClient;
use super::session::SessionFile;

const RECORD_ACTION_LXM: &str = "tools.cairn.admin.recordAction";
const REVOKE_ACTION_LXM: &str = "tools.cairn.admin.revokeAction";
const GET_SUBJECT_HISTORY_LXM: &str = "tools.cairn.admin.getSubjectHistory";
const GET_SUBJECT_STRIKES_LXM: &str = "tools.cairn.admin.getSubjectStrikes";

// ============================================================
// `cairn moderator action` — record a graduated-action moderation
// event. Backs `recordAction` admin XRPC (#51). Wraps both the
// generic --type form and the warn / note shorthands (which are
// implemented as preset-type calls into this same orchestrator).
// ============================================================

/// Input to `cairn moderator action / warn / note`.
#[derive(Debug, Clone)]
pub struct RecordActionInput {
    /// Subject — `did:*` for an account, `at://...` for a record.
    /// Server auto-routes to `subject_did` vs `subject_uri`.
    pub subject: String,
    /// Graduated-action category as the wire string
    /// (`warning` / `note` / `temp_suspension` / `indef_suspension`
    /// / `takedown`).
    pub action_type: String,
    /// One or more reason identifiers from the operator's
    /// `[moderation_reasons]` vocabulary. Multi-reason: server
    /// resolves severe-wins / highest-base-weight.
    pub reasons: Vec<String>,
    /// ISO-8601 duration (e.g. `P7D`). Required iff `action_type
    /// == "temp_suspension"`; rejected for other types.
    pub duration: Option<String>,
    /// Optional moderator-facing note stored on the row.
    pub note: Option<String>,
    /// Optional list of report row ids that motivated this action.
    pub report_ids: Vec<i64>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Wire-shaped response from `tools.cairn.admin.recordAction`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecordResponse {
    /// Inserted subject_actions row id.
    #[serde(rename = "actionId")]
    pub action_id: i64,
    /// Reason's base_weight before dampening.
    #[serde(rename = "strikeValueBase")]
    pub strike_value_base: u32,
    /// Strike weight actually applied after dampening.
    #[serde(rename = "strikeValueApplied")]
    pub strike_value_applied: u32,
    /// `true` iff the curve was consulted at action time.
    #[serde(rename = "wasDampened")]
    pub was_dampened: bool,
    /// Subject's strike count BEFORE this action — frozen for
    /// forensic history.
    #[serde(rename = "strikesAtTimeOfAction")]
    pub strikes_at_time_of_action: u32,
}

/// Submit a recordAction request. Wraps the
/// `tools.cairn.admin.recordAction` handler at
/// [src/server/admin/record_action.rs](..).
pub async fn record(
    session: &mut SessionFile,
    session_path: &Path,
    input: RecordActionInput,
) -> Result<RecordResponse, CliError> {
    if input.reasons.is_empty() {
        return Err(CliError::Config("at least one --reason is required".into()));
    }
    if !input.subject.starts_with("did:") && !input.subject.starts_with("at://") {
        return Err(CliError::Config(format!(
            "subject must start with `did:` or `at://`; got {:?}",
            input.subject
        )));
    }

    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, RECORD_ACTION_LXM).await?;

    let mut body = json!({
        "subject": input.subject,
        "type": input.action_type,
        "reasons": input.reasons,
    });
    if let Some(d) = &input.duration {
        body["duration"] = json!(d);
    }
    if let Some(n) = &input.note {
        body["note"] = json!(n);
    }
    if !input.report_ids.is_empty() {
        body["reportIds"] = json!(input.report_ids);
    }

    let url = format!("{cairn_server}/xrpc/{RECORD_ACTION_LXM}");
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
    cairn_response::<RecordResponse>(url, resp).await
}

/// Human-readable one-liner for `cairn moderator action / warn / note`.
pub fn format_record_human(resp: &RecordResponse) -> String {
    if resp.strike_value_applied == 0 {
        format!("Recorded action {} (no strikes)", resp.action_id)
    } else if resp.was_dampened {
        format!(
            "Recorded action {} (+{} strike{}, dampened from {})",
            resp.action_id,
            resp.strike_value_applied,
            if resp.strike_value_applied == 1 {
                ""
            } else {
                "s"
            },
            resp.strike_value_base,
        )
    } else {
        format!(
            "Recorded action {} (+{} strike{})",
            resp.action_id,
            resp.strike_value_applied,
            if resp.strike_value_applied == 1 {
                ""
            } else {
                "s"
            },
        )
    }
}

/// JSON output for `cairn moderator action / warn / note`.
pub fn format_record_json(resp: &RecordResponse) -> String {
    serde_json::to_string_pretty(resp).expect("RecordResponse serializes")
}

// ============================================================
// `cairn moderator revoke` — revoke a previously-recorded action.
// Backs `revokeAction` admin XRPC.
// ============================================================

/// Input to `cairn moderator revoke`.
#[derive(Debug, Clone)]
pub struct RevokeActionInput {
    /// subject_actions.id to revoke.
    pub action_id: i64,
    /// Optional rationale stored on the row's revoked_reason column.
    pub reason: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Wire-shaped response from `tools.cairn.admin.revokeAction`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevokeResponse {
    /// The revoked row's id.
    #[serde(rename = "actionId")]
    pub action_id: i64,
    /// RFC-3339 wall-clock the revocation took effect.
    #[serde(rename = "revokedAt")]
    pub revoked_at: String,
}

/// Submit a revokeAction request.
pub async fn revoke(
    session: &mut SessionFile,
    session_path: &Path,
    input: RevokeActionInput,
) -> Result<RevokeResponse, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, REVOKE_ACTION_LXM).await?;

    let mut body = json!({"actionId": input.action_id});
    if let Some(r) = &input.reason {
        body["reason"] = json!(r);
    }

    let url = format!("{cairn_server}/xrpc/{REVOKE_ACTION_LXM}");
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
    cairn_response::<RevokeResponse>(url, resp).await
}

/// Human-readable one-liner for `cairn moderator revoke`.
pub fn format_revoke_human(resp: &RevokeResponse) -> String {
    format!("Revoked action {} at {}", resp.action_id, resp.revoked_at)
}

/// JSON output for `cairn moderator revoke`.
pub fn format_revoke_json(resp: &RevokeResponse) -> String {
    serde_json::to_string_pretty(resp).expect("RevokeResponse serializes")
}

// ============================================================
// `cairn moderator history` — list subject_actions for a subject.
// Backs `getSubjectHistory` admin XRPC (#52 / read-half of #53).
// ============================================================

/// Input to `cairn moderator history`.
#[derive(Debug, Clone)]
pub struct HistoryInput {
    /// Subject DID. AT-URIs are normalized to the parent DID
    /// before sending; this matches the lexicon's account-rollup
    /// invariant (strike accounting is always at the account
    /// level).
    pub subject: String,
    /// Optional AT-URI filter — when set, narrows to record-level
    /// actions on that URI.
    pub subject_uri: Option<String>,
    /// `false` excludes revoked actions from the response. Default
    /// `true` (lexicon default).
    pub include_revoked: bool,
    /// RFC-3339 timestamp lower bound on `effective_at`.
    pub since: Option<String>,
    /// Page size. Server caps at 250; default 50.
    pub limit: Option<i64>,
    /// Opaque pagination cursor.
    pub cursor: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

impl Default for HistoryInput {
    fn default() -> Self {
        Self {
            subject: String::new(),
            subject_uri: None,
            include_revoked: true,
            since: None,
            limit: None,
            cursor: None,
            cairn_server_override: None,
        }
    }
}

/// One row in a `getSubjectHistory` response. Field set tracks
/// `tools.cairn.admin.defs#subjectAction`; optional fields use
/// `serde(default)` so deserialization tolerates server-side
/// projections that drop them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryEntry {
    /// `subject_actions.id` — primary key.
    pub id: i64,
    /// Account DID this action attributes to. Always the parent
    /// DID for record-level actions.
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    /// AT-URI for record-level actions; absent for account-level.
    #[serde(
        rename = "subjectUri",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub subject_uri: Option<String>,
    /// DID of the moderator/admin that recorded the action.
    #[serde(rename = "actorDid")]
    pub actor_did: String,
    /// `warning` / `note` / `temp_suspension` / `indef_suspension` /
    /// `takedown`.
    #[serde(rename = "actionType")]
    pub action_type: String,
    /// Reason identifiers from the `[moderation_reasons]` vocabulary.
    #[serde(rename = "reasonCodes")]
    pub reason_codes: Vec<String>,
    /// Original ISO-8601 duration string (e.g. `P7D`); only present
    /// for `temp_suspension`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duration: Option<String>,
    /// RFC-3339 wall-clock the action took effect.
    #[serde(rename = "effectiveAt")]
    pub effective_at: String,
    /// RFC-3339 wall-clock the action ends; only `temp_suspension`.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<String>,
    /// Moderator-facing rationale stored on the row.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub notes: Option<String>,
    /// Report ids that motivated this action, if any.
    #[serde(rename = "reportIds", skip_serializing_if = "Option::is_none", default)]
    pub report_ids: Option<Vec<i64>>,
    /// Reason's `base_weight` before dampening.
    #[serde(rename = "strikeValueBase")]
    pub strike_value_base: i64,
    /// Strike weight actually applied after dampening.
    #[serde(rename = "strikeValueApplied")]
    pub strike_value_applied: i64,
    /// `true` iff the dampening curve was consulted at action time.
    #[serde(rename = "wasDampened")]
    pub was_dampened: bool,
    /// Subject's `current_strike_count` BEFORE this action.
    #[serde(rename = "strikesAtTimeOfAction")]
    pub strikes_at_time_of_action: i64,
    /// RFC-3339 revocation wall-clock; absent if not revoked.
    #[serde(rename = "revokedAt", skip_serializing_if = "Option::is_none", default)]
    pub revoked_at: Option<String>,
    /// DID of the moderator/admin who revoked this action; absent
    /// if not revoked.
    #[serde(
        rename = "revokedByDid",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub revoked_by_did: Option<String>,
    /// Free-text revocation rationale; absent if not provided.
    #[serde(
        rename = "revokedReason",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub revoked_reason: Option<String>,
    /// `audit_log.id` of the row this action's intent was attested
    /// as.
    #[serde(
        rename = "auditLogId",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub audit_log_id: Option<i64>,
    /// RFC-3339 wall-clock at INSERT.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Wire-shaped response from `tools.cairn.admin.getSubjectHistory`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryResponse {
    /// Matched actions, newest-first.
    pub actions: Vec<HistoryEntry>,
    /// Opaque pagination cursor; absent when this is the final page.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cursor: Option<String>,
}

/// Fetch one page of history. Pagination across pages is the
/// caller's job — the dispatcher loops on the returned cursor.
/// Mirrors `cli/report.rs::list` posture.
pub async fn history(
    session: &mut SessionFile,
    session_path: &Path,
    input: HistoryInput,
) -> Result<HistoryResponse, CliError> {
    if !input.subject.starts_with("did:") {
        return Err(CliError::Config(format!(
            "subject must be a DID (`did:...`); got {:?}",
            input.subject
        )));
    }

    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, GET_SUBJECT_HISTORY_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{GET_SUBJECT_HISTORY_LXM}");
    let limit_owned = input.limit.map(|n| n.to_string());
    let mut query: Vec<(&str, &str)> = vec![("subject", input.subject.as_str())];
    if let Some(u) = &input.subject_uri {
        query.push(("subjectUri", u.as_str()));
    }
    if !input.include_revoked {
        query.push(("includeRevoked", "false"));
    }
    if let Some(s) = &input.since {
        query.push(("since", s.as_str()));
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
    cairn_response::<HistoryResponse>(url, resp).await
}

/// Tabular human renderer for `cairn moderator history`. Columns:
/// id | when | type | reasons | applied (vs base) | dampened | revoked.
/// Empty result renders as a friendly "no actions" line rather than an
/// empty table — matches the listReports posture from v1.2.
pub fn format_history_human(resp: &HistoryResponse, subject: &str) -> String {
    use std::fmt::Write;
    if resp.actions.is_empty() {
        let mut s = format!("No actions recorded for {subject}");
        if let Some(c) = &resp.cursor {
            let _ = write!(s, "\nnext cursor: {c}");
        }
        return s;
    }

    let id_w = resp
        .actions
        .iter()
        .map(|e| e.id.to_string().len())
        .max()
        .unwrap_or(2)
        .max(2);
    let type_w = resp
        .actions
        .iter()
        .map(|e| e.action_type.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let reasons_w = resp
        .actions
        .iter()
        .map(|e| e.reason_codes.join(",").len().min(40))
        .max()
        .unwrap_or(7)
        .max(7);

    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:>id_w$}  {:<24}  {:<type_w$}  {:<reasons_w$}  {:>9}  {:<8}  {:<8}",
        "ID",
        "EFFECTIVE_AT",
        "TYPE",
        "REASONS",
        "APPLIED",
        "DAMPENED",
        "REVOKED",
        id_w = id_w,
        type_w = type_w,
        reasons_w = reasons_w,
    );
    for e in &resp.actions {
        let reasons = e.reason_codes.join(",");
        let reasons = if reasons.len() > 40 {
            format!("{}…", &reasons[..39])
        } else {
            reasons
        };
        let applied = if e.strike_value_applied != e.strike_value_base {
            format!("{}/{}", e.strike_value_applied, e.strike_value_base)
        } else {
            e.strike_value_applied.to_string()
        };
        let dampened = if e.was_dampened { "yes" } else { "no" };
        let revoked = if e.revoked_at.is_some() { "yes" } else { "no" };
        let _ = writeln!(
            s,
            "{:>id_w$}  {:<24}  {:<type_w$}  {:<reasons_w$}  {:>9}  {:<8}  {:<8}",
            e.id,
            e.effective_at,
            e.action_type,
            reasons,
            applied,
            dampened,
            revoked,
            id_w = id_w,
            type_w = type_w,
            reasons_w = reasons_w,
        );
    }
    if let Some(c) = &resp.cursor {
        let _ = write!(s, "next cursor: {c}");
    } else if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// JSON renderer for `cairn moderator history`. The full
/// [`HistoryResponse`] verbatim.
pub fn format_history_json(resp: &HistoryResponse) -> String {
    serde_json::to_string_pretty(resp).expect("HistoryResponse serializes")
}

// ============================================================
// `cairn moderator strikes` — current strike state for a subject.
// Backs `getSubjectStrikes` admin XRPC (#52 / read-half of #53).
// ============================================================

/// Input to `cairn moderator strikes`.
#[derive(Debug, Clone)]
pub struct StrikesInput {
    /// Subject DID. The endpoint enforces the DID-prefix shape;
    /// the CLI checks early so a bad shape doesn't cost an HTTP
    /// round-trip.
    pub subject: String,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Wire-shaped response from `tools.cairn.admin.getSubjectStrikes`.
/// Mirrors `tools.cairn.admin.defs#subjectStrikeState`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StrikesResponse {
    /// Active strike total after decay and revocation.
    #[serde(rename = "currentStrikeCount")]
    pub current_strike_count: u32,
    /// Lifetime sum of strike_value_applied (ignores decay + revoke).
    #[serde(rename = "rawTotal")]
    pub raw_total: u32,
    /// Strikes lost to time-based decay across unrevoked actions.
    #[serde(rename = "decayedCount")]
    pub decayed_count: u32,
    /// Strikes that have been revoked.
    #[serde(rename = "revokedCount")]
    pub revoked_count: u32,
    /// `true` iff `currentStrikeCount <= policy.good_standing_threshold`.
    #[serde(rename = "goodStanding")]
    pub good_standing: bool,
    /// Currently-active suspension if any.
    #[serde(
        rename = "activeSuspension",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub active_suspension: Option<ActiveSuspensionView>,
    /// Days until the most recent strike-bearing action falls out
    /// of the decay window. Omitted when `currentStrikeCount == 0`.
    #[serde(
        rename = "decayWindowRemainingDays",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub decay_window_remaining_days: Option<u32>,
    /// RFC-3339 effective_at of the most recent strike-bearing
    /// unrevoked action. Absent if none.
    #[serde(
        rename = "lastActionAt",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub last_action_at: Option<String>,
    /// ATProto labels cairn-mod is currently emitting against the
    /// subject (#65, v1.5). One entry per non-revoked, non-negated
    /// action that emitted labels, ordered most-recent-first.
    /// Always present; empty array when nothing is active. Surfaced
    /// here so `cairn moderator strikes --json` carries the same
    /// envelope as the wire response, and so `cairn moderator
    /// labels` can render the same field as its primary output.
    #[serde(rename = "activeLabels", default)]
    pub active_labels: Vec<ActiveLabelView>,
}

/// Per-action active-label entry returned on
/// [`StrikesResponse::active_labels`]. Mirrors
/// `tools.cairn.admin.defs#activeLabel`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActiveLabelView {
    /// Action label `val` (e.g., `!takedown`).
    pub val: String,
    /// `subject_actions.id` of the source action.
    #[serde(rename = "actionId")]
    pub action_id: i64,
    /// `subject_actions.action_type` for the source row.
    #[serde(rename = "actionType")]
    pub action_type: String,
    /// Reason codes whose reason-labels were emitted alongside the
    /// action label. Always present (may be empty).
    #[serde(rename = "reasonCodes")]
    pub reason_codes: Vec<String>,
    /// RFC-3339 expiry of the action's emitted labels; absent for
    /// non-temp_suspension actions.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<String>,
}

/// Active-suspension sub-object surfaced on a [`StrikesResponse`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActiveSuspensionView {
    /// `temp_suspension` or `indef_suspension`.
    #[serde(rename = "actionType")]
    pub action_type: String,
    /// RFC-3339 wall-clock the suspension took effect.
    #[serde(rename = "effectiveAt")]
    pub effective_at: String,
    /// RFC-3339 wall-clock the suspension ends; absent for indef.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<String>,
}

/// Fetch the subject's current strike state.
pub async fn strikes(
    session: &mut SessionFile,
    session_path: &Path,
    input: StrikesInput,
) -> Result<StrikesResponse, CliError> {
    if !input.subject.starts_with("did:") {
        return Err(CliError::Config(format!(
            "subject must be a DID (`did:...`); got {:?}",
            input.subject
        )));
    }
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, GET_SUBJECT_STRIKES_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{GET_SUBJECT_STRIKES_LXM}");
    let client = build_client();
    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .query(&[("subject", input.subject.as_str())])
        .send()
        .await
        .map_err(|source| CliError::Http {
            url: url.clone(),
            source,
        })?;
    cairn_response::<StrikesResponse>(url, resp).await
}

/// Multi-line human renderer for `cairn moderator strikes`. Sections:
/// summary numbers, suspension state (if any), trajectory.
pub fn format_strikes_human(resp: &StrikesResponse, subject: &str) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "Strike state for {subject}");
    let _ = writeln!(s, "  current strikes:    {}", resp.current_strike_count);
    let _ = writeln!(
        s,
        "  good standing:      {}",
        if resp.good_standing { "yes" } else { "no" }
    );
    let _ = writeln!(s, "  raw total:          {}", resp.raw_total);
    let _ = writeln!(s, "  decayed:            {}", resp.decayed_count);
    let _ = writeln!(s, "  revoked:            {}", resp.revoked_count);
    match &resp.active_suspension {
        None => {
            let _ = writeln!(s, "  active suspension:  none");
        }
        Some(susp) => {
            let when = match &susp.expires_at {
                None => format!("{} (indefinite)", susp.effective_at),
                Some(e) => format!("{} → {}", susp.effective_at, e),
            };
            let _ = writeln!(s, "  active suspension:  {} {}", susp.action_type, when);
        }
    }
    if let Some(t) = &resp.last_action_at {
        let _ = writeln!(s, "  last action:        {t}");
    }
    if let Some(d) = resp.decay_window_remaining_days {
        let _ = writeln!(s, "  returns to good standing in: {d} day(s)");
    }
    if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// JSON renderer for `cairn moderator strikes`.
pub fn format_strikes_json(resp: &StrikesResponse) -> String {
    serde_json::to_string_pretty(resp).expect("StrikesResponse serializes")
}

// ============================================================
// `cairn moderator labels <subject>` (#66, v1.5).
//
// Reads the same `tools.cairn.admin.getSubjectStrikes` envelope
// as `cairn moderator strikes`, but renders only the `active_labels`
// field. The fetch path is shared with `strikes` (single source of
// HTTP code); divergence is at the formatting layer.
// ============================================================

/// Input for [`labels`]. Mirrors [`StrikesInput`] one-to-one — the
/// CLI surfaces them as separate subcommands for UX clarity even
/// though the underlying XRPC request is identical.
#[derive(Debug, Clone)]
pub struct LabelsInput {
    /// Subject DID. Pre-validated for the `did:` prefix; the
    /// endpoint also enforces this.
    pub subject: String,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Fetch the subject's active-label state. Internally calls the
/// same getSubjectStrikes XRPC as [`strikes`]; renderers below
/// pull the `active_labels` field off the envelope.
pub async fn labels(
    session: &mut SessionFile,
    session_path: &Path,
    input: LabelsInput,
) -> Result<StrikesResponse, CliError> {
    strikes(
        session,
        session_path,
        StrikesInput {
            subject: input.subject,
            cairn_server_override: input.cairn_server_override,
        },
    )
    .await
}

/// Tabular human renderer for `cairn moderator labels`.
///
/// One row per emitted label: each [`ActiveLabelView`] expands to
/// the action label's row plus one row per reason code. The action
/// context (id, type, reasons, expiry) repeats across every row
/// belonging to the same action so an operator scanning the table
/// can see every label's provenance in one line.
///
/// Reason-label `val`s are reconstructed by prefixing each
/// `reason_code` with the default `reason-` prefix. The wire shape
/// doesn't carry the operator's configured prefix, so a custom
/// `[label_emission].reason_label_prefix` in operator config will
/// drift here. Tracked for follow-up if a real deployment surfaces
/// a non-default prefix.
pub fn format_labels_human(resp: &StrikesResponse, subject: &str) -> String {
    use std::fmt::Write;
    if resp.active_labels.is_empty() {
        return format!("No active labels for {subject}");
    }

    let mut s = String::new();
    let _ = writeln!(s, "Active labels for {subject}");

    // Two-pass render: pass 1 collects rows so column widths come
    // from real content; pass 2 prints with consistent spacing.
    let mut rows: Vec<[String; 5]> = Vec::new();
    for entry in &resp.active_labels {
        let reasons_joined = if entry.reason_codes.is_empty() {
            "-".to_string()
        } else {
            entry.reason_codes.join(",")
        };
        let expires = entry.expires_at.as_deref().unwrap_or("-").to_string();
        // Action label first.
        rows.push([
            entry.val.clone(),
            entry.action_id.to_string(),
            entry.action_type.clone(),
            reasons_joined.clone(),
            expires.clone(),
        ]);
        // Then one row per reason code, val=`reason-<code>`.
        for code in &entry.reason_codes {
            rows.push([
                format!("reason-{code}"),
                entry.action_id.to_string(),
                entry.action_type.clone(),
                reasons_joined.clone(),
                expires.clone(),
            ]);
        }
    }

    let headers = [
        "LABEL_VAL",
        "ACTION_ID",
        "ACTION_TYPE",
        "REASONS",
        "EXPIRES_AT",
    ];
    let mut widths = [0usize; 5];
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
    let _ = writeln!(
        s,
        "  {h0:<w0$}  {h1:<w1$}  {h2:<w2$}  {h3:<w3$}  {h4:<w4$}",
        h0 = headers[0],
        h1 = headers[1],
        h2 = headers[2],
        h3 = headers[3],
        h4 = headers[4],
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4],
    );
    for row in &rows {
        let _ = writeln!(
            s,
            "  {c0:<w0$}  {c1:<w1$}  {c2:<w2$}  {c3:<w3$}  {c4:<w4$}",
            c0 = row[0],
            c1 = row[1],
            c2 = row[2],
            c3 = row[3],
            c4 = row[4],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4],
        );
    }
    if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// JSON renderer for `cairn moderator labels`. Returns just the
/// `activeLabels` array — the subcommand's job is "show me labels,"
/// so the JSON output mirrors that. Operators wanting the full
/// envelope use `cairn moderator strikes --json`.
pub fn format_labels_json(resp: &StrikesResponse) -> String {
    serde_json::to_string_pretty(&resp.active_labels).expect("Vec<ActiveLabelView> serializes")
}

// ============================================================
// Shared helpers (mirrors the cli/report.rs pattern).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_input_rejects_bad_subject() {
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
        // synchronous validation runs before any HTTP — no runtime needed.
        let path = std::path::PathBuf::from("/tmp/nonexistent-session");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(record(
                &mut session,
                &path,
                RecordActionInput {
                    subject: "bad-shape".into(),
                    action_type: "takedown".into(),
                    reasons: vec!["spam".into()],
                    duration: None,
                    note: None,
                    report_ids: vec![],
                    cairn_server_override: None,
                },
            ))
            .unwrap_err();
        assert!(matches!(err, CliError::Config(_)));
    }

    #[test]
    fn record_input_rejects_empty_reasons() {
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
            .block_on(record(
                &mut session,
                &path,
                RecordActionInput {
                    subject: "did:plc:abc".into(),
                    action_type: "takedown".into(),
                    reasons: vec![],
                    duration: None,
                    note: None,
                    report_ids: vec![],
                    cairn_server_override: None,
                },
            ))
            .unwrap_err();
        assert!(matches!(err, CliError::Config(_)));
    }

    #[test]
    fn format_record_human_dampened_includes_base() {
        let r = RecordResponse {
            action_id: 7,
            strike_value_base: 4,
            strike_value_applied: 1,
            was_dampened: true,
            strikes_at_time_of_action: 0,
        };
        let s = format_record_human(&r);
        assert!(s.contains("dampened"));
        assert!(s.contains("from 4"));
    }

    #[test]
    fn format_record_human_zero_strikes_says_no_strikes() {
        let r = RecordResponse {
            action_id: 7,
            strike_value_base: 0,
            strike_value_applied: 0,
            was_dampened: false,
            strikes_at_time_of_action: 0,
        };
        let s = format_record_human(&r);
        assert!(s.contains("no strikes"));
    }

    #[test]
    fn format_revoke_human_shows_id_and_timestamp() {
        let r = RevokeResponse {
            action_id: 7,
            revoked_at: "2026-04-26T12:00:00.000Z".into(),
        };
        let s = format_revoke_human(&r);
        assert!(s.contains("7"));
        assert!(s.contains("2026-04-26"));
    }

    // ---------- labels (#66) ----------

    fn empty_strikes_response() -> StrikesResponse {
        StrikesResponse {
            current_strike_count: 0,
            raw_total: 0,
            decayed_count: 0,
            revoked_count: 0,
            good_standing: true,
            active_suspension: None,
            decay_window_remaining_days: None,
            last_action_at: None,
            active_labels: vec![],
        }
    }

    #[test]
    fn format_labels_human_empty_says_no_active_labels() {
        let resp = empty_strikes_response();
        let s = format_labels_human(&resp, "did:plc:abc");
        assert_eq!(s, "No active labels for did:plc:abc");
    }

    #[test]
    fn format_labels_human_takedown_no_reasons_emits_one_row() {
        // emit_reason_labels=false at recording time → emitted action
        // label only, reason_codes empty.
        let mut resp = empty_strikes_response();
        resp.active_labels.push(ActiveLabelView {
            val: "!takedown".into(),
            action_id: 42,
            action_type: "takedown".into(),
            reason_codes: vec![],
            expires_at: None,
        });
        let s = format_labels_human(&resp, "did:plc:abc");
        assert!(s.contains("Active labels for did:plc:abc"));
        assert!(s.contains("LABEL_VAL"));
        assert!(s.contains("!takedown"));
        assert!(s.contains("42"));
        assert!(s.contains("takedown"));
        // No reason-* rows when reason_codes is empty.
        assert!(!s.contains("reason-"));
        // REASONS column carries `-` placeholder.
        let row_count = s.lines().filter(|l| l.contains("!takedown")).count();
        assert_eq!(row_count, 1);
    }

    #[test]
    fn format_labels_human_takedown_with_two_reasons_emits_three_rows() {
        let mut resp = empty_strikes_response();
        resp.active_labels.push(ActiveLabelView {
            val: "!takedown".into(),
            action_id: 42,
            action_type: "takedown".into(),
            reason_codes: vec!["harassment".into(), "hate-speech".into()],
            expires_at: None,
        });
        let s = format_labels_human(&resp, "did:plc:abc");
        assert!(s.contains("!takedown"));
        assert!(s.contains("reason-harassment"));
        assert!(s.contains("reason-hate-speech"));
        // REASONS column: comma-joined.
        assert!(s.contains("harassment,hate-speech"));
    }

    #[test]
    fn format_labels_human_temp_suspension_shows_expires_at_column() {
        let mut resp = empty_strikes_response();
        resp.active_labels.push(ActiveLabelView {
            val: "!hide".into(),
            action_id: 38,
            action_type: "temp_suspension".into(),
            reason_codes: vec!["spam".into()],
            expires_at: Some("2026-05-04T12:00:00.000Z".into()),
        });
        let s = format_labels_human(&resp, "did:plc:abc");
        assert!(s.contains("temp_suspension"));
        assert!(s.contains("2026-05-04T12:00:00.000Z"));
        // Both the action-label row and the reason-label row carry
        // the same expiry (each row is fully self-describing).
        let with_exp = s
            .lines()
            .filter(|l| l.contains("2026-05-04T12:00:00.000Z"))
            .count();
        assert_eq!(with_exp, 2, "action row + reason row both carry expiry");
    }

    #[test]
    fn format_labels_human_indef_suspension_shows_dash_in_expires_at() {
        let mut resp = empty_strikes_response();
        resp.active_labels.push(ActiveLabelView {
            val: "!hide".into(),
            action_id: 38,
            action_type: "indef_suspension".into(),
            reason_codes: vec![],
            expires_at: None,
        });
        let s = format_labels_human(&resp, "did:plc:abc");
        assert!(s.contains("indef_suspension"));
        // The action-label data row's trailing column is `-`.
        let action_row = s
            .lines()
            .find(|l| l.contains("!hide") && l.contains("38"))
            .expect("action row present");
        assert!(action_row.trim_end().ends_with('-'));
    }

    #[test]
    fn format_labels_human_multiple_actions_renders_all() {
        let mut resp = empty_strikes_response();
        // Most-recent first per #65's ordering.
        resp.active_labels.push(ActiveLabelView {
            val: "!hide".into(),
            action_id: 50,
            action_type: "temp_suspension".into(),
            reason_codes: vec!["spam".into()],
            expires_at: Some("2026-05-04T12:00:00.000Z".into()),
        });
        resp.active_labels.push(ActiveLabelView {
            val: "!takedown".into(),
            action_id: 42,
            action_type: "takedown".into(),
            reason_codes: vec!["hate-speech".into()],
            expires_at: None,
        });
        let s = format_labels_human(&resp, "did:plc:abc");
        // Both actions present.
        assert!(s.contains("!hide"));
        assert!(s.contains("!takedown"));
        assert!(s.contains("reason-spam"));
        assert!(s.contains("reason-hate-speech"));
        // Order: action_id 50 (newer) appears before 42 (older) in
        // the rendered output.
        let pos_50 = s.find("50").expect("action 50 row present");
        let pos_42 = s.find(" 42 ").expect("action 42 row present");
        assert!(pos_50 < pos_42, "most-recent action renders first");
    }

    #[test]
    fn format_labels_json_returns_only_active_labels_array() {
        // The JSON output is the activeLabels array, not the full
        // strikes envelope. Operators wanting the full state use
        // `cairn moderator strikes --json`.
        let mut resp = empty_strikes_response();
        resp.current_strike_count = 7; // would-be-noisy field in full envelope
        resp.active_labels.push(ActiveLabelView {
            val: "!takedown".into(),
            action_id: 42,
            action_type: "takedown".into(),
            reason_codes: vec!["spam".into()],
            expires_at: None,
        });
        let json = format_labels_json(&resp);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array(), "labels JSON is the array, not the envelope");
        assert_eq!(v[0]["val"], "!takedown");
        assert_eq!(v[0]["actionId"], 42);
        assert_eq!(v[0]["actionType"], "takedown");
        assert_eq!(v[0]["reasonCodes"], serde_json::json!(["spam"]));
        // currentStrikeCount must NOT appear in the labels JSON.
        let s = json.as_str();
        assert!(
            !s.contains("currentStrikeCount"),
            "labels --json drops the strikes envelope fields"
        );
    }

    #[test]
    fn format_labels_json_empty_active_labels_is_empty_array() {
        let resp = empty_strikes_response();
        let json = format_labels_json(&resp);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v, serde_json::json!([]));
    }
}
