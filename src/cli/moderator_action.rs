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
}
