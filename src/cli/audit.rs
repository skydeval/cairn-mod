//! `cairn audit list` — admin-side audit log queries (#6).
//!
//! Wraps `tools.cairn.admin.listAuditLog`
//! (src/server/admin/list_audit_log.rs). **Admin role only** —
//! the server's auth check uses `verify_and_authorize_admin_only`,
//! so a moderator-role session file produces a 403 here. Document
//! the contract in user-facing surfaces (#6 README + design-doc
//! sections).
//!
//! Query parameters mirror the handler's `Params`: optional
//! `actor`, `action`, `outcome`, `since` (RFC-3339, server parses
//! to ms via `parse_rfc3339_ms`), `until` (same), `limit`, `cursor`.
//! The CLI passes RFC-3339 strings through; no client-side
//! conversion. `outcome` is `"success"` or `"failure"`.
//!
//! Pattern matches `cli/report.rs` exactly: typed `Input` →
//! `list()` orchestrator → typed `Response` → pure `format_*`
//! functions.

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::error::CliError;
use super::pds::{PdsClient, PdsError};
use super::session::SessionFile;

const LIST_AUDIT_LOG_LXM: &str = "tools.cairn.admin.listAuditLog";

/// Wire-shape of one row in a `listAuditLog` response. Mirrors
/// the server's `AuditEntry` projection.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditEntry {
    /// Audit row primary key (monotonic, also the cursor unit).
    pub id: i64,
    /// RFC-3339 UTC timestamp the row was committed.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Audit action discriminator (e.g. `"label_applied"`,
    /// `"report_resolved"`, `"reporter_flagged"`).
    pub action: String,
    /// DID of the moderator/admin/operator that triggered the
    /// action.
    #[serde(rename = "actorDid")]
    pub actor_did: String,
    /// Optional target identifier (DID or AT-URI; depends on
    /// action).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    /// Optional CID pin on the target (for record-targeted
    /// actions like label-apply with strongRef).
    #[serde(rename = "targetCid", skip_serializing_if = "Option::is_none", default)]
    pub target_cid: Option<String>,
    /// `"success"` or `"failure"`.
    pub outcome: String,
    /// Free-text or JSON payload describing the action; schema
    /// per-action (see `crate::writer::AUDIT_REASON_*`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

/// `listAuditLog` response envelope.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuditListResponse {
    /// Matched entries, newest first.
    pub entries: Vec<AuditEntry>,
    /// Opaque next-page cursor. Present iff more results
    /// available.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cursor: Option<String>,
}

/// Input to `cairn audit list`.
#[derive(Debug, Clone, Default)]
pub struct AuditListInput {
    /// Filter by actor DID. Server matches exact equality.
    pub actor: Option<String>,
    /// Filter by action discriminator (e.g. `"label_applied"`).
    /// Server validates against `AUDIT_ACTION_VALUES`.
    pub action: Option<String>,
    /// Filter by outcome (`"success"` or `"failure"`). Server
    /// validates against `AUDIT_OUTCOME_VALUES`.
    pub outcome: Option<String>,
    /// RFC-3339 inclusive lower bound on `created_at`.
    pub since: Option<String>,
    /// RFC-3339 inclusive upper bound on `created_at`.
    pub until: Option<String>,
    /// Max rows to return. Server clamps to [1, 250]; default 50.
    pub limit: Option<i64>,
    /// Opaque pagination cursor from a prior response.
    pub cursor: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Query the audit log via the admin HTTP endpoint.
///
/// Wraps the `tools.cairn.admin.listAuditLog` handler at
/// [src/server/admin/list_audit_log.rs](..) — GET with
/// query-string filters; server enforces ADMIN role
/// (`verify_and_authorize_admin_only`), validates the
/// `action` / `outcome` enums, parses `since` / `until` from
/// RFC-3339, and returns a newest-first page with optional
/// `cursor` for the next call.
pub async fn list(
    session: &mut SessionFile,
    session_path: &Path,
    input: AuditListInput,
) -> Result<AuditListResponse, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, LIST_AUDIT_LOG_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{LIST_AUDIT_LOG_LXM}");
    let limit_owned = input.limit.map(|n| n.to_string());
    let mut query: Vec<(&str, &str)> = Vec::new();
    if let Some(a) = &input.actor {
        query.push(("actor", a.as_str()));
    }
    if let Some(a) = &input.action {
        query.push(("action", a.as_str()));
    }
    if let Some(o) = &input.outcome {
        query.push(("outcome", o.as_str()));
    }
    if let Some(s) = &input.since {
        query.push(("since", s.as_str()));
    }
    if let Some(u) = &input.until {
        query.push(("until", u.as_str()));
    }
    if let Some(n) = &limit_owned {
        query.push(("limit", n.as_str()));
    }
    if let Some(c) = &input.cursor {
        query.push(("cursor", c.as_str()));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest build");
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
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::CairnStatus { url, status, body });
    }
    let bytes = resp.bytes().await.map_err(|source| CliError::Http {
        url: url.clone(),
        source,
    })?;
    serde_json::from_slice::<AuditListResponse>(&bytes)
        .map_err(|source| CliError::MalformedResponse { url, source })
}

/// Tabular human output for `cairn audit list`. Columns: id,
/// created_at, action, actor_did (truncated), outcome. Trailing
/// `next cursor: …` line when a next page exists. Reason
/// payloads are not included in the table — they're often
/// multi-line JSON; use `--json` for full inspection.
pub fn format_list_human(resp: &AuditListResponse) -> String {
    use std::fmt::Write;
    if resp.entries.is_empty() {
        let mut s = "(no audit entries)".to_string();
        if let Some(c) = &resp.cursor {
            let _ = write!(s, "\nnext cursor: {c}");
        }
        return s;
    }
    let id_w = resp
        .entries
        .iter()
        .map(|e| e.id.to_string().len())
        .max()
        .unwrap_or(2)
        .max(2);
    let action_w = resp
        .entries
        .iter()
        .map(|e| e.action.len().min(28))
        .max()
        .unwrap_or(6)
        .max(6);
    let actor_w = resp
        .entries
        .iter()
        .map(|e| e.actor_did.len().min(40))
        .max()
        .unwrap_or(8)
        .max(8);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:>id_w$}  {:<24}  {:<action_w$}  {:<actor_w$}  {:<7}",
        "ID",
        "CREATED_AT",
        "ACTION",
        "ACTOR_DID",
        "OUTCOME",
        id_w = id_w,
        action_w = action_w,
        actor_w = actor_w,
    );
    for e in &resp.entries {
        let action = truncate(&e.action, 28);
        let actor = truncate(&e.actor_did, 40);
        let _ = writeln!(
            s,
            "{:>id_w$}  {:<24}  {:<action_w$}  {:<actor_w$}  {:<7}",
            e.id,
            e.created_at,
            action,
            actor,
            e.outcome,
            id_w = id_w,
            action_w = action_w,
            actor_w = actor_w,
        );
    }
    if let Some(c) = &resp.cursor {
        let _ = write!(s, "next cursor: {c}");
    } else if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// JSON envelope for `cairn audit list`.
pub fn format_list_json(resp: &AuditListResponse) -> String {
    serde_json::to_string_pretty(resp).expect("AuditListResponse serializes")
}

// ============================================================
// Shared helpers (mirror src/cli/report.rs)
// ============================================================

/// Char-aware right-truncation with trailing `…`. Local copy of
/// the helper in `cli/report.rs` — left as duplication for v1.1;
/// factor when 6+ identical copies exist (per session N3).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

/// §5.3 auto-refresh helper. Same shape as the one in
/// `cli/report.rs`; not factored to a shared module yet (per
/// session N3 — duplication threshold not yet hit).
async fn acquire_service_auth(
    pds: &PdsClient,
    session: &mut SessionFile,
    session_path: &Path,
    lxm: &str,
) -> Result<String, CliError> {
    match pds
        .get_service_auth(&session.access_jwt, &session.cairn_service_did, lxm)
        .await
    {
        Ok(t) => Ok(t),
        Err(PdsError::Unauthorized {
            context: "getServiceAuth",
            ..
        }) => {
            let refreshed = pds.refresh_session(&session.refresh_jwt).await?;
            session.access_jwt = refreshed.access_jwt;
            session.refresh_jwt = refreshed.refresh_jwt;
            session.save(session_path)?;
            Ok(pds
                .get_service_auth(&session.access_jwt, &session.cairn_service_did, lxm)
                .await?)
        }
        Err(other) => Err(other.into()),
    }
}
