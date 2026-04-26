//! `cairn audit list` (#6) and `cairn audit show <id>` (#26) —
//! admin-side audit log queries.
//!
//! Wrap `tools.cairn.admin.listAuditLog`
//! (src/server/admin/list_audit_log.rs) and
//! `tools.cairn.admin.getAuditLog` (src/server/admin/get_audit_log.rs).
//! **Admin role only** — the server's auth check uses
//! `verify_and_authorize_admin_only`, so a moderator-role session
//! file produces a 403 surfaced as `CliError::CairnStatus { status: 403, .. }`.
//!
//! `list` query parameters mirror the handler's `Params`: optional
//! `actor`, `action`, `outcome`, `since` (RFC-3339, server parses
//! to ms via `parse_rfc3339_ms`), `until` (same), `limit`, `cursor`.
//! The CLI passes RFC-3339 strings through; no client-side
//! conversion. `outcome` is `"success"` or `"failure"`.
//!
//! `show` takes a single `id` query param and returns the bare
//! `auditEntry` shape (no envelope). On an unknown id the server
//! returns `AuditEntryNotFound` 404, which surfaces as
//! `CliError::CairnStatus { status: 404, body: "{\"error\":\"AuditEntryNotFound\",..}" }`
//! — distinct from the 403 mod-role posture.
//!
//! Pattern matches `cli/report.rs` exactly: typed `Input` →
//! `list()` / `show()` orchestrator → typed `Response` → pure
//! `format_*` functions.

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::auth::acquire_service_auth;
use super::error::CliError;
use super::output::truncate;
use super::pds::PdsClient;
use super::session::SessionFile;

const LIST_AUDIT_LOG_LXM: &str = "tools.cairn.admin.listAuditLog";
const GET_AUDIT_LOG_LXM: &str = "tools.cairn.admin.getAuditLog";

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
    /// Hex-encoded SHA-256 (64 lowercase chars) of the prior row's
    /// row_hash. Absent for pre-v1.3 / pre-rebuild rows — the
    /// trust-horizon convention from #39/#40. Present rows always
    /// carry both this and `row_hash`.
    #[serde(rename = "prevHash", skip_serializing_if = "Option::is_none", default)]
    pub prev_hash: Option<String>,
    /// Hex-encoded SHA-256 (64 lowercase chars) of
    /// `prevHash || dag_cbor_canonical(row_content)`. Absent for
    /// pre-v1.3 / pre-rebuild rows.
    #[serde(rename = "rowHash", skip_serializing_if = "Option::is_none", default)]
    pub row_hash: Option<String>,
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
// `cairn audit show <id>` — wraps tools.cairn.admin.getAuditLog
// (src/server/admin/get_audit_log.rs). Admin role required.
// Returns the bare auditEntry shape (no envelope).
// ============================================================

/// Input to `cairn audit show`.
#[derive(Debug, Clone)]
pub struct AuditShowInput {
    /// Audit row primary key to fetch.
    pub id: i64,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Fetch a single audit log entry by id via the admin HTTP endpoint.
///
/// Wraps the `tools.cairn.admin.getAuditLog` handler at
/// [src/server/admin/get_audit_log.rs](..) — GET with `id` query
/// param; server enforces ADMIN role
/// (`verify_and_authorize_admin_only`) and returns
/// `AuditEntryNotFound` 404 on unknown id, surfaced here as
/// `CliError::CairnStatus { status: 404, body: ... }` with the
/// server's typed error name in the body.
pub async fn show(
    session: &mut SessionFile,
    session_path: &Path,
    input: AuditShowInput,
) -> Result<AuditEntry, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, GET_AUDIT_LOG_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{GET_AUDIT_LOG_LXM}");
    let id_str = input.id.to_string();
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest build");
    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .query(&[("id", id_str.as_str())])
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
    serde_json::from_slice::<AuditEntry>(&bytes)
        .map_err(|source| CliError::MalformedResponse { url, source })
}

/// Multi-line field/value output for `cairn audit show`. Includes
/// every field present on the entry; omits absent payload optionals
/// (target, targetCid, reason). `reason` is rendered as-is — when
/// it's structured JSON, use `--json` to pipe through `jq`.
///
/// `prev_hash` and `row_hash` (#42, v1.3) are always rendered: if
/// the row is pre-attestation (NULL hashes), the value is shown as
/// `(pre-attestation)` so the operator sees the trust horizon
/// explicitly rather than inferring it from a missing line. Hex
/// values are full 64-char lowercase strings; the genesis row's
/// `prev_hash` is the all-zeros sentinel (see #39).
pub fn format_show_human(entry: &AuditEntry) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "Audit entry {}", entry.id);
    let _ = writeln!(s, "  created_at:  {}", entry.created_at);
    let _ = writeln!(s, "  action:      {}", entry.action);
    let _ = writeln!(s, "  actor_did:   {}", entry.actor_did);
    let _ = writeln!(s, "  outcome:     {}", entry.outcome);
    if let Some(t) = &entry.target {
        let _ = writeln!(s, "  target:      {t}");
    }
    if let Some(c) = &entry.target_cid {
        let _ = writeln!(s, "  target_cid:  {c}");
    }
    if let Some(r) = &entry.reason {
        let _ = writeln!(s, "  reason:      {r}");
    }
    let _ = writeln!(
        s,
        "  prev_hash:   {}",
        entry
            .prev_hash
            .as_deref()
            .unwrap_or(PRE_ATTESTATION_DISPLAY)
    );
    let _ = write!(
        s,
        "  row_hash:    {}",
        entry.row_hash.as_deref().unwrap_or(PRE_ATTESTATION_DISPLAY)
    );
    s
}

/// Sentinel rendered in `format_show_human` for pre-attestation
/// rows (those with NULL `prev_hash` / `row_hash`). Chosen over
/// `null` / `<empty>` because absence is operationally meaningful —
/// the trust horizon — and a sentinel that reads as a deliberate
/// label rather than a missing field surfaces that meaning.
const PRE_ATTESTATION_DISPLAY: &str = "(pre-attestation)";

/// JSON output for `cairn audit show`. Pretty-printed for shell
/// readability; `jq` consumers see the canonical wire shape.
pub fn format_show_json(entry: &AuditEntry) -> String {
    serde_json::to_string_pretty(entry).expect("AuditEntry serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(reason: Option<&str>) -> AuditEntry {
        AuditEntry {
            id: 42,
            created_at: "2026-04-23T00:00:00.000Z".into(),
            action: "label_applied".into(),
            actor_did: "did:plc:moderator0000000000000000".into(),
            target: Some("at://did:plc:target/col/rec".into()),
            target_cid: Some("bafytest".into()),
            outcome: "success".into(),
            reason: reason.map(str::to_string),
            // Mid-chain row: both hashes present as 64-char hex.
            prev_hash: Some("a".repeat(64)),
            row_hash: Some("b".repeat(64)),
        }
    }

    #[test]
    fn format_show_human_includes_all_present_fields() {
        let s = format_show_human(&sample(Some(r#"{"val":"spam"}"#)));
        assert!(s.contains("Audit entry 42"));
        assert!(s.contains("created_at:  2026-04-23T00:00:00.000Z"));
        assert!(s.contains("action:      label_applied"));
        assert!(s.contains("actor_did:   did:plc:moderator0000000000000000"));
        assert!(s.contains("outcome:     success"));
        assert!(s.contains("target:      at://did:plc:target/col/rec"));
        assert!(s.contains("target_cid:  bafytest"));
        assert!(s.contains(r#"reason:      {"val":"spam"}"#));
        assert!(s.contains(&format!("prev_hash:   {}", "a".repeat(64))));
        assert!(s.contains(&format!("row_hash:    {}", "b".repeat(64))));
    }

    #[test]
    fn format_show_human_omits_absent_optionals() {
        let mut e = sample(None);
        e.target = None;
        e.target_cid = None;
        let s = format_show_human(&e);
        assert!(!s.contains("target:"));
        assert!(!s.contains("target_cid:"));
        assert!(!s.contains("reason:"));
    }

    #[test]
    fn format_show_human_pre_attestation_row_renders_sentinel() {
        // Pre-v1.3 / pre-rebuild row: NULL hashes. Display must show
        // the sentinel so operators see the trust horizon explicitly
        // — never silently omit (which would read as "field missing"
        // rather than "row pre-dates attestation").
        let mut e = sample(None);
        e.prev_hash = None;
        e.row_hash = None;
        let s = format_show_human(&e);
        assert!(
            s.contains("prev_hash:   (pre-attestation)"),
            "missing pre-attestation sentinel for prev_hash: {s}"
        );
        assert!(
            s.contains("row_hash:    (pre-attestation)"),
            "missing pre-attestation sentinel for row_hash: {s}"
        );
    }

    #[test]
    fn format_show_human_genesis_row_renders_zero_sentinel_verbatim() {
        // Row id=1 (genesis) carries the all-zeros prev_hash sentinel
        // (see #39). Display it as-is — keen-eyed operators recognize
        // the sentinel; special-casing creates yet another display
        // path to maintain.
        let mut e = sample(None);
        e.id = 1;
        e.prev_hash = Some("0".repeat(64));
        e.row_hash = Some("c".repeat(64));
        let s = format_show_human(&e);
        assert!(s.contains("Audit entry 1"));
        assert!(s.contains(&format!("prev_hash:   {}", "0".repeat(64))));
        assert!(s.contains(&format!("row_hash:    {}", "c".repeat(64))));
        assert!(
            !s.contains("genesis"),
            "genesis row must not be special-cased in display: {s}"
        );
    }

    #[test]
    fn format_show_json_round_trips_with_hashes() {
        let e = sample(Some(r#"{"val":"spam","neg":false}"#));
        let json = format_show_json(&e);
        let parsed: AuditEntry = serde_json::from_str(&json).expect("round trip");
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.action, "label_applied");
        assert_eq!(
            parsed.target.as_deref(),
            Some("at://did:plc:target/col/rec")
        );
        assert_eq!(
            parsed.reason.as_deref(),
            Some(r#"{"val":"spam","neg":false}"#)
        );
        assert_eq!(parsed.prev_hash.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!(parsed.row_hash.as_deref(), Some("b".repeat(64).as_str()));
        // The on-wire JSON must use camelCase per the lexicon.
        assert!(
            json.contains("\"prevHash\""),
            "wire JSON must use camelCase prevHash: {json}"
        );
        assert!(
            json.contains("\"rowHash\""),
            "wire JSON must use camelCase rowHash: {json}"
        );
    }

    #[test]
    fn format_show_json_pre_attestation_row_omits_hash_fields() {
        let mut e = sample(None);
        e.prev_hash = None;
        e.row_hash = None;
        let json = format_show_json(&e);
        assert!(
            !json.contains("prevHash"),
            "pre-attestation: prevHash must be field-absent: {json}"
        );
        assert!(
            !json.contains("rowHash"),
            "pre-attestation: rowHash must be field-absent: {json}"
        );
    }
}
