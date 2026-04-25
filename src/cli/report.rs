//! `cairn report {create, list, view, resolve, flag, unflag}` — thin
//! wrappers over the moderation + admin XRPC endpoints Cairn exposes
//! (#7 + #16).
//!
//! Every subcommand follows the same flow:
//! 1. Load the session file (required).
//! 2. Mint a fresh service-auth JWT via PDS `getServiceAuth`. On
//!    401, call `refreshSession` once, persist rotated tokens
//!    atomically (§5.3 auto-refresh path), retry.
//! 3. Issue the HTTP call to Cairn with the service-auth token.
//! 4. Return a typed response the CLI dispatcher turns into
//!    human or JSON output via the per-subcommand `format_*_{human, json}`
//!    pairs.
//!
//! Each orchestrator function's doc-comment cites the handler it
//! wraps so a future reader can jump from CLI code to server code
//! without grep.

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::error::CliError;
use super::pds::{PdsClient, PdsError};
use super::session::SessionFile;

const CREATE_REPORT_LXM: &str = "com.atproto.moderation.createReport";

/// Input to `cairn report create` — wire-agnostic so the CLI flags
/// + the tests can drive it the same way.
#[derive(Debug, Clone)]
pub struct ReportCreateInput {
    /// Subject identifier: `did:*` for an account, `at://...` for a
    /// record. Must be paired with `cid` for record subjects.
    pub subject: String,
    /// Only meaningful for `at://` subjects — pins the report to a
    /// record version per §F11's strongRef shape.
    pub cid: Option<String>,
    /// Lexicon-spec reason type (e.g.,
    /// `com.atproto.moderation.defs#reasonSpam`).
    pub reason_type: String,
    /// Optional free-text body (≤2KB at Cairn per §F11, enforced
    /// server-side; the CLI does not pre-truncate).
    pub reason: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Successful `createReport` response — only the fields the CLI
/// displays. Extra fields are ignored by serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateReportResponse {
    /// Report row primary key assigned by Cairn's writer.
    pub id: i64,
    /// RFC-3339 Z timestamp when the report row was committed.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Lexicon-spec reason type Cairn echoed back (`com.atproto.
    /// moderation.defs#reason*`).
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    /// Authenticated reporter DID — the `iss` from the
    /// service-auth JWT the CLI minted.
    #[serde(rename = "reportedBy")]
    pub reported_by: String,
    /// Subject union per §F11 — either a
    /// `com.atproto.admin.defs#repoRef` or a
    /// `com.atproto.repo.strongRef`. Opaque on the CLI side;
    /// displayed as JSON when `--json` is set.
    pub subject: Value,
}

/// Build the `subject` union payload per §F11. Returns
/// `CliError::Config` for malformed input — `main.rs` maps that to
/// the usage exit code (argument-shape problems surface here, not
/// as Cairn 400s).
fn build_subject(subject: &str, cid: Option<&str>) -> Result<Value, CliError> {
    if let Some(rest) = subject.strip_prefix("at://") {
        // `rest` is retained only to force validation — an empty
        // body after the prefix means the user passed literally
        // `at://`.
        if rest.is_empty() {
            return Err(CliError::Config(
                "--subject at://... must include a repo and path".into(),
            ));
        }
        let cid =
            cid.ok_or_else(|| CliError::Config("record subjects (at://...) require --cid".into()))?;
        Ok(json!({
            "$type": "com.atproto.repo.strongRef",
            "uri": subject,
            "cid": cid,
        }))
    } else if subject.starts_with("did:") {
        if cid.is_some() {
            return Err(CliError::Config(
                "--cid is not meaningful for account (did:) subjects".into(),
            ));
        }
        Ok(json!({
            "$type": "com.atproto.admin.defs#repoRef",
            "did": subject,
        }))
    } else {
        Err(CliError::Config(format!(
            "--subject must start with `did:` or `at://`; got {subject}"
        )))
    }
}

/// Submit the report. Mutates `session` in place on a mid-call
/// token refresh and persists the rotation atomically before
/// returning. `session_path` is the SAME path the caller loaded
/// from, so the file on disk stays in sync.
pub async fn create(
    session: &mut SessionFile,
    session_path: &Path,
    input: ReportCreateInput,
) -> Result<CreateReportResponse, CliError> {
    let subject = build_subject(&input.subject, input.cid.as_deref())?;
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .to_string();

    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, CREATE_REPORT_LXM).await?;

    let url = format!(
        "{}/xrpc/com.atproto.moderation.createReport",
        cairn_server.trim_end_matches('/')
    );
    let body = json!({
        "reasonType": input.reason_type,
        "reason": input.reason,
        "subject": subject,
    });

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest build");
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

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::CairnStatus { url, status, body });
    }
    let bytes = resp.bytes().await.map_err(|source| CliError::Http {
        url: url.clone(),
        source,
    })?;
    serde_json::from_slice::<CreateReportResponse>(&bytes)
        .map_err(|source| CliError::MalformedResponse { url, source })
}

/// Machine-readable `--json` renderer for `cairn report create`.
///
/// Renamed from `format_json` to `format_create_json` ahead of the
/// multi-subcommand expansion in this commit — the bare name would
/// collide with `format_list_json` / `format_view_json` added below.
pub fn format_create_json(resp: &CreateReportResponse) -> String {
    serde_json::to_string_pretty(resp).expect("CreateReportResponse serializes")
}

/// Human-readable one-liner for `cairn report create` — default
/// output when `--json` is not set.
///
/// Renamed from `format_human` to `format_create_human` ahead of the
/// multi-subcommand expansion.
pub fn format_create_human(resp: &CreateReportResponse) -> String {
    format!("Report {} created at {}", resp.id, resp.created_at)
}

// ============================================================
// `cairn report list` — wraps tools.cairn.admin.listReports
// (src/server/admin/list_reports.rs). Admin OR moderator role.
// ============================================================

const LIST_REPORTS_LXM: &str = "tools.cairn.admin.listReports";

/// Subject-union wire shape. Deserializes the server's
/// `{ $type: ..., ... }` tagged representation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "$type")]
pub enum ReportSubject {
    /// `com.atproto.admin.defs#repoRef` — account subject.
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    Repo {
        /// Subject DID.
        did: String,
    },
    /// `com.atproto.repo.strongRef` — record subject, CID-pinned.
    #[serde(rename = "com.atproto.repo.strongRef")]
    Strong {
        /// Subject AT-URI.
        uri: String,
        /// Content-address hash at report time.
        cid: String,
    },
}

/// One row in a `listReports` response. Deliberately omits the
/// `reason` field — the server's `ReportListEntry` projection drops
/// it per §F11 and the CLI's shape preserves that invariant
/// type-level.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportListEntry {
    /// Report row primary key.
    pub id: i64,
    /// RFC-3339 timestamp the report was filed.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Lexicon-spec reason type.
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    /// Subject the report targets.
    pub subject: ReportSubject,
    /// Authenticated reporter DID.
    #[serde(rename = "reportedBy")]
    pub reported_by: String,
    /// `"pending"` or `"resolved"`.
    pub status: String,
    /// When the report was resolved, if resolved.
    #[serde(
        rename = "resolvedAt",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolved_at: Option<String>,
    /// Admin / moderator DID that resolved the report.
    #[serde(
        rename = "resolvedBy",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolved_by: Option<String>,
    /// Label value applied on resolution, if any.
    #[serde(
        rename = "resolutionLabel",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolution_label: Option<String>,
    /// Free-text resolution rationale, if provided.
    #[serde(
        rename = "resolutionReason",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolution_reason: Option<String>,
}

/// Input to `cairn report list`.
#[derive(Debug, Clone, Default)]
pub struct ReportListInput {
    /// Filter by status (`"pending"` or `"resolved"`). Passed
    /// through unchanged; server rejects unknown values.
    pub status: Option<String>,
    /// Filter by reporter DID.
    pub reported_by: Option<String>,
    /// Max rows to return. Server clamps to [1, 250]; default 50.
    pub limit: Option<i64>,
    /// Opaque pagination cursor from a prior response.
    pub cursor: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// `listReports` response envelope.
#[derive(Debug, Deserialize, Serialize)]
pub struct ReportListResponse {
    /// Matched reports, newest first.
    pub reports: Vec<ReportListEntry>,
    /// Opaque next-page cursor. Present iff more results available.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cursor: Option<String>,
}

/// Query the reports table via the admin HTTP endpoint.
///
/// Wraps the `tools.cairn.admin.listReports` handler at
/// [src/server/admin/list_reports.rs](..) — GET with query-string
/// filters; server enforces role (`verify_and_authorize`, mod OR
/// admin) and the reason-leak invariant via the `ReportListEntry`
/// projection.
pub async fn list(
    session: &mut SessionFile,
    session_path: &Path,
    input: ReportListInput,
) -> Result<ReportListResponse, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, LIST_REPORTS_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{LIST_REPORTS_LXM}");
    // Build query params. Owned strings for limit because reqwest
    // wants &str bindings.
    let limit_owned = input.limit.map(|n| n.to_string());
    let mut query: Vec<(&str, &str)> = Vec::new();
    if let Some(s) = &input.status {
        query.push(("status", s.as_str()));
    }
    if let Some(r) = &input.reported_by {
        query.push(("reportedBy", r.as_str()));
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
    cairn_response::<ReportListResponse>(url, resp).await
}

/// Tabular human output for `cairn report list`. Columns: id,
/// status, reporter (truncated), subject (summary), reason-type
/// (truncated), created_at. Trailing `next cursor: …` line when
/// a next page exists.
pub fn format_list_human(resp: &ReportListResponse) -> String {
    use std::fmt::Write;
    if resp.reports.is_empty() {
        let mut s = "(no reports)".to_string();
        if let Some(c) = &resp.cursor {
            let _ = write!(s, "\nnext cursor: {c}");
        }
        return s;
    }
    let id_w = resp
        .reports
        .iter()
        .map(|e| e.id.to_string().len())
        .max()
        .unwrap_or(2)
        .max(2);
    let reporter_w = resp
        .reports
        .iter()
        .map(|e| e.reported_by.len().min(40))
        .max()
        .unwrap_or(8)
        .max(8);
    let subject_w = resp
        .reports
        .iter()
        .map(|e| subject_summary(&e.subject).len().min(40))
        .max()
        .unwrap_or(8)
        .max(8);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:>id_w$}  {:<9}  {:<reporter_w$}  {:<subject_w$}  {:<20}",
        "ID",
        "STATUS",
        "REPORTER",
        "SUBJECT",
        "CREATED_AT",
        id_w = id_w,
        reporter_w = reporter_w,
        subject_w = subject_w,
    );
    for e in &resp.reports {
        let reporter = truncate(&e.reported_by, 40);
        let subj = truncate(&subject_summary(&e.subject), 40);
        let _ = writeln!(
            s,
            "{:>id_w$}  {:<9}  {:<reporter_w$}  {:<subject_w$}  {:<20}",
            e.id,
            e.status,
            reporter,
            subj,
            e.created_at,
            id_w = id_w,
            reporter_w = reporter_w,
            subject_w = subject_w,
        );
    }
    if let Some(c) = &resp.cursor {
        let _ = write!(s, "next cursor: {c}");
    } else if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// JSON envelope for `cairn report list`.
pub fn format_list_json(resp: &ReportListResponse) -> String {
    serde_json::to_string_pretty(resp).expect("ReportListResponse serializes")
}

// ============================================================
// `cairn report view` — wraps tools.cairn.admin.getReport
// (src/server/admin/get_report.rs). Admin OR moderator role.
// ============================================================

const GET_REPORT_LXM: &str = "tools.cairn.admin.getReport";

/// Full report record — includes `reason` body (admin-authenticated
/// only, per §F11).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportDetail {
    /// Report row primary key.
    pub id: i64,
    /// RFC-3339 timestamp the report was filed.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Lexicon-spec reason type.
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    /// Free-text body. Server permits this field only for admin
    /// fetches (`getReport` / `resolveReport` response).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    /// Subject the report targets.
    pub subject: ReportSubject,
    /// Authenticated reporter DID.
    #[serde(rename = "reportedBy")]
    pub reported_by: String,
    /// `"pending"` or `"resolved"`.
    pub status: String,
    /// When the report was resolved, if resolved.
    #[serde(
        rename = "resolvedAt",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolved_at: Option<String>,
    /// Admin / moderator DID that resolved the report.
    #[serde(
        rename = "resolvedBy",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolved_by: Option<String>,
    /// Label value applied on resolution, if any.
    #[serde(
        rename = "resolutionLabel",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolution_label: Option<String>,
    /// Free-text resolution rationale, if provided.
    #[serde(
        rename = "resolutionReason",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub resolution_reason: Option<String>,
}

/// Input to `cairn report view`.
#[derive(Debug, Clone)]
pub struct ReportViewInput {
    /// Report row primary key to fetch.
    pub id: i64,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Fetch a single report record (with reason body).
///
/// Wraps the `tools.cairn.admin.getReport` handler at
/// [src/server/admin/get_report.rs](..) — GET with `id` query
/// param; server enforces role (`verify_and_authorize`, mod OR
/// admin) and returns `ReportDetail` (full body included, §F11
/// permitted for admin-authenticated access).
pub async fn view(
    session: &mut SessionFile,
    session_path: &Path,
    input: ReportViewInput,
) -> Result<ReportDetail, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, GET_REPORT_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{GET_REPORT_LXM}");
    let id_str = input.id.to_string();
    let client = build_client();
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
    cairn_response::<ReportDetail>(url, resp).await
}

/// Multi-line field/value output for `cairn report view`.
pub fn format_view_human(detail: &ReportDetail) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "Report {}", detail.id);
    let _ = writeln!(s, "  status:         {}", detail.status);
    let _ = writeln!(s, "  created_at:     {}", detail.created_at);
    let _ = writeln!(s, "  reported_by:    {}", detail.reported_by);
    let _ = writeln!(s, "  reason_type:    {}", detail.reason_type);
    if let Some(r) = &detail.reason {
        let _ = writeln!(s, "  reason:         {r}");
    }
    let _ = writeln!(s, "  subject:        {}", subject_summary(&detail.subject));
    if let Some(t) = &detail.resolved_at {
        let _ = writeln!(s, "  resolved_at:    {t}");
    }
    if let Some(by) = &detail.resolved_by {
        let _ = writeln!(s, "  resolved_by:    {by}");
    }
    if let Some(lab) = &detail.resolution_label {
        let _ = writeln!(s, "  resolution_label: {lab}");
    }
    if let Some(r) = &detail.resolution_reason {
        let _ = writeln!(s, "  resolution_reason: {r}");
    }
    if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// JSON output for `cairn report view`.
pub fn format_view_json(detail: &ReportDetail) -> String {
    serde_json::to_string_pretty(detail).expect("ReportDetail serializes")
}

// ============================================================
// `cairn report resolve` — wraps tools.cairn.admin.resolveReport
// (src/server/admin/resolve_report.rs). Admin OR moderator role.
// Resolve with `apply_label = Some(...)` to apply a label and
// resolve in one transaction; `apply_label = None` resolves
// without applying (the "dismiss" semantic in operator UX terms).
// ============================================================

const RESOLVE_REPORT_LXM: &str = "tools.cairn.admin.resolveReport";

/// Optional label-application sub-object on `cairn report resolve`.
/// Mirrors the server handler's `InputApplyLabel` shape.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyLabelArg {
    /// AT-URI or DID the label targets. Server enforces
    /// `at://` or `did:` prefix.
    pub uri: String,
    /// CID pin for record subjects. Required iff `uri` is `at://`
    /// per §F11 strongRef shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Label value. Server clamps to 1..=128 bytes and (when
    /// configured) checks against the labeler's allowlist.
    pub val: String,
    /// Optional RFC-3339 expiration for the applied label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
}

/// Input to `cairn report resolve`.
#[derive(Debug, Clone)]
pub struct ReportResolveInput {
    /// Report row primary key to resolve.
    pub id: i64,
    /// Optional inline label application. `None` resolves without
    /// applying a label (the "dismiss" workflow); `Some(_)` resolves
    /// AND applies in one server transaction.
    pub apply_label: Option<ApplyLabelArg>,
    /// Operator-facing rationale. Stored on the report row and
    /// echoed back in the response.
    pub reason: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Resolve a report.
///
/// Wraps the `tools.cairn.admin.resolveReport` handler at
/// [src/server/admin/resolve_report.rs](..) — POST body shape:
/// ```json
/// { "id": <i64>, "applyLabel": { ... }?, "reason": <string>? }
/// ```
/// Server enforces role (`verify_and_authorize`, mod OR admin),
/// validates `applyLabel.val` length + URI prefix + label-allowlist
/// pre-dispatch, and returns the resolved `ReportDetail`. Audit
/// attribution is the JWT iss the CLI's session-auth produces.
pub async fn resolve(
    session: &mut SessionFile,
    session_path: &Path,
    input: ReportResolveInput,
) -> Result<ReportDetail, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, RESOLVE_REPORT_LXM).await?;

    // Build the wire body. `applyLabel` is camelCase per the
    // lexicon; serde's rename + the Serialize derive on
    // `ApplyLabelArg` handle the rest.
    let mut body = json!({ "id": input.id });
    if let Some(apply) = &input.apply_label {
        body["applyLabel"] = serde_json::to_value(apply).expect("ApplyLabelArg serializes");
    }
    if let Some(r) = &input.reason {
        body["reason"] = json!(r);
    }

    let url = format!("{cairn_server}/xrpc/{RESOLVE_REPORT_LXM}");
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
    cairn_response::<ReportDetail>(url, resp).await
}

/// Human one-liner for `cairn report resolve`. Names whether a
/// label was applied so the operator sees the side-effect at a
/// glance.
pub fn format_resolve_human(detail: &ReportDetail) -> String {
    let label = detail
        .resolution_label
        .as_deref()
        .map(|v| format!(" with label {v}"))
        .unwrap_or_default();
    format!("Resolved report {}{}", detail.id, label)
}

/// JSON output for `cairn report resolve` — the resolved
/// [`ReportDetail`].
pub fn format_resolve_json(detail: &ReportDetail) -> String {
    serde_json::to_string_pretty(detail).expect("ReportDetail serializes")
}

// ============================================================
// Shared helpers
// ============================================================

/// Build the shared reqwest client. Centralized so the 30s
/// timeout is applied uniformly to every subcommand.
fn build_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest build")
}

/// Parse a Cairn HTTP response into a typed body, mapping non-2xx
/// to [`CliError::CairnStatus`] and JSON-parse failures to
/// [`CliError::MalformedResponse`].
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

/// Human-display summary of a report subject. Returns either the
/// DID (account subject) or `"<uri>@<cid>"` (record subject).
fn subject_summary(s: &ReportSubject) -> String {
    match s {
        ReportSubject::Repo { did } => did.clone(),
        ReportSubject::Strong { uri, cid } => format!("{uri}@{cid}"),
    }
}

/// Right-truncate `s` to `max` chars with a trailing `…` when
/// shortened. Used by the list-table renderer.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

/// Factored-out `acquire_service_auth` — takes the LXM as a
/// parameter so every subcommand in this module can reuse the
/// §5.3 auto-refresh flow. The existing per-subcommand
/// `acquire_service_auth` inside the `create` path is NOT
/// refactored away in this commit to avoid a second mechanical
/// rename; follow-up once #7's additional subcommands land.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_did_maps_to_repo_ref() {
        let v = build_subject("did:plc:example", None).unwrap();
        assert_eq!(v["$type"], "com.atproto.admin.defs#repoRef");
        assert_eq!(v["did"], "did:plc:example");
    }

    #[test]
    fn subject_at_uri_requires_cid() {
        let err = build_subject("at://did:plc:x/col/r", None).unwrap_err();
        assert!(matches!(err, CliError::Config(_)));
    }

    #[test]
    fn subject_at_uri_with_cid_maps_to_strong_ref() {
        let v = build_subject("at://did:plc:x/col/r", Some("bafy")).unwrap();
        assert_eq!(v["$type"], "com.atproto.repo.strongRef");
        assert_eq!(v["uri"], "at://did:plc:x/col/r");
        assert_eq!(v["cid"], "bafy");
    }

    #[test]
    fn subject_did_with_cid_rejected() {
        let err = build_subject("did:plc:x", Some("bafy")).unwrap_err();
        assert!(matches!(err, CliError::Config(_)));
    }

    #[test]
    fn subject_unknown_shape_rejected() {
        let err = build_subject("bsky.example/profile", None).unwrap_err();
        assert!(matches!(err, CliError::Config(_)));
    }
}
