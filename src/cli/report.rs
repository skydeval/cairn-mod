//! `cairn report create` — submit a `com.atproto.moderation.createReport`.
//!
//! Flow:
//! 1. Load session (required).
//! 2. Mint a fresh service auth JWT via PDS `getServiceAuth`. On
//!    401 at this step, try `refreshSession` once, persist the
//!    rotated tokens atomically (§5.3 auto-refresh path), retry.
//! 3. POST the report to Cairn. Return the server's response body
//!    so the caller can print either the ID or a `--json` echo.

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
    let token = acquire_service_auth(&pds, session, session_path).await?;

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

/// §5.3 auto-refresh: on a 401 from `getServiceAuth`, call
/// `refreshSession` once, persist the rotated tokens atomically,
/// and retry. A 401 on the retry — or any failure on
/// `refreshSession` itself — surfaces as the underlying error so
/// the exit-code mapping in [`CliError`] can classify it as AUTH
/// (triggering the "run `cairn login`" message at the dispatcher).
async fn acquire_service_auth(
    pds: &PdsClient,
    session: &mut SessionFile,
    session_path: &Path,
) -> Result<String, CliError> {
    match pds
        .get_service_auth(
            &session.access_jwt,
            &session.cairn_service_did,
            CREATE_REPORT_LXM,
        )
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
                .get_service_auth(
                    &session.access_jwt,
                    &session.cairn_service_did,
                    CREATE_REPORT_LXM,
                )
                .await?)
        }
        Err(other) => Err(other.into()),
    }
}

/// Machine-readable `--json` renderer. Extracted so main.rs can
/// choose between this and a human-readable line.
pub fn format_json(resp: &CreateReportResponse) -> String {
    serde_json::to_string_pretty(resp).expect("CreateReportResponse serializes")
}

/// Human-readable one-liner — default output when `--json` is not
/// set.
pub fn format_human(resp: &CreateReportResponse) -> String {
    format!("Report {} created at {}", resp.id, resp.created_at)
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
