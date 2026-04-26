//! `cairn retention sweep` — admin-side trigger for the §F4
//! retention sweep (#12).
//!
//! Wraps `tools.cairn.admin.retentionSweep`
//! (src/server/admin/retention_sweep.rs). **Admin role only** —
//! the server's auth check uses `verify_and_authorize_admin_only`,
//! so a moderator-role session file produces a 403 here.
//!
//! Pattern matches `cli/audit.rs` and `cli/report.rs` exactly:
//! typed `Input` → orchestrator (`sweep`) → typed `Response` →
//! pure `format_*` functions.

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::auth::acquire_service_auth;
use super::error::CliError;
use super::pds::PdsClient;
use super::session::SessionFile;

const RETENTION_SWEEP_LXM: &str = "tools.cairn.admin.retentionSweep";

/// Wire-shape of a `retentionSweep` response. Mirrors the
/// server's `Output` struct (camelCase JSON, snake_case Rust).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SweepResponse {
    /// Total rows deleted across all batches.
    #[serde(rename = "rowsDeleted")]
    pub rows_deleted: i64,
    /// Number of batched DELETE round-trips issued.
    pub batches: u64,
    /// Wall-clock duration of the full sweep, in milliseconds.
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    /// Cutoff days actually applied. `None` when the labeler was
    /// started with no retention cutoff configured (sweep is a
    /// no-op and the server omits the field).
    #[serde(
        rename = "retentionDaysApplied",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub retention_days_applied: Option<u32>,
}

/// Input to `cairn retention sweep`. The HTTP endpoint takes no
/// per-call parameters — the cutoff is whatever `retention_days`
/// the labeler was started with — but we keep the typed input so
/// session-related overrides have a place to live.
#[derive(Debug, Clone, Default)]
pub struct SweepInput {
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Trigger a retention sweep via the admin HTTP endpoint.
///
/// Wraps the `tools.cairn.admin.retentionSweep` handler at
/// [src/server/admin/retention_sweep.rs](..) — POST with empty
/// JSON body; server enforces ADMIN role
/// (`verify_and_authorize_admin_only`), runs `WriterHandle::sweep`
/// in the writer task, writes one audit row, and returns the
/// aggregate `SweepResponse`.
pub async fn sweep(
    session: &mut SessionFile,
    session_path: &Path,
    input: SweepInput,
) -> Result<SweepResponse, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, RETENTION_SWEEP_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{RETENTION_SWEEP_LXM}");
    let client = Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .expect("reqwest build");
    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .header("content-type", "application/json")
        .body("{}")
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
    serde_json::from_slice::<SweepResponse>(&bytes)
        .map_err(|source| CliError::MalformedResponse { url, source })
}

/// Human-readable single-line summary for `cairn retention sweep`.
/// Renders an explicit "no cutoff configured" note when the server
/// omits `retentionDaysApplied`, since "0 rows deleted" otherwise
/// hides the difference between "all rows in retention" and
/// "retention is off".
pub fn format_sweep_human(resp: &SweepResponse) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = write!(
        s,
        "rows_deleted={} batches={} duration_ms={}",
        resp.rows_deleted, resp.batches, resp.duration_ms,
    );
    match resp.retention_days_applied {
        Some(days) => {
            let _ = write!(s, " retention_days={days}");
        }
        None => {
            let _ = write!(s, " (no retention cutoff configured; sweep was a no-op)");
        }
    }
    s
}

/// JSON envelope for `cairn retention sweep`.
pub fn format_sweep_json(resp: &SweepResponse) -> String {
    serde_json::to_string_pretty(resp).expect("SweepResponse serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_human_shows_retention_days_when_present() {
        let resp = SweepResponse {
            rows_deleted: 42,
            batches: 3,
            duration_ms: 87,
            retention_days_applied: Some(180),
        };
        let s = format_sweep_human(&resp);
        assert!(s.contains("rows_deleted=42"));
        assert!(s.contains("batches=3"));
        assert!(s.contains("retention_days=180"));
    }

    #[test]
    fn format_human_notes_no_cutoff_when_field_absent() {
        let resp = SweepResponse {
            rows_deleted: 0,
            batches: 1,
            duration_ms: 0,
            retention_days_applied: None,
        };
        let s = format_sweep_human(&resp);
        assert!(s.contains("rows_deleted=0"));
        assert!(s.contains("no retention cutoff configured"));
    }

    #[test]
    fn format_json_omits_retention_days_when_none() {
        let resp = SweepResponse {
            rows_deleted: 0,
            batches: 1,
            duration_ms: 0,
            retention_days_applied: None,
        };
        let json = format_sweep_json(&resp);
        assert!(
            !json.contains("retentionDaysApplied"),
            "skip_serializing_if drops the field"
        );
    }

    #[test]
    fn deserializes_server_camelcase_shape() {
        let body = r#"{"rowsDeleted":7,"batches":2,"durationMs":15,"retentionDaysApplied":30}"#;
        let r: SweepResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.rows_deleted, 7);
        assert_eq!(r.batches, 2);
        assert_eq!(r.duration_ms, 15);
        assert_eq!(r.retention_days_applied, Some(30));
    }
}
