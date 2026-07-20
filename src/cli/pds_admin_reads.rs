//! `cairn pds-admin events query` / `cairn pds-admin statuses query`
//! (v1.8.3, §4.6 / Workstream C) — the first consumers of the
//! read-side trait methods.
//!
//! Unlike the pds-admin *action* subcommands (which go through the
//! recordAction HTTP path so the writer task owns dispatch + audit),
//! the read subcommands construct the configured backend directly
//! and query the upstream PDS: reads are non-mutating, write no
//! `pds_admin_audit` rows, and need no recordAction round-trip.
//!
//! Flow per command: resolve `[pds_admin]` policy → construct the
//! configured backend → probe (populates the capability set the
//! read dispatch gates on) → query → print the response as pretty
//! JSON (camelCase, matching Aurora's wire). `OzoneBackend` returns
//! `Unsupported` from the read methods (exit code
//! `BACKEND_UNSUPPORTED`); the probe step is skipped for Ozone
//! since its reads never dispatch.

use crate::cli::error::CliError;
use crate::config::Config;
use crate::pds_admin::rust::read_types::{
    EventWithContext, PaginatedResponse, QueryEventsFilter, QueryStatusesFilter, StatusWithContext,
};
use crate::pds_admin::{
    OzoneBackend, PdsAdminBackend, PdsAdminBackendConfig, PdsAdminPolicy, RustBackend,
};

/// Construct the configured backend for a direct CLI read.
///
/// Requires `[pds_admin].enabled = true` with a resolvable backend
/// (same three boot gates as `cairn serve`; `RustBackend::new` here
/// reads the signing-key env var). For the Rust backend, runs the
/// startup probe so the capability set is populated before the
/// read dispatch's capability gate runs.
async fn backend_for_reads(config: &Config) -> Result<Box<dyn PdsAdminBackend>, CliError> {
    let policy = PdsAdminPolicy::from_config(config)
        .map_err(|e| CliError::Config(format!("pds_admin policy: {e}")))?;
    if !policy.enabled {
        return Err(CliError::Config(
            "[pds_admin].enabled = false — the read subcommands query the configured \
             PDS-admin backend; enable the bridge and configure a backend first"
                .to_string(),
        ));
    }
    let backend_config = policy
        .backend
        .as_ref()
        .ok_or_else(|| CliError::Config("pds_admin enabled but no backend resolved".to_string()))?;
    match backend_config {
        PdsAdminBackendConfig::Ozone(cfg) => {
            // Reads are Unsupported on Ozone; construct anyway so
            // the error comes from the trait method (uniform exit
            // path + message), not a bespoke CLI branch.
            let backend = OzoneBackend::new(cfg)
                .map_err(|e| CliError::Config(format!("ozone backend: {e}")))?;
            Ok(Box::new(backend))
        }
        PdsAdminBackendConfig::Rust(cfg) => {
            let backend = RustBackend::new(cfg)
                .map_err(|e| CliError::Config(format!("rust backend: {e}")))?;
            // Probe populates the capability set the read gate
            // checks. A probe failure is surfaced directly — the
            // operator's next step is the same as for a failed
            // read (fix connectivity/auth/capability).
            backend.probe().await?;
            Ok(Box::new(backend))
        }
    }
}

/// Append a pagination hint when more pages remain.
fn with_pagination_hint(mut rendered: String, cursor: Option<&str>) -> String {
    if let Some(cursor) = cursor {
        rendered.push_str(&format!(
            "\n// more pages remain — re-run with --cursor {cursor}"
        ));
    }
    rendered
}

/// `cairn pds-admin events query` body. Returns the rendered
/// stdout payload.
pub async fn events_query(
    config: &Config,
    filter: QueryEventsFilter,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let page: PaginatedResponse<EventWithContext> =
        backend.query_events(filter, cursor, limit).await?;
    let rendered = serde_json::to_string_pretty(&page)
        .map_err(|e| CliError::Config(format!("render response: {e}")))?;
    Ok(with_pagination_hint(rendered, page.cursor.as_deref()))
}

/// `cairn pds-admin statuses query` body.
pub async fn statuses_query(
    config: &Config,
    filter: QueryStatusesFilter,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let page: PaginatedResponse<StatusWithContext> =
        backend.query_statuses(filter, cursor, limit).await?;
    let rendered = serde_json::to_string_pretty(&page)
        .map_err(|e| CliError::Config(format!("render response: {e}")))?;
    Ok(with_pagination_hint(rendered, page.cursor.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_hint_appended_only_when_cursor_present() {
        let with = with_pagination_hint("{}".to_string(), Some("abc"));
        assert!(with.contains("--cursor abc"));
        let without = with_pagination_hint("{}".to_string(), None);
        assert_eq!(without, "{}");
    }
}
