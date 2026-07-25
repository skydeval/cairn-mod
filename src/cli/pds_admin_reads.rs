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
    AppealDetail, AppealView, EventWithContext, ListAppealsFilter, PaginatedResponse,
    QueryEventsFilter, QueryStatusesFilter, StatusWithContext, SubjectContextResponse,
    SubjectHistoryFilter,
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
pub async fn backend_for_reads(config: &Config) -> Result<Box<dyn PdsAdminBackend>, CliError> {
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
    kryphocron_only: bool,
) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let mut page: PaginatedResponse<EventWithContext> =
        backend.query_events(filter, cursor, limit).await?;
    if kryphocron_only {
        retain_kryphocron_events(&mut page.items);
    }
    let rendered = serde_json::to_string_pretty(&page)
        .map_err(|e| CliError::Config(format!("render response: {e}")))?;
    Ok(with_pagination_hint(rendered, page.cursor.as_deref()))
}

/// Prefix marking Aurora's kryphocron moderation events. All 12
/// `kryphocron_*` `event_type` values (Aurora `admin/events.rs:249-262`)
/// share it, so a prefix test both selects the current set and admits
/// future kryphocron event types without a hand-maintained list.
const KRYPHOCRON_EVENT_PREFIX: &str = "kryphocron_";

/// Client-side `--kryphocron-only` filter (v1.8.14 §7.3): keep only
/// events whose `event_type` is a kryphocron moderation event. Applied
/// to the fetched page because Aurora's `event_type` filter matches one
/// exact value, not a prefix.
fn retain_kryphocron_events(items: &mut Vec<EventWithContext>) {
    items.retain(|e| e.event_type.starts_with(KRYPHOCRON_EVENT_PREFIX));
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

/// `cairn pds-admin events get <id>` body (v1.8.4). Single fetch —
/// no pagination hint; the response is one `EventWithContext`.
pub async fn events_get(config: &Config, event_id: i64) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let event: EventWithContext = backend.get_event(event_id).await?;
    serde_json::to_string_pretty(&event)
        .map_err(|e| CliError::Config(format!("render response: {e}")))
}

/// `cairn pds-admin subjects context <did>` body (v1.8.4).
/// Account-scoped: the query parameter is a plain DID (Aurora's
/// `GetSubjectContextParams { did }`).
pub async fn subjects_context(config: &Config, did: &str) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let context: SubjectContextResponse = backend.get_subject_context(did).await?;
    serde_json::to_string_pretty(&context)
        .map_err(|e| CliError::Config(format!("render response: {e}")))
}

/// `cairn pds-admin subjects history <did>` body (v1.8.4). The
/// history rows are **action rows** (`StatusWithContext`), not
/// events — same element type as `statuses query`.
pub async fn subjects_history(
    config: &Config,
    did: &str,
    filter: SubjectHistoryFilter,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let page: PaginatedResponse<StatusWithContext> = backend
        .get_subject_history(did, filter, cursor, limit)
        .await?;
    let rendered = serde_json::to_string_pretty(&page)
        .map_err(|e| CliError::Config(format!("render response: {e}")))?;
    Ok(with_pagination_hint(rendered, page.cursor.as_deref()))
}

/// `cairn pds-admin appeals list` body (v1.8.4).
pub async fn appeals_list(
    config: &Config,
    filter: ListAppealsFilter,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let page: PaginatedResponse<AppealView> = backend.list_appeals(filter, cursor, limit).await?;
    let rendered = serde_json::to_string_pretty(&page)
        .map_err(|e| CliError::Config(format!("render response: {e}")))?;
    Ok(with_pagination_hint(rendered, page.cursor.as_deref()))
}

/// `cairn pds-admin appeals get <id>` body (v1.8.4). Single fetch;
/// the response is an `AppealDetail` (list-view fields + timeline).
pub async fn appeals_get(config: &Config, appeal_id: i64) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let detail: AppealDetail = backend.get_appeal(appeal_id).await?;
    serde_json::to_string_pretty(&detail)
        .map_err(|e| CliError::Config(format!("render response: {e}")))
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

    fn event(event_type: &str) -> EventWithContext {
        EventWithContext {
            id: 1,
            event_type: event_type.to_string(),
            actor_did: "did:plc:actor".to_string(),
            actor_handle: None,
            subject: None,
            subject_handle: None,
            details: serde_json::Value::Null,
            created_at: "2026-07-25T00:00:00.000Z".to_string(),
        }
    }

    /// Aurora's 12 kryphocron `event_type` values on the queryEvents
    /// surface (`admin/events.rs:249-262` @ Aurora 2ffeb1a). Pinned so a
    /// drift in the substrate vocabulary trips this test. All share the
    /// `kryphocron_` prefix the `--kryphocron-only` filter keys on.
    const KRYPHOCRON_EVENT_TYPES: &[&str] = &[
        "kryphocron_bind_granted",
        "kryphocron_bind_denied",
        "kryphocron_audience_check_denied",
        "kryphocron_reborrow_failed",
        "kryphocron_composite_rollback_marker",
        "kryphocron_audience_updated",
        "kryphocron_block_changed",
        "kryphocron_mute_changed",
        "kryphocron_threadgate_changed",
        "kryphocron_fallback",
        "kryphocron_recovery_write",
        "kryphocron_system_cleanup",
    ];

    #[test]
    fn all_twelve_kryphocron_event_types_share_the_filter_prefix() {
        assert_eq!(KRYPHOCRON_EVENT_TYPES.len(), 12);
        for et in KRYPHOCRON_EVENT_TYPES {
            assert!(
                et.starts_with(KRYPHOCRON_EVENT_PREFIX),
                "{et} must carry the kryphocron_ prefix"
            );
        }
    }

    #[test]
    fn retain_kryphocron_events_keeps_only_kryphocron() {
        let mut items = vec![
            event("account_takedown"),
            event("kryphocron_bind_granted"),
            event("record_takedown"),
            event("kryphocron_system_cleanup"),
        ];
        retain_kryphocron_events(&mut items);
        assert_eq!(items.len(), 2);
        assert!(
            items
                .iter()
                .all(|e| e.event_type.starts_with("kryphocron_"))
        );
    }

    #[test]
    fn retain_kryphocron_events_keeps_all_twelve() {
        let mut items: Vec<_> = KRYPHOCRON_EVENT_TYPES.iter().map(|t| event(t)).collect();
        retain_kryphocron_events(&mut items);
        assert_eq!(items.len(), 12);
    }

    #[test]
    fn retain_kryphocron_events_empties_a_non_kryphocron_page() {
        let mut items = vec![event("account_takedown"), event("label_applied")];
        retain_kryphocron_events(&mut items);
        assert!(items.is_empty());
    }
}
