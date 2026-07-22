//! `cairn pds-admin metrics` / `runtime get|set` /
//! `moderator-activity` (v1.8.9, v2 §6, chainlink #151).
//!
//! All four are direct-dispatch commands on the configured backend
//! (the `pds_admin_reads` scaffold — no recordAction round-trip).
//! `runtime set` is the one write: it dispatches
//! `setRuntimeSetting` (SuperAdmin upstream) and then best-effort
//! records the outcome in the local `runtime_settings_writes`
//! ledger — Aurora's own chain entry is the authoritative audit
//! record; a ledger-insert failure logs and does not fail the
//! command.
//!
//! Key posture (LB-5): no local key allowlist, no local value
//! validation — Aurora's 36-key `KNOWN_RUNTIME_KEYS` is
//! authoritative and its rejection message enumerates the known
//! keys. The `<value>` argument parses as JSON first, falling back
//! to a JSON string (so `full` and `"full"` both work and
//! structured values stay expressible).

use sqlx::{Pool, Sqlite};

use crate::cli::error::CliError;
use crate::cli::pds_admin_reads::backend_for_reads;
use crate::config::Config;
use crate::pds_admin::rust::ops_types::{
    InstanceMetrics, RuntimeSetting, SetRuntimeSettingOutcome,
};
use crate::pds_admin::rust::read_types::QueryEventsFilter;

/// Parse a CLI `<value>` argument: JSON first, string fallback.
pub fn parse_value_arg(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_string()))
}

fn opt_f64(v: Option<f64>) -> String {
    // Absence is meaningful — render as '-', never 0 (v2 §3.1).
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string())
}

fn opt_i64(v: Option<i64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string())
}

/// `cairn pds-admin metrics`.
pub async fn metrics(config: &Config, json: bool) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let m: InstanceMetrics = backend.get_instance_metrics().await?;
    if json {
        return Ok(serde_json::to_string_pretty(&m)
            .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")));
    }
    Ok(format!(
        "system health\n  status: {}  version: {}  uptime: {:.0}s\n  \
         http in-flight: {}  sessions: {}  background jobs: {}\n\
         resource usage\n  memory: {} bytes  cpu: {} s  open fds: {}\n  \
         db pool: {} ({} idle)\n\
         account growth\n  24h: {}  7d: {}  30d: {}  total: {}\n\
         federation\n  enabled: {}  relay connected: {}  known instances: {}",
        m.system_health.status,
        m.system_health.version,
        m.system_health.uptime_seconds,
        m.system_health.active_http_requests,
        m.system_health.active_sessions,
        m.system_health.active_background_jobs,
        opt_f64(m.resource_usage.memory_resident_bytes),
        opt_f64(m.resource_usage.cpu_seconds_total),
        opt_i64(m.resource_usage.open_fds),
        m.resource_usage.db_pool_size,
        m.resource_usage.db_pool_idle_connections,
        m.account_growth.signups_last_24h,
        m.account_growth.signups_last_7d,
        m.account_growth.signups_last_30d,
        m.account_growth.total_accounts,
        m.federation_health.federation_enabled,
        m.federation_health.relay_connected,
        m.federation_health.known_instances,
    ))
}

/// `cairn pds-admin runtime get <key>`.
pub async fn runtime_get(config: &Config, key: &str, json: bool) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let s: RuntimeSetting = backend.get_runtime_setting(key).await?;
    if json {
        return Ok(serde_json::to_string_pretty(&s)
            .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")));
    }
    let mut line = format!("{} = {} (source: {:?})", s.key, s.value, s.source);
    if let (Some(at), Some(by)) = (s.last_modified.as_deref(), s.last_modified_by.as_deref()) {
        line.push_str(&format!(" [last set: {at} by {by}]"));
    }
    Ok(line)
}

/// `cairn pds-admin runtime set <key> <value> --reason <R>`:
/// dispatch, then best-effort ledger insert.
pub async fn runtime_set(
    config: &Config,
    pool: &Pool<Sqlite>,
    key: &str,
    value_raw: &str,
    reason: &str,
) -> Result<String, CliError> {
    let value = parse_value_arg(value_raw);
    let backend = backend_for_reads(config).await?;
    let outcome: SetRuntimeSettingOutcome =
        backend.set_runtime_setting(key, &value, reason).await?;

    // Local ledger (v2 §5.1): best-effort — the upstream chain
    // entry is the authoritative record.
    let insert = sqlx::query(
        "INSERT INTO runtime_settings_writes (key, value, rationale, aurora_audit_entry_id)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (aurora_audit_entry_id) DO NOTHING",
    )
    .bind(&outcome.key)
    .bind(outcome.new_value.to_string())
    .bind(reason)
    .bind(&outcome.audit_entry_id)
    .execute(pool)
    .await;
    if let Err(e) = insert {
        tracing::error!(
            target: "cairn_mod::pds_admin::runtime",
            error = %e,
            audit_entry_id = %outcome.audit_entry_id,
            "runtime_settings_writes ledger insert failed; upstream chain entry \
             remains the authoritative record"
        );
    }

    Ok(format!(
        "set {} from {} to {} (upstream audit entry {})",
        outcome.key, outcome.previous_value, outcome.new_value, outcome.audit_entry_id
    ))
}

/// `cairn pds-admin moderator-activity <did>`: pages the
/// v1.8.3-shipped actor-scoped `query_events` (LB-7: CLI-only —
/// zero new trait surface) and renders a per-type summary plus
/// the rows, newest-first (Aurora's window ordering).
pub async fn moderator_activity(
    config: &Config,
    did: &str,
    after: Option<&str>,
    before: Option<&str>,
    limit: u32,
    json: bool,
) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let filter = QueryEventsFilter {
        actor: Some(did.to_string()),
        after: after.map(str::to_string),
        before: before.map(str::to_string),
        ..Default::default()
    };
    let mut events = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let remaining = (limit as usize).saturating_sub(events.len());
        if remaining == 0 {
            break;
        }
        let page = backend
            .query_events(
                filter.clone(),
                cursor.as_deref(),
                Some(remaining.min(100) as u32),
            )
            .await?;
        let empty = page.items.is_empty();
        events.extend(page.items);
        match page.cursor {
            Some(c) if !empty && events.len() < limit as usize => cursor = Some(c),
            _ => break,
        }
    }

    if json {
        return Ok(serde_json::to_string_pretty(&events)
            .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")));
    }
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for e in &events {
        *counts.entry(e.event_type.as_str()).or_default() += 1;
    }
    let mut out = format!("moderator activity for {did} — {} event(s)\n", events.len());
    for (event_type, n) in &counts {
        out.push_str(&format!("  {event_type}: {n}\n"));
    }
    for e in &events {
        out.push_str(&format!(
            "{}  #{}  {}  subject: {}  {}\n",
            e.created_at,
            e.id,
            e.event_type,
            e.subject
                .as_ref()
                .map(|s| format!("{s:?}"))
                .unwrap_or_else(|| "-".to_string()),
            e.details,
        ));
    }
    Ok(out.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn value_arg_parses_json_with_string_fallback() {
        assert_eq!(parse_value_arg("\"full\""), json!("full"));
        assert_eq!(parse_value_arg("full"), json!("full"));
        assert_eq!(parse_value_arg("true"), json!(true));
        assert_eq!(parse_value_arg("42"), json!(42));
        assert_eq!(parse_value_arg("{\"a\": 1}"), json!({"a": 1}));
        // Malformed JSON degrades to a string, not an error.
        assert_eq!(parse_value_arg("{not json"), json!("{not json"));
    }
}

// ===========================================================================
// v1.8.10 ops visibility subgroup (v2 §6, chainlink #155)
// ===========================================================================

/// Append the F19 operator hint to `Terminal` failures from the
/// capability-bare ops block: a 404 here means "this upstream
/// doesn't ship the endpoint", and describeCapabilities is
/// advisory — the honest pointer is the upstream's own output +
/// release notes.
fn with_f19_hint(nsid: &str, err: CliError) -> CliError {
    match err {
        CliError::Backend(crate::pds_admin::BackendError::Terminal(msg)) => {
            CliError::Backend(crate::pds_admin::BackendError::Terminal(format!(
                "{msg}\nthis upstream may not ship {nsid}; endpoint availability varies \
                 by PDS version — check tools.aurora.describeCapabilities output and \
                 your Aurora release notes"
            )))
        }
        other => other,
    }
}

/// Render a `Value` body: format the known headline fields that
/// are present (field-presence checks, never validation), then
/// fall through to pretty JSON for everything else / on shape
/// surprise. Pass-through discipline: the body is never
/// restructured.
fn render_value_with_known(value: &serde_json::Value, known: &[(&str, &str)]) -> String {
    let mut lines = Vec::new();
    if let Some(obj) = value.as_object() {
        for (label, pointer) in known {
            if let Some(v) = value.pointer(pointer) {
                lines.push(format!("{label}: {v}"));
            }
        }
        let recognized: std::collections::BTreeSet<&str> = known
            .iter()
            .filter_map(|(_, p)| p.trim_start_matches('/').split('/').next())
            .collect();
        let unrecognized: Vec<&String> = obj
            .keys()
            .filter(|k| !recognized.contains(k.as_str()))
            .collect();
        if !unrecognized.is_empty() || lines.is_empty() {
            lines.push(
                serde_json::to_string_pretty(value)
                    .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")),
            );
        }
        lines.join("\n")
    } else {
        serde_json::to_string_pretty(value)
            .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}"))
    }
}

/// Which v1.8.10 ops read to run — one enum so the CLI handler
/// stays a single function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpsRead {
    /// `getSystemHealth`.
    Health,
    /// `getSequencerStatus`.
    Sequencer,
    /// `getFederationStatus` (typed).
    Federation,
    /// `getBlobStatistics`.
    Blobs,
    /// `getDatabaseStatus`.
    Database,
    /// `getResourceUsage`.
    Resources,
    /// `getVersionInfo`.
    Version,
    /// `getSystemMetrics`.
    SystemMetrics,
}

impl OpsRead {
    fn nsid(self) -> &'static str {
        match self {
            Self::Health => "tools.aurora.ops.getSystemHealth",
            Self::Sequencer => "tools.aurora.ops.getSequencerStatus",
            Self::Federation => "tools.aurora.ops.getFederationStatus",
            Self::Blobs => "tools.aurora.ops.getBlobStatistics",
            Self::Database => "tools.aurora.ops.getDatabaseStatus",
            Self::Resources => "tools.aurora.ops.getResourceUsage",
            Self::Version => "tools.aurora.ops.getVersionInfo",
            Self::SystemMetrics => "tools.aurora.ops.getSystemMetrics",
        }
    }

    /// Known headline fields (formatter-only; M-1) as
    /// (label, JSON pointer) pairs.
    fn known_fields(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Health => &[
                ("status", "/status"),
                ("version", "/version"),
                ("uptime seconds", "/uptime_seconds"),
                ("active http requests", "/active_http_requests"),
                ("active sessions", "/active_sessions"),
            ],
            Self::Database => &[
                ("status", "/status"),
                ("pool size", "/pool/size"),
                ("idle connections", "/pool/idle_connections"),
                ("latency ms", "/latency_ms"),
                ("total accounts", "/statistics/total_accounts"),
            ],
            Self::Resources => &[
                ("memory resident bytes", "/memory/resident_bytes"),
                ("cpu seconds total", "/cpu/seconds_total"),
                ("open file descriptors", "/file_descriptors/open"),
            ],
            Self::Version => &[
                ("version", "/version"),
                ("service did", "/service_did"),
                ("rust version", "/rust_version"),
                ("build profile", "/build_profile"),
            ],
            Self::SystemMetrics => &[
                ("uptime seconds", "/uptime_seconds"),
                ("cache hit rate %", "/cache/hit_rate_percent"),
                ("sequencer current sequence", "/sequencer/current_sequence"),
                ("total accounts", "/accounts/total"),
            ],
            // Dynamically-assembled / aggregate bodies: rendered
            // via the pretty-JSON fallback (M-1: expand at
            // implementer's discretion once observed).
            Self::Sequencer | Self::Blobs => &[],
            Self::Federation => &[], // typed path, not used
        }
    }
}

/// `cairn pds-admin ops <sub>` — one entry point for the eight
/// v1.8.10 reads (`metrics` keeps its dedicated function above).
pub async fn ops_read(config: &Config, which: OpsRead, json: bool) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    if which == OpsRead::Federation {
        let s = backend
            .get_federation_status()
            .await
            .map_err(CliError::from)
            .map_err(|e| with_f19_hint(which.nsid(), e))?;
        if json {
            return Ok(serde_json::to_string_pretty(&s)
                .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")));
        }
        return Ok(format!(
            "federation enabled: {}\nservice did: {}\nrelays: {} (connected: {})\n\
             discovery enabled: {}\nsearch enabled: {}\nknown instances: {}\nstatus: {}",
            s.enabled,
            s.service_did,
            s.relay_count,
            s.relay_connected,
            s.discovery_enabled,
            s.search_enabled,
            s.known_instances,
            s.status,
        ));
    }
    let value = match which {
        OpsRead::Health => backend.get_system_health().await,
        OpsRead::Sequencer => backend.get_sequencer_status().await,
        OpsRead::Blobs => backend.get_blob_statistics().await,
        OpsRead::Database => backend.get_database_status().await,
        OpsRead::Resources => backend.get_resource_usage().await,
        OpsRead::Version => backend.get_version_info().await,
        OpsRead::SystemMetrics => backend.get_system_metrics().await,
        OpsRead::Federation => unreachable!("typed path handled above"),
    }
    .map_err(CliError::from)
    .map_err(|e| with_f19_hint(which.nsid(), e))?;

    if json {
        return Ok(serde_json::to_string_pretty(&value)
            .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")));
    }
    Ok(render_value_with_known(&value, which.known_fields()))
}

// ===========================================================================
// v1.8.11 probe CLI (series-wrap item 8, chainlink #159)
// ===========================================================================

/// Registry-vs-advertised capability match report (v1.8.11 item
/// 8). Pure function over the probe's advertised strings so the
/// match logic is unit-testable without a backend.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityMatchReport {
    /// Registered families whose wire string is advertised.
    pub advertised_and_registered: Vec<String>,
    /// Advertised strings whose family is not in cairn-mod's
    /// registry (upstream extension — advisory, not an error).
    pub advertised_not_registered: Vec<String>,
    /// Registered families the upstream does not advertise
    /// (upstream drift, older PDS, or un-opted surfaces).
    pub registered_not_advertised: Vec<String>,
}

impl CapabilityMatchReport {
    /// Build from the probe's advertised wire strings against
    /// the shipped `CAPABILITY_CLASSIFICATIONS` registry.
    pub fn build(advertised: &[String]) -> Self {
        use crate::pds_admin::types::{CAPABILITY_CLASSIFICATIONS, parse_capability_string};
        let advertised_families: std::collections::BTreeSet<String> = advertised
            .iter()
            .filter_map(|s| parse_capability_string(s).map(|(family, _)| family))
            .collect();
        let mut advertised_and_registered = Vec::new();
        let mut registered_not_advertised = Vec::new();
        for (family, _) in CAPABILITY_CLASSIFICATIONS {
            if advertised_families.contains(*family) {
                advertised_and_registered.push((*family).to_string());
            } else {
                registered_not_advertised.push((*family).to_string());
            }
        }
        let registered: std::collections::BTreeSet<&str> = CAPABILITY_CLASSIFICATIONS
            .iter()
            .map(|(family, _)| *family)
            .collect();
        let advertised_not_registered = advertised
            .iter()
            .filter(|s| {
                parse_capability_string(s)
                    .map(|(family, _)| !registered.contains(family.as_str()))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        Self {
            advertised_and_registered,
            advertised_not_registered,
            registered_not_advertised,
        }
    }

    /// All shipped families advertised?
    pub fn all_match(&self) -> bool {
        self.registered_not_advertised.is_empty()
    }
}

/// `cairn pds-admin probe` — run the shipped startup probe on
/// demand and report the registry-vs-advertised match.
pub async fn probe(config: &Config, json: bool) -> Result<String, CliError> {
    let backend = backend_for_reads(config).await?;
    let report = backend.probe().await?;
    let matches = CapabilityMatchReport::build(&report.capabilities);

    if json {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "backend": report.backend_name,
            "pdsUrl": report.pds_url,
            "detectedVersion": report.detected_version,
            "advertised": report.capabilities,
            "match": matches,
            "allShippedFamiliesMatch": matches.all_match(),
        }))
        .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")));
    }

    let mut out = format!(
        "backend: {}\npds url: {}\ndetected version: {}\n\n",
        report.backend_name,
        report.pds_url,
        report.detected_version.as_deref().unwrap_or("-"),
    );
    out.push_str(&format!(
        "advertised and registered ({}):\n",
        matches.advertised_and_registered.len()
    ));
    for f in &matches.advertised_and_registered {
        out.push_str(&format!("  {f}\n"));
    }
    if !matches.advertised_not_registered.is_empty() {
        out.push_str(&format!(
            "advertised but not registered — upstream extension? ({}):\n",
            matches.advertised_not_registered.len()
        ));
        for f in &matches.advertised_not_registered {
            out.push_str(&format!("  {f}\n"));
        }
    }
    if !matches.registered_not_advertised.is_empty() {
        out.push_str(&format!(
            "registered but not advertised — upstream drift? ({}):\n",
            matches.registered_not_advertised.len()
        ));
        for f in &matches.registered_not_advertised {
            out.push_str(&format!("  {f}\n"));
        }
    }
    out.push_str(&if matches.all_match() {
        "verdict: all shipped families match".to_string()
    } else {
        format!(
            "verdict: {} mismatch(es) — investigate",
            matches.registered_not_advertised.len()
        )
    });
    Ok(out)
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[test]
    fn match_report_full_registry_matches() {
        // All 10 registered families advertised (+ one unknown).
        let advertised: Vec<String> = [
            "mod-events-emit-v1",
            "moderator-activity-v1",
            "subject-context-v1",
            "subject-history-v1",
            "appeals-v1",
            "audit-trail-v1",
            "batch-takedown-v1",
            "mod-events-stream-v1",
            "instance-metrics-v1",
            "runtime-settings-v1",
            "queue-stats-v1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let r = CapabilityMatchReport::build(&advertised);
        assert_eq!(r.advertised_and_registered.len(), 10);
        assert_eq!(r.advertised_not_registered, vec!["queue-stats-v1"]);
        assert!(r.registered_not_advertised.is_empty());
        assert!(r.all_match());
    }

    #[test]
    fn match_report_flags_drift() {
        let advertised = vec!["mod-events-emit-v1".to_string()];
        let r = CapabilityMatchReport::build(&advertised);
        assert!(!r.all_match());
        assert_eq!(r.advertised_and_registered, vec!["mod-events-emit"]);
        assert_eq!(r.registered_not_advertised.len(), 9);
    }
}
