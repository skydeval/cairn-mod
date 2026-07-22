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
