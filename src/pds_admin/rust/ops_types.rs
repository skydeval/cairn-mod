//! Wire mirrors for the v1.8.9 ops-and-runtime surfaces
//! (v2 §3/§4, chainlink #151).
//!
//! Mirrors Aurora-Locus at `2ffeb1a`: `OpsInstanceMetrics` (+ four
//! sub-structs, `admin.rs:6546-6608`), `GetRuntimeSettingOutput` +
//! `SettingSource` (`aurora_admin.rs:4014-4049`), and
//! `SetRuntimeSettingOutput` (`:5293-5299`). Public module — the
//! v1.8.10 ops-console starter imports these mirrors (umbrella
//! §4.A.10 forward-commitment).
//!
//! **Absence is meaningful on the metrics mirror**: Aurora omits
//! the three uninstrumented `resource_usage` counters rather than
//! zero-filling ("fields that aren't populated from existing
//! instrumentation are omitted rather than zero-filled, so absence
//! is meaningful"). The mirror preserves that with `Option` +
//! `#[serde(default)]` — renderers must show absent as absent,
//! never as `0`.

use serde::{Deserialize, Serialize};

/// Mirror of Aurora's `OpsInstanceMetrics` — the
/// `getInstanceMetrics` response (v2 §3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceMetrics {
    /// DB-probe status + service/process gauges.
    pub system_health: SystemHealth,
    /// Process/pool resource counters.
    pub resource_usage: ResourceUsage,
    /// Signup counts over trailing windows.
    pub account_growth: AccountGrowth,
    /// Federation subsystem summary.
    pub federation_health: FederationHealth,
}

/// Mirror of Aurora's `OpsSystemHealth`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemHealth {
    /// `"healthy"` if a `SELECT 1` against the account DB
    /// succeeded, else `"unhealthy"`.
    pub status: String,
    /// Aurora's service version string.
    pub version: String,
    /// Process uptime.
    pub uptime_seconds: f64,
    /// In-flight HTTP requests gauge.
    pub active_http_requests: i64,
    /// Active sessions gauge.
    pub active_sessions: i64,
    /// Active background jobs gauge.
    pub active_background_jobs: i64,
}

/// Mirror of Aurora's `OpsResourceUsage`. The three optionals are
/// **key-omitted when absent** upstream (not instrumented on the
/// platform) — absent ≠ zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceUsage {
    /// Resident memory in bytes, when the prometheus collector
    /// surfaces it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_resident_bytes: Option<f64>,
    /// Cumulative CPU seconds, when surfaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_seconds_total: Option<f64>,
    /// Open file descriptors, when surfaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_fds: Option<i64>,
    /// DB pool size (always present).
    pub db_pool_size: u32,
    /// Idle pool connections (always present).
    pub db_pool_idle_connections: u32,
}

/// Mirror of Aurora's `OpsAccountGrowth`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountGrowth {
    /// Signups in the last 24 hours.
    pub signups_last_24h: i64,
    /// Signups in the last 7 days.
    pub signups_last_7d: i64,
    /// Signups in the last 30 days.
    pub signups_last_30d: i64,
    /// Total accounts.
    pub total_accounts: i64,
}

/// Mirror of Aurora's `OpsFederationHealth`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationHealth {
    /// Federation subsystem enabled.
    pub federation_enabled: bool,
    /// Relay client connected.
    pub relay_connected: bool,
    /// Known peer count (0 when disabled/empty).
    pub known_instances: i64,
}

/// Origin tier of a resolved runtime-setting value — Aurora's
/// `SettingSource`, wire-encoded as the bare strings `"Runtime"` /
/// `"File"` / `"Default"` / `"RecoveryMode"` (custom Serialize
/// upstream; serde's external unit-variant representation matches
/// exactly). Four-tier resolution: recovery env override (top,
/// `moderation-mode` only) → runtime row → file YAML → compiled
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingSource {
    /// Operator-set runtime row.
    Runtime,
    /// File-tier YAML loaded at startup.
    File,
    /// Compiled-in default (also the unknown-key answer — the
    /// endpoint has no 404 path).
    Default,
    /// `AURORA_RECOVERY_MODE` forced `moderation-mode` to
    /// `"full"` — surfaced verbatim so operators see the override
    /// (umbrella F16; first-class, not an error).
    RecoveryMode,
}

/// Mirror of Aurora's `GetRuntimeSettingOutput` (v2 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSetting {
    /// The queried key, echoed.
    pub key: String,
    /// Resolved value (arbitrary JSON).
    pub value: serde_json::Value,
    /// Which tier answered.
    pub source: SettingSource,
    /// RFC3339 of the runtime row's last write; `None` for
    /// file/default/recovery answers.
    pub last_modified: Option<String>,
    /// DID that last wrote the runtime row; `None` likewise.
    pub last_modified_by: Option<String>,
}

/// Mirror of Aurora's `SetRuntimeSettingOutput` (v2 §3.3) — the
/// full value diff plus the upstream audit-chain entry id (String
/// on the wire, A5). There is deliberately no event id: setting
/// writes emit no moderation event (v2 §5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRuntimeSettingOutcome {
    /// The written key, echoed.
    pub key: String,
    /// Value before the write (compiled default when no runtime
    /// row existed).
    pub previous_value: serde_json::Value,
    /// Value after the write.
    pub new_value: serde_json::Value,
    /// Aurora's audit-chain entry id for the write.
    pub audit_entry_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn metrics_parse_full_shape() {
        let m: InstanceMetrics = serde_json::from_value(json!({
            "systemHealth": {
                "status": "healthy", "version": "0.10.0",
                "uptimeSeconds": 12.5, "activeHttpRequests": 3,
                "activeSessions": 7, "activeBackgroundJobs": 1
            },
            "resourceUsage": {
                "memoryResidentBytes": 1048576.0,
                "cpuSecondsTotal": 42.0, "openFds": 128,
                "dbPoolSize": 10, "dbPoolIdleConnections": 8
            },
            "accountGrowth": {
                "signupsLast24h": 1, "signupsLast7d": 5,
                "signupsLast30d": 20, "totalAccounts": 300
            },
            "federationHealth": {
                "federationEnabled": true, "relayConnected": false,
                "knownInstances": 4
            },
            "someFutureField": true
        }))
        .unwrap();
        assert_eq!(m.system_health.status, "healthy");
        assert_eq!(m.resource_usage.open_fds, Some(128));
        assert_eq!(m.account_growth.total_accounts, 300);
        assert!(m.federation_health.federation_enabled);
    }

    #[test]
    fn metrics_absent_optionals_stay_none_never_zero() {
        // Aurora key-omits uninstrumented counters; absence is
        // meaningful (v2 §3.1 wire-form table).
        let m: InstanceMetrics = serde_json::from_value(json!({
            "systemHealth": {
                "status": "unhealthy", "version": "0.10.0",
                "uptimeSeconds": 1.0, "activeHttpRequests": 0,
                "activeSessions": 0, "activeBackgroundJobs": 0
            },
            "resourceUsage": {"dbPoolSize": 10, "dbPoolIdleConnections": 10},
            "accountGrowth": {
                "signupsLast24h": 0, "signupsLast7d": 0,
                "signupsLast30d": 0, "totalAccounts": 0
            },
            "federationHealth": {
                "federationEnabled": false, "relayConnected": false,
                "knownInstances": 0
            }
        }))
        .unwrap();
        assert!(m.resource_usage.memory_resident_bytes.is_none());
        assert!(m.resource_usage.cpu_seconds_total.is_none());
        assert!(m.resource_usage.open_fds.is_none());
    }

    #[test]
    fn setting_source_four_bare_strings() {
        for (wire, variant) in [
            ("Runtime", SettingSource::Runtime),
            ("File", SettingSource::File),
            ("Default", SettingSource::Default),
            ("RecoveryMode", SettingSource::RecoveryMode),
        ] {
            let parsed: SettingSource = serde_json::from_value(json!(wire)).unwrap();
            assert_eq!(parsed, variant);
        }
        assert!(serde_json::from_value::<SettingSource>(json!("recoveryMode")).is_err());
    }

    #[test]
    fn runtime_setting_recovery_mode_read_parses_first_class() {
        let s: RuntimeSetting = serde_json::from_value(json!({
            "key": "moderation-mode",
            "value": "full",
            "source": "RecoveryMode",
            "lastModified": null,
            "lastModifiedBy": null
        }))
        .unwrap();
        assert_eq!(s.source, SettingSource::RecoveryMode);
        assert_eq!(s.value, json!("full"));
        assert!(s.last_modified.is_none());
    }

    #[test]
    fn set_outcome_carries_full_diff_and_string_audit_id() {
        let o: SetRuntimeSettingOutcome = serde_json::from_value(json!({
            "key": "moderation-mode",
            "previousValue": "full",
            "newValue": "reduced",
            "auditEntryId": "917"
        }))
        .unwrap();
        assert_eq!(o.previous_value, json!("full"));
        assert_eq!(o.new_value, json!("reduced"));
        assert_eq!(o.audit_entry_id, "917");
    }
}

/// Mirror of Aurora's `FederationStatusResponse` — the one typed
/// response in the v1.8.10 ops visibility subset
/// (`admin.rs:9408-9428` at `2ffeb1a`; v1.8.10 v2 §3.3). The wire
/// is **camelCase** (`#[serde(rename_all = "camelCase")]` on the
/// upstream struct — R1 LB-1); Aurora derives Serialize only
/// (server-side response type), this mirror derives both per
/// module convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationStatusResponse {
    /// Whether federation is enabled.
    pub enabled: bool,
    /// Service DID for this PDS.
    pub service_did: String,
    // u64 not usize: wire is width-agnostic; JSON numbers don't
    // carry platform width (D-1).
    /// Number of configured relay servers.
    pub relay_count: u64,
    /// Whether the relay client is connected.
    pub relay_connected: bool,
    /// Whether PDS discovery is enabled.
    pub discovery_enabled: bool,
    /// Whether federated search is enabled.
    pub search_enabled: bool,
    /// Number of known PDS instances.
    pub known_instances: u64,
    /// Status message.
    pub status: String,
}

#[cfg(test)]
mod federation_status_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn federation_status_parses_camel_case_wire() {
        // LB-1 positive-path pin: this IS the wire form Aurora
        // sends (rename_all = camelCase upstream).
        let s: FederationStatusResponse = serde_json::from_value(json!({
            "enabled": true,
            "serviceDid": "did:web:pds.example.com",
            "relayCount": 3,
            "relayConnected": true,
            "discoveryEnabled": false,
            "searchEnabled": false,
            "knownInstances": 7,
            "status": "federating",
            "someFutureField": 1
        }))
        .unwrap();
        assert_eq!(s.service_did, "did:web:pds.example.com");
        assert_eq!(s.relay_count, 3);
        assert_eq!(s.known_instances, 7);
    }

    #[test]
    fn federation_status_rejects_snake_case_body() {
        // Pins the rename_all attribute: a snake_case body must
        // fail field lookup (v1's backwards polarity inverted at
        // R1).
        let r: Result<FederationStatusResponse, _> = serde_json::from_value(json!({
            "enabled": true,
            "service_did": "did:web:x",
            "relay_count": 1,
            "relay_connected": false,
            "discovery_enabled": false,
            "search_enabled": false,
            "known_instances": 0,
            "status": "s"
        }));
        assert!(r.is_err());
    }
}
