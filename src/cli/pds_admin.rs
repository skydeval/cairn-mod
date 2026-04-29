//! `cairn pds-admin {takedown, suspend, restore}` (#99, Phase E) —
//! manual escape hatch for the PDS-admin bridge (#87).
//!
//! Production path is policy-automation + label-emission firing
//! the bridge automatically (the writer's post-commit dispatch
//! per #87). This subcommand exists for **testing the bridge
//! during Phase B verification** and for **operator one-off
//! escalations** — and explicitly does NOT skip the strike
//! accounting / audit chain.
//!
//! # Routing
//!
//! HTTP-routed via `tools.cairn.admin.{recordAction, revokeAction}`
//! against the running `cairn serve`. Same pattern as `cairn
//! moderator action` / `cairn moderator revoke`. The writer task's
//! post-commit dispatch (introduced in #87) fires the
//! `OzoneBackend` call automatically when the action_type is
//! takedown / temp_suspension / indef_suspension.
//!
//! Why HTTP not direct-DB: the bridge dispatch lives inside the
//! writer task. Direct-DB would either bypass the dispatch (wrong
//! semantics) or force the CLI to spawn a writer (heavyweight, and
//! conflicts with a running `cairn serve`). HTTP routes the action
//! through the canonical pipeline.
//!
//! # `--config` purpose
//!
//! The CLI loads the operator config to:
//!
//! 1. Pre-flight check `[pds_admin].enabled = true`. Without this
//!    check, a misconfigured operator would issue a recordAction,
//!    have it succeed, and only learn the bridge was disabled when
//!    looking at logs — the CLI catches the case upfront.
//! 2. Read the DB path for the post-call `pds_admin_audit` lookup
//!    (so the CLI can show the operator the bridge outcome).
//!
//! The `--config` operator must point at the **same** config the
//! running `cairn serve` is using; otherwise the pre-flight check
//! is meaningless. v1.7 doesn't enforce this — operator
//! responsibility.
//!
//! # `restore` semantics
//!
//! cairn-mod has no first-class "restore" action_type. Restoration
//! is a `revoke_action` of the most recent unrevoked
//! takedown / temp_suspension / indef_suspension. The CLI:
//!
//! 1. Reads the most-recent unrevoked active suspension row from
//!    `subject_actions` (direct DB).
//! 2. Calls `tools.cairn.admin.revokeAction` with that row's id
//!    via HTTP.
//! 3. The writer's post-commit dispatch fires
//!    `OzoneBackend::restore_account`.
//!
//! Operators wanting a specific action_id (rather than "most
//! recent") should use `cairn moderator revoke <action_id>` —
//! `cairn pds-admin restore <did>` is the convenience case.

use std::path::Path;

use serde::Serialize;
use sqlx::{Pool, Sqlite};

use crate::config::Config;

use super::error::CliError;
use super::moderator_action::{
    RecordActionInput, RecordResponse, RevokeActionInput, RevokeResponse, record, revoke,
};
use super::session::SessionFile;

/// Reserved reason code recorded on every `cairn pds-admin`-driven
/// recordAction. Operators must declare this in
/// `[moderation_reasons]` if they want manual bridge escalations
/// to succeed; otherwise the writer surfaces `ReasonNotFound` and
/// the CLI prints the underlying error.
///
/// Mirrors the `xrpc-gateway-default` and `policy-threshold`
/// reserved-reason pattern: a single declared name the operator
/// must opt into.
pub const PDS_ADMIN_DEFAULT_REASON_CODE: &str = "pds-admin-cli";

/// Outcome of `cairn pds-admin {takedown, suspend}`. Wraps the
/// recordAction response plus the just-fired pds_admin_audit row
/// (when the bridge dispatch produced one).
#[derive(Debug, Clone, Serialize)]
pub struct PdsAdminTakedownOutcome {
    /// The recordAction response. `actionId` is the new
    /// subject_actions row.
    pub record: RecordResponse,
    /// Bridge dispatch outcome — `Some` when a `pds_admin_audit`
    /// row matching the precipitating action was found within the
    /// CLI's polling window. `None` when no audit row appeared
    /// (bridge disabled, dispatch hadn't fired yet by the time the
    /// CLI looked, or the operator's config disabled the bridge).
    pub bridge: Option<PdsAdminAuditView>,
}

/// Outcome of `cairn pds-admin restore`. Wraps the revokeAction
/// response plus the pds_admin_audit row (when a bridge-driven
/// `restore_account` call fired).
#[derive(Debug, Clone, Serialize)]
pub struct PdsAdminRestoreOutcome {
    /// The revokeAction response.
    pub revoke: RevokeResponse,
    /// `Some` when a pds_admin_audit row for the
    /// restore_account dispatch was found.
    pub bridge: Option<PdsAdminAuditView>,
}

/// Wire-shaped projection of one `pds_admin_audit` row for CLI
/// output. Hash-chain columns (`prev_hash`, `row_hash`) and
/// internal book-keeping are omitted; this is operator-facing.
#[derive(Debug, Clone, Serialize)]
pub struct PdsAdminAuditView {
    /// `pds_admin_audit.id`.
    pub id: i64,
    /// `pds_admin_audit.precipitating_action_id`.
    pub precipitating_action_id: i64,
    /// Backend method that was attempted (e.g. `takedown_account`).
    pub backend_method: String,
    /// Backend-assigned identifier, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_action_id: Option<String>,
    /// `success` / `network` / `auth` / `rate_limited` / etc.
    pub outcome: String,
    /// Backend-supplied error code, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable error message, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Retry-After hint, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<i64>,
}

// ==========================================================================
// Config preflight
// ==========================================================================

/// Verify `[pds_admin].enabled = true` in the loaded config. The
/// CLI calls this before issuing the recordAction so a
/// misconfigured operator gets a precise error pointing at the
/// config block, rather than a successful recordAction with a
/// silently-no-op bridge.
pub fn verify_pds_admin_enabled(config: &Config) -> Result<(), CliError> {
    let policy = crate::pds_admin::PdsAdminPolicy::from_config(config)
        .map_err(|e| CliError::Config(format!("[pds_admin]: {e}")))?;
    if !policy.enabled {
        return Err(CliError::Config(
            "[pds_admin] bridge is disabled in this config; \
             set [pds_admin].enabled = true (and configure a backend) \
             before using `cairn pds-admin`"
                .into(),
        ));
    }
    Ok(())
}

// ==========================================================================
// Direct-DB helpers
// ==========================================================================

/// Fetch the most-recent unrevoked active-suspension
/// `subject_actions` row for a subject. Used by `restore` to
/// resolve the action_id to revoke.
///
/// Returns `Ok(None)` when no active suspension exists; the
/// caller surfaces this as a USAGE-coded CliError rather than
/// silently no-op'ing.
pub async fn find_active_suspension_action_id(
    pool: &Pool<Sqlite>,
    subject_did: &str,
) -> sqlx::Result<Option<i64>> {
    let row = sqlx::query!(
        r#"SELECT id as "id!: i64"
           FROM subject_actions
           WHERE subject_did = ?1
             AND action_type IN ('takedown', 'temp_suspension', 'indef_suspension')
             AND revoked_at IS NULL
           ORDER BY id DESC
           LIMIT 1"#,
        subject_did,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.id))
}

/// Look up the `pds_admin_audit` row matching the precipitating
/// action_id. Returns `Ok(None)` when no audit row is found —
/// either the bridge hasn't dispatched yet (the CLI is racing the
/// writer's post-commit hook), or the bridge is disabled, or the
/// dispatch produced an `Unsupported` outcome that wasn't
/// audit-logged.
pub async fn find_pds_admin_audit_for_action(
    pool: &Pool<Sqlite>,
    precipitating_action_id: i64,
) -> sqlx::Result<Option<PdsAdminAuditView>> {
    let row = sqlx::query!(
        r#"SELECT
             id                       AS "id!: i64",
             precipitating_action_id  AS "precipitating_action_id!: i64",
             backend_method           AS "backend_method!: String",
             backend_action_id,
             outcome                  AS "outcome!: String",
             error_code,
             error_message,
             retry_after_seconds
           FROM pds_admin_audit
           WHERE precipitating_action_id = ?1
           ORDER BY id DESC
           LIMIT 1"#,
        precipitating_action_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| PdsAdminAuditView {
        id: r.id,
        precipitating_action_id: r.precipitating_action_id,
        backend_method: r.backend_method,
        backend_action_id: r.backend_action_id,
        outcome: r.outcome,
        error_code: r.error_code,
        error_message: r.error_message,
        retry_after_seconds: r.retry_after_seconds,
    }))
}

// ==========================================================================
// Orchestrators
// ==========================================================================

/// `cairn pds-admin takedown <did>` — record a Takedown action via
/// HTTP, then look up the bridge dispatch outcome.
#[allow(clippy::too_many_arguments)]
pub async fn takedown(
    pool: &Pool<Sqlite>,
    session: &mut SessionFile,
    session_path: &Path,
    subject_did: &str,
    reason: &str,
    notes: Option<String>,
    cairn_server_override: Option<String>,
) -> Result<PdsAdminTakedownOutcome, CliError> {
    let record_resp = record(
        session,
        session_path,
        RecordActionInput {
            subject: subject_did.to_string(),
            action_type: "takedown".to_string(),
            reasons: vec![reason.to_string()],
            duration: None,
            note: notes,
            report_ids: Vec::new(),
            cairn_server_override,
        },
    )
    .await?;

    // The writer's post-commit dispatch is async vs. the HTTP
    // response: the recordAction returns once the action is
    // persisted, but the bridge call may still be in flight. Look
    // up the audit row; if absent, the CLI prints "bridge dispatch
    // pending" so operators know to re-check.
    let bridge = find_pds_admin_audit_for_action(pool, record_resp.action_id)
        .await
        .map_err(|e| CliError::Startup(format!("pds_admin_audit lookup: {e}")))?;

    Ok(PdsAdminTakedownOutcome {
        record: record_resp,
        bridge,
    })
}

/// `cairn pds-admin suspend <did>` — record a temp_suspension (when
/// `--duration` is set) or indef_suspension (otherwise) via HTTP.
/// Same bridge-dispatch lookup as takedown.
#[allow(clippy::too_many_arguments)]
pub async fn suspend(
    pool: &Pool<Sqlite>,
    session: &mut SessionFile,
    session_path: &Path,
    subject_did: &str,
    reason: &str,
    duration: Option<String>,
    notes: Option<String>,
    cairn_server_override: Option<String>,
) -> Result<PdsAdminTakedownOutcome, CliError> {
    let action_type = if duration.is_some() {
        "temp_suspension"
    } else {
        "indef_suspension"
    };
    let record_resp = record(
        session,
        session_path,
        RecordActionInput {
            subject: subject_did.to_string(),
            action_type: action_type.to_string(),
            reasons: vec![reason.to_string()],
            duration,
            note: notes,
            report_ids: Vec::new(),
            cairn_server_override,
        },
    )
    .await?;

    let bridge = find_pds_admin_audit_for_action(pool, record_resp.action_id)
        .await
        .map_err(|e| CliError::Startup(format!("pds_admin_audit lookup: {e}")))?;

    Ok(PdsAdminTakedownOutcome {
        record: record_resp,
        bridge,
    })
}

/// `cairn pds-admin restore <did>` — find the most-recent
/// unrevoked takedown/suspension for the subject, revoke it via
/// HTTP, then look up the bridge dispatch.
pub async fn restore(
    pool: &Pool<Sqlite>,
    session: &mut SessionFile,
    session_path: &Path,
    subject_did: &str,
    reason: Option<String>,
    cairn_server_override: Option<String>,
) -> Result<PdsAdminRestoreOutcome, CliError> {
    let action_id = find_active_suspension_action_id(pool, subject_did)
        .await
        .map_err(|e| CliError::Startup(format!("subject_actions lookup: {e}")))?
        .ok_or_else(|| {
            CliError::Config(format!(
                "no active takedown / suspension to restore for subject {subject_did}"
            ))
        })?;

    let revoke_resp = revoke(
        session,
        session_path,
        RevokeActionInput {
            action_id,
            reason,
            cairn_server_override,
        },
    )
    .await?;

    let bridge = find_pds_admin_audit_for_action(pool, revoke_resp.action_id)
        .await
        .map_err(|e| CliError::Startup(format!("pds_admin_audit lookup: {e}")))?;

    Ok(PdsAdminRestoreOutcome {
        revoke: revoke_resp,
        bridge,
    })
}

// ==========================================================================
// Output formatters
// ==========================================================================

/// Human-readable two-line output for takedown / suspend.
pub fn format_takedown_human(out: &PdsAdminTakedownOutcome) -> String {
    let mut s = format!(
        "Recorded action {} (subject taken down)",
        out.record.action_id
    );
    if let Some(b) = &out.bridge {
        s.push_str(&format!(
            "\nbridge: {} via {} (id={})",
            b.outcome,
            b.backend_method,
            b.backend_action_id.as_deref().unwrap_or("-")
        ));
        if let Some(err) = &b.error_message {
            s.push_str(&format!("\nerror: {err}"));
        }
    } else {
        s.push_str("\nbridge: dispatch pending — check `cairn moderator events` shortly");
    }
    s
}

/// Single-line JSON for takedown / suspend (tooling).
pub fn format_takedown_json(out: &PdsAdminTakedownOutcome) -> String {
    serde_json::to_string(out).expect("PdsAdminTakedownOutcome serializes")
}

/// Human-readable two-line output for restore.
pub fn format_restore_human(out: &PdsAdminRestoreOutcome) -> String {
    let mut s = format!(
        "Revoked action {} at {}",
        out.revoke.action_id, out.revoke.revoked_at
    );
    if let Some(b) = &out.bridge {
        s.push_str(&format!(
            "\nbridge: {} via {} (id={})",
            b.outcome,
            b.backend_method,
            b.backend_action_id.as_deref().unwrap_or("-")
        ));
        if let Some(err) = &b.error_message {
            s.push_str(&format!("\nerror: {err}"));
        }
    } else {
        s.push_str("\nbridge: dispatch pending — check `cairn moderator events` shortly");
    }
    s
}

/// Single-line JSON for restore (tooling).
pub fn format_restore_json(out: &PdsAdminRestoreOutcome) -> String {
    serde_json::to_string(out).expect("PdsAdminRestoreOutcome serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pds_admin_default_reason_code_is_hyphenated() {
        // §F22.1 reason-code naming convention. Pinned because the
        // operator's [moderation_reasons] config uses the same
        // string and a drift would silently break manual bridge
        // calls.
        assert_eq!(PDS_ADMIN_DEFAULT_REASON_CODE, "pds-admin-cli");
    }

    #[test]
    fn format_takedown_human_no_bridge_marks_pending() {
        let out = PdsAdminTakedownOutcome {
            record: RecordResponse {
                action_id: 7,
                strike_value_base: 0,
                strike_value_applied: 0,
                was_dampened: false,
                strikes_at_time_of_action: 0,
            },
            bridge: None,
        };
        let s = format_takedown_human(&out);
        assert!(s.contains("Recorded action 7"));
        assert!(s.contains("dispatch pending"));
    }

    #[test]
    fn format_takedown_human_with_bridge_includes_outcome() {
        let out = PdsAdminTakedownOutcome {
            record: RecordResponse {
                action_id: 9,
                strike_value_base: 0,
                strike_value_applied: 0,
                was_dampened: false,
                strikes_at_time_of_action: 0,
            },
            bridge: Some(PdsAdminAuditView {
                id: 11,
                precipitating_action_id: 9,
                backend_method: "takedown_account".into(),
                backend_action_id: Some("backend-id-42".into()),
                outcome: "success".into(),
                error_code: None,
                error_message: None,
                retry_after_seconds: None,
            }),
        };
        let s = format_takedown_human(&out);
        assert!(s.contains("Recorded action 9"));
        assert!(s.contains("bridge: success via takedown_account"));
        assert!(s.contains("backend-id-42"));
    }

    #[test]
    fn format_takedown_human_with_failed_bridge_includes_error() {
        let out = PdsAdminTakedownOutcome {
            record: RecordResponse {
                action_id: 1,
                strike_value_base: 0,
                strike_value_applied: 0,
                was_dampened: false,
                strikes_at_time_of_action: 0,
            },
            bridge: Some(PdsAdminAuditView {
                id: 2,
                precipitating_action_id: 1,
                backend_method: "takedown_account".into(),
                backend_action_id: None,
                outcome: "auth".into(),
                error_code: Some("AuthRequired".into()),
                error_message: Some("invalid app password".into()),
                retry_after_seconds: None,
            }),
        };
        let s = format_takedown_human(&out);
        assert!(s.contains("bridge: auth"));
        assert!(s.contains("error: invalid app password"));
    }

    #[test]
    fn format_restore_human_with_bridge_includes_outcome() {
        let out = PdsAdminRestoreOutcome {
            revoke: RevokeResponse {
                action_id: 3,
                revoked_at: "2026-04-29T00:00:00.000Z".into(),
            },
            bridge: Some(PdsAdminAuditView {
                id: 4,
                precipitating_action_id: 3,
                backend_method: "restore_account".into(),
                backend_action_id: None,
                outcome: "success".into(),
                error_code: None,
                error_message: None,
                retry_after_seconds: None,
            }),
        };
        let s = format_restore_human(&out);
        assert!(s.contains("Revoked action 3"));
        assert!(s.contains("bridge: success via restore_account"));
    }

    #[test]
    fn format_takedown_json_round_trips() {
        let out = PdsAdminTakedownOutcome {
            record: RecordResponse {
                action_id: 1,
                strike_value_base: 0,
                strike_value_applied: 0,
                was_dampened: false,
                strikes_at_time_of_action: 0,
            },
            bridge: None,
        };
        let s = format_takedown_json(&out);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["record"]["actionId"].as_i64(), Some(1));
        assert!(v["bridge"].is_null());
    }
}
