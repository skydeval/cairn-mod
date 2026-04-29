//! Post-recordAction PDS-admin dispatch (#87, v1.7).
//!
//! Bridges cairn-mod's recordAction pipeline (§F20-F22) to the
//! configured [`PdsAdminBackend`] (v1.7 = `OzoneBackend` only).
//! Called by the writer task in [`crate::writer`] after a
//! `subject_actions` row has been committed and labels have been
//! emitted; this module decides whether to dispatch a backend
//! call, fires it, and audit-logs the result.
//!
//! # Failure semantics (per §A13)
//!
//! - The recordAction transaction has **already committed** by
//!   the time this runs. Backend-call failures do **not** roll
//!   back the cairn-mod-side action.
//! - On backend-call failure, log loudly (`WARN` for transient
//!   variants, `ERROR` for operator-actionable variants like
//!   `Auth` / `Validation`), record the failure in
//!   `pds_admin_audit`, and return.
//! - On audit-insert failure, log at `ERROR` and return — do
//!   NOT propagate to the writer task; the cairn-mod-side action
//!   stays committed regardless. The audit divergence is a
//!   discoverability issue, not a correctness issue at this
//!   layer.
//! - cairn-mod does NOT retry. Retry policy lands in v1.8 with
//!   operator feedback informing it.
//!
//! # Method-selection logic
//!
//! 1. If [`PdsAdminPolicy::enabled`] is false → no-op.
//! 2. Look up the action_type in
//!    [`PdsAdminPolicy::action_map`]. Missing key → no-op
//!    (defensive — #83's resolver guarantees coverage but a
//!    future config-shape change shouldn't crash here).
//! 3. [`ActionMapEntry::Skip`] → no-op.
//! 4. [`ActionMapEntry::Method`] → dispatch:
//!    - `TakedownAccount` (v1.7 implemented) → call the trait
//!      method.
//!    - `SuspendAccount` (lands in #88) → call the trait method;
//!      `OzoneBackend`'s body currently `unimplemented!()`s,
//!      which would panic. Acceptable in-cycle; #88 fills it in
//!      before any tagged release.
//!    - `RestoreAccount` → log error and skip. recordAction
//!      doesn't carry a prior backend action id; restore is
//!      reachable only from the revokeAction path (separate
//!      flow, future cycle).
//!    - `ApplyLabel` / `NegateLabel` → log warn and skip. #83's
//!      action_map validation already warned at config-load;
//!      this is defense-in-depth.

use std::sync::Arc;

use sqlx::{Pool, Sqlite};

use crate::moderation::types::ActionType;
use crate::pds_admin::audit::record_pds_admin_call;
use crate::pds_admin::backend::{BackendActionId, BackendError, PdsAdminBackend};
use crate::pds_admin::config::{ActionMapEntry, BackendMethod, PdsAdminPolicy};

/// Bundled v1.7 PDS-admin runtime: the resolved
/// [`PdsAdminPolicy`] from #83 + the trait-object backend the
/// dispatch fires against.
///
/// `Option<PdsAdminBridge>` is what the writer task carries. When
/// `None` (operator declared no `[pds_admin]` block, or
/// `enabled = false`), the dispatch is short-circuited at the
/// writer-task layer without even constructing this struct.
#[derive(Clone)]
pub struct PdsAdminBridge {
    /// Resolved policy. The `enabled` flag is checked again on
    /// every call (defensive — could become stale relative to a
    /// future hot-reload feature).
    pub policy: PdsAdminPolicy,
    /// Trait-object backend. v1.7 wires `OzoneBackend`; v1.8
    /// will add `LocusBackend` selectable per
    /// [`PdsAdminPolicy::backend`].
    pub backend: Arc<dyn PdsAdminBackend>,
}

/// Snapshot of the just-committed recordAction's fields the
/// dispatch needs. Borrowed from the writer's
/// `RecordActionRequest` to avoid cloning the whole struct
/// across the post-commit boundary.
#[derive(Debug, Clone, Copy)]
pub struct DispatchContext<'a> {
    /// `subject_actions(id)` of the just-committed row.
    pub action_id: i64,
    /// Cairn-mod-side action-type discriminator.
    pub action_type: ActionType,
    /// Subject DID (extracted from the request via
    /// `route_subject` in writer.rs).
    pub subject_did: &'a str,
    /// Operator-vocabulary reason identifiers. The first entry
    /// is propagated to the backend's `ref` / `reason` field;
    /// remaining entries are recorded in the cairn-mod-side
    /// audit log only.
    pub reason_codes: &'a [String],
    /// Optional moderator-facing free text. Currently NOT
    /// mirrored to the backend (it's a cairn-mod-internal
    /// artifact; bsky-PDS's `takedown.ref` field is for
    /// cross-system tracking, not narrative content).
    pub notes: Option<&'a str>,
}

/// Dispatch the post-recordAction PDS-admin call (if any).
///
/// Idempotent on a `None` bridge: callers can pass `&None`
/// without checking `enabled` themselves. Returns no error
/// because failures are logged + audited, not propagated; the
/// recordAction transaction has already committed.
pub async fn dispatch_after_record_action(
    bridge: Option<&PdsAdminBridge>,
    pool: &Pool<Sqlite>,
    ctx: DispatchContext<'_>,
) {
    let Some(bridge) = bridge else {
        return;
    };
    if !bridge.policy.enabled {
        return;
    }
    let entry = bridge
        .policy
        .action_map
        .get(&ctx.action_type)
        .copied()
        .unwrap_or(ActionMapEntry::Skip);
    let method = match entry {
        ActionMapEntry::Skip => return,
        ActionMapEntry::Method(m) => m,
    };

    // Defense-in-depth gating for methods that don't make sense
    // from the recordAction path. #83's config-load validation
    // catches the label cases with a warning; the runtime gate
    // ensures we never actually touch those trait methods.
    match method {
        BackendMethod::ApplyLabel | BackendMethod::NegateLabel => {
            tracing::warn!(
                action_id = ctx.action_id,
                method = method.as_wire_str(),
                "pds_admin action_map routes recordAction to a label method; \
                 cairn-mod's subscribeLabels (§F4) is the label distribution surface (§A5). \
                 Skipping at runtime; #83's config validation already warned at startup."
            );
            return;
        }
        BackendMethod::RestoreAccount => {
            tracing::error!(
                action_id = ctx.action_id,
                "pds_admin action_map routes recordAction to restore_account; \
                 recordAction has no prior backend action id (restore is via revokeAction). \
                 Operator config bug. Skipping."
            );
            return;
        }
        BackendMethod::TakedownAccount | BackendMethod::SuspendAccount => {}
    }

    let reason = ctx.reason_codes.first().map(String::as_str).unwrap_or("");

    let started_at = crate::writer::epoch_ms_now();
    let call_result = invoke_backend_method(
        bridge.backend.as_ref(),
        method,
        ctx.subject_did,
        reason,
        ctx.notes,
        ctx.action_id,
    )
    .await;
    let completed_at = crate::writer::epoch_ms_now();

    log_call_outcome(method, ctx.action_id, ctx.subject_did, &call_result);

    // Project the per-method success into the unified
    // `Option<BackendActionId>` shape that
    // `record_pds_admin_call` accepts. Per #87:
    // `BackendMethod::returns_action_id()` single-sources the
    // convention.
    let unified: std::result::Result<Option<BackendActionId>, BackendError> =
        match (method.returns_action_id(), call_result) {
            (true, Ok(id)) => Ok(Some(id)),
            (false, Ok(_)) => Ok(None),
            (_, Err(e)) => Err(e),
        };

    if let Err(e) = record_pds_admin_call(
        pool,
        ctx.action_id,
        method,
        unified,
        started_at,
        completed_at,
    )
    .await
    {
        // Audit-row failure does NOT propagate — the
        // cairn-mod-side action remains committed regardless.
        tracing::error!(
            error = %e,
            action_id = ctx.action_id,
            method = method.as_wire_str(),
            "pds_admin audit insert failed; cairn-mod-side action remains committed"
        );
    }
}

/// Dispatch the trait method whose shape matches `method`. The
/// match arms unify on `Result<BackendActionId, BackendError>`
/// even for unit-result methods — those return a synthesized
/// "ignored" id that the caller drops via `returns_action_id()`.
///
/// In v1.7 only `TakedownAccount` reaches here as an
/// implemented method; `SuspendAccount` panics via
/// `unimplemented!()` until #88 lands its body. The
/// non-record-action methods (`RestoreAccount`, `ApplyLabel`,
/// `NegateLabel`) are filtered out before we get here.
async fn invoke_backend_method(
    backend: &dyn PdsAdminBackend,
    method: BackendMethod,
    did: &str,
    reason: &str,
    notes: Option<&str>,
    action_id: i64,
) -> std::result::Result<BackendActionId, BackendError> {
    match method {
        BackendMethod::TakedownAccount => {
            backend
                .takedown_account(did, reason, notes, action_id)
                .await
        }
        BackendMethod::SuspendAccount => {
            // duration_days is not yet plumbed from
            // RecordActionRequest.duration_iso → days here; #88
            // lands the parsing alongside the suspend_account
            // body. The unimplemented!() in OzoneBackend means
            // this path panics in #87's intermediate state, which
            // is acceptable per the prompt: "no one will trigger
            // suspend before #88 lands."
            backend
                .suspend_account(did, reason, None, notes, action_id)
                .await
        }
        BackendMethod::RestoreAccount | BackendMethod::ApplyLabel | BackendMethod::NegateLabel => {
            // Filtered out by the dispatch caller; reaching this
            // arm would be a bug in this module.
            unreachable!(
                "invoke_backend_method dispatched non-record-action method {method:?}; \
                 dispatch_after_record_action should have filtered it"
            )
        }
    }
}

/// Emit a structured tracing log line summarizing the call
/// outcome. `WARN` for transient/network variants, `ERROR` for
/// operator-actionable variants, `INFO` for success. Severity
/// matches the `outcome` column the audit row will record so
/// log-level subscribers and audit-table queries agree.
fn log_call_outcome<T>(
    method: BackendMethod,
    action_id: i64,
    subject_did: &str,
    result: &std::result::Result<T, BackendError>,
) {
    match result {
        Ok(_) => tracing::info!(
            action_id,
            subject_did,
            method = method.as_wire_str(),
            "pds_admin backend call succeeded"
        ),
        Err(BackendError::Unsupported(msg)) => tracing::error!(
            action_id,
            subject_did,
            method = method.as_wire_str(),
            error = %msg,
            "pds_admin backend rejected method as unsupported (operator config issue)"
        ),
        Err(BackendError::Network(e)) => tracing::warn!(
            action_id,
            subject_did,
            method = method.as_wire_str(),
            error = %e,
            "pds_admin backend call failed at the network layer (transient; not retried in v1.7)"
        ),
        Err(BackendError::Auth(e)) => tracing::error!(
            action_id,
            subject_did,
            method = method.as_wire_str(),
            error = %e,
            "pds_admin backend rejected our admin auth (operator must rotate credentials)"
        ),
        Err(BackendError::RateLimited {
            message,
            retry_after_seconds,
        }) => tracing::warn!(
            action_id,
            subject_did,
            method = method.as_wire_str(),
            retry_after_seconds = ?retry_after_seconds,
            error = %message,
            "pds_admin backend rate-limited the call (not retried in v1.7)"
        ),
        Err(BackendError::Conflict(e)) => tracing::warn!(
            action_id,
            subject_did,
            method = method.as_wire_str(),
            error = %e,
            "pds_admin backend reported state conflict"
        ),
        Err(BackendError::RemoteError { code, message }) => tracing::warn!(
            action_id,
            subject_did,
            method = method.as_wire_str(),
            error_code = %code,
            error = %message,
            "pds_admin backend returned an unrecognized error envelope"
        ),
        Err(BackendError::Validation(e)) => tracing::error!(
            action_id,
            subject_did,
            method = method.as_wire_str(),
            error = %e,
            "pds_admin backend rejected our request as malformed (cairn-mod-side bug)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pds_admin::types::Subject;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Test backend that records every call and returns a
    /// canned response. Lets us verify the dispatch fires the
    /// right method without making any HTTP calls.
    struct RecordingBackend {
        calls: Mutex<Vec<RecordedCall>>,
        takedown_response: Mutex<Option<std::result::Result<BackendActionId, BackendError>>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedCall {
        method: &'static str,
        did: String,
        reason: String,
        action_id: i64,
    }

    impl RecordingBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                takedown_response: Mutex::new(None),
            })
        }

        fn with_takedown_ok(self: &Arc<Self>, id: &str) {
            *self.takedown_response.lock().unwrap() = Some(Ok(BackendActionId::new(id)));
        }

        fn with_takedown_err(self: &Arc<Self>, err: BackendError) {
            *self.takedown_response.lock().unwrap() = Some(Err(err));
        }

        fn calls(&self) -> Vec<RecordedCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl PdsAdminBackend for RecordingBackend {
        async fn takedown_account(
            &self,
            did: &str,
            reason: &str,
            _notes: Option<&str>,
            precipitating_action_id: i64,
        ) -> std::result::Result<BackendActionId, BackendError> {
            self.calls.lock().unwrap().push(RecordedCall {
                method: "takedown_account",
                did: did.to_string(),
                reason: reason.to_string(),
                action_id: precipitating_action_id,
            });
            self.takedown_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Ok(BackendActionId::new(format!(
                        "test:{did}:{precipitating_action_id}"
                    )))
                })
        }

        async fn suspend_account(
            &self,
            _did: &str,
            _reason: &str,
            _duration_days: Option<u32>,
            _notes: Option<&str>,
            _precipitating_action_id: i64,
        ) -> std::result::Result<BackendActionId, BackendError> {
            unimplemented!("test backend does not stub suspend_account")
        }

        async fn restore_account(
            &self,
            _did: &str,
            _prior_action_id: &BackendActionId,
            _reason: &str,
        ) -> std::result::Result<(), BackendError> {
            unimplemented!()
        }

        async fn apply_label(
            &self,
            _subject: &Subject,
            _val: &str,
            _expires_days: Option<u32>,
        ) -> std::result::Result<(), BackendError> {
            self.calls.lock().unwrap().push(RecordedCall {
                method: "apply_label",
                did: String::new(),
                reason: String::new(),
                action_id: 0,
            });
            Err(BackendError::Unsupported("test"))
        }

        async fn negate_label(
            &self,
            _subject: &Subject,
            _val: &str,
        ) -> std::result::Result<(), BackendError> {
            unimplemented!()
        }
    }

    fn policy_with_action_map(
        enabled: bool,
        action_map: BTreeMap<ActionType, ActionMapEntry>,
    ) -> PdsAdminPolicy {
        // `backend: None` is a deliberate test-only shape. Dispatch
        // doesn't read `policy.backend` — the trait-object backend on
        // the `PdsAdminBridge` is what actually fires. v1.7's
        // resolver always populates `policy.backend = Some(_)` when
        // `enabled = true`, but for these unit tests we don't need
        // it; the runtime invariant lives in #83's resolver, not
        // here.
        PdsAdminPolicy {
            enabled,
            backend: None,
            action_map,
        }
    }

    async fn fresh_pool() -> Pool<Sqlite> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dispatch-test.db");
        let pool = crate::storage::open(&path).await.unwrap();
        Box::leak(Box::new(dir));
        pool
    }

    async fn fixture_subject_action(pool: &Pool<Sqlite>) -> i64 {
        sqlx::query_scalar!(
            r#"INSERT INTO subject_actions (
                subject_did, subject_uri, actor_did, action_type, reason_codes,
                duration, effective_at, expires_at, notes, report_ids,
                strike_value_base, strike_value_applied, was_dampened,
                strikes_at_time_of_action, audit_log_id, created_at,
                actor_kind, triggered_by_policy_rule
             ) VALUES ('did:plc:s', NULL, 'did:plc:m', 'takedown', '["spam"]',
                       NULL, ?1, NULL, NULL, NULL, 1, 1, 0, 1, NULL, ?1,
                       'moderator', NULL)
             RETURNING id AS "id!""#,
            1_700_000_000_000_i64
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    fn ctx<'a>(action_id: i64, did: &'a str) -> DispatchContext<'a> {
        static REASONS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        let reasons = REASONS.get_or_init(|| vec!["spam".into()]);
        DispatchContext {
            action_id,
            action_type: ActionType::Takedown,
            subject_did: did,
            reason_codes: reasons,
            notes: None,
        }
    }

    #[tokio::test]
    async fn dispatch_noop_when_bridge_none() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        // Should not error, should not insert any audit row.
        dispatch_after_record_action(None, &pool, ctx(action_id, "did:plc:s")).await;
        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM pds_admin_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn dispatch_noop_when_policy_disabled() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(false, BTreeMap::new()),
            backend: backend.clone(),
        };
        dispatch_after_record_action(Some(&bridge), &pool, ctx(action_id, "did:plc:s")).await;
        assert!(backend.calls().is_empty(), "no backend call when disabled");
        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM pds_admin_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn dispatch_skips_when_action_type_is_skip() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        let mut map = BTreeMap::new();
        map.insert(ActionType::Takedown, ActionMapEntry::Skip);
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };
        dispatch_after_record_action(Some(&bridge), &pool, ctx(action_id, "did:plc:s")).await;
        assert!(backend.calls().is_empty());
        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM pds_admin_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn dispatch_takedown_records_audit_on_success() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        backend.with_takedown_ok("ozone:did:plc:s:42");
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::Takedown,
            ActionMapEntry::Method(BackendMethod::TakedownAccount),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };
        dispatch_after_record_action(Some(&bridge), &pool, ctx(action_id, "did:plc:s")).await;

        let calls = backend.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, "takedown_account");
        assert_eq!(calls[0].did, "did:plc:s");
        assert_eq!(calls[0].action_id, action_id);

        let audit_rows = crate::pds_admin::audit::list_pds_admin_audit_for_action(&pool, action_id)
            .await
            .unwrap();
        assert_eq!(audit_rows.len(), 1);
        assert_eq!(
            audit_rows[0].outcome,
            crate::pds_admin::AuditOutcome::Success
        );
        assert_eq!(
            audit_rows[0].backend_action_id.as_ref().unwrap().as_str(),
            "ozone:did:plc:s:42"
        );
    }

    #[tokio::test]
    async fn dispatch_takedown_records_audit_on_failure() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        backend.with_takedown_err(BackendError::Network("connection refused".into()));
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::Takedown,
            ActionMapEntry::Method(BackendMethod::TakedownAccount),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };
        dispatch_after_record_action(Some(&bridge), &pool, ctx(action_id, "did:plc:s")).await;

        let audit_rows = crate::pds_admin::audit::list_pds_admin_audit_for_action(&pool, action_id)
            .await
            .unwrap();
        assert_eq!(audit_rows.len(), 1);
        assert_eq!(
            audit_rows[0].outcome,
            crate::pds_admin::AuditOutcome::Network
        );
        assert_eq!(
            audit_rows[0].error_message.as_deref(),
            Some("connection refused")
        );
        assert!(audit_rows[0].backend_action_id.is_none());
    }

    #[tokio::test]
    async fn dispatch_label_method_skips_with_warn() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::Takedown,
            ActionMapEntry::Method(BackendMethod::ApplyLabel),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };
        dispatch_after_record_action(Some(&bridge), &pool, ctx(action_id, "did:plc:s")).await;
        assert!(
            backend.calls().is_empty(),
            "label method must NOT actually be called from recordAction dispatch"
        );
        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM pds_admin_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn dispatch_restore_method_skips_with_error_log() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::Takedown,
            ActionMapEntry::Method(BackendMethod::RestoreAccount),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };
        dispatch_after_record_action(Some(&bridge), &pool, ctx(action_id, "did:plc:s")).await;
        assert!(backend.calls().is_empty());
    }
}
