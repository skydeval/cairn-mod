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
use crate::pds_admin::types::Subject;

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
    /// Record AT-URI when the underlying `subject_actions` row
    /// targets a record (v1.8.2, §4.5.1). `None` for
    /// account-level actions. Presence participates in the
    /// subject-shape routing in this module's dispatch helper.
    pub subject_uri: Option<&'a str>,
    /// Record CID when known (v1.8.2, §4.5.1). NOTE:
    /// `subject_actions` has no CID column at v1.8.2, so the
    /// recordAction pipeline always passes `None` — the
    /// auto-elevation arm that needs `(uri, cid)` both present
    /// is exercised only by direct callers/tests until a CID
    /// source lands. A record-targeting row without a CID
    /// rejects at dispatch with `Validation` per §4.5.1's
    /// no-fallback rule (it does NOT fall back to v1.7's
    /// account-level takedown).
    pub subject_cid: Option<&'a str>,
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
    /// ISO-8601 duration string from the recordAction request
    /// (e.g. `P7D`, `PT24H`). Required for `temp_suspension`,
    /// rejected for everything else by the recorder. The
    /// dispatch parses this into `duration_days` for
    /// `suspend_account`'s wire encoding (#89). `None` for
    /// non-temp_suspension actions.
    pub duration_iso: Option<&'a str>,
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
        BackendMethod::TakedownAccount
        | BackendMethod::SuspendAccount
        | BackendMethod::TakedownRecord => {}
    }

    let reason = ctx.reason_codes.first().map(String::as_str).unwrap_or("");
    // §5.7: an empty reason_codes vec is fixable operator
    // misconfiguration, not a dispatch-stopper — the action still
    // reaches the PDS, but the upstream moderator view shows no
    // reason. WARN so operators can find and fix it.
    if reason.is_empty() {
        tracing::warn!(
            target: "cairn_mod::pds_admin::rust::dispatch",
            action_id = ctx.action_id,
            method = method.as_wire_str(),
            "dispatching backend action with empty rationale (subject_actions row has \
             empty reason_codes); the upstream moderator view will show no reason"
        );
    }

    // v1.8.2 §4.5.1: subject-shape-aware sub-routing. A
    // record-targeting row (uri + cid both present) under an
    // account-verb action_map entry auto-elevates to
    // takedown_record; the audit row and log lines record the
    // method that was actually dispatched.
    let effective_method = match (method, ctx.subject_uri, ctx.subject_cid) {
        (BackendMethod::TakedownAccount, Some(_), Some(_)) => BackendMethod::TakedownRecord,
        _ => method,
    };

    // Duration plumbing for SuspendAccount (#89). For other
    // methods, duration_days is meaningless and ignored.
    // Parse failures here are logged and dispatched as None
    // (the suspension still goes through, but bsky-PDS's
    // operator-visible ref field will say `duration_days=indef`
    // which is wrong-but-safe — the cairn-mod-side action is
    // still a temp_suspension; reconciliation is the operator's).
    let duration_days = match (method, ctx.duration_iso) {
        (BackendMethod::SuspendAccount, Some(iso)) => match parse_duration_iso_to_days(iso) {
            Ok(days) => Some(days),
            Err(e) => {
                tracing::error!(
                    action_id = ctx.action_id,
                    duration_iso = iso,
                    error = %e,
                    "pds_admin: failed to parse temp_suspension duration; dispatching with duration_days=indef (cairn-mod-side action is still temp_suspension)"
                );
                None
            }
        },
        _ => None,
    };

    let started_at = crate::writer::epoch_ms_now();
    let call_result = invoke_backend_method(
        bridge.backend.as_ref(),
        method,
        ctx.subject_did,
        ctx.subject_uri,
        ctx.subject_cid,
        reason,
        ctx.notes,
        duration_days,
        ctx.action_id,
    )
    .await;
    let completed_at = crate::writer::epoch_ms_now();

    log_call_outcome(
        effective_method,
        ctx.action_id,
        ctx.subject_did,
        &call_result,
    );
    warn_rust_backend_capability_gap(bridge, effective_method, ctx.action_id, &call_result);

    // Project the per-method success into the unified
    // `Option<BackendActionId>` shape that
    // `record_pds_admin_call` accepts. Per #87:
    // `BackendMethod::returns_action_id()` single-sources the
    // convention. Keyed on `effective_method` so an auto-elevated
    // record takedown records its returned action id.
    let unified: std::result::Result<Option<BackendActionId>, BackendError> =
        match (effective_method.returns_action_id(), call_result) {
            (true, Ok(id)) => Ok(Some(id)),
            (false, Ok(_)) => Ok(None),
            (_, Err(e)) => Err(e),
        };

    if let Err(e) = record_pds_admin_call(
        pool,
        ctx.action_id,
        effective_method,
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
            method = effective_method.as_wire_str(),
            "pds_admin audit insert failed; cairn-mod-side action remains committed"
        );
    }
}

/// Dispatch the trait method whose shape matches `method`, with
/// subject-shape-aware sub-routing for the takedown verbs
/// (v1.8.2, §4.5.1). The match arms unify on
/// `Result<BackendActionId, BackendError>` even for unit-result
/// methods — those return a synthesized "ignored" id that the
/// caller drops via `returns_action_id()`.
///
/// **Routing rule (exhaustive over the shape space — no
/// catch-all, no silent shape coercion):**
///
/// - account-verb + account-shaped row → `takedown_account`;
/// - account-verb + fully record-shaped row (uri AND cid) →
///   auto-elevates to `takedown_record`;
/// - explicit record-verb + fully record-shaped row →
///   `takedown_record`;
/// - **partial** record coordinates (uri without cid, or cid
///   without uri) under either takedown verb, or an explicit
///   record-verb without full coordinates → `Validation`. Never
///   coerced into a whole-account takedown; never quietly
///   dropped.
///
/// `duration_days` is honored only by `SuspendAccount`; other
/// methods ignore it. Suspend keeps v1.7's account-level
/// semantics regardless of row shape (record-level suspension is
/// not a thing on either backend's wire).
#[allow(clippy::too_many_arguments)]
async fn invoke_backend_method(
    backend: &dyn PdsAdminBackend,
    method: BackendMethod,
    did: &str,
    subject_uri: Option<&str>,
    subject_cid: Option<&str>,
    reason: &str,
    notes: Option<&str>,
    duration_days: Option<u32>,
    action_id: i64,
) -> std::result::Result<BackendActionId, BackendError> {
    match (method, subject_uri, subject_cid) {
        // Account-verb, account-shaped row.
        (BackendMethod::TakedownAccount, None, None) => {
            backend
                .takedown_account(did, reason, notes, action_id)
                .await
        }
        // Account-verb, fully record-shaped row: auto-elevate.
        // Explicit record-verb, fully record-shaped row: direct.
        (BackendMethod::TakedownAccount, Some(uri), Some(cid))
        | (BackendMethod::TakedownRecord, Some(uri), Some(cid)) => {
            let subject = Subject::record(did, uri, Some(cid.to_string()));
            backend
                .takedown_record(&subject, reason, notes, action_id)
                .await
        }
        // Partial record coordinates under either takedown verb,
        // or explicit record-verb without full coordinates:
        // malformed. Reject; do not elevate, coerce, or fall back
        // to account-shape dispatch (§4.5.1).
        (BackendMethod::TakedownAccount, Some(_), None)
        | (BackendMethod::TakedownAccount, None, Some(_))
        | (BackendMethod::TakedownRecord, _, _) => Err(BackendError::Validation(format!(
            "takedown dispatch with partial or missing record coordinates \
             (uri present: {}, cid present: {}); subject shape must be fully \
             account (no uri/cid) or fully record (both uri and cid)",
            subject_uri.is_some(),
            subject_cid.is_some(),
        ))),
        // Suspend: account-level semantics regardless of row shape
        // (v1.7 behavior unchanged per §4.5.1 "other methods").
        (BackendMethod::SuspendAccount, _, _) => {
            backend
                .suspend_account(did, reason, duration_days, notes, action_id)
                .await
        }
        (
            BackendMethod::RestoreAccount | BackendMethod::ApplyLabel | BackendMethod::NegateLabel,
            _,
            _,
        ) => {
            // Filtered out by the dispatch caller; reaching this
            // arm would be a bug in this module.
            unreachable!(
                "invoke_backend_method dispatched non-record-action method {method:?}; \
                 dispatch_after_record_action should have filtered it"
            )
        }
    }
}

/// Parse an ISO-8601 duration string into days, rounded down.
///
/// Reuses [`crate::writer::parse_iso8601_duration`] (the same
/// parser the recorder validates `RecordActionRequest.duration_iso`
/// with at the input boundary) so cairn-mod has one source of
/// truth for "what duration shapes are acceptable."
///
/// Sub-day suspensions (e.g. `PT12H`) round down to 0 days. The
/// bsky-PDS `ref` field then encodes `duration_days=0`, which
/// is operator-visible signal but not protocol-meaningful (the
/// suspension lift is still cairn-mod-driven, not bsky-PDS-driven,
/// so the day-rounding doesn't affect when the lift fires).
/// Non-day-aligned operator config is uncommon enough to punt on.
///
/// Returns `Err(crate::error::Error::Signing(_))` for malformed
/// input (matches the parser's existing error type), or for
/// durations exceeding `u32::MAX` days (~11.7 million years —
/// nonsense in practice but handled cleanly).
pub(crate) fn parse_duration_iso_to_days(iso: &str) -> crate::error::Result<u32> {
    let secs = crate::writer::parse_iso8601_duration(iso)?;
    let days = secs / 86_400;
    u32::try_from(days).map_err(|_| {
        crate::error::Error::Signing(format!("duration {iso:?}: {days} days exceeds u32::MAX"))
    })
}

// ===========================================================================
// Revoke-action dispatch (#89)
// ===========================================================================

/// Snapshot of a revoke-action commit the PDS-admin restore
/// dispatch needs.
#[derive(Debug, Clone, Copy)]
pub struct RevokeDispatchContext<'a> {
    /// `subject_actions(id)` of the action being revoked. Used
    /// both for the audit-row FK (the restore call's
    /// `precipitating_action_id` is the original action's id —
    /// "show me everything cairn-mod tried to do on the PDS for
    /// this action" returns the takedown AND the restore in
    /// chain order) AND for looking up the prior backend call.
    pub action_id: i64,
    /// Subject DID of the action being revoked.
    pub subject_did: &'a str,
    /// Optional revocation rationale from the moderator. Encoded
    /// in the backend's `ref` field for cross-system traceability;
    /// empty string when absent.
    pub revoke_reason: Option<&'a str>,
}

/// Dispatch the post-revokeAction PDS-admin call (if any).
///
/// Looks up the prior `pds_admin_audit` row for the action
/// being revoked — specifically, the most recent `success`-outcome
/// row with a non-NULL `backend_action_id`. If found, fires
/// [`PdsAdminBackend::restore_account`] against that
/// `BackendActionId`. If not found (action was never propagated
/// to the PDS, or the original call failed), logs a warning and
/// skips — there's nothing on the PDS side to undo.
///
/// Same failure semantics as
/// [`dispatch_after_record_action`]: log loudly, audit-record,
/// don't propagate. The cairn-mod-side revocation has already
/// committed by this point.
pub async fn dispatch_after_revoke_action(
    bridge: Option<&PdsAdminBridge>,
    pool: &Pool<Sqlite>,
    ctx: RevokeDispatchContext<'_>,
) {
    let Some(bridge) = bridge else {
        return;
    };
    if !bridge.policy.enabled {
        return;
    }

    // Look up prior PDS-side calls for this action. The
    // list_pds_admin_audit_for_action API returns rows in chain
    // order (call_completed_at ASC, ties broken on id ASC); we
    // want the most recent success.
    let prior_calls =
        match crate::pds_admin::list_pds_admin_audit_for_action(pool, ctx.action_id).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    action_id = ctx.action_id,
                    "pds_admin revoke dispatch: pds_admin_audit lookup failed; \
                     skipping restore (cairn-mod-side revocation is committed)"
                );
                return;
            }
        };
    let prior = prior_calls
        .iter()
        .rev()
        .find(|r| {
            r.outcome == crate::pds_admin::AuditOutcome::Success && r.backend_action_id.is_some()
        })
        .cloned();

    let Some(prior) = prior else {
        tracing::warn!(
            action_id = ctx.action_id,
            "pds_admin revoke dispatch: no prior successful PDS call for this action; \
             skipping restore (action was never propagated to PDS, or original call \
             failed). cairn-mod-side revocation remains committed."
        );
        return;
    };

    // SAFETY: the find predicate above guaranteed Some.
    let prior_action_id = prior
        .backend_action_id
        .expect("filter retains only rows with backend_action_id = Some");
    let reason = ctx.revoke_reason.unwrap_or("");

    let started_at = crate::writer::epoch_ms_now();
    let call_result = bridge
        .backend
        .restore_account(ctx.subject_did, &prior_action_id, reason)
        .await;
    let completed_at = crate::writer::epoch_ms_now();

    log_call_outcome(
        BackendMethod::RestoreAccount,
        ctx.action_id,
        ctx.subject_did,
        &call_result,
    );
    warn_rust_backend_capability_gap(
        bridge,
        BackendMethod::RestoreAccount,
        ctx.action_id,
        &call_result,
    );

    // Project Result<(), BackendError> into the unified
    // Result<Option<BackendActionId>, BackendError> shape.
    // restore_account is a unit-result method, so success carries
    // no new BackendActionId — the audit row's backend_action_id
    // column is None (the prior_action_id is preserved in the
    // ref field on the wire, but the audit row's column refers to
    // the call's RETURN value, not its input).
    let unified: std::result::Result<Option<BackendActionId>, BackendError> = match call_result {
        Ok(()) => Ok(None),
        Err(e) => Err(e),
    };

    if let Err(e) = record_pds_admin_call(
        pool,
        ctx.action_id,
        BackendMethod::RestoreAccount,
        unified,
        started_at,
        completed_at,
    )
    .await
    {
        tracing::error!(
            error = %e,
            action_id = ctx.action_id,
            method = BackendMethod::RestoreAccount.as_wire_str(),
            "pds_admin audit insert failed for restore call; cairn-mod-side revocation \
             remains committed"
        );
    }
}

/// v1.8.1 §4.7: operator-visible warning when a RustBackend
/// dispatch returns [`BackendError::CapabilityNotAdvertised`].
///
/// Gated on [`should_warn_rust_backend_dispatch`] — a stateless
/// predicate over `(enabled, backend = Rust)`; one warning per
/// dispatched call (per-family dedup is deliberately deferred —
/// it would require call-site state the umbrella doesn't commit
/// at v1.8.1). Warning target matches the capability-refresh
/// warning channel (umbrella §5.2) so operators watch one scope.
fn warn_rust_backend_capability_gap<T>(
    bridge: &PdsAdminBridge,
    method: BackendMethod,
    action_id: i64,
    result: &std::result::Result<T, BackendError>,
) {
    let Err(BackendError::CapabilityNotAdvertised(capability)) = result else {
        return;
    };
    if !crate::pds_admin::config::should_warn_rust_backend_dispatch(&bridge.policy) {
        return;
    }
    tracing::warn!(
        target: "cairn_mod::pds_admin::rust::capability",
        action_id,
        method = method.as_wire_str(),
        capability = %capability,
        "pds_admin: RustBackend dispatch skipped — the target PDS does not advertise \
         capability \"{capability}\". v1.8.1's RustBackend is inspector-only; every \
         dispatch records an audit-failure row until v1.8.2's protocol-parity work \
         lands (see acknowledge_v1_8_1_audit_divergence)."
    );
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
        Err(e) => {
            // Severity selection by variant operator affordance:
            // - Transient → WARN (transient; not retried in v1.7)
            // - Auth, Validation, Unsupported, ArchitecturallyForbidden,
            //   CapabilityNotAdvertised → ERROR (operator-actionable)
            // - Terminal → WARN (upstream-state; investigate but not
            //   a cairn-mod-side bug)
            let category = e.variant_name();
            let message = e.message();
            let retry_after_seconds = e.retry_after_seconds();
            let error_code = e.error_code();
            match e {
                BackendError::Transient(_) => tracing::warn!(
                    action_id,
                    subject_did,
                    method = method.as_wire_str(),
                    error_category = category,
                    error_code = ?error_code,
                    retry_after_seconds = ?retry_after_seconds,
                    error = %message,
                    "pds_admin backend call failed transiently (not retried in v1.7)"
                ),
                BackendError::Auth(_) => tracing::error!(
                    action_id,
                    subject_did,
                    method = method.as_wire_str(),
                    error_category = category,
                    error = %message,
                    "pds_admin backend rejected our admin auth (operator must rotate credentials)"
                ),
                BackendError::Terminal(_) => tracing::warn!(
                    action_id,
                    subject_did,
                    method = method.as_wire_str(),
                    error_category = category,
                    error_code = ?error_code,
                    error = %message,
                    "pds_admin backend rejected the call on upstream state (operator should investigate)"
                ),
                BackendError::Validation(_) => tracing::error!(
                    action_id,
                    subject_did,
                    method = method.as_wire_str(),
                    error_category = category,
                    error_code = ?error_code,
                    error = %message,
                    "pds_admin backend rejected our request as malformed (cairn-mod-side bug)"
                ),
                BackendError::CapabilityNotAdvertised(_) => tracing::error!(
                    action_id,
                    subject_did,
                    method = method.as_wire_str(),
                    error_category = category,
                    error = %message,
                    "pds_admin backend does not advertise the required capability (operator config issue)"
                ),
                BackendError::Unsupported => tracing::error!(
                    action_id,
                    subject_did,
                    method = method.as_wire_str(),
                    error_category = category,
                    "pds_admin backend does not implement this method (switch backends if needed)"
                ),
                BackendError::ArchitecturallyForbidden(_) => tracing::error!(
                    action_id,
                    subject_did,
                    method = method.as_wire_str(),
                    error_category = category,
                    error = %message,
                    "pds_admin backend method architecturally forbidden by cairn-mod (configuration bug — should be rejected at action_map validation)"
                ),
            }
        }
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
            Err(BackendError::Unsupported)
        }

        async fn negate_label(
            &self,
            _subject: &Subject,
            _val: &str,
        ) -> std::result::Result<(), BackendError> {
            unimplemented!()
        }

        async fn probe(
            &self,
        ) -> std::result::Result<crate::pds_admin::backend::ProbeReport, BackendError> {
            unimplemented!("RecordingBackend test stub: probe not exercised by dispatch tests")
        }

        async fn query_events(
            &self,
            _filter: crate::pds_admin::rust::read_types::QueryEventsFilter,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::PaginatedResponse<
                crate::pds_admin::rust::read_types::EventWithContext,
            >,
            BackendError,
        > {
            unimplemented!("test backend does not stub query_events")
        }

        async fn query_statuses(
            &self,
            _filter: crate::pds_admin::rust::read_types::QueryStatusesFilter,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::PaginatedResponse<
                crate::pds_admin::rust::read_types::StatusWithContext,
            >,
            BackendError,
        > {
            unimplemented!("test backend does not stub query_statuses")
        }

        async fn get_event(
            &self,
            _event_id: i64,
        ) -> std::result::Result<crate::pds_admin::rust::read_types::EventWithContext, BackendError>
        {
            unimplemented!("test backend does not stub get_event")
        }

        async fn get_subject_context(
            &self,
            _did: &str,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::SubjectContextResponse,
            BackendError,
        > {
            unimplemented!("test backend does not stub get_subject_context")
        }

        async fn get_subject_history(
            &self,
            _did: &str,
            _filter: crate::pds_admin::rust::read_types::SubjectHistoryFilter,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::PaginatedResponse<
                crate::pds_admin::rust::read_types::StatusWithContext,
            >,
            BackendError,
        > {
            unimplemented!("test backend does not stub get_subject_history")
        }

        async fn list_appeals(
            &self,
            _filter: crate::pds_admin::rust::read_types::ListAppealsFilter,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::PaginatedResponse<
                crate::pds_admin::rust::read_types::AppealView,
            >,
            BackendError,
        > {
            unimplemented!("test backend does not stub list_appeals")
        }

        async fn get_appeal(
            &self,
            _appeal_id: i64,
        ) -> std::result::Result<crate::pds_admin::rust::read_types::AppealDetail, BackendError>
        {
            unimplemented!("test backend does not stub get_appeal")
        }

        async fn takedown_record(
            &self,
            subject: &Subject,
            reason: &str,
            _notes: Option<&str>,
            precipitating_action_id: i64,
        ) -> std::result::Result<BackendActionId, BackendError> {
            self.calls.lock().unwrap().push(RecordedCall {
                method: "takedown_record",
                did: subject.did.clone(),
                reason: reason.to_string(),
                action_id: precipitating_action_id,
            });
            self.takedown_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Ok(BackendActionId::new(format!(
                        "test:record:{precipitating_action_id}"
                    )))
                })
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
            subject_uri: None,
            subject_cid: None,
            reason_codes: reasons,
            notes: None,
            duration_iso: None,
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
        backend.with_takedown_err(BackendError::Transient("connection refused".into()));
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

    // ===== ISO-8601 → days parsing (#89) =====

    #[test]
    fn parse_duration_iso_to_days_handles_known_formats() {
        // ISO-8601 day-aligned forms cover the v1.7 production
        // range. Reuse cases the recorder's parser already
        // exercises so any divergence between the two sites
        // surfaces here.
        assert_eq!(parse_duration_iso_to_days("P7D").unwrap(), 7);
        assert_eq!(parse_duration_iso_to_days("P1W").unwrap(), 7);
        assert_eq!(parse_duration_iso_to_days("P14D").unwrap(), 14);
        assert_eq!(parse_duration_iso_to_days("P30D").unwrap(), 30);
    }

    #[test]
    fn parse_duration_iso_to_days_rounds_sub_day_down() {
        // Sub-day suspensions round down to 0. Matches the
        // doc-comment's "sub-day → 0 days" contract; operators
        // wanting hour-resolution suspensions are an edge case
        // v1.7 punts on.
        assert_eq!(parse_duration_iso_to_days("PT12H").unwrap(), 0);
        assert_eq!(parse_duration_iso_to_days("PT30M").unwrap(), 0);
        assert_eq!(parse_duration_iso_to_days("PT1S").unwrap(), 0);
    }

    #[test]
    fn parse_duration_iso_to_days_rejects_malformed() {
        assert!(parse_duration_iso_to_days("not a duration").is_err());
        assert!(parse_duration_iso_to_days("7D").is_err()); // missing P prefix
        assert!(parse_duration_iso_to_days("P").is_err()); // empty
        assert!(parse_duration_iso_to_days("P1Y").is_err()); // years not supported per recorder
    }

    // ===== SuspendAccount dispatch with duration plumbing (#89) =====

    fn temp_suspension_ctx<'a>(
        action_id: i64,
        did: &'a str,
        iso: Option<&'a str>,
    ) -> DispatchContext<'a> {
        static REASONS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        let reasons = REASONS.get_or_init(|| vec!["spam".into()]);
        DispatchContext {
            action_id,
            action_type: ActionType::TempSuspension,
            subject_did: did,
            subject_uri: None,
            subject_cid: None,
            reason_codes: reasons,
            notes: None,
            duration_iso: iso,
        }
    }

    #[tokio::test]
    async fn dispatch_suspend_with_duration_passes_days_to_backend() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = SuspensionRecordingBackend::new();
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::TempSuspension,
            ActionMapEntry::Method(BackendMethod::SuspendAccount),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };

        dispatch_after_record_action(
            Some(&bridge),
            &pool,
            temp_suspension_ctx(action_id, "did:plc:s", Some("P7D")),
        )
        .await;

        let calls = backend.suspend_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].duration_days, Some(7));
        assert_eq!(calls[0].did, "did:plc:s");
    }

    #[tokio::test]
    async fn dispatch_suspend_with_no_duration_passes_none() {
        // IndefSuspension or unparseable → None passed through.
        // (The recorder requires temp_suspension to have a
        // duration, but the ActionMapEntry could route an
        // IndefSuspension here in practice.)
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = SuspensionRecordingBackend::new();
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::IndefSuspension,
            ActionMapEntry::Method(BackendMethod::SuspendAccount),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };

        let mut indef_ctx = ctx(action_id, "did:plc:s");
        indef_ctx.action_type = ActionType::IndefSuspension;
        dispatch_after_record_action(Some(&bridge), &pool, indef_ctx).await;

        let calls = backend.suspend_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].duration_days, None);
    }

    #[tokio::test]
    async fn dispatch_suspend_with_malformed_duration_logs_and_passes_none() {
        // Per #89's design: parse failure falls through with
        // duration_days=None rather than aborting the dispatch.
        // The cairn-mod-side action is still committed; the
        // bsky-PDS ref will say `duration_days=indef` which is
        // wrong-but-safe.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = SuspensionRecordingBackend::new();
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::TempSuspension,
            ActionMapEntry::Method(BackendMethod::SuspendAccount),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };

        dispatch_after_record_action(
            Some(&bridge),
            &pool,
            temp_suspension_ctx(action_id, "did:plc:s", Some("not-a-duration")),
        )
        .await;

        let calls = backend.suspend_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].duration_days, None,
            "malformed duration → None (logged at error level)"
        );
    }

    // ===== Revoke dispatch (#89) =====

    #[tokio::test]
    async fn revoke_dispatch_noop_when_bridge_none() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        dispatch_after_revoke_action(
            None,
            &pool,
            RevokeDispatchContext {
                action_id,
                subject_did: "did:plc:s",
                revoke_reason: None,
            },
        )
        .await;
        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM pds_admin_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn revoke_dispatch_skips_when_no_prior_pds_call() {
        // The action was never propagated to the PDS (no
        // pds_admin_audit row); revoke has nothing to undo.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = SuspensionRecordingBackend::new();
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, BTreeMap::new()),
            backend: backend.clone(),
        };
        dispatch_after_revoke_action(
            Some(&bridge),
            &pool,
            RevokeDispatchContext {
                action_id,
                subject_did: "did:plc:s",
                revoke_reason: Some("oops"),
            },
        )
        .await;
        assert!(
            backend.restore_calls.lock().unwrap().is_empty(),
            "no prior call → no restore"
        );
    }

    #[tokio::test]
    async fn revoke_dispatch_calls_restore_with_prior_action_id() {
        // Setup: pretend a takedown succeeded for action_id by
        // writing the audit row directly. Then dispatch_revoke
        // should pick up that BackendActionId and pass it to
        // restore_account.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        crate::pds_admin::record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new("ozone:did:plc:s:42"))),
            10,
            20,
        )
        .await
        .unwrap();

        let backend = SuspensionRecordingBackend::new();
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, BTreeMap::new()),
            backend: backend.clone(),
        };

        dispatch_after_revoke_action(
            Some(&bridge),
            &pool,
            RevokeDispatchContext {
                action_id,
                subject_did: "did:plc:s",
                revoke_reason: Some("manual lift"),
            },
        )
        .await;

        // Snapshot + drop the mutex guard before the next await
        // (clippy::await_holding_lock is enforced as -D warnings).
        let snapshot = {
            let restores = backend.restore_calls.lock().unwrap();
            restores
                .iter()
                .map(|r| (r.did.clone(), r.prior_id.clone(), r.reason.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0, "did:plc:s");
        assert_eq!(snapshot[0].1, "ozone:did:plc:s:42");
        assert_eq!(snapshot[0].2, "manual lift");

        // The restore call's audit row landed.
        let rows = crate::pds_admin::list_pds_admin_audit_for_action(&pool, action_id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "takedown + restore audit rows");
        assert_eq!(rows[1].backend_method, BackendMethod::RestoreAccount);
        assert_eq!(rows[1].outcome, crate::pds_admin::AuditOutcome::Success);
        assert!(rows[1].backend_action_id.is_none());
    }

    #[tokio::test]
    async fn revoke_dispatch_skips_when_prior_call_failed() {
        // Prior call recorded as Network failure (no
        // backend_action_id) — revoke has no id to refer to,
        // logs a warning and skips.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        crate::pds_admin::record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Err(BackendError::Transient("dns".into())),
            10,
            20,
        )
        .await
        .unwrap();

        let backend = SuspensionRecordingBackend::new();
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, BTreeMap::new()),
            backend: backend.clone(),
        };
        dispatch_after_revoke_action(
            Some(&bridge),
            &pool,
            RevokeDispatchContext {
                action_id,
                subject_did: "did:plc:s",
                revoke_reason: None,
            },
        )
        .await;
        assert!(
            backend.restore_calls.lock().unwrap().is_empty(),
            "no successful prior → no restore"
        );
    }

    // Test backend that records suspend AND restore calls. Used
    // by the SuspendAccount + revoke tests above.
    struct SuspensionRecordingBackend {
        suspend_calls: Mutex<Vec<RecordedSuspend>>,
        restore_calls: Mutex<Vec<RecordedRestore>>,
    }

    #[derive(Debug)]
    struct RecordedSuspend {
        did: String,
        duration_days: Option<u32>,
    }

    #[derive(Debug)]
    struct RecordedRestore {
        did: String,
        prior_id: String,
        reason: String,
    }

    impl SuspensionRecordingBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                suspend_calls: Mutex::new(Vec::new()),
                restore_calls: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl PdsAdminBackend for SuspensionRecordingBackend {
        async fn takedown_account(
            &self,
            _did: &str,
            _reason: &str,
            _notes: Option<&str>,
            _id: i64,
        ) -> std::result::Result<BackendActionId, BackendError> {
            unreachable!("test backend does not stub takedown")
        }

        async fn suspend_account(
            &self,
            did: &str,
            _reason: &str,
            duration_days: Option<u32>,
            _notes: Option<&str>,
            id: i64,
        ) -> std::result::Result<BackendActionId, BackendError> {
            self.suspend_calls.lock().unwrap().push(RecordedSuspend {
                did: did.to_string(),
                duration_days,
            });
            Ok(BackendActionId::new(format!("ozone:{did}:{id}")))
        }

        async fn restore_account(
            &self,
            did: &str,
            prior_action_id: &BackendActionId,
            reason: &str,
        ) -> std::result::Result<(), BackendError> {
            self.restore_calls.lock().unwrap().push(RecordedRestore {
                did: did.to_string(),
                prior_id: prior_action_id.as_str().to_string(),
                reason: reason.to_string(),
            });
            Ok(())
        }

        async fn apply_label(
            &self,
            _subject: &Subject,
            _val: &str,
            _expires_days: Option<u32>,
        ) -> std::result::Result<(), BackendError> {
            unreachable!()
        }

        async fn negate_label(
            &self,
            _subject: &Subject,
            _val: &str,
        ) -> std::result::Result<(), BackendError> {
            unreachable!()
        }

        async fn probe(
            &self,
        ) -> std::result::Result<crate::pds_admin::backend::ProbeReport, BackendError> {
            unreachable!("SuspensionRecordingBackend test stub: probe not exercised here")
        }

        async fn query_events(
            &self,
            _filter: crate::pds_admin::rust::read_types::QueryEventsFilter,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::PaginatedResponse<
                crate::pds_admin::rust::read_types::EventWithContext,
            >,
            BackendError,
        > {
            unimplemented!("test backend does not stub query_events")
        }

        async fn query_statuses(
            &self,
            _filter: crate::pds_admin::rust::read_types::QueryStatusesFilter,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::PaginatedResponse<
                crate::pds_admin::rust::read_types::StatusWithContext,
            >,
            BackendError,
        > {
            unimplemented!("test backend does not stub query_statuses")
        }

        async fn get_event(
            &self,
            _event_id: i64,
        ) -> std::result::Result<crate::pds_admin::rust::read_types::EventWithContext, BackendError>
        {
            unimplemented!("test backend does not stub get_event")
        }

        async fn get_subject_context(
            &self,
            _did: &str,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::SubjectContextResponse,
            BackendError,
        > {
            unimplemented!("test backend does not stub get_subject_context")
        }

        async fn get_subject_history(
            &self,
            _did: &str,
            _filter: crate::pds_admin::rust::read_types::SubjectHistoryFilter,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::PaginatedResponse<
                crate::pds_admin::rust::read_types::StatusWithContext,
            >,
            BackendError,
        > {
            unimplemented!("test backend does not stub get_subject_history")
        }

        async fn list_appeals(
            &self,
            _filter: crate::pds_admin::rust::read_types::ListAppealsFilter,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> std::result::Result<
            crate::pds_admin::rust::read_types::PaginatedResponse<
                crate::pds_admin::rust::read_types::AppealView,
            >,
            BackendError,
        > {
            unimplemented!("test backend does not stub list_appeals")
        }

        async fn get_appeal(
            &self,
            _appeal_id: i64,
        ) -> std::result::Result<crate::pds_admin::rust::read_types::AppealDetail, BackendError>
        {
            unimplemented!("test backend does not stub get_appeal")
        }

        async fn takedown_record(
            &self,
            _subject: &Subject,
            _reason: &str,
            _notes: Option<&str>,
            _precipitating_action_id: i64,
        ) -> std::result::Result<BackendActionId, BackendError> {
            unreachable!("test backend does not stub takedown_record")
        }
    }

    // ===== v1.8.2 subject-shape routing (§4.5.1) =====

    fn ctx_shaped<'a>(
        action_id: i64,
        did: &'a str,
        uri: Option<&'a str>,
        cid: Option<&'a str>,
    ) -> DispatchContext<'a> {
        static REASONS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        let reasons = REASONS.get_or_init(|| vec!["spam".into()]);
        DispatchContext {
            action_id,
            action_type: ActionType::Takedown,
            subject_did: did,
            subject_uri: uri,
            subject_cid: cid,
            reason_codes: reasons,
            notes: None,
            duration_iso: None,
        }
    }

    #[tokio::test]
    async fn record_shaped_row_auto_elevates_to_takedown_record() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        backend.with_takedown_ok("evt-elevated");
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::Takedown,
            ActionMapEntry::Method(BackendMethod::TakedownAccount),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };

        dispatch_after_record_action(
            Some(&bridge),
            &pool,
            ctx_shaped(
                action_id,
                "did:plc:s",
                Some("at://did:plc:s/app.bsky.feed.post/r1"),
                Some("bafyr1"),
            ),
        )
        .await;

        // The backend saw takedown_record, not takedown_account.
        let calls = backend.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, "takedown_record");

        // The audit row records the effective method and passes the
        // 0008-extended CHECK, with the returned action id.
        let row: (String, Option<String>, String) = sqlx::query_as(
            "SELECT backend_method, backend_action_id, outcome \
             FROM pds_admin_audit WHERE precipitating_action_id = ?1",
        )
        .bind(action_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "takedown_record");
        assert_eq!(row.1.as_deref(), Some("evt-elevated"));
        assert_eq!(row.2, "success");
    }

    #[tokio::test]
    async fn partial_record_coordinates_reject_with_validation_not_account_takedown() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::Takedown,
            ActionMapEntry::Method(BackendMethod::TakedownAccount),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };

        // uri present, cid absent — the shape every record-targeted
        // recordAction row has at v1.8.2 (subject_actions carries no
        // CID column). §4.5.1's no-fallback rule: Validation, and
        // crucially NO account-level takedown fires.
        dispatch_after_record_action(
            Some(&bridge),
            &pool,
            ctx_shaped(
                action_id,
                "did:plc:s",
                Some("at://did:plc:s/app.bsky.feed.post/r1"),
                None,
            ),
        )
        .await;

        assert!(
            backend.calls().is_empty(),
            "no backend method may fire for a partially-shaped subject"
        );
        let row: (String, Option<String>, String) = sqlx::query_as(
            "SELECT backend_method, backend_action_id, outcome \
             FROM pds_admin_audit WHERE precipitating_action_id = ?1",
        )
        .bind(action_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.2, "validation");
        assert_eq!(row.0, "takedown_account");
        assert!(row.1.is_none());
    }

    #[tokio::test]
    async fn explicit_takedown_record_route_without_coordinates_rejects() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::Takedown,
            ActionMapEntry::Method(BackendMethod::TakedownRecord),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };

        dispatch_after_record_action(
            Some(&bridge),
            &pool,
            ctx_shaped(action_id, "did:plc:s", None, None),
        )
        .await;

        assert!(backend.calls().is_empty());
        let row: (String, String) = sqlx::query_as(
            "SELECT backend_method, outcome \
             FROM pds_admin_audit WHERE precipitating_action_id = ?1",
        )
        .bind(action_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "takedown_record");
        assert_eq!(row.1, "validation");
    }

    #[tokio::test]
    async fn explicit_takedown_record_route_with_full_coordinates_dispatches() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let backend = RecordingBackend::new();
        backend.with_takedown_ok("evt-direct");
        let mut map = BTreeMap::new();
        map.insert(
            ActionType::Takedown,
            ActionMapEntry::Method(BackendMethod::TakedownRecord),
        );
        let bridge = PdsAdminBridge {
            policy: policy_with_action_map(true, map),
            backend: backend.clone(),
        };

        dispatch_after_record_action(
            Some(&bridge),
            &pool,
            ctx_shaped(
                action_id,
                "did:plc:s",
                Some("at://did:plc:s/c/r"),
                Some("bafyr2"),
            ),
        )
        .await;

        let calls = backend.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, "takedown_record");
    }
}
