//! Single-writer task (§F5 / §10 architecture).
//!
//! All mutations to `labels`, `label_sequence`, `audit_log`, and
//! `server_instance_lease` flow through one task that owns the write pool.
//! Other components obtain a cheaply-cloneable [`WriterHandle`] and submit
//! [`ApplyLabelRequest`] / [`NegateLabelRequest`] over an mpsc channel;
//! replies travel on per-request oneshot channels so the caller may cancel
//! (drop the future) without corrupting writer state — the transaction
//! still commits, the reply is discarded.
//!
//! Invariants this module enforces, any of which is load-bearing:
//!
//! - **Single instance.** On startup [`spawn`] either acquires the lease
//!   row in `server_instance_lease` (id = 1) or returns
//!   [`Error::LeaseHeld`]. A background heartbeat updates `last_heartbeat`
//!   every 10s; a second Cairn started against the same file sees a
//!   <60s-old heartbeat and refuses. The 60s threshold is 6× the heartbeat
//!   interval — tolerant of a single missed tick, strict enough that a
//!   legitimately-orphaned lease (hard crash, unclean shutdown) ages out
//!   before the operator manually restarts.
//!
//! - **Monotonic seq.** Sequence values come from
//!   `label_sequence.seq` (AUTOINCREMENT) reserved inside the same
//!   transaction as the `labels` INSERT. Under AUTOINCREMENT, SQLite
//!   never reuses a seq value even across rollbacks.
//!
//! - **Monotonic cts.** For each `(src, uri, val)` tuple the writer
//!   clamps to `max(wall_now, prev_cts + 1ms)` (§6.1) using the
//!   `labels_tuple_idx` composite index for the prev-cts lookup.
//!
//! - **Audit-per-write.** Every successful label INSERT produces exactly
//!   one `audit_log` row **in the same transaction**. The audit row's
//!   `reason` column carries a JSON object documenting the event
//!   ({"val", "neg", "moderator_reason"}). See [`AUDIT_REASON_SCHEMA`].
//!
//! - **Sign-then-insert.** `sign_label` runs between sequence reservation
//!   and the labels INSERT. The signed bytes include `ver` but not `seq`
//!   or `signing_key_id` (§6.2 step 1, §6.1: seq lives on the frame, not
//!   the label).

use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proto_blue_crypto::{K256Keypair, Keypair as _, format_multikey};
use sqlx::{Pool, Sqlite};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time::{MissedTickBehavior, interval};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::label::Label;
use crate::labels::emission::{
    ActionForEmission, LabelDraft, resolve_action_labels, resolve_reason_labels,
};
use crate::moderation::decay::calculate_strike_state;
use crate::moderation::policy::StrikePolicy;
use crate::moderation::reasons::ReasonVocabulary;
use crate::moderation::strike::{
    StrikeApplication, calculate as strike_calculate, resolve_primary_reason,
};
use crate::moderation::types::{ActionRecord, ActionType};
use crate::moderation::window::compute_position_in_window;
use crate::server::RetentionConfig;
use crate::signing::sign_label;
use crate::signing_key::SigningKey;

/// Lease freshness threshold (§F5). A lease younger than this is held by
/// a live peer; younger than 10s would be flaky under a single missed
/// heartbeat, older than ~2× the value risks a genuine zombie blocking a
/// legitimate restart for too long.
pub(crate) const LEASE_STALE_MS: i64 = 60_000;

/// Heartbeat interval. 10s × 6 = 60s staleness budget per the threshold.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Granularity at which the writer checks "is it time to start the
/// scheduled sweep?". Daily fires bucketed by UTC hour means we don't
/// need finer than this; 60s keeps the check cost negligible (one
/// `Instant::now()` comparison + an `Option` peek per minute).
const SWEEP_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Upper bound on queued write commands. Moderators rarely drive more
/// than single-digit req/s even on busy operators; 64 is a comfortable
/// overshoot that still makes backpressure visible quickly under a bug.
const COMMAND_BUFFER: usize = 64;

/// Broadcast buffer for [`LabelEvent`] fan-out. Slow subscribers hit
/// `RecvError::Lagged` past this; the subscribeLabels endpoint (#7) turns
/// that into a client-connection close.
const BROADCAST_BUFFER: usize = 1024;

/// Audit-log `reason` JSON schema for `label_applied` / `label_negated`.
/// Centralized as a doc constant so future actions (signing_key_added,
/// report_resolved, etc.) have an obvious place to register their shape.
///
/// ```json
/// {
///   "val": "<label value>",
///   "neg": true | false,
///   "moderator_reason": "<free text>" | null
/// }
/// ```
#[doc(alias = "audit_log.reason")]
pub const AUDIT_REASON_SCHEMA: &str =
    "label_applied / label_negated: { val, neg, moderator_reason }";

/// Audit-log `reason` JSON schema for `report_resolved` (§F12 resolveReport
/// atomicity — two rows land in one transaction: the inner label_applied
/// per [`AUDIT_REASON_SCHEMA`] plus this one).
///
/// ```json
/// {
///   "applied_label_val": "<val>" | null,
///   "resolution_reason": "<free text>" | null
/// }
/// ```
#[doc(alias = "audit_log.reason.report_resolved")]
pub const AUDIT_REASON_RESOLVE_REPORT: &str =
    "report_resolved: { applied_label_val, resolution_reason }";

/// Audit-log `reason` JSON schema for `reporter_flagged` /
/// `reporter_unflagged` (§F12 flagReporter).
///
/// ```json
/// {
///   "did": "<flagged DID>",
///   "suppressed": true | false,
///   "moderator_reason": "<free text>" | null
/// }
/// ```
#[doc(alias = "audit_log.reason.flag_reporter")]
pub const AUDIT_REASON_FLAG_REPORTER: &str =
    "reporter_flagged / reporter_unflagged: { did, suppressed, moderator_reason }";

/// Audit-log `reason` JSON schema for `retention_sweep` (§F4 — written
/// only by the operator-initiated admin path; the scheduled-fire
/// path does NOT audit per Q6/D2). Captures the result of the sweep
/// run for reconstruction-friendly ops queries.
///
/// ```json
/// {
///   "rows_deleted": <i64>,
///   "batches": <u64>,
///   "duration_ms": <u64>,
///   "retention_days_applied": <u32> | null
/// }
/// ```
#[doc(alias = "audit_log.reason.retention_sweep")]
pub const AUDIT_REASON_RETENTION_SWEEP: &str =
    "retention_sweep: { rows_deleted, batches, duration_ms, retention_days_applied }";

/// Closed set of `audit_log.action` values emitted by Cairn write paths.
///
/// §F10: audit rows only for moderation decisions, not for input/operational
/// events — `createReport` (input) intentionally does NOT audit. The
/// listAuditLog handler validates its `action` query param against this
/// exact set; unknown values return `InvalidRequest` rather than silently
/// matching zero rows.
///
/// Adding a new moderation action requires: (1) the handler writes an
/// `INSERT INTO audit_log (action, ...)` row, (2) the value is added here,
/// (3) the `reason` schema for the new action is documented as a const
/// alongside [`AUDIT_REASON_SCHEMA`] and friends.
pub const AUDIT_ACTION_VALUES: &[&str] = &[
    "label_applied",
    "label_negated",
    "pending_policy_action_confirmed",
    "pending_policy_action_dismissed",
    "report_resolved",
    "reporter_flagged",
    "reporter_unflagged",
    "retention_sweep",
    "subject_action_recorded",
    "subject_action_revoked",
];

/// Closed set of `audit_log.outcome` values matching the SQL `CHECK`
/// constraint in `migrations/0001_init.sql`. listAuditLog validates the
/// `outcome` query param against this set; the SQL constraint itself is
/// the durable source of truth — this slice mirrors it so the handler
/// can reject invalid values pre-query without round-tripping to SQLite.
pub const AUDIT_OUTCOME_VALUES: &[&str] = &["success", "failure"];

/// RFC-3339 with millisecond precision. `Z` is appended by
/// [`rfc3339_from_epoch_ms`] and stripped by [`parse_rfc3339_ms`] — kept
/// out of the format description because `time::OffsetDateTime::parse`
/// can't infer a UTC offset from the literal character `Z`, and
/// symmetric Z-handling at the string boundary is simpler than switching
/// parsing-only to `well_known::Rfc3339`.
const CTS_FORMAT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

/// Moderator request to apply a label (positive event).
#[derive(Debug, Clone)]
pub struct ApplyLabelRequest {
    /// The DID of the moderator issuing the request. Becomes
    /// `audit_log.actor_did`. `src` on the label itself is the writer's
    /// service DID, not this.
    pub actor_did: String,
    /// AT-URI or DID of the subject being labeled.
    pub uri: String,
    /// Optional record-version pin. Present means "this specific version";
    /// absent means "all versions / the account" per §6.1.
    pub cid: Option<String>,
    /// Label value, ≤128 bytes (validated on insert by schema CHECK and
    /// by caller-side input validation on the XRPC boundary).
    pub val: String,
    /// Optional expiration timestamp (RFC-3339 Z). Stored only; expiry
    /// enforcement is v1.1 (§F7).
    pub exp: Option<String>,
    /// Free-text reason recorded to `audit_log` only. Not signed, not
    /// included in the label record.
    pub moderator_reason: Option<String>,
}

/// Moderator request to negate (withdraw) a previously-applied label.
///
/// Uniqueness is at the `(src, uri, val)` tuple. The negation copies the
/// most-recent applied event's `cid` so the negation pins the same record
/// version — callers don't supply it.
#[derive(Debug, Clone)]
pub struct NegateLabelRequest {
    /// Moderator DID issuing the negation. Becomes
    /// `audit_log.actor_did`.
    pub actor_did: String,
    /// AT-URI or DID of the subject whose label is being withdrawn.
    /// The `cid` pinning (if any) is copied from the prior apply.
    pub uri: String,
    /// Label value being negated. Must match an existing applied
    /// label on `(src, uri, val)` or the call errors with
    /// `LabelNotFound`.
    pub val: String,
    /// Free-text reason recorded to `audit_log` only.
    pub moderator_reason: Option<String>,
}

/// A committed label event. Returned by `apply_label` / `negate_label` and
/// broadcast to subscribers (subscribeLabels consumers in #7). Wire
/// serialization is that consumer's concern — the LabelEvent itself
/// carries no serde derive because the canonical encoding for the wire is
/// the DAG-CBOR path in `crate::signing`, not serde JSON.
#[derive(Debug, Clone)]
pub struct LabelEvent {
    /// Frame sequence number from `label_sequence`. Strictly monotonic.
    pub seq: i64,
    /// The full signed label (`sig` populated).
    pub label: Label,
}

/// Internal write command. One variant per public method.
enum WriteCommand {
    Apply(ApplyLabelRequest, oneshot::Sender<Result<LabelEvent>>),
    Negate(NegateLabelRequest, oneshot::Sender<Result<LabelEvent>>),
    ResolveReport(
        ResolveReportRequest,
        oneshot::Sender<Result<ResolvedReport>>,
    ),
    Sweep(SweepRequest, oneshot::Sender<Result<SweepBatchResult>>),
    /// Append a hash-chained audit row (#39). Used by in-process
    /// callers that don't have an existing transaction (e.g.,
    /// `retentionSweep` after the sweep itself completes). Callers
    /// that already hold a transaction (writer-internal handlers,
    /// `flag_reporter`) call [`crate::audit::append::append_in_tx`]
    /// directly within that transaction instead.
    AppendAudit(
        crate::audit::append::AuditRowForAppend,
        oneshot::Sender<Result<i64>>,
    ),
    /// Record a graduated-action subject_actions row (§F20 / #51).
    /// Single-transaction: input validation, strike calculation,
    /// subject_actions INSERT, strike_state UPSERT, audit_log
    /// hash-chain append.
    RecordAction(RecordActionRequest, oneshot::Sender<Result<RecordedAction>>),
    /// Revoke a previously-recorded subject_actions row (§F20 /
    /// #51). Single-transaction: row lookup + state-check,
    /// revoked_at UPDATE, strike_state recompute, audit_log
    /// hash-chain append.
    RevokeAction(RevokeActionRequest, oneshot::Sender<Result<RevokedAction>>),
    /// Confirm a pending policy action (§F22 / #74). Promotes the
    /// pending row's proposed action to a real `subject_actions`
    /// row (actor_kind='moderator', triggered_by_policy_rule
    /// preserves the rule name as forensic provenance), emits
    /// labels, UPDATEs the pending row's resolution columns, and
    /// recomputes strike state — all hash-chained under one
    /// `pending_policy_action_confirmed` audit row.
    ConfirmPendingAction(
        ConfirmPendingActionRequest,
        oneshot::Sender<Result<ConfirmedPendingAction>>,
    ),
    /// Dismiss a pending policy action (§F22 / #75). Single-
    /// transaction: pending row load + state-check, UPDATE to
    /// resolution='dismissed', `pending_policy_action_dismissed`
    /// audit row. No subject_actions row, no label emission, no
    /// strike-state change — the moderator is explicitly closing
    /// the loop on what the policy engine flagged.
    DismissPendingAction(
        DismissPendingActionRequest,
        oneshot::Sender<Result<DismissedPendingAction>>,
    ),
    Shutdown(oneshot::Sender<Result<()>>),
}

/// Inline label-application sub-object for [`ResolveReportRequest`].
/// Structurally aligned with [`ApplyLabelRequest`] minus the
/// moderator-reason (that field on the outer request already captures
/// the resolution rationale; the label's own audit reason is derived
/// from the resolution flow).
#[derive(Debug, Clone)]
pub struct ApplyLabelInline {
    /// Subject the label applies to (AT-URI or DID).
    pub uri: String,
    /// Optional record-version pin; `None` targets the account / all
    /// versions of the record.
    pub cid: Option<String>,
    /// Label value to apply (≤128 bytes).
    pub val: String,
    /// Optional expiration timestamp (RFC-3339 Z). Stored only;
    /// enforcement is v1.1.
    pub exp: Option<String>,
}

/// Resolution outcome (#27): the implicit "with-label vs without-label"
/// semantic, made explicit. The wire shape is `applyLabel: Option<…>`
/// per the `resolveReport` lexicon; this enum is internal and the
/// handler maps `None → Dismiss` / `Some(_) → ApplyLabel(_)` at the
/// HTTP boundary.
#[derive(Debug, Clone)]
pub enum ResolutionAction {
    /// Resolve without emitting a label (the operator-UX "dismiss"
    /// flow). `resolution_label` on the row stays NULL.
    Dismiss,
    /// Resolve and emit a label in the same transaction. The label's
    /// `val` is also recorded as `resolution_label` on the report row.
    ApplyLabel(ApplyLabelInline),
}

impl ResolutionAction {
    /// Borrow the inner `ApplyLabelInline` if this is an `ApplyLabel`
    /// variant. Convenience for the writer's UPDATE / audit code that
    /// needs both the optional label *and* its `val` projection.
    pub fn as_apply(&self) -> Option<&ApplyLabelInline> {
        match self {
            ResolutionAction::Dismiss => None,
            ResolutionAction::ApplyLabel(a) => Some(a),
        }
    }
}

/// Request to resolve a report (§F12 `resolveReport`). The optional
/// label is applied **in the same transaction** as the report status
/// update and both audit rows — §F5 single-writer invariant plus §F12
/// atomicity requirement documented in the `resolveReport` lexicon.
#[derive(Debug, Clone)]
pub struct ResolveReportRequest {
    /// Moderator DID issuing the resolution. Becomes
    /// `audit_log.actor_did` on both the label-applied (if any) and
    /// report_resolved rows.
    pub actor_did: String,
    /// Primary key of the report being resolved.
    pub report_id: i64,
    /// Whether the resolution emits a label or just closes the report.
    /// Replaces the pre-#27 `apply_label: Option<ApplyLabelInline>`
    /// representation; semantically identical, named for the operator
    /// UX (dismiss vs apply-label).
    pub action: ResolutionAction,
    /// Free-text resolution rationale recorded to audit_log.
    pub resolution_reason: Option<String>,
}

/// Result of a successful resolve. `label_event` is `Some(..)` iff
/// the request carried `apply_label`; the broadcast has already
/// happened inside the writer task post-commit.
#[derive(Debug, Clone)]
pub struct ResolvedReport {
    /// The updated report row (status now `resolved`).
    pub report: crate::report::Report,
    /// The emitted label event, if the resolution included an
    /// `apply_label`. Signed, broadcast, and committed as part of
    /// the same transaction as the report UPDATE.
    pub label_event: Option<LabelEvent>,
}

/// Trigger for the retention sweep (§F4). Carries no per-call
/// parameters today — the cutoff comes from `retention_days` baked
/// into the writer at spawn time, not from the request — but is
/// kept as a typed unit so a future "sweep with explicit override
/// for this one run" remains a non-breaking change to the variant.
#[derive(Debug, Clone, Default)]
pub struct SweepRequest;

/// Per-batch outcome from one sweep dispatch through the writer's
/// internal `WriteCommand::Sweep` channel. The writer task processes
/// ONE batch per command so its main `select!` can interleave
/// incoming label writes between batches (§F4 + §F5 — single-writer
/// invariant + bounded latency). Callers who want a full sweep loop
/// until [`Self::has_more`] is `false`; the [`WriterHandle::sweep`]
/// convenience wrapper does this internally.
#[derive(Debug, Clone)]
pub struct SweepBatchResult {
    /// Rows deleted in this batch. Zero means "no more old rows
    /// match the cutoff" — caller stops looping.
    pub rows_deleted: i64,
    /// `true` when the batch hit the configured `sweep_batch_size`
    /// limit and a follow-up batch may find more rows. `false`
    /// indicates the batch was partial (last batch) and the sweep
    /// is complete.
    pub has_more: bool,
    /// Cutoff days actually applied. `None` when the writer was
    /// spawned with `retention_days = None` — the sweep is a no-op
    /// in that configuration and `rows_deleted` is always 0.
    pub retention_days_applied: Option<u32>,
}

/// Request to record a new subject_actions row (§F20 / #51 graduated-
/// action moderation). The handler validates the inputs, computes
/// the strike value at action time via the v1.4 calculators
/// (#48/#49/#50/#51), inserts the row, updates the strike-state
/// cache, and writes a hash-chained audit_log row — all in a
/// single transaction per §F5 atomicity.
#[derive(Debug, Clone)]
pub struct RecordActionRequest {
    /// Raw subject — DID (`did:plc:...`, `did:web:...`) or AT-URI
    /// (`at://did:.../col/r`). The handler routes to subject_did vs
    /// subject_uri based on prefix; for AT-URIs the parent repo DID
    /// is extracted as subject_did and strike accounting rolls up
    /// to the account.
    pub subject: String,
    /// DID of the moderator/admin recording the action (JWT iss
    /// from XRPC; CLI caller DID otherwise). Becomes
    /// subject_actions.actor_did and audit_log.actor_did.
    pub actor_did: String,
    /// Graduated-action category. The handler enforces:
    /// `temp_suspension` requires `duration_iso`; everything else
    /// rejects it.
    pub action_type: ActionType,
    /// Operator-vocabulary identifiers from `[moderation_reasons]`.
    /// Must be non-empty. Multi-reason resolution: severe wins; else
    /// highest base_weight wins; ties → first-listed.
    pub reason_codes: Vec<String>,
    /// ISO-8601 duration string (e.g. `P7D`). Required for
    /// `temp_suspension`; rejected for other types. Stored verbatim
    /// on the row for display; `expires_at` is the canonical
    /// "when does it end" surface.
    pub duration_iso: Option<String>,
    /// Optional moderator-facing rationale.
    pub notes: Option<String>,
    /// Optional report row ids that motivated this action.
    pub report_ids: Vec<i64>,
}

/// Result of a successful [`WriterHandle::record_action`]. The
/// admin handler echoes these fields verbatim in the
/// `tools.cairn.admin.recordAction` response; the CLI surfaces them
/// in human and JSON output.
#[derive(Debug, Clone)]
pub struct RecordedAction {
    /// Inserted subject_actions row id.
    pub action_id: i64,
    /// Reason's `base_weight` before dampening. `0` for warning/note.
    pub strike_value_base: u32,
    /// Strike weight actually applied after dampening.
    pub strike_value_applied: u32,
    /// `true` iff the dampening curve was consulted (see #49).
    pub was_dampened: bool,
    /// Subject's `current_strike_count` BEFORE this action — frozen
    /// for forensic history.
    pub strikes_at_time_of_action: u32,
}

/// Request to revoke a previously-recorded subject_actions row
/// (§F20 / #51). Sets the row's revoked_at/revoked_by_did/
/// revoked_reason columns (the schema's no-update-except-revoke
/// trigger permits exactly this NULL→non-NULL transition);
/// recomputes the strike-state cache; writes a hash-chained
/// audit_log row. All in a single transaction.
#[derive(Debug, Clone)]
pub struct RevokeActionRequest {
    /// subject_actions.id to revoke. Errors with
    /// [`Error::ActionNotFound`] when the row doesn't exist;
    /// [`Error::ActionAlreadyRevoked`] when revoked_at is already
    /// non-NULL.
    pub action_id: i64,
    /// DID of the moderator/admin performing the revocation.
    pub revoked_by_did: String,
    /// Optional rationale stored on the row's revoked_reason column.
    pub revoked_reason: Option<String>,
}

/// Result of a successful [`WriterHandle::revoke_action`].
#[derive(Debug, Clone)]
pub struct RevokedAction {
    /// The revoked row's id (echoed for confirmation).
    pub action_id: i64,
    /// Wall-clock the revocation took effect, as RFC-3339 Z
    /// (matches the [`AUDIT_REASON_RECORD_ACTION`] surface for
    /// consumer convenience).
    pub revoked_at: String,
}

/// Request to confirm a pending policy action (§F22 / #74). The
/// pending row's proposed action is "promoted" to a real
/// `subject_actions` row (actor_kind='moderator'; the moderator
/// takes responsibility by confirming) with `triggered_by_policy_rule`
/// preserved as forensic provenance. Single-transaction: pending
/// load + state-check, subject_actions INSERT, label emission,
/// pending UPDATE (resolution='confirmed'), strike-state recompute,
/// audit_log hash-chain append.
#[derive(Debug, Clone)]
pub struct ConfirmPendingActionRequest {
    /// `pending_policy_actions.id` to confirm. Errors with
    /// [`Error::PendingActionNotFound`] when the row doesn't
    /// exist; [`Error::PendingAlreadyResolved`] when the
    /// resolution column is already non-NULL.
    pub pending_id: i64,
    /// DID of the moderator confirming the pending. Becomes the
    /// new subject_actions row's `actor_did` and the audit row's
    /// `actor_did`, and lands on `pending_policy_actions.resolved_by_did`.
    pub moderator_did: String,
    /// Optional moderator-facing rationale. Stored on the new
    /// subject_actions row's `notes` column and echoed in the audit
    /// row's reason JSON as `moderator_note` for forensic
    /// reconstruction.
    pub note: Option<String>,
}

/// Result of a successful [`WriterHandle::confirm_pending_action`].
#[derive(Debug, Clone)]
pub struct ConfirmedPendingAction {
    /// Inserted subject_actions row id (the materialized action).
    pub action_id: i64,
    /// The pending row that was just resolved (echoed for
    /// confirmation).
    pub pending_id: i64,
    /// Wall-clock the confirmation took effect, as RFC-3339 Z.
    pub resolved_at: String,
}

/// Request to dismiss a pending policy action (§F22 / #75). The
/// pending row stays in the table as forensic record with
/// `resolution = 'dismissed'`; no subject_actions row, no label
/// emission, no strike-state change. Single-transaction: pending
/// load + state-check, UPDATE, audit_log hash-chain append.
///
/// Note that there is no `SubjectTakendown` defensive check here
/// (unlike confirm in #74): explicit dismissal is meaningful
/// regardless of takedown state, and is in fact part of the
/// cleanup path #76 will automate when a takedown lands.
#[derive(Debug, Clone)]
pub struct DismissPendingActionRequest {
    /// `pending_policy_actions.id` to dismiss. Errors with
    /// [`Error::PendingActionNotFound`] when the row doesn't
    /// exist; [`Error::PendingAlreadyResolved`] when the
    /// resolution column is already non-NULL (already confirmed
    /// or dismissed).
    pub pending_id: i64,
    /// DID of the moderator dismissing the pending. Lands on
    /// `pending_policy_actions.resolved_by_did` and the audit
    /// row's `actor_did`.
    pub moderator_did: String,
    /// Optional moderator-facing rationale. Captured in the
    /// audit row's reason JSON as `moderator_reason` (option
    /// (b) per the design — the pending table tracks resolution
    /// state; rationale lives in audit). The pending row itself
    /// has no `resolved_reason` column.
    pub reason: Option<String>,
}

/// Result of a successful [`WriterHandle::dismiss_pending_action`].
#[derive(Debug, Clone)]
pub struct DismissedPendingAction {
    /// The pending row that was just resolved (echoed for
    /// confirmation).
    pub pending_id: i64,
    /// Wall-clock the dismissal took effect, as RFC-3339 Z.
    pub resolved_at: String,
}

/// Aggregate result of a full sweep run (returned by
/// [`WriterHandle::sweep`] after looping over batches).
#[derive(Debug, Clone)]
pub struct SweepResult {
    /// Total rows deleted across all batches.
    pub rows_deleted: i64,
    /// Number of batches issued.
    pub batches: u64,
    /// Wall-clock duration of the full sweep, in milliseconds.
    pub duration_ms: u64,
    /// Cutoff days actually applied, or `None` when the writer's
    /// `retention_days` is `None` (sweep is a no-op).
    pub retention_days_applied: Option<u32>,
}

/// Cheap handle to the writer task. Clones share the same underlying
/// mpsc channel; a drop of the last clone is a silent shutdown signal
/// to the writer task (receiver closes). For a clean shutdown that
/// releases the lease row, call [`WriterHandle::shutdown`].
#[derive(Debug, Clone)]
pub struct WriterHandle {
    tx: mpsc::Sender<WriteCommand>,
    broadcast_tx: broadcast::Sender<LabelEvent>,
    /// Flipped to `true` when the writer task starts its shutdown path.
    /// Exposed via [`WriterHandle::shutdown_signal`] so peer components
    /// (the subscribeLabels handler, future maintenance tasks) can close
    /// their own resources cleanly. Using a watch channel rather than the
    /// broadcast-channel close signal because clones of `WriterHandle`
    /// keep `broadcast_tx` alive — receivers would otherwise never see
    /// `RecvError::Closed`.
    shutdown_rx: watch::Receiver<bool>,
}

impl WriterHandle {
    /// Submit an apply-label request. Resolves when the writer has
    /// committed the transaction and broadcast the event, or returns an
    /// `Err` describing why the write was rejected.
    pub async fn apply_label(&self, req: ApplyLabelRequest) -> Result<LabelEvent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::Apply(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Submit a negate-label request. Returns [`Error::LabelNotFound`] if
    /// no applied label currently exists for `(service_did, uri, val)`.
    pub async fn negate_label(&self, req: NegateLabelRequest) -> Result<LabelEvent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::Negate(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Resolve a report, optionally applying a label in the same
    /// atomic transaction. The label INSERT + audit row + report
    /// UPDATE + resolution audit row all commit together or not at
    /// all; the label broadcast fires post-commit inside the writer
    /// task (§F5 + §F12 atomicity contract).
    ///
    /// Errors:
    /// - [`Error::ReportNotFound`] — `report_id` doesn't exist.
    /// - [`Error::ReportAlreadyResolved`] — report is not in the
    ///   `pending` state. Handler maps to a generic `InvalidRequest`.
    pub async fn resolve_report(&self, req: ResolveReportRequest) -> Result<ResolvedReport> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::ResolveReport(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Trigger a §F4 retention sweep through the writer task. Loops
    /// over single-batch dispatches until a batch returns
    /// `has_more = false`, aggregating rows + duration.
    /// Other writer commands interleave between batches (single-writer
    /// invariant + bounded latency).
    ///
    /// Returns `rows_deleted = 0, batches = 0` when the writer was
    /// spawned with `retention_days = None` (sweep configured off):
    /// the first batch returns immediately and the loop exits with
    /// the no-op result.
    pub async fn sweep(&self, _req: SweepRequest) -> Result<SweepResult> {
        let start = std::time::Instant::now();
        let mut total_rows: i64 = 0;
        let mut batches: u64 = 0;

        loop {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.tx
                .send(WriteCommand::Sweep(SweepRequest, reply_tx))
                .await
                .map_err(|_| Error::Signing("writer task is shut down".into()))?;
            let batch = reply_rx
                .await
                .map_err(|_| Error::Signing("writer dropped reply channel".into()))??;

            total_rows += batch.rows_deleted;
            // Count the no-op early-exit batch too — it represents
            // the round-trip the caller paid for. Useful for tracing.
            batches += 1;

            if !batch.has_more {
                return Ok(SweepResult {
                    rows_deleted: total_rows,
                    batches,
                    duration_ms: start.elapsed().as_millis() as u64,
                    retention_days_applied: batch.retention_days_applied,
                });
            }
        }
    }

    /// Record a graduated-action moderation event (§F20 / #51).
    /// The writer validates inputs, computes the strike value at
    /// action time via the v1.4 calculators (#48/#49/#50/#51),
    /// inserts the subject_actions row, updates the strike-state
    /// cache, and writes a hash-chained audit_log row — all in a
    /// single transaction. Errors:
    ///
    /// - [`Error::ReasonNotFound`] when a reason identifier is not
    ///   declared in `[moderation_reasons]`.
    /// - [`Error::DurationRequiredForTempSuspension`] for
    ///   `temp_suspension` without `duration_iso`.
    /// - [`Error::DurationOnlyForTempSuspension`] for non-temp
    ///   types with `duration_iso` set.
    /// - [`Error::Signing`] for malformed subject / duration / etc.
    pub async fn record_action(&self, req: RecordActionRequest) -> Result<RecordedAction> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::RecordAction(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Revoke a previously-recorded action (§F20 / #51). Errors:
    ///
    /// - [`Error::ActionNotFound`] when no row matches `action_id`.
    /// - [`Error::ActionAlreadyRevoked`] when the row's revoked_at
    ///   is already non-NULL — the schema trigger forbids
    ///   re-revocation; the handler catches it before the UPDATE.
    pub async fn revoke_action(&self, req: RevokeActionRequest) -> Result<RevokedAction> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::RevokeAction(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Confirm a pending policy action (§F22 / #74). The proposed
    /// action carried on the pending row is materialized as a real
    /// `subject_actions` row (actor_kind='moderator',
    /// triggered_by_policy_rule preserves the rule that proposed
    /// it), labels emit per [`crate::labels::policy::LabelEmissionPolicy`],
    /// the pending row's resolution columns transition NULL →
    /// 'confirmed', and the strike-state cache is recomputed — all
    /// in one transaction under a single
    /// `pending_policy_action_confirmed` audit row. Errors:
    ///
    /// - [`Error::PendingActionNotFound`] when no row matches
    ///   `pending_id`.
    /// - [`Error::PendingAlreadyResolved`] when the row's
    ///   resolution column is already non-NULL.
    /// - [`Error::SubjectTakendown`] when the subject already
    ///   carries an unrevoked Takedown — defensive guard against
    ///   the auto-dismissal-on-takedown race (#76).
    pub async fn confirm_pending_action(
        &self,
        req: ConfirmPendingActionRequest,
    ) -> Result<ConfirmedPendingAction> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::ConfirmPendingAction(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Dismiss a pending policy action (§F22 / #75). The pending
    /// row's resolution columns transition NULL → 'dismissed' and
    /// a single hash-chained `pending_policy_action_dismissed`
    /// audit row commits with the UPDATE — no subject_actions
    /// row, no label emission, no strike-state change. The
    /// pending row stays in the table as forensic record
    /// (confirmed_action_id stays NULL since no action was
    /// created).
    ///
    /// Errors:
    ///
    /// - [`Error::PendingActionNotFound`] when no row matches
    ///   `pending_id`.
    /// - [`Error::PendingAlreadyResolved`] when the row's
    ///   resolution column is already non-NULL.
    pub async fn dismiss_pending_action(
        &self,
        req: DismissPendingActionRequest,
    ) -> Result<DismissedPendingAction> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::DismissPendingAction(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Append a hash-chained audit row through the writer task (#39).
    /// Used by in-process callers that don't already hold a transaction
    /// — e.g., `retentionSweep`'s post-sweep audit row. Callers that
    /// have an open transaction (writer-internal handlers,
    /// `flag_reporter`) use [`crate::audit::append::append_in_tx`]
    /// directly so the audit row commits atomically with the rest of
    /// their work. Cross-process CLIs (publish/unpublish-service-
    /// record) use [`crate::audit::append::append_via_pool`].
    ///
    /// Returns the inserted `audit_log.id`.
    pub async fn append_audit(&self, row: crate::audit::append::AuditRowForAppend) -> Result<i64> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::AppendAudit(row, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Subscribe to committed events. The returned receiver lags past
    /// the internal broadcast buffer; the consumer (subscribeLabels, #7)
    /// turns `RecvError::Lagged` into a connection close.
    pub fn subscribe(&self) -> broadcast::Receiver<LabelEvent> {
        self.broadcast_tx.subscribe()
    }

    /// Count of live broadcast receivers. Exposed for test sync points
    /// (the WS handler subscribes asynchronously after upgrade; tests
    /// that want to emit an event "after the subscriber is ready" poll
    /// this until it reaches the expected count). Not a production hot
    /// path — `broadcast::Sender::receiver_count` walks an atomic chain.
    pub fn receiver_count(&self) -> usize {
        self.broadcast_tx.receiver_count()
    }

    /// Observe writer lifecycle. The returned receiver starts at `false`
    /// and flips to `true` once exactly, when the writer has accepted a
    /// shutdown command and is about to release the lease. Holders close
    /// downstream connections gracefully on the `true` transition.
    pub fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Explicit shutdown. Drains in-flight writes, releases the lease
    /// row, stops the heartbeat, and returns. Idempotent-ish: calling on
    /// an already-shut-down writer returns a channel-closed error, not a
    /// panic.
    pub async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::Shutdown(reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is already shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }
}

/// Start the writer task. Acquires the instance lease, bootstraps the
/// `signing_keys` row if empty, and spawns the event loop + heartbeat.
///
/// `service_did` stamps `labels.src` on every emitted event. `key` must
/// be the private key whose public form is recorded (or will be recorded)
/// in `signing_keys`.
///
/// `retention_days` is the §F4 retention cutoff in days. `None` disables
/// the retention sweep entirely (`WriteCommand::Sweep` becomes a no-op
/// returning `rows_deleted = 0`); `Some(N)` lets the sweep delete labels
/// whose `created_at` is older than `now - N days`. Source of truth is
/// [`crate::SubscribeConfig::retention_days`] — pass it through verbatim.
///
/// `retention` is the sweep execution policy (schedule + batching);
/// distinct from `retention_days` per the [§F4 split](crate::RetentionConfig).
///
/// `reason_vocabulary` and `strike_policy` are the resolved v1.4
/// moderation surface (#47 / #48). The recorder (#51 RecordAction
/// handler) consults them at action time to validate reason codes
/// and compute strike values. They're held by the writer task so
/// the recorder doesn't have to thread them through every call.
/// Operators restart `cairn serve` to change either — same posture
/// as `[labeler]` config.
///
/// `label_emission_policy` is the resolved `[label_emission]`
/// surface (#58, v1.5). The recorder (#60) consults it post-INSERT
/// to translate the freshly-recorded action into ATProto labels
/// emitted in the same transaction. Held by the writer task for
/// the same reason as the v1.4 surfaces above.
#[allow(clippy::too_many_arguments)]
pub async fn spawn(
    pool: Pool<Sqlite>,
    key: SigningKey,
    service_did: String,
    retention_days: Option<u32>,
    retention: RetentionConfig,
    reason_vocabulary: ReasonVocabulary,
    strike_policy: StrikePolicy,
    label_emission_policy: crate::labels::policy::LabelEmissionPolicy,
    policy_automation_policy: crate::policy::automation::PolicyAutomationPolicy,
) -> Result<WriterHandle> {
    let instance_id = acquire_lease(&pool).await?;
    let signing_key_id = ensure_signing_key_row(&pool, &key).await?;

    let (tx, rx) = mpsc::channel(COMMAND_BUFFER);
    let (broadcast_tx, _first_rx) = broadcast::channel(BROADCAST_BUFFER);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let writer = Writer {
        pool,
        key,
        service_did,
        signing_key_id,
        instance_id,
        rx,
        broadcast_tx: broadcast_tx.clone(),
        shutdown_tx,
        retention_days,
        retention,
        reason_vocabulary,
        strike_policy,
        label_emission_policy,
        policy_automation_policy,
    };

    tokio::spawn(writer.run());

    Ok(WriterHandle {
        tx,
        broadcast_tx,
        shutdown_rx,
    })
}

// ---------- Writer task ----------

struct Writer {
    pool: Pool<Sqlite>,
    key: SigningKey,
    service_did: String,
    signing_key_id: i64,
    instance_id: String,
    rx: mpsc::Receiver<WriteCommand>,
    broadcast_tx: broadcast::Sender<LabelEvent>,
    shutdown_tx: watch::Sender<bool>,
    /// Retention cutoff in days. `None` makes the sweep a no-op.
    /// Source of truth is [`crate::SubscribeConfig::retention_days`].
    retention_days: Option<u32>,
    /// Sweep execution policy (schedule + batching).
    retention: RetentionConfig,
    /// Resolved [moderation_reasons] vocabulary (#47). Consulted by
    /// the RecordAction handler to validate reason codes and look
    /// up base_weight / severe.
    reason_vocabulary: ReasonVocabulary,
    /// Resolved [strike_policy] (#48). Consulted by the RecordAction
    /// handler for the dampening curve, threshold, and decay
    /// parameters.
    strike_policy: StrikePolicy,
    /// Resolved [label_emission] (#58, v1.5). Consulted by the
    /// RecordAction handler post-INSERT to translate the action into
    /// ATProto labels, emitted in the same tx.
    label_emission_policy: crate::labels::policy::LabelEmissionPolicy,
    /// Resolved [policy_automation] (#71, v1.6). Consulted by the
    /// RecordAction handler post-emission to evaluate threshold-
    /// crossing rules and either auto-record a consequent action
    /// or queue a `pending_policy_actions` row for moderator
    /// review (#73).
    policy_automation_policy: crate::policy::automation::PolicyAutomationPolicy,
}

/// Internal accumulator for an in-flight scheduled sweep. Lives only
/// while [`Writer::run`] is mid-sweep; absent between sweeps.
struct SweepRunState {
    started_at: Instant,
    rows: i64,
    batches: u64,
}

impl Writer {
    /// Compute the next absolute [`Instant`] at which the scheduled
    /// sweep should fire, or `None` when the sweep is disabled.
    ///
    /// "Disabled" = `sweep_enabled = false` OR `retention_days = None`.
    /// In the second case the sweep would be a no-op anyway; skipping
    /// the timer entirely keeps the run loop quiet.
    ///
    /// Targets the next occurrence of `sweep_run_at_utc_hour:00:00`
    /// UTC. If we're already past that hour today, target tomorrow at
    /// the same hour.
    fn compute_next_sweep_fire(&self) -> Option<Instant> {
        if !self.retention.sweep_enabled || self.retention_days.is_none() {
            return None;
        }
        let now_utc = OffsetDateTime::now_utc();
        let target_hour = self.retention.sweep_run_at_utc_hour;
        let target_today_time = time::Time::from_hms(target_hour, 0, 0)
            .expect("hour validated < 24 by Config::validate");
        let target_today = now_utc.replace_time(target_today_time);
        let target_dt = if target_today <= now_utc {
            target_today + time::Duration::days(1)
        } else {
            target_today
        };
        let wait = target_dt - now_utc;
        let wait_secs = wait.whole_seconds().max(0) as u64;
        Some(Instant::now() + Duration::from_secs(wait_secs))
    }

    async fn run(mut self) {
        let mut heartbeat_timer = interval(HEARTBEAT_INTERVAL);
        heartbeat_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // First tick fires immediately; skip it — we just acquired the lease
        // with a fresh timestamp, so touching it again is redundant.
        heartbeat_timer.tick().await;

        // Scheduled-sweep wiring (§F4). The check timer wakes the run
        // loop once a minute to evaluate "is it time to start a sweep?";
        // when a sweep starts, `sweep_state` is populated and the
        // immediate-batch arm runs one batch per loop iteration until
        // `has_more = false`. Inter-batch yielding to incoming commands
        // is automatic — the biased select prefers `rx.recv()` and
        // `heartbeat_timer.tick()` over running another batch.
        let mut sweep_check_timer = interval(SWEEP_CHECK_INTERVAL);
        sweep_check_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        sweep_check_timer.tick().await;

        let mut next_scheduled_fire: Option<Instant> = self.compute_next_sweep_fire();
        let mut sweep_state: Option<SweepRunState> = None;

        loop {
            let sweep_in_progress = sweep_state.is_some();
            tokio::select! {
                biased;
                // Prefer draining write commands over heartbeats so a
                // steady-state of inbound work does not starve itself
                // behind a background housekeeping task.
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(WriteCommand::Apply(req, reply)) => {
                            let res = self.handle_apply(req).await;
                            // Caller may have cancelled; dropping the reply is fine.
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::Negate(req, reply)) => {
                            let res = self.handle_negate(req).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::ResolveReport(req, reply)) => {
                            let res = self.handle_resolve_report(req).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::Sweep(req, reply)) => {
                            // Single-batch dispatch — the caller loops
                            // until has_more=false. Per-batch return
                            // lets the writer's biased select pick up
                            // pending Apply / Negate / ResolveReport
                            // commands between batches (§F4 + §F5).
                            let res = self.handle_sweep(req).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::AppendAudit(row, reply)) => {
                            let res = self.handle_append_audit(row).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::RecordAction(req, reply)) => {
                            let res = self.handle_record_action(req).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::RevokeAction(req, reply)) => {
                            let res = self.handle_revoke_action(req).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::ConfirmPendingAction(req, reply)) => {
                            let res = self.handle_confirm_pending_action(req).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::DismissPendingAction(req, reply)) => {
                            let res = self.handle_dismiss_pending_action(req).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::Shutdown(reply)) => {
                            // Flip the shutdown watch *before* releasing the
                            // lease so subscriber tasks see the signal while
                            // the DB is still accessible for their close-
                            // frame sends.
                            let _ = self.shutdown_tx.send(true);
                            let res = self.release_lease().await;
                            let _ = reply.send(res);
                            return;
                        }
                        None => {
                            // All handles dropped without explicit shutdown.
                            // Best-effort lease release so a same-process
                            // restart doesn't trip the 60s wait.
                            let _ = self.shutdown_tx.send(true);
                            if let Err(e) = self.release_lease().await {
                                tracing::error!("lease release on handle drop: {e}");
                            }
                            return;
                        }
                    }
                }
                _ = heartbeat_timer.tick() => {
                    if let Err(e) = self.heartbeat().await {
                        // Transient DB errors are logged, not fatal. A
                        // sustained failure is caught at the next-instance
                        // startup check — not at this writer's expense.
                        tracing::error!("lease heartbeat failed: {e}");
                    }
                }
                _ = sweep_check_timer.tick() => {
                    if sweep_state.is_none()
                        && let Some(fire_at) = next_scheduled_fire
                        && Instant::now() >= fire_at
                    {
                        sweep_state = Some(SweepRunState {
                            started_at: Instant::now(),
                            rows: 0,
                            batches: 0,
                        });
                        next_scheduled_fire = Some(fire_at + Duration::from_secs(86_400));
                        tracing::info!(
                            retention_days = ?self.retention_days,
                            sweep_batch_size = self.retention.sweep_batch_size,
                            "scheduled retention sweep starting"
                        );
                    }
                }
                // Always-ready arm gated on sweep_in_progress. With biased
                // order this ranks below rx.recv() + the two timers, so
                // normal commands and heartbeats interleave naturally
                // between batches (§F4 inter-batch yield, §F5 single-
                // writer invariant).
                _ = std::future::ready(()), if sweep_in_progress => {
                    match self.handle_sweep(SweepRequest).await {
                        Ok(batch) => {
                            let state = sweep_state
                                .as_mut()
                                .expect("sweep_in_progress => sweep_state Some");
                            state.rows += batch.rows_deleted;
                            state.batches += 1;
                            if !batch.has_more {
                                let final_state = sweep_state.take().expect("just set");
                                tracing::info!(
                                    rows_deleted = final_state.rows,
                                    batches = final_state.batches,
                                    duration_ms = final_state.started_at.elapsed().as_millis() as u64,
                                    retention_days_applied = ?batch.retention_days_applied,
                                    "scheduled retention sweep complete"
                                );
                            }
                        }
                        Err(e) => {
                            let final_state = sweep_state.take();
                            tracing::error!(
                                error = %e,
                                batches_done = final_state.as_ref().map(|s| s.batches).unwrap_or(0),
                                rows_so_far = final_state.as_ref().map(|s| s.rows).unwrap_or(0),
                                "scheduled retention sweep batch failed; aborting run (will retry on next schedule)"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Process one batch of the §F4 retention sweep. Single-batch
    /// dispatch — see [`WriteCommand::Sweep`] for the loop ordering.
    ///
    /// Returns immediately with `rows_deleted = 0, has_more = false`
    /// when `retention_days` is `None`. Otherwise issues one
    /// `DELETE FROM labels WHERE created_at < cutoff LIMIT N` in its
    /// own transaction; sets `has_more = true` iff the batch hit the
    /// `sweep_batch_size` limit (suggesting more rows may match).
    ///
    /// Errors are propagated as `Err(_)` rather than swallowed: a
    /// transient DB failure should surface to the operator on a
    /// manual sweep, and to the schedule-loop logger on a scheduled
    /// sweep. Idempotency (Q5) means the next sweep retries cleanly.
    async fn handle_sweep(&self, _req: SweepRequest) -> Result<SweepBatchResult> {
        let Some(days) = self.retention_days else {
            return Ok(SweepBatchResult {
                rows_deleted: 0,
                has_more: false,
                retention_days_applied: None,
            });
        };

        let cutoff_ms = epoch_ms_now() - (days as i64) * 86_400_000;
        let limit = self.retention.sweep_batch_size;

        let mut tx = self.pool.begin().await?;
        // SQLite's DELETE doesn't support LIMIT without the
        // SQLITE_ENABLE_UPDATE_DELETE_LIMIT compile flag (off in
        // bundled builds). The rowid IN (SELECT ... LIMIT) trick is
        // the canonical portable workaround.
        let result = sqlx::query!(
            "DELETE FROM labels WHERE rowid IN (
               SELECT rowid FROM labels WHERE created_at < ?1 LIMIT ?2
             )",
            cutoff_ms,
            limit,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let rows = result.rows_affected() as i64;
        Ok(SweepBatchResult {
            rows_deleted: rows,
            has_more: rows >= limit,
            retention_days_applied: Some(days),
        })
    }

    /// Handler for [`WriteCommand::AppendAudit`]. Opens its own
    /// transaction (BEGIN DEFERRED — fine because the writer task is
    /// the only in-process audit appender during a `cairn serve`
    /// session, and cross-process appenders use BEGIN IMMEDIATE on
    /// their side), inserts the audit row with a freshly-computed
    /// hash, commits.
    async fn handle_append_audit(
        &self,
        row: crate::audit::append::AuditRowForAppend,
    ) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        let id = crate::audit::append::append_in_tx(&mut tx, &row).await?;
        tx.commit().await?;
        Ok(id)
    }

    async fn handle_apply(&self, req: ApplyLabelRequest) -> Result<LabelEvent> {
        let mut tx = self.pool.begin().await?;
        let created_at = epoch_ms_now();
        let event = self.apply_label_inner(&mut tx, &req, created_at).await?;
        tx.commit().await?;
        // No-receivers is not a write failure (§plan point G).
        let _ = self.broadcast_tx.send(event.clone());
        Ok(event)
    }

    /// Inner label-application pipeline: reserve seq → clamp cts →
    /// sign → INSERT label → INSERT audit. Does NOT commit the
    /// transaction and does NOT broadcast — caller handles both.
    ///
    /// Extracted from `handle_apply` so `handle_resolve_report` can
    /// reuse it inside the same transaction as the report update,
    /// preserving §F5's single-writer-owns-label-emission invariant
    /// (this helper only runs on the writer task; no other code path
    /// can access seq allocation or cts clamping).
    async fn apply_label_inner(
        &self,
        tx: &mut sqlx::Transaction<'_, Sqlite>,
        req: &ApplyLabelRequest,
        created_at_ms: i64,
    ) -> Result<LabelEvent> {
        let event = self
            .sign_and_persist_label(
                tx,
                &req.val,
                &req.uri,
                req.cid.as_deref(),
                false,
                req.exp.as_deref(),
                created_at_ms,
            )
            .await?;

        let audit_reason = build_audit_reason(&req.val, false, req.moderator_reason.as_deref());
        crate::audit::append::append_in_tx(
            tx,
            &crate::audit::append::AuditRowForAppend {
                created_at: created_at_ms,
                action: "label_applied".into(),
                actor_did: req.actor_did.clone(),
                target: Some(req.uri.clone()),
                target_cid: req.cid.clone(),
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        Ok(event)
    }

    /// Tx-scoped sign-and-persist core for one label row: reserve
    /// seq → fetch prev cts → clamp → build wire-level [`Label`] →
    /// sign → INSERT into `labels`. Returns the seq + signed label.
    /// Does NOT write audit rows and does NOT broadcast — callers
    /// own both (the post-tx broadcast and any audit row layered
    /// over the bare label INSERT).
    ///
    /// Reused by [`Self::apply_label_inner`] (which adds a
    /// `label_applied` audit row) and by
    /// [`Self::handle_record_action`] (which writes one consolidated
    /// `subject_action_recorded` audit row capturing the action plus
    /// every emitted label, rather than per-label rows). Both reach
    /// it only from the single writer task, preserving §F5.
    #[allow(clippy::too_many_arguments)]
    async fn sign_and_persist_label(
        &self,
        tx: &mut sqlx::Transaction<'_, Sqlite>,
        val: &str,
        uri: &str,
        cid: Option<&str>,
        neg: bool,
        exp: Option<&str>,
        created_at_ms: i64,
    ) -> Result<LabelEvent> {
        let seq = reserve_seq(tx).await?;
        let prev_cts: Option<String> = sqlx::query_scalar!(
            // sqlx type override — MAX() strips column origin metadata so
            // sqlx can't infer the TEXT+nullable shape on its own. `?:`
            // forces the nullable wrapper (Option<String>).
            r#"SELECT MAX(cts) AS "max_cts?: String" FROM labels
               WHERE src = ?1 AND uri = ?2 AND val = ?3"#,
            self.service_did,
            uri,
            val,
        )
        .fetch_one(&mut **tx)
        .await?;

        let cts = clamp_cts(created_at_ms, prev_cts.as_deref())?;

        let cid_owned = cid.map(str::to_string);
        let exp_owned = exp.map(str::to_string);
        let val_owned = val.to_string();
        let uri_owned = uri.to_string();

        let mut label = Label {
            ver: 1,
            src: self.service_did.clone(),
            uri: uri_owned,
            cid: cid_owned,
            val: val_owned,
            neg,
            cts,
            exp: exp_owned,
            sig: None,
        };
        label.sig = Some(sign_label(&self.key, &label)?);
        let sig_bytes = label.sig.expect("just set").to_vec();

        let neg_int: i64 = if neg { 1 } else { 0 };
        sqlx::query!(
            "INSERT INTO labels (seq, ver, src, uri, cid, val, neg, cts, exp, sig, signing_key_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            seq,
            label.ver,
            label.src,
            label.uri,
            label.cid,
            label.val,
            neg_int,
            label.cts,
            label.exp,
            sig_bytes,
            self.signing_key_id,
            created_at_ms,
        )
        .execute(&mut **tx)
        .await?;

        Ok(LabelEvent { seq, label })
    }

    /// Tx-scoped wrapper around [`Self::sign_and_persist_label`] that
    /// converts a [`LabelDraft`] (the emission core's purpose-shaped
    /// output, with `cts/exp` as `SystemTime`) into the wire-level
    /// arguments. Used by [`Self::handle_record_action`] to sign +
    /// persist every draft produced by `resolve_action_labels` /
    /// `resolve_reason_labels`. The draft's `cts` is informational
    /// here — the actual cts on the labels row comes from
    /// `clamp_cts(created_at_ms, prev_cts)` inside
    /// [`Self::sign_and_persist_label`]. In v1.5 the recorder calls
    /// the resolvers with `now = effective_at`, so the two are
    /// equal pre-clamp.
    async fn sign_and_persist_label_from_draft(
        &self,
        tx: &mut sqlx::Transaction<'_, Sqlite>,
        draft: &LabelDraft,
        created_at_ms: i64,
    ) -> Result<LabelEvent> {
        let exp_str = match draft.exp {
            Some(st) => Some(rfc3339_from_epoch_ms(systemtime_to_epoch_ms(st)?)?),
            None => None,
        };
        self.sign_and_persist_label(
            tx,
            &draft.val,
            &draft.uri,
            draft.cid.as_deref(),
            draft.neg,
            exp_str.as_deref(),
            created_at_ms,
        )
        .await
    }

    /// Insert the auto-recorded `subject_actions` row produced by a
    /// `[policy_automation]` rule firing (#73, v1.6,
    /// `mode=auto`). Runs the same shape as the moderator-recorded
    /// path: predict id, write audit row, INSERT, verify, emit
    /// labels (action label + reason labels), append linkage rows.
    /// All inside the existing transaction.
    ///
    /// Differs from the moderator path in three places:
    /// - `actor_kind = 'policy'` and `actor_did =
    ///   SYNTHETIC_POLICY_ACTOR_DID`.
    /// - `triggered_by_policy_rule = rule.name`.
    /// - The audit reason JSON has NO `policy_consequence` field
    ///   (the auto-action is the consequence; the precipitating
    ///   action's audit row carries the cross-reference).
    #[allow(clippy::too_many_arguments)]
    async fn insert_policy_auto_action(
        &self,
        tx: &mut sqlx::Transaction<'_, Sqlite>,
        rule: &crate::policy::automation::PolicyRule,
        subject_did: &str,
        subject_uri: Option<&str>,
        history_plus_precip: &[ActionRecord],
        state_after_precip: &crate::moderation::decay::StrikeState,
        now_systemtime: SystemTime,
        created_at: i64,
        predicted_auto_id: i64,
        label_events: &mut Vec<LabelEvent>,
    ) -> Result<i64> {
        // The rule's reason_codes resolve via the operator's
        // [moderation_reasons] vocabulary — config validation in
        // #71 guarantees every code is declared, so the resolver
        // always succeeds here.
        let primary = resolve_primary_reason(&rule.reason_codes, &self.reason_vocabulary)?;

        // Strike state for the auto-action: starts from
        // state_after_precip's count. Position-in-window is
        // computed from history+precipitating (the auto-action
        // hasn't been INSERTed yet).
        let strikes_at_time_of_auto = state_after_precip.current_count;
        let position =
            compute_position_in_window(history_plus_precip, &self.strike_policy, now_systemtime);
        let calc: StrikeApplication = strike_calculate(
            strikes_at_time_of_auto,
            &primary,
            &self.strike_policy,
            position,
        );
        // Note/Warning don't carry strikes regardless of reason.
        // Defense-in-depth (mirrors the moderator path).
        let (strike_base, strike_applied, was_dampened) = match rule.action_type {
            ActionType::Note | ActionType::Warning => (0u32, 0u32, false),
            _ => (calc.base_weight, calc.applied, calc.was_dampened),
        };

        // Auto-action expiry: derive from rule.duration when
        // action_type == TempSuspension. #71 already enforced the
        // pairing at config-load time.
        let auto_expires_at: Option<i64> = match (rule.action_type, rule.duration) {
            (ActionType::TempSuspension, Some(d)) => Some(created_at + (d.as_secs() as i64) * 1000),
            _ => None,
        };
        let auto_duration_iso: Option<String> = match (rule.action_type, rule.duration) {
            (ActionType::TempSuspension, Some(d)) => {
                // Round-trip: rule.duration was parsed from the
                // operator's config. We store the original
                // `P{n}D` / `PT{n}H` shape verbatim so audit
                // readers see what the operator declared.
                // Reconstruction would require remembering the
                // original string; v1.6 just regenerates a
                // canonical form (PT<seconds>S) for the row's
                // `duration` column. Operators reading the row
                // can compute the wall-clock end via
                // `expires_at`; the duration column is display-
                // only.
                Some(format!("PT{}S", d.as_secs()))
            }
            _ => None,
        };

        // Resolve labels for the auto-action.
        let action_for_emission = ActionForEmission {
            action_type: rule.action_type,
            expires_at: auto_expires_at.map(epoch_ms_to_systemtime),
            subject_did: subject_did.to_string(),
            subject_uri: subject_uri.map(str::to_string),
            reason_codes: rule.reason_codes.clone(),
            cid: None,
        };
        let action_drafts = resolve_action_labels(
            &action_for_emission,
            &self.label_emission_policy,
            now_systemtime,
        );
        let reason_drafts = resolve_reason_labels(
            &action_for_emission,
            &self.label_emission_policy,
            now_systemtime,
        );
        let emitted_labels_for_audit: Vec<serde_json::Value> = action_drafts
            .iter()
            .chain(reason_drafts.iter())
            .map(|d| serde_json::json!({"val": d.val, "uri": d.uri}))
            .collect();

        // Predict + verify the auto-action's id matches what we
        // reserved when building the precipitating audit row's
        // policy_consequence pointer.
        let next_id = predict_next_subject_action_id(tx).await?;
        if next_id != predicted_auto_id {
            return Err(Error::Signing(format!(
                "policy auto-action: predicted id {predicted_auto_id} but next-id is now {next_id}; \
                 policy_consequence reservation diverged"
            )));
        }

        let audit_reason = build_record_action_audit_reason(
            next_id,
            rule.action_type,
            &primary.identifier,
            &rule.reason_codes,
            strike_base,
            strike_applied,
            was_dampened,
            &emitted_labels_for_audit,
            "policy",
            Some(&rule.name),
            None,
        );
        let audit_target = subject_uri
            .map(str::to_string)
            .unwrap_or_else(|| subject_did.to_string());
        let auto_audit_log_id = crate::audit::append::append_in_tx(
            tx,
            &crate::audit::append::AuditRowForAppend {
                created_at,
                action: "subject_action_recorded".into(),
                actor_did: crate::policy::automation::SYNTHETIC_POLICY_ACTOR_DID.to_string(),
                target: Some(audit_target),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        // INSERT the auto-action row. actor_kind = 'policy'
        // discriminates from moderator-recorded rows; actor_did =
        // SYNTHETIC_POLICY_ACTOR_DID gives downstream filtering
        // a stable identifier; triggered_by_policy_rule preserves
        // provenance for audit + revocation.
        let action_type_str = rule.action_type.as_db_str();
        let was_dampened_int: i64 = if was_dampened { 1 } else { 0 };
        let strikes_at_time_i64 = strikes_at_time_of_auto as i64;
        let strike_base_i64 = strike_base as i64;
        let strike_applied_i64 = strike_applied as i64;
        let reason_codes_json = serde_json::to_string(&rule.reason_codes)
            .map_err(|e| Error::Signing(format!("serialize policy reason_codes: {e}")))?;
        let actor_kind_policy = "policy";
        let synth_actor = crate::policy::automation::SYNTHETIC_POLICY_ACTOR_DID;
        let auto_inserted_id = sqlx::query_scalar!(
            "INSERT INTO subject_actions (
                subject_did, subject_uri, actor_did, action_type, reason_codes,
                duration, effective_at, expires_at, notes, report_ids,
                strike_value_base, strike_value_applied, was_dampened,
                strikes_at_time_of_action, audit_log_id, created_at,
                actor_kind, triggered_by_policy_rule
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             RETURNING id",
            subject_did,
            subject_uri,
            synth_actor,
            action_type_str,
            reason_codes_json,
            auto_duration_iso,
            created_at,
            auto_expires_at,
            None::<String>,
            strike_base_i64,
            strike_applied_i64,
            was_dampened_int,
            strikes_at_time_i64,
            auto_audit_log_id,
            created_at,
            actor_kind_policy,
            rule.name,
        )
        .fetch_one(&mut **tx)
        .await?;

        if auto_inserted_id != predicted_auto_id {
            return Err(Error::Signing(format!(
                "policy auto-action inserted at id {auto_inserted_id} but predicted \
                 {predicted_auto_id}; audit chain captured the predicted id (corrupted)"
            )));
        }

        // Emit labels for the auto-action — same path as the
        // moderator-recorded action's emission. Idempotency
        // guards from #64 are no-ops on a fresh INSERT.
        let mut auto_action_label_val: Option<String> = None;
        for draft in &action_drafts {
            let event = self
                .sign_and_persist_label_from_draft(tx, draft, created_at)
                .await?;
            if auto_action_label_val.is_none() {
                auto_action_label_val = Some(draft.val.clone());
            }
            label_events.push(event);
        }
        if let Some(ref val) = auto_action_label_val {
            sqlx::query!(
                "UPDATE subject_actions SET emitted_label_uri = ?1 WHERE id = ?2",
                val,
                auto_inserted_id,
            )
            .execute(&mut **tx)
            .await?;
        }
        for (draft, reason_code) in reason_drafts.iter().zip(rule.reason_codes.iter()) {
            let event = self
                .sign_and_persist_label_from_draft(tx, draft, created_at)
                .await?;
            sqlx::query!(
                "INSERT INTO subject_action_reason_labels
                   (action_id, reason_code, emitted_label_uri, emitted_at)
                 VALUES (?1, ?2, ?3, ?4)",
                auto_inserted_id,
                reason_code,
                draft.val,
                created_at,
            )
            .execute(&mut **tx)
            .await?;
            label_events.push(event);
        }

        // ---------- takedown cascade (#76, v1.6) ----------
        //
        // A policy-auto-recorded Takedown auto-dismisses every
        // unresolved pending_policy_actions row for the subject —
        // including any pending whose own rule fired in mode=flag
        // earlier in the subject's history. The cascade's
        // resolved_by_did is the synthetic policy DID, marking
        // the dismissal as system-driven rather than moderator-
        // driven for downstream filtering.
        //
        // The pending row that the rule itself proposed (when
        // this auto-action's own rule was originally mode=flag)
        // can't appear here: a rule firing in mode=auto inserts a
        // subject_actions row directly via this function and does
        // NOT create a pending_policy_actions row. The cascade
        // sees only OTHER subject pendings.
        if rule.action_type == ActionType::Takedown {
            auto_dismiss_pendings_on_takedown(
                tx,
                subject_did,
                subject_uri,
                auto_inserted_id,
                crate::policy::automation::SYNTHETIC_POLICY_ACTOR_DID,
                created_at,
            )
            .await?;
        }

        Ok(auto_inserted_id)
    }

    /// Insert a `pending_policy_actions` row for a `mode=flag`
    /// rule firing (#73, v1.6). The pending row holds the
    /// proposed action's shape until a moderator confirms (#74)
    /// or dismisses (#75); no `subject_actions` row, no label
    /// emission. The precipitating action's audit row already
    /// cross-references this pending row's id via the
    /// `policy_consequence` field.
    #[allow(clippy::too_many_arguments)]
    async fn insert_pending_policy_action(
        &self,
        tx: &mut sqlx::Transaction<'_, Sqlite>,
        rule: &crate::policy::automation::PolicyRule,
        subject_did: &str,
        subject_uri: Option<&str>,
        triggering_action_id: i64,
        created_at: i64,
        predicted_pending_id: i64,
    ) -> Result<i64> {
        let action_type_str = rule.action_type.as_db_str();
        let duration_ms: Option<i64> = match (rule.action_type, rule.duration) {
            (ActionType::TempSuspension, Some(d)) => Some((d.as_secs() as i64) * 1000),
            _ => None,
        };
        let reason_codes_json = serde_json::to_string(&rule.reason_codes).map_err(|e| {
            Error::Signing(format!("serialize policy reason_codes for pending: {e}"))
        })?;

        let inserted_id_opt = sqlx::query_scalar!(
            r#"INSERT INTO pending_policy_actions (
                subject_did, subject_uri, action_type, duration_ms,
                reason_codes, triggered_by_policy_rule, triggered_at,
                triggering_action_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             RETURNING id AS "id!: i64""#,
            subject_did,
            subject_uri,
            action_type_str,
            duration_ms,
            reason_codes_json,
            rule.name,
            created_at,
            triggering_action_id,
        )
        .fetch_one(&mut **tx)
        .await?;
        let inserted_id: i64 = inserted_id_opt;

        if inserted_id != predicted_pending_id {
            return Err(Error::Signing(format!(
                "pending_policy_actions inserted at id {inserted_id} but predicted \
                 {predicted_pending_id}; policy_consequence reservation diverged"
            )));
        }
        Ok(inserted_id)
    }

    async fn handle_negate(&self, req: NegateLabelRequest) -> Result<LabelEvent> {
        let mut tx = self.pool.begin().await?;

        // Most-recent event for the tuple. Not-found OR latest-is-already-
        // a-negation both surface as LabelNotFound (§F6).
        let latest = sqlx::query!(
            "SELECT neg, cid FROM labels
             WHERE src = ?1 AND uri = ?2 AND val = ?3
             ORDER BY seq DESC LIMIT 1",
            self.service_did,
            req.uri,
            req.val,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let cid = match latest {
            Some(row) if row.neg == 0 => row.cid,
            _ => {
                return Err(Error::LabelNotFound {
                    src: self.service_did.clone(),
                    uri: req.uri,
                    val: req.val,
                });
            }
        };

        let seq = reserve_seq(&mut tx).await?;
        // Prev cts lookup is the same query as apply; tuple uniqueness is
        // on (src, uri, val) regardless of neg.
        let prev_cts: Option<String> = sqlx::query_scalar!(
            // sqlx type override — MAX() strips column origin metadata so
            // sqlx can't infer the TEXT+nullable shape on its own. `?:`
            // forces the nullable wrapper (Option<String>).
            r#"SELECT MAX(cts) AS "max_cts?: String" FROM labels
               WHERE src = ?1 AND uri = ?2 AND val = ?3"#,
            self.service_did,
            req.uri,
            req.val,
        )
        .fetch_one(&mut *tx)
        .await?;

        let wall_now_ms = epoch_ms_now();
        let cts = clamp_cts(wall_now_ms, prev_cts.as_deref())?;

        let mut label = Label {
            ver: 1,
            src: self.service_did.clone(),
            uri: req.uri.clone(),
            cid: cid.clone(),
            val: req.val.clone(),
            neg: true,
            cts: cts.clone(),
            exp: None, // Negations never carry an expiry.
            sig: None,
        };
        label.sig = Some(sign_label(&self.key, &label)?);
        let sig_bytes = label.sig.expect("just set").to_vec();

        let created_at = wall_now_ms;
        let neg_int: i64 = 1;
        sqlx::query!(
            "INSERT INTO labels (seq, ver, src, uri, cid, val, neg, cts, exp, sig, signing_key_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            seq,
            label.ver,
            label.src,
            label.uri,
            label.cid,
            label.val,
            neg_int,
            label.cts,
            label.exp,
            sig_bytes,
            self.signing_key_id,
            created_at,
        )
        .execute(&mut *tx)
        .await?;

        let audit_reason = build_audit_reason(&req.val, true, req.moderator_reason.as_deref());
        crate::audit::append::append_in_tx(
            &mut tx,
            &crate::audit::append::AuditRowForAppend {
                created_at,
                action: "label_negated".into(),
                actor_did: req.actor_did.clone(),
                target: Some(req.uri.clone()),
                target_cid: cid.clone(),
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        tx.commit().await?;

        let event = LabelEvent { seq, label };
        let _ = self.broadcast_tx.send(event.clone());
        Ok(event)
    }

    /// Atomic resolveReport flow — §F12 requires label INSERT +
    /// audit(label_applied) + report UPDATE + audit(report_resolved)
    /// all commit together or not at all. Everything happens inside
    /// one SQLite transaction on the writer task, preserving §F5's
    /// single-writer invariant for the optional label emission.
    ///
    /// Returns [`Error::ReportNotFound`] if the report doesn't
    /// exist, [`Error::ReportAlreadyResolved`] if it is not in
    /// `status='pending'`. Label-value validation is a handler
    /// concern (the handler consults `AdminConfig.label_values`
    /// before sending the command here — saves a writer round-trip
    /// on invalid input and keeps the anti-leak message local).
    async fn handle_resolve_report(&self, req: ResolveReportRequest) -> Result<ResolvedReport> {
        use crate::report::ReportStatus;

        let mut tx = self.pool.begin().await?;

        // 1. Load the report; confirm pending status.
        let current = sqlx::query_as!(
            crate::report::Report,
            r#"SELECT
                 id                 AS "id!: i64",
                 created_at         AS "created_at!: String",
                 reported_by        AS "reported_by!: String",
                 reason_type        AS "reason_type!: String",
                 reason,
                 subject_type       AS "subject_type!: String",
                 subject_did        AS "subject_did!: String",
                 subject_uri,
                 subject_cid,
                 status             AS "status!: ReportStatus",
                 resolved_at,
                 resolved_by,
                 resolution_label,
                 resolution_reason
               FROM reports WHERE id = ?1"#,
            req.report_id,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let mut report = current.ok_or(Error::ReportNotFound { id: req.report_id })?;
        if report.status != ReportStatus::Pending {
            return Err(Error::ReportAlreadyResolved { id: req.report_id });
        }

        let created_at = epoch_ms_now();

        // 2. Optional label-apply BEFORE the report UPDATE so audit
        // row insertion order reflects logical sequence
        // (label_applied, then report_resolved — §G per #15 criteria).
        let label_event = if let Some(apply) = req.action.as_apply() {
            let apply_req = ApplyLabelRequest {
                actor_did: req.actor_did.clone(),
                uri: apply.uri.clone(),
                cid: apply.cid.clone(),
                val: apply.val.clone(),
                exp: apply.exp.clone(),
                // The label's own audit_reason JSON captures {val,
                // neg, moderator_reason}; the resolution-level reason
                // goes on the report_resolved audit row below.
                moderator_reason: None,
            };
            Some(
                self.apply_label_inner(&mut tx, &apply_req, created_at)
                    .await?,
            )
        } else {
            None
        };

        // 3. UPDATE reports.
        let resolved_at_rfc = rfc3339_from_epoch_ms(created_at)?;
        let resolution_label = req.action.as_apply().map(|a| a.val.clone());
        let resolved_status = ReportStatus::Resolved;
        sqlx::query!(
            "UPDATE reports SET
                status = ?1,
                resolved_at = ?2,
                resolved_by = ?3,
                resolution_label = ?4,
                resolution_reason = ?5
             WHERE id = ?6",
            resolved_status,
            resolved_at_rfc,
            req.actor_did,
            resolution_label,
            req.resolution_reason,
            req.report_id,
        )
        .execute(&mut *tx)
        .await?;

        // 4. Audit: report_resolved.
        let audit_reason = build_resolve_audit_reason(
            req.action.as_apply().map(|a| a.val.as_str()),
            req.resolution_reason.as_deref(),
        );
        crate::audit::append::append_in_tx(
            &mut tx,
            &crate::audit::append::AuditRowForAppend {
                created_at,
                action: "report_resolved".into(),
                actor_did: req.actor_did.clone(),
                target: Some(req.report_id.to_string()),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        tx.commit().await?;

        // 5. Broadcast (post-commit, per §F5 broadcast-after-commit rule).
        if let Some(event) = &label_event {
            let _ = self.broadcast_tx.send(event.clone());
        }

        // 6. Mutate the loaded report struct to reflect the committed
        // state and return it. Avoids a re-fetch round-trip since we
        // know exactly what changed.
        report.status = ReportStatus::Resolved;
        report.resolved_at = Some(resolved_at_rfc);
        report.resolved_by = Some(req.actor_did);
        report.resolution_label = resolution_label;
        report.resolution_reason = req.resolution_reason;

        Ok(ResolvedReport {
            report,
            label_event,
        })
    }

    /// Atomic recordAction flow (§F20 / #51). Validates inputs,
    /// resolves the primary reason, computes strike values via the
    /// v1.4 calculators (#48/#49/#50/#51), inserts the audit_log
    /// row first (so subject_actions can carry audit_log_id at
    /// INSERT — the schema's no-update-except-revoke trigger
    /// forbids backfilling it later), inserts the subject_actions
    /// row, then UPSERTs subject_strike_state. All in one
    /// transaction.
    async fn handle_record_action(&self, req: RecordActionRequest) -> Result<RecordedAction> {
        // ---------- pre-flight validation ----------

        if req.reason_codes.is_empty() {
            return Err(Error::Signing(
                "recordAction: reason_codes must be non-empty".into(),
            ));
        }
        // Note/Warning don't take reasons in the §F20 design intent,
        // but the issue body says "warning requires --reason" for
        // the audit trail. Accept reasons for all types; only
        // strike-bearing types actually use them for strike
        // calculation.
        match req.action_type {
            ActionType::TempSuspension => {
                if req.duration_iso.as_deref().unwrap_or("").is_empty() {
                    return Err(Error::DurationRequiredForTempSuspension);
                }
            }
            _ => {
                if req.duration_iso.is_some() {
                    return Err(Error::DurationOnlyForTempSuspension);
                }
            }
        }

        let (subject_did, subject_uri) = route_subject(&req.subject)?;

        // Resolve primary reason against the writer's vocabulary.
        // Vocabulary lookups are cheap; doing it before opening the
        // transaction keeps a bad-reason failure from acquiring the
        // SQLite write lock unnecessarily.
        let primary = resolve_primary_reason(&req.reason_codes, &self.reason_vocabulary)?;

        // Parse duration (cheap; pre-tx for the same reason).
        let duration_secs = match (req.action_type, req.duration_iso.as_deref()) {
            (ActionType::TempSuspension, Some(iso)) => Some(parse_iso8601_duration(iso)?),
            _ => None,
        };

        // ---------- transaction ----------

        let mut tx = self.pool.begin().await?;
        let created_at = epoch_ms_now();
        let effective_at = created_at;
        let expires_at: Option<i64> = duration_secs.map(|s| effective_at + (s as i64) * 1000);

        // Load history for strike + position calculation. id-ascending
        // (oldest-first) per the calculators' contract.
        let history = load_subject_actions_for_calc(&mut tx, &subject_did).await?;

        // Compute current count via the decay calculator.
        let now_systemtime = epoch_ms_to_systemtime(created_at);
        let pre_state = calculate_strike_state(&history, &self.strike_policy, now_systemtime);
        let strikes_at_time_of_action = pre_state.current_count;

        // Compute position and strike value.
        let position = compute_position_in_window(&history, &self.strike_policy, now_systemtime);
        let calc: StrikeApplication = strike_calculate(
            strikes_at_time_of_action,
            &primary,
            &self.strike_policy,
            position,
        );

        // Note/Warning don't carry strikes regardless of reason
        // (§F20 design + #48 semantics). Override with zero values
        // and was_dampened=false; defense-in-depth for an operator
        // who attaches a strike-bearing reason to a Note row.
        let (strike_base, strike_applied, was_dampened) = match req.action_type {
            ActionType::Note | ActionType::Warning => (0u32, 0u32, false),
            _ => (calc.base_weight, calc.applied, calc.was_dampened),
        };

        // Compute label-emission drafts before the audit row so the
        // audit reason JSON captures every (val, uri) tuple this
        // action will produce. The drafts are pure data — no I/O,
        // no signing — so committing them to the audit row before
        // signing is safe; the actual label INSERTs land below in
        // the same tx, and any failure rolls everything back.
        //
        // LabelDraft.cid is None for v1.5: subject CIDs aren't yet
        // plumbed through RecordActionRequest. The
        // ActionForEmission.cid field is reserved for the wiring a
        // future ticket adds via admin XRPC + CLI.
        let action_for_emission = ActionForEmission {
            action_type: req.action_type,
            expires_at: expires_at.map(epoch_ms_to_systemtime),
            subject_did: subject_did.clone(),
            subject_uri: subject_uri.clone(),
            reason_codes: req.reason_codes.clone(),
            cid: None,
        };
        let action_drafts = resolve_action_labels(
            &action_for_emission,
            &self.label_emission_policy,
            now_systemtime,
        );
        let reason_drafts = resolve_reason_labels(
            &action_for_emission,
            &self.label_emission_policy,
            now_systemtime,
        );
        let emitted_labels_for_audit: Vec<serde_json::Value> = action_drafts
            .iter()
            .chain(reason_drafts.iter())
            .map(|d| serde_json::json!({"val": d.val, "uri": d.uri}))
            .collect();

        // Build audit_log reason JSON before the INSERT so the
        // audit row can carry the resolved values for forensic
        // reconstruction.
        // action_id is unknown until subject_actions INSERT, so we
        // patch it in after that step.
        let reason_codes_json = serde_json::to_string(&req.reason_codes)
            .map_err(|e| Error::Signing(format!("serialize reason_codes: {e}")))?;
        let report_ids_json = if req.report_ids.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&req.report_ids)
                    .map_err(|e| Error::Signing(format!("serialize report_ids: {e}")))?,
            )
        };

        // Append audit_log row first. target = subject_did (the
        // account being moderated); target_cid = None. We don't
        // know action_id yet — pass 0 as a placeholder; the actual
        // id is patched into the reason JSON after the
        // subject_actions INSERT, but only the reason JSON gets
        // the patch. The audit row's hash chain locks at this
        // INSERT, so the action_id is captured at write time.
        //
        // Order rationale: audit_log first so subject_actions
        // can carry audit_log_id at INSERT (the trigger forbids
        // UPDATE of audit_log_id). The audit row's reason JSON
        // captures the action_id IT will reference, computed
        // post-INSERT via the next-id query.
        let next_action_id = predict_next_subject_action_id(&mut tx).await?;

        // ---------- policy evaluation (#73, v1.6) ----------
        //
        // Evaluate operator-declared rules BEFORE writing the
        // precipitating audit row so the audit reason JSON's
        // `policy_consequence` field can cross-reference the
        // predicted auto-action id (mode=auto) or the predicted
        // pending row id (mode=flag). Hash chain locks the
        // bundle (action + policy consequence) atomically.
        //
        // The evaluator is pure — it consumes already-computed
        // strike states and projections. We construct
        // `state_after_precip` synthetically (history + the
        // about-to-INSERT precipitating row's effect) so we can
        // call into #72 before the row actually lands. This
        // matches the v1.5 #60 pattern of computing label
        // drafts pre-INSERT and verifying via the
        // predict-then-verify dance.
        let policy_eval_history =
            load_subject_actions_for_policy_eval(&mut tx, &subject_did).await?;
        let pending_eval_actions = load_pending_for_policy_eval(&mut tx, &subject_did).await?;
        let synthetic_precip = ActionRecord {
            strike_value_applied: strike_applied,
            effective_at: now_systemtime,
            revoked_at: None,
            action_type: req.action_type,
            expires_at: expires_at.map(epoch_ms_to_systemtime),
            was_dampened,
        };
        let mut history_plus_precip = history.clone();
        history_plus_precip.push(synthetic_precip);
        let state_after_precip =
            calculate_strike_state(&history_plus_precip, &self.strike_policy, now_systemtime);

        // Project the synthetic precipitating action onto
        // ActionForPolicyEval shape and append to the eval
        // history; the evaluator's takedown-detection +
        // idempotency checks include the row that's about to
        // INSERT (matters when this very recordAction is itself
        // a takedown — the evaluator returns None immediately).
        let mut policy_eval_history_plus_precip = policy_eval_history.clone();
        policy_eval_history_plus_precip.push(crate::policy::evaluator::ActionForPolicyEval {
            effective_at: now_systemtime,
            action_type: req.action_type,
            revoked_at: None,
            triggered_by_policy_rule: None,
        });

        let firing_rule = crate::policy::evaluator::resolve_firing_rule(
            &pre_state,
            &state_after_precip,
            &policy_eval_history_plus_precip,
            &pending_eval_actions,
            &self.policy_automation_policy,
        );

        // Reserve IDs + build policy_consequence pointer for the
        // precipitating audit row. For mode=auto the auto-action
        // id is `next_action_id + 1` (the writer task is the only
        // in-process appender, so consecutive INSERTs assign
        // consecutive ids; the predict-then-verify check below
        // catches any drift). For mode=flag we predict the next
        // pending_policy_actions id.
        let (policy_consequence, predicted_auto_action_id, predicted_pending_id, firing_rule_owned) =
            if let Some(rule) = firing_rule {
                match rule.mode {
                    crate::policy::automation::PolicyMode::Auto => {
                        let auto_id = next_action_id + 1;
                        let pc = serde_json::json!({
                            "rule_fired": rule.name,
                            "mode": "auto",
                            "auto_action_id": auto_id,
                        });
                        (Some(pc), Some(auto_id), None, Some(rule.clone()))
                    }
                    crate::policy::automation::PolicyMode::Flag => {
                        let pending_id = predict_next_pending_action_id(&mut tx).await?;
                        let pc = serde_json::json!({
                            "rule_fired": rule.name,
                            "mode": "flag",
                            "pending_action_id": pending_id,
                        });
                        (Some(pc), None, Some(pending_id), Some(rule.clone()))
                    }
                }
            } else {
                (None, None, None, None)
            };

        let audit_reason = build_record_action_audit_reason(
            next_action_id,
            req.action_type,
            &primary.identifier,
            &req.reason_codes,
            strike_base,
            strike_applied,
            was_dampened,
            &emitted_labels_for_audit,
            "moderator",
            None,
            policy_consequence,
        );
        let audit_target = subject_uri.clone().unwrap_or_else(|| subject_did.clone());
        let audit_log_id = crate::audit::append::append_in_tx(
            &mut tx,
            &crate::audit::append::AuditRowForAppend {
                created_at,
                action: "subject_action_recorded".into(),
                actor_did: req.actor_did.clone(),
                target: Some(audit_target),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        // INSERT subject_actions. action_type goes through
        // ActionType::as_db_str so the SQL CHECK constraint binds
        // the same set as the Rust enum.
        // actor_kind = 'moderator' here — this is the moderator-
        // recorded path; the policy-recorded path lower in this
        // function sets 'policy' explicitly.
        let action_type_str = req.action_type.as_db_str();
        let was_dampened_int: i64 = if was_dampened { 1 } else { 0 };
        let strikes_at_time_i64 = strikes_at_time_of_action as i64;
        let strike_base_i64 = strike_base as i64;
        let strike_applied_i64 = strike_applied as i64;
        let actor_kind_moderator = "moderator";
        let inserted_id = sqlx::query_scalar!(
            "INSERT INTO subject_actions (
                subject_did, subject_uri, actor_did, action_type, reason_codes,
                duration, effective_at, expires_at, notes, report_ids,
                strike_value_base, strike_value_applied, was_dampened,
                strikes_at_time_of_action, audit_log_id, created_at,
                actor_kind, triggered_by_policy_rule
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, NULL)
             RETURNING id",
            subject_did,
            subject_uri,
            req.actor_did,
            action_type_str,
            reason_codes_json,
            req.duration_iso,
            effective_at,
            expires_at,
            req.notes,
            report_ids_json,
            strike_base_i64,
            strike_applied_i64,
            was_dampened_int,
            strikes_at_time_i64,
            audit_log_id,
            created_at,
            actor_kind_moderator,
        )
        .fetch_one(&mut *tx)
        .await?;

        if inserted_id != next_action_id {
            // Audit row already committed; we'd have to invalidate
            // it. With BEGIN DEFERRED + the writer task being the
            // only in-process appender, the predict-vs-insert
            // race is closed — but if it ever fires, surface as
            // an internal error rather than a silent mismatch.
            return Err(Error::Signing(format!(
                "subject_actions inserted at id {inserted_id} but predicted {next_action_id}; audit chain captured the predicted id (corrupted)"
            )));
        }

        // ---------- idempotency guard (#64, v1.5) ----------
        //
        // Defense-in-depth: skip emission for any state already
        // present on the row. v1.5's recordAction flow always
        // finds these queries returning the empty/NULL case (the
        // INSERT just landed and nothing else has touched the row
        // yet), so the guard is structurally a no-op in
        // production. It exists to protect against future paths
        // that might invoke emission against a row already
        // carrying linkage state — backfill migrations, retry
        // helpers, alternate code paths — and against bugs that
        // would otherwise silently produce duplicate (src, uri,
        // val) records on the wire.
        //
        // The audit row's `emitted_labels` was already written
        // above (intent, derived from the drafts). In v1.5 normal
        // flow intent matches reality. If a future defensive
        // scenario fires the guard and skips emissions, the audit
        // row will claim more emissions than the labels table
        // holds. That divergence is the future-implementer's
        // responsibility to handle (e.g., by adding a re-emission
        // entry point that constructs its own audit row); v1.5
        // accepts the limitation because the divergence is
        // structurally unreachable from this code path.
        //
        // The guard's "fire" branch is structurally unreachable
        // from the public XRPC + writer-task API in v1.5 (every
        // recordAction goes through this same INSERT). That makes
        // it untestable end-to-end without a re-emission entry
        // point we don't ship; the pure decision logic is
        // exercised via unit tests on
        // `should_skip_action_label_emission` /
        // `should_skip_reason_emission` instead.
        let existing_action_label_val: Option<String> = sqlx::query_scalar!(
            "SELECT emitted_label_uri FROM subject_actions WHERE id = ?1",
            inserted_id,
        )
        .fetch_one(&mut *tx)
        .await?;
        let existing_reason_codes: Vec<String> = sqlx::query_scalar!(
            "SELECT reason_code FROM subject_action_reason_labels WHERE action_id = ?1",
            inserted_id,
        )
        .fetch_all(&mut *tx)
        .await?;
        let existing_reason_set: HashSet<&str> =
            existing_reason_codes.iter().map(String::as_str).collect();

        // ---------- emission (#60, v1.5) ----------
        //
        // Sign + persist each draft (action label first so its
        // seq < reason labels'), then UPDATE
        // subject_actions.emitted_label_uri, then write per-reason
        // linkage rows. All in the same tx as the action INSERT
        // and the audit row. Failure here rolls back everything
        // up to and including the audit row, so the audit chain
        // never claims emission that didn't happen.
        //
        // Empty action_drafts (note / suppressed warning / policy
        // disabled) cleanly short-circuits both loops, leaves
        // emitted_label_uri NULL, and writes no reason-label
        // linkage rows — the action still records, just without
        // an ATProto label tail.
        let mut label_events: Vec<LabelEvent> =
            Vec::with_capacity(action_drafts.len() + reason_drafts.len());
        let mut action_label_val: Option<String> = None;
        if !should_skip_action_label_emission(existing_action_label_val.as_deref()) {
            for draft in &action_drafts {
                let event = self
                    .sign_and_persist_label_from_draft(&mut tx, draft, effective_at)
                    .await?;
                if action_label_val.is_none() {
                    action_label_val = Some(draft.val.clone());
                }
                label_events.push(event);
            }

            if let Some(ref val) = action_label_val {
                // emitted_label_uri stores the action label's `val`,
                // not a URI: ATProto labels have no canonical URI; the
                // discriminator within (src=service_did, uri=subject,
                // val) is just the val. Column name predates the
                // realization (#57); locked once shipped.
                sqlx::query!(
                    "UPDATE subject_actions SET emitted_label_uri = ?1 WHERE id = ?2",
                    val,
                    inserted_id,
                )
                .execute(&mut *tx)
                .await?;
            }
        }

        // Per-(action, reason) linkage rows. resolve_reason_labels
        // emits drafts in `reason_codes` order, so a parallel
        // iteration recovers the source reason_code without
        // re-parsing the label val. Reasons whose linkage row
        // already exists are skipped per the idempotency guard
        // above.
        for (draft, reason_code) in reason_drafts.iter().zip(req.reason_codes.iter()) {
            if should_skip_reason_emission(reason_code, &existing_reason_set) {
                continue;
            }
            let event = self
                .sign_and_persist_label_from_draft(&mut tx, draft, effective_at)
                .await?;
            sqlx::query!(
                "INSERT INTO subject_action_reason_labels
                   (action_id, reason_code, emitted_label_uri, emitted_at)
                 VALUES (?1, ?2, ?3, ?4)",
                inserted_id,
                reason_code,
                draft.val,
                effective_at,
            )
            .execute(&mut *tx)
            .await?;
            label_events.push(event);
        }

        // ---------- policy consequence (#73, v1.6) ----------
        //
        // If a rule fires, this is where the consequence lands —
        // either a second `subject_actions` row (mode=auto) with
        // its own audit row + label emission, or a
        // `pending_policy_actions` row (mode=flag) awaiting
        // moderator review. All in the same transaction as the
        // precipitating action; failure rolls everything back.
        if let Some(rule) = firing_rule_owned.as_ref() {
            match rule.mode {
                crate::policy::automation::PolicyMode::Auto => {
                    let auto_id =
                        predicted_auto_action_id.expect("auto rule firing reserved an id above");
                    self.insert_policy_auto_action(
                        &mut tx,
                        rule,
                        &subject_did,
                        subject_uri.as_deref(),
                        &history_plus_precip,
                        &state_after_precip,
                        now_systemtime,
                        created_at,
                        auto_id,
                        &mut label_events,
                    )
                    .await?;
                }
                crate::policy::automation::PolicyMode::Flag => {
                    let pending_id =
                        predicted_pending_id.expect("flag rule firing reserved an id above");
                    self.insert_pending_policy_action(
                        &mut tx,
                        rule,
                        &subject_did,
                        subject_uri.as_deref(),
                        inserted_id,
                        created_at,
                        pending_id,
                    )
                    .await?;
                }
            }
        }

        // ---------- takedown cascade (#76, v1.6) ----------
        //
        // Moderator-recorded Takedown auto-dismisses every
        // unresolved pending_policy_actions row for the subject.
        // The cascade audit rows hash-chain after the
        // precipitating action's audit row (and any policy-
        // consequence audit row from the auto-action branch
        // above), so a forensic reader sees: takedown → cascade
        // dismissals, in commit order.
        //
        // Note: the policy evaluator (#72) returns None when the
        // precipitating action itself is a Takedown (its
        // subject_is_takendown gate fires post-precip-projection),
        // so `firing_rule_owned` is always None on this path —
        // the cascade is the only consequence of a moderator
        // takedown.
        if req.action_type == ActionType::Takedown {
            auto_dismiss_pendings_on_takedown(
                &mut tx,
                &subject_did,
                subject_uri.as_deref(),
                inserted_id,
                &req.actor_did,
                created_at,
            )
            .await?;
        }

        // Recompute strike state for the cache. Reload history with
        // the new row so the cache reflects post-insert reality.
        // Includes the auto-recorded action when one fired.
        let post_history = load_subject_actions_for_calc(&mut tx, &subject_did).await?;
        let post_state = calculate_strike_state(&post_history, &self.strike_policy, now_systemtime);

        let post_count_i64 = post_state.current_count as i64;
        sqlx::query!(
            "INSERT INTO subject_strike_state (subject_did, current_strike_count, last_action_at, last_recompute_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(subject_did) DO UPDATE SET
                 current_strike_count = excluded.current_strike_count,
                 last_action_at = excluded.last_action_at,
                 last_recompute_at = excluded.last_recompute_at",
            subject_did,
            post_count_i64,
            created_at,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // Broadcast each emitted label to subscribeLabels consumers.
        // Order matches the persistence order (action label first,
        // then reasons). No-receivers is not a write failure
        // (§plan point G).
        for event in label_events {
            let _ = self.broadcast_tx.send(event);
        }

        Ok(RecordedAction {
            action_id: inserted_id,
            strike_value_base: strike_base,
            strike_value_applied: strike_applied,
            was_dampened,
            strikes_at_time_of_action,
        })
    }

    /// Atomic revokeAction flow (§F20 / #51). Looks up the row,
    /// verifies state, sets the revoked_* columns (the schema's
    /// no-update-except-revoke trigger permits this NULL→non-NULL
    /// transition), recomputes strike_state for the subject, and
    /// appends an audit_log row. All in one transaction.
    async fn handle_revoke_action(&self, req: RevokeActionRequest) -> Result<RevokedAction> {
        let mut tx = self.pool.begin().await?;

        // Look up the row + check current state. Pull the fields
        // needed for both v1.4 revocation (subject_did, revoked_at)
        // and v1.5 #62 negation (subject_uri, emitted_label_uri).
        let row = sqlx::query!(
            "SELECT subject_did, subject_uri, emitted_label_uri, revoked_at
             FROM subject_actions WHERE id = ?1",
            req.action_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let row = row.ok_or(Error::ActionNotFound(req.action_id))?;
        if row.revoked_at.is_some() {
            return Err(Error::ActionAlreadyRevoked(req.action_id));
        }

        let revoked_at_ms = epoch_ms_now();

        // UPDATE the revocation columns. The schema trigger permits
        // NULL→non-NULL on these three columns; any other column
        // change in this UPDATE would abort.
        sqlx::query!(
            "UPDATE subject_actions
             SET revoked_at = ?1, revoked_by_did = ?2, revoked_reason = ?3
             WHERE id = ?4",
            revoked_at_ms,
            req.revoked_by_did,
            req.revoked_reason,
            req.action_id,
        )
        .execute(&mut *tx)
        .await?;

        // ---------- negation (#62, v1.5) ----------
        //
        // Read the action's emitted-label linkage from storage
        // (NOT from current policy — see module docs for the
        // val-from-storage rule). For each emitted val, sign and
        // persist a fresh label row with neg=true targeting the
        // same (src, uri, val) tuple. The original rows stay in
        // place; ATProto consumers honor the latest record per
        // tuple and so see the negation. Reason linkage rows
        // (subject_action_reason_labels) are PRESERVED — they're
        // forensic record of "at this point these labels were
        // emitted," not a cache of what's currently in force.
        //
        // exp = None on every negation. The original temp_suspension
        // label may have carried an expiry (its exp said "stop
        // honoring me at this wall-clock"), but the negation itself
        // is a permanent statement that supersedes the original;
        // expiring the negation would resurrect the original label
        // in consumer caches.
        //
        // Action that was never emitted (note, suppressed warning,
        // emission disabled at recording time) → both the action
        // label fetch and the reason-label fetch yield zero rows
        // and the negation step is a no-op. The revocation
        // audit row still lands with negated_labels = [].
        let label_uri = row
            .subject_uri
            .clone()
            .unwrap_or_else(|| row.subject_did.clone());

        // Reason-label linkage rows ordered by reason_code for
        // deterministic audit shape. Original emission order isn't
        // recoverable (storage doesn't preserve req.reason_codes
        // ordering), and ATProto consumers don't care about
        // negation order; alphabetical is the cheapest stable
        // ordering for forensic readers.
        let reason_linkage = sqlx::query!(
            "SELECT reason_code, emitted_label_uri
             FROM subject_action_reason_labels
             WHERE action_id = ?1
             ORDER BY reason_code ASC",
            req.action_id,
        )
        .fetch_all(&mut *tx)
        .await?;

        let mut negated_for_audit: Vec<serde_json::Value> = Vec::new();
        if let Some(ref val) = row.emitted_label_uri {
            negated_for_audit.push(serde_json::json!({
                "val": val,
                "uri": label_uri,
            }));
        }
        for r in &reason_linkage {
            negated_for_audit.push(serde_json::json!({
                "val": r.emitted_label_uri,
                "uri": label_uri,
            }));
        }

        // Audit row first — captures the negation set in the hash
        // chain before the label INSERTs land. Mirrors #60's
        // emission-side ordering: a forensic reader who sees the
        // audit row knows what labels SHOULD have been written;
        // the labels table is the witness. tx atomicity guarantees
        // they agree.
        let audit_reason = build_revoke_action_audit_reason(
            req.action_id,
            req.revoked_reason.as_deref(),
            &negated_for_audit,
        );
        crate::audit::append::append_in_tx(
            &mut tx,
            &crate::audit::append::AuditRowForAppend {
                created_at: revoked_at_ms,
                action: "subject_action_revoked".into(),
                actor_did: req.revoked_by_did.clone(),
                target: Some(req.action_id.to_string()),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        // Sign + persist each negation label. Action label first so
        // its seq < reason negations'.
        let mut negation_events: Vec<LabelEvent> = Vec::with_capacity(1 + reason_linkage.len());
        if let Some(ref val) = row.emitted_label_uri {
            let event = self
                .sign_and_persist_label(
                    &mut tx,
                    val,
                    &label_uri,
                    None, // cid: not plumbed in v1.5
                    true, // neg
                    None, // exp: negations don't expire
                    revoked_at_ms,
                )
                .await?;
            negation_events.push(event);
        }
        for r in &reason_linkage {
            let event = self
                .sign_and_persist_label(
                    &mut tx,
                    &r.emitted_label_uri,
                    &label_uri,
                    None,
                    true,
                    None,
                    revoked_at_ms,
                )
                .await?;
            negation_events.push(event);
        }

        // Recompute strike state for the subject. The decay
        // calculator excludes revoked rows from current_count.
        let post_history = load_subject_actions_for_calc(&mut tx, &row.subject_did).await?;
        let now_systemtime = epoch_ms_to_systemtime(revoked_at_ms);
        let post_state = calculate_strike_state(&post_history, &self.strike_policy, now_systemtime);

        let post_count_i64 = post_state.current_count as i64;
        sqlx::query!(
            "INSERT INTO subject_strike_state (subject_did, current_strike_count, last_action_at, last_recompute_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(subject_did) DO UPDATE SET
                 current_strike_count = excluded.current_strike_count,
                 last_recompute_at = excluded.last_recompute_at",
            row.subject_did,
            post_count_i64,
            revoked_at_ms,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // Broadcast each negation to subscribeLabels consumers
        // post-commit. Same ordering and no-receivers-is-fine
        // posture as the emission path (§plan point G).
        for event in negation_events {
            let _ = self.broadcast_tx.send(event);
        }

        Ok(RevokedAction {
            action_id: req.action_id,
            revoked_at: rfc3339_from_epoch_ms(revoked_at_ms)?,
        })
    }

    /// Atomic confirmPendingAction flow (§F22 / #74). Loads the
    /// pending row, validates state, materializes the proposed
    /// action as a real `subject_actions` row (actor_kind =
    /// 'moderator', triggered_by_policy_rule preserved as
    /// provenance), emits labels, UPDATEs the pending row's
    /// resolution columns, recomputes strike state, and writes a
    /// hash-chained `pending_policy_action_confirmed` audit row —
    /// all in one transaction.
    ///
    /// Strike values are computed at confirmation time, not at
    /// proposal time: the moderator is the one taking
    /// responsibility, and the subject's strike state may have
    /// shifted since the rule fired (e.g., decay, intervening
    /// revocations). The resulting subject_actions row's
    /// `effective_at` and `expires_at` (for temp_suspension)
    /// likewise anchor on `now`, not on the original triggered_at.
    ///
    /// No policy-evaluation re-runs against the new row: the
    /// originating rule is already-fired (per #72's idempotency,
    /// which gates on triggered_by_policy_rule), and rule-fan-out
    /// from a confirmation would compound moderator-tier
    /// authority. The single audit row reflects this single
    /// decision.
    async fn handle_confirm_pending_action(
        &self,
        req: ConfirmPendingActionRequest,
    ) -> Result<ConfirmedPendingAction> {
        let mut tx = self.pool.begin().await?;

        // ---------- load + validate pending ----------
        let pending = sqlx::query!(
            r#"SELECT
                 subject_did             AS "subject_did!: String",
                 subject_uri,
                 action_type             AS "action_type!: String",
                 duration_ms,
                 reason_codes            AS "reason_codes!: String",
                 triggered_by_policy_rule AS "triggered_by_policy_rule!: String",
                 resolution
               FROM pending_policy_actions
               WHERE id = ?1"#,
            req.pending_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let pending = pending.ok_or(Error::PendingActionNotFound(req.pending_id))?;
        if pending.resolution.is_some() {
            return Err(Error::PendingAlreadyResolved(req.pending_id));
        }

        let action_type = ActionType::from_db_str(&pending.action_type).ok_or_else(|| {
            Error::Signing(format!(
                "pending_policy_actions row has invalid action_type {:?}",
                pending.action_type
            ))
        })?;

        // ---------- defensive: subject_takendown ----------
        //
        // #76 (auto-dismissal-on-takedown) is meant to resolve all
        // pendings the moment a takedown lands — so reaching this
        // path with an active takedown means a race the auto-dismiss
        // hasn't closed yet. Reject defensively rather than
        // materialize a redundant action under terminal-severity
        // semantics.
        let history = load_subject_actions_for_calc(&mut tx, &pending.subject_did).await?;
        let subject_is_takendown = history
            .iter()
            .any(|a| a.action_type == ActionType::Takedown && a.revoked_at.is_none());
        if subject_is_takendown {
            return Err(Error::SubjectTakendown(pending.subject_did.clone()));
        }

        // ---------- decode pending fields ----------
        let reason_codes: Vec<String> = serde_json::from_str(&pending.reason_codes)
            .map_err(|e| Error::Signing(format!("parse pending reason_codes: {e}")))?;
        if reason_codes.is_empty() {
            return Err(Error::Signing(
                "confirmPendingAction: pending row has empty reason_codes".into(),
            ));
        }

        // Vocabulary lookup. The pending was originally created
        // with rule.reason_codes (config-validated against
        // [moderation_reasons] at startup per #71), so this should
        // always resolve — but the vocabulary may have shifted
        // since the pending was queued, so route the failure
        // through the same ReasonNotFound surface the moderator
        // path uses.
        let primary = resolve_primary_reason(&reason_codes, &self.reason_vocabulary)?;

        // ---------- strike calc at confirmation time ----------
        let now_ms = epoch_ms_now();
        let now_systemtime = epoch_ms_to_systemtime(now_ms);
        let pre_state = calculate_strike_state(&history, &self.strike_policy, now_systemtime);
        let strikes_at_time_of_action = pre_state.current_count;
        let position = compute_position_in_window(&history, &self.strike_policy, now_systemtime);
        let calc: StrikeApplication = strike_calculate(
            strikes_at_time_of_action,
            &primary,
            &self.strike_policy,
            position,
        );
        let (strike_base, strike_applied, was_dampened) = match action_type {
            ActionType::Note | ActionType::Warning => (0u32, 0u32, false),
            _ => (calc.base_weight, calc.applied, calc.was_dampened),
        };

        // ---------- effective_at / expires_at ----------
        //
        // Confirmation is when the action takes effect, so
        // expires_at re-anchors on `now`. duration_ms was frozen
        // on the pending row at proposal time (rule.duration via
        // #71 / #73); the canonical wire shape is `PT<seconds>S`
        // matching the policy auto-action path.
        let effective_at = now_ms;
        let expires_at: Option<i64> = pending.duration_ms.map(|d| effective_at + d);
        let duration_iso: Option<String> = pending.duration_ms.map(|d| format!("PT{}S", d / 1000));

        // ---------- emission drafts ----------
        let action_for_emission = ActionForEmission {
            action_type,
            expires_at: expires_at.map(epoch_ms_to_systemtime),
            subject_did: pending.subject_did.clone(),
            subject_uri: pending.subject_uri.clone(),
            reason_codes: reason_codes.clone(),
            cid: None,
        };
        let action_drafts = resolve_action_labels(
            &action_for_emission,
            &self.label_emission_policy,
            now_systemtime,
        );
        let reason_drafts = resolve_reason_labels(
            &action_for_emission,
            &self.label_emission_policy,
            now_systemtime,
        );
        let emitted_labels_for_audit: Vec<serde_json::Value> = action_drafts
            .iter()
            .chain(reason_drafts.iter())
            .map(|d| serde_json::json!({"val": d.val, "uri": d.uri}))
            .collect();

        // ---------- predict + audit ----------
        let next_action_id = predict_next_subject_action_id(&mut tx).await?;

        let audit_reason = build_pending_confirmed_audit_reason(
            req.pending_id,
            &pending.triggered_by_policy_rule,
            next_action_id,
            action_type,
            &primary.identifier,
            &reason_codes,
            strike_base,
            strike_applied,
            was_dampened,
            &emitted_labels_for_audit,
            req.note.as_deref(),
        );
        let audit_target = pending
            .subject_uri
            .clone()
            .unwrap_or_else(|| pending.subject_did.clone());
        let audit_log_id = crate::audit::append::append_in_tx(
            &mut tx,
            &crate::audit::append::AuditRowForAppend {
                created_at: now_ms,
                action: "pending_policy_action_confirmed".into(),
                actor_did: req.moderator_did.clone(),
                target: Some(audit_target),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        // ---------- INSERT subject_actions ----------
        //
        // actor_kind = 'moderator' (the moderator takes
        // responsibility by confirming); triggered_by_policy_rule
        // preserves the rule that proposed the action — forensic
        // provenance plus the idempotency-gate input for #72's
        // already-fired check.
        let action_type_str = action_type.as_db_str();
        let was_dampened_int: i64 = if was_dampened { 1 } else { 0 };
        let strikes_at_time_i64 = strikes_at_time_of_action as i64;
        let strike_base_i64 = strike_base as i64;
        let strike_applied_i64 = strike_applied as i64;
        let reason_codes_json = serde_json::to_string(&reason_codes)
            .map_err(|e| Error::Signing(format!("serialize reason_codes for confirm: {e}")))?;
        let actor_kind_moderator = "moderator";
        let inserted_id = sqlx::query_scalar!(
            "INSERT INTO subject_actions (
                subject_did, subject_uri, actor_did, action_type, reason_codes,
                duration, effective_at, expires_at, notes, report_ids,
                strike_value_base, strike_value_applied, was_dampened,
                strikes_at_time_of_action, audit_log_id, created_at,
                actor_kind, triggered_by_policy_rule
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             RETURNING id",
            pending.subject_did,
            pending.subject_uri,
            req.moderator_did,
            action_type_str,
            reason_codes_json,
            duration_iso,
            effective_at,
            expires_at,
            req.note,
            strike_base_i64,
            strike_applied_i64,
            was_dampened_int,
            strikes_at_time_i64,
            audit_log_id,
            now_ms,
            actor_kind_moderator,
            pending.triggered_by_policy_rule,
        )
        .fetch_one(&mut *tx)
        .await?;
        if inserted_id != next_action_id {
            return Err(Error::Signing(format!(
                "confirm subject_actions inserted at id {inserted_id} but predicted \
                 {next_action_id}; audit chain captured the predicted id (corrupted)"
            )));
        }

        // ---------- emit labels ----------
        //
        // Same pattern as handle_record_action and
        // insert_policy_auto_action: action label first (its seq
        // < reason labels'), then per-(action, reason) linkage
        // rows. Fresh INSERT so the #64 idempotency guard is a
        // no-op; skipped here for clarity.
        let mut label_events: Vec<LabelEvent> =
            Vec::with_capacity(action_drafts.len() + reason_drafts.len());
        let mut action_label_val: Option<String> = None;
        for draft in &action_drafts {
            let event = self
                .sign_and_persist_label_from_draft(&mut tx, draft, effective_at)
                .await?;
            if action_label_val.is_none() {
                action_label_val = Some(draft.val.clone());
            }
            label_events.push(event);
        }
        if let Some(ref val) = action_label_val {
            sqlx::query!(
                "UPDATE subject_actions SET emitted_label_uri = ?1 WHERE id = ?2",
                val,
                inserted_id,
            )
            .execute(&mut *tx)
            .await?;
        }
        for (draft, reason_code) in reason_drafts.iter().zip(reason_codes.iter()) {
            let event = self
                .sign_and_persist_label_from_draft(&mut tx, draft, effective_at)
                .await?;
            sqlx::query!(
                "INSERT INTO subject_action_reason_labels
                   (action_id, reason_code, emitted_label_uri, emitted_at)
                 VALUES (?1, ?2, ?3, ?4)",
                inserted_id,
                reason_code,
                draft.val,
                effective_at,
            )
            .execute(&mut *tx)
            .await?;
            label_events.push(event);
        }

        // ---------- UPDATE pending: NULL → 'confirmed' ----------
        //
        // The schema trigger (migration 0005) permits this single
        // NULL → non-NULL transition on resolution / resolved_at /
        // resolved_by_did / confirmed_action_id; any other change
        // to the row would abort. Setting all four columns
        // together so the row's invariant
        // ("confirmed implies confirmed_action_id non-NULL")
        // holds at every queryable instant.
        let confirmed_resolution = "confirmed";
        sqlx::query!(
            "UPDATE pending_policy_actions
             SET resolution = ?1,
                 resolved_at = ?2,
                 resolved_by_did = ?3,
                 confirmed_action_id = ?4
             WHERE id = ?5",
            confirmed_resolution,
            now_ms,
            req.moderator_did,
            inserted_id,
            req.pending_id,
        )
        .execute(&mut *tx)
        .await?;

        // ---------- takedown cascade (#76, v1.6) ----------
        //
        // Confirming a pending whose proposed action is a Takedown
        // makes the subject takendown the moment the new
        // subject_actions row INSERTed; the cascade then dismisses
        // every OTHER unresolved pending for the subject. The
        // pending currently being confirmed is naturally excluded
        // because its UPDATE to resolution='confirmed' has already
        // landed above — the cascade's `WHERE resolution IS NULL`
        // filter sees it as 'confirmed', not NULL.
        //
        // resolved_by_did on cascaded rows is the confirming
        // moderator's DID — not the synthetic policy DID — because
        // the moderator chose to confirm the takedown and is the
        // ultimate authority for the cascade.
        if action_type == ActionType::Takedown {
            auto_dismiss_pendings_on_takedown(
                &mut tx,
                &pending.subject_did,
                pending.subject_uri.as_deref(),
                inserted_id,
                &req.moderator_did,
                now_ms,
            )
            .await?;
        }

        // ---------- recompute strike state ----------
        let post_history = load_subject_actions_for_calc(&mut tx, &pending.subject_did).await?;
        let post_state = calculate_strike_state(&post_history, &self.strike_policy, now_systemtime);
        let post_count_i64 = post_state.current_count as i64;
        sqlx::query!(
            "INSERT INTO subject_strike_state (subject_did, current_strike_count, last_action_at, last_recompute_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(subject_did) DO UPDATE SET
                 current_strike_count = excluded.current_strike_count,
                 last_action_at = excluded.last_action_at,
                 last_recompute_at = excluded.last_recompute_at",
            pending.subject_did,
            post_count_i64,
            now_ms,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // ---------- broadcast ----------
        for event in label_events {
            let _ = self.broadcast_tx.send(event);
        }

        Ok(ConfirmedPendingAction {
            action_id: inserted_id,
            pending_id: req.pending_id,
            resolved_at: rfc3339_from_epoch_ms(now_ms)?,
        })
    }

    /// Atomic dismissPendingAction flow (§F22 / #75). Loads the
    /// pending row, validates state, UPDATEs the resolution
    /// columns to 'dismissed', and writes a hash-chained
    /// `pending_policy_action_dismissed` audit row — all in one
    /// transaction. Inverse of `handle_confirm_pending_action`:
    /// no subject_actions row, no label emission, no strike-state
    /// recompute. The pending row stays in the table as forensic
    /// record (`confirmed_action_id` stays NULL; only confirmed
    /// pendings link forward to a materialized action).
    ///
    /// No `SubjectTakendown` defensive check (unlike confirm in
    /// #74): explicit dismissal is meaningful regardless of
    /// takedown state, and is in fact part of the cleanup path
    /// #76 will automate when a takedown lands.
    async fn handle_dismiss_pending_action(
        &self,
        req: DismissPendingActionRequest,
    ) -> Result<DismissedPendingAction> {
        let mut tx = self.pool.begin().await?;

        // ---------- load + validate pending ----------
        let pending = sqlx::query!(
            r#"SELECT
                 subject_did             AS "subject_did!: String",
                 subject_uri,
                 action_type             AS "action_type!: String",
                 reason_codes            AS "reason_codes!: String",
                 triggered_by_policy_rule AS "triggered_by_policy_rule!: String",
                 resolution
               FROM pending_policy_actions
               WHERE id = ?1"#,
            req.pending_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let pending = pending.ok_or(Error::PendingActionNotFound(req.pending_id))?;
        if pending.resolution.is_some() {
            return Err(Error::PendingAlreadyResolved(req.pending_id));
        }

        let now_ms = epoch_ms_now();

        // ---------- audit row ----------
        //
        // Reason JSON cross-references the pending row and echoes
        // the proposed-action shape (action_type, reason_codes)
        // so a forensic reader can reconstruct "moderator
        // dismissed a proposed indef_suspension for spam"
        // without joining to pending_policy_actions. subject_did
        // / actor_did are already on the audit_log row's target /
        // actor_did — not duplicated in the reason JSON.
        let reason_codes_for_audit: serde_json::Value =
            serde_json::from_str(&pending.reason_codes).unwrap_or(serde_json::Value::Null);
        let audit_reason = build_pending_dismissed_audit_reason(
            req.pending_id,
            &pending.triggered_by_policy_rule,
            &pending.action_type,
            reason_codes_for_audit,
            req.reason.as_deref(),
        );
        let audit_target = pending
            .subject_uri
            .clone()
            .unwrap_or_else(|| pending.subject_did.clone());
        crate::audit::append::append_in_tx(
            &mut tx,
            &crate::audit::append::AuditRowForAppend {
                created_at: now_ms,
                action: "pending_policy_action_dismissed".into(),
                actor_did: req.moderator_did.clone(),
                target: Some(audit_target),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        // ---------- UPDATE pending: NULL → 'dismissed' ----------
        //
        // The schema trigger (migration 0005) permits this single
        // NULL → non-NULL transition on resolution / resolved_at
        // / resolved_by_did; confirmed_action_id stays NULL by
        // design (no action was created). Setting all three
        // columns together so the row's "dismissed implies who
        // and when" invariant holds at every queryable instant.
        let dismissed_resolution = "dismissed";
        sqlx::query!(
            "UPDATE pending_policy_actions
             SET resolution = ?1,
                 resolved_at = ?2,
                 resolved_by_did = ?3
             WHERE id = ?4",
            dismissed_resolution,
            now_ms,
            req.moderator_did,
            req.pending_id,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(DismissedPendingAction {
            pending_id: req.pending_id,
            resolved_at: rfc3339_from_epoch_ms(now_ms)?,
        })
    }

    async fn heartbeat(&self) -> Result<()> {
        let now_ms = epoch_ms_now();
        sqlx::query!(
            "UPDATE server_instance_lease SET last_heartbeat = ?1
             WHERE id = 1 AND instance_id = ?2",
            now_ms,
            self.instance_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn release_lease(&self) -> Result<()> {
        sqlx::query!(
            "DELETE FROM server_instance_lease WHERE id = 1 AND instance_id = ?1",
            self.instance_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ---------- Lease + key bootstrap ----------

/// Acquire the §F5 single-instance lease.
///
/// Returns the new instance id on success. Returns
/// [`Error::LeaseHeld`] when an existing row's `last_heartbeat` is
/// still within [`LEASE_STALE_MS`] — i.e., another writer is live.
///
/// Exposed as `pub(crate)` so one-shot CLI tools that mutate
/// `audit_log` (`cairn audit-rebuild`, #40) can assert the same
/// "no live writer" invariant the long-running serve process holds.
/// The CLI tool releases via [`release_lease_by_id`] when done.
pub(crate) async fn acquire_lease(pool: &Pool<Sqlite>) -> Result<String> {
    let now_ms = epoch_ms_now();

    let existing =
        sqlx::query!("SELECT instance_id, last_heartbeat FROM server_instance_lease WHERE id = 1")
            .fetch_optional(pool)
            .await?;

    if let Some(row) = existing {
        let age_ms = (now_ms - row.last_heartbeat).max(0);
        if age_ms < LEASE_STALE_MS {
            return Err(Error::LeaseHeld {
                instance_id: row.instance_id,
                age_secs: (age_ms / 1000) as u64,
            });
        }
    }

    let new_id = Uuid::new_v4().to_string();
    // INSERT OR REPLACE on id=1: takes over a stale lease row if present,
    // or creates the row on first startup. Legal because the staleness
    // check above confirms no live peer.
    sqlx::query!(
        "INSERT INTO server_instance_lease (id, instance_id, acquired_at, last_heartbeat)
         VALUES (1, ?1, ?2, ?2)
         ON CONFLICT(id) DO UPDATE SET
             instance_id = excluded.instance_id,
             acquired_at = excluded.acquired_at,
             last_heartbeat = excluded.last_heartbeat",
        new_id,
        now_ms,
    )
    .execute(pool)
    .await?;

    Ok(new_id)
}

/// Release a lease acquired via [`acquire_lease`] by its instance id.
/// Free-function counterpart to [`Writer::release_lease`] for callers
/// that don't own a `Writer` (one-shot CLI tools that just hold the
/// lease for the duration of a data migration).
pub(crate) async fn release_lease_by_id(pool: &Pool<Sqlite>, instance_id: &str) -> Result<()> {
    sqlx::query!(
        "DELETE FROM server_instance_lease WHERE id = 1 AND instance_id = ?1",
        instance_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn ensure_signing_key_row(pool: &Pool<Sqlite>, key: &SigningKey) -> Result<i64> {
    let kp = K256Keypair::from_private_key(key.expose_secret())?;
    let my_multibase = format_multikey("ES256K", &kp.public_key_compressed());

    let existing =
        sqlx::query!("SELECT id, public_key_multibase FROM signing_keys ORDER BY id LIMIT 1")
            .fetch_optional(pool)
            .await?;

    if let Some(row) = existing {
        if row.public_key_multibase != my_multibase {
            return Err(Error::Signing(format!(
                "signing_keys.public_key_multibase ({}) does not match the loaded signing key's derived public key ({}) — key rotation is v1.1 scope",
                row.public_key_multibase, my_multibase
            )));
        }
        return Ok(row.id);
    }

    let now_ms = epoch_ms_now();
    let valid_from = rfc3339_from_epoch_ms(now_ms)?;
    let id = sqlx::query_scalar!(
        "INSERT INTO signing_keys (public_key_multibase, valid_from, valid_to, created_at)
         VALUES (?1, ?2, NULL, ?3)
         RETURNING id",
        my_multibase,
        valid_from,
        now_ms,
    )
    .fetch_one(pool)
    .await?;

    Ok(id)
}

// ---------- Pure helpers (unit-testable without a DB) ----------

async fn reserve_seq(tx: &mut sqlx::SqliteConnection) -> Result<i64> {
    // label_sequence has a single auto-increment column; `DEFAULT VALUES`
    // triggers a fresh allocation. Under AUTOINCREMENT the assigned seq
    // is never reused even across rolled-back transactions — this is what
    // gives us "strictly monotonic, no gaps from writer's perspective."
    let seq = sqlx::query_scalar!("INSERT INTO label_sequence DEFAULT VALUES RETURNING seq")
        .fetch_one(tx)
        .await?;
    Ok(seq)
}

/// §6.1 monotonicity clamp. `prev_cts_str`, when present, is expected to
/// be in the writer's canonical `CTS_FORMAT`.
fn clamp_cts(wall_now_ms: i64, prev_cts_str: Option<&str>) -> Result<String> {
    let effective_ms = match prev_cts_str {
        Some(s) => {
            let prev_ms = parse_rfc3339_ms(s)?;
            wall_now_ms.max(prev_ms + 1)
        }
        None => wall_now_ms,
    };
    rfc3339_from_epoch_ms(effective_ms)
}

/// Epoch-ms → RFC-3339 Z with millisecond precision. `pub(crate)` so
/// peer modules (admin/audit_view, future retention sweep) share the
/// single formatter used on the writer's timestamp boundary.
pub(crate) fn rfc3339_from_epoch_ms(ms: i64) -> Result<String> {
    let nanos: i128 = (ms as i128) * 1_000_000;
    let dt = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|e| Error::Signing(format!("epoch ms {ms} out of range: {e}")))?;
    let formatted = dt
        .format(&CTS_FORMAT)
        .map_err(|e| Error::Signing(format!("format cts: {e}")))?;
    Ok(format!("{formatted}Z"))
}

/// RFC-3339 Z with millisecond precision → epoch-ms. `pub(crate)` so
/// admin handlers can validate `since` / `until` query params against
/// the same parser the writer uses on its input boundary.
pub(crate) fn parse_rfc3339_ms(s: &str) -> Result<i64> {
    let stripped = s
        .strip_suffix('Z')
        .ok_or_else(|| Error::Signing(format!("cts {s:?} missing trailing Z")))?;
    let pdt = PrimitiveDateTime::parse(stripped, &CTS_FORMAT)
        .map_err(|e| Error::Signing(format!("parse cts {s:?}: {e}")))?;
    let nanos = pdt.assume_utc().unix_timestamp_nanos();
    Ok((nanos / 1_000_000) as i64)
}

/// Current wall-clock time as Unix epoch milliseconds. `pub(crate)` so
/// peer modules (server, future retention sweep) share one implementation
/// rather than each inlining `SystemTime::now()` with its own error
/// handling.
pub(crate) fn epoch_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
}

fn build_audit_reason(val: &str, neg: bool, moderator_reason: Option<&str>) -> String {
    let body = serde_json::json!({
        "val": val,
        "neg": neg,
        "moderator_reason": moderator_reason,
    });
    body.to_string()
}

/// `report_resolved` audit reason JSON — see [`AUDIT_REASON_RESOLVE_REPORT`]
/// for the schema.
fn build_resolve_audit_reason(
    applied_label_val: Option<&str>,
    resolution_reason: Option<&str>,
) -> String {
    serde_json::json!({
        "applied_label_val": applied_label_val,
        "resolution_reason": resolution_reason,
    })
    .to_string()
}

/// `retention_sweep` audit reason JSON — see
/// [`AUDIT_REASON_RETENTION_SWEEP`] for the schema. Shared with the
/// retentionSweep admin handler (audited only on the operator-
/// initiated path per Q6/D2).
pub(crate) fn build_retention_sweep_audit_reason(result: &SweepResult) -> String {
    serde_json::json!({
        "rows_deleted": result.rows_deleted,
        "batches": result.batches,
        "duration_ms": result.duration_ms,
        "retention_days_applied": result.retention_days_applied,
    })
    .to_string()
}

/// Audit-log `reason` JSON schema for `subject_action_recorded`
/// (§F20 / #51 graduated-action moderation). Captures the action_id,
/// action_type, primary reason resolved at record time, the full
/// list of declared reasons, the strike value applied, and whether
/// dampening fired — enough for forensic reconstruction without
/// requiring a join to subject_actions.
///
/// ```json
/// {
///   "action_id": <i64>,
///   "action_type": "<warning|note|temp_suspension|indef_suspension|takedown>",
///   "primary_reason": "<identifier>",
///   "reason_codes": ["<id1>", "<id2>"],
///   "strike_value_base": <u32>,
///   "strike_value_applied": <u32>,
///   "was_dampened": <bool>
/// }
/// ```
#[doc(alias = "audit_log.reason.subject_action_recorded")]
pub const AUDIT_REASON_RECORD_ACTION: &str = "subject_action_recorded: { action_id, action_type, primary_reason, reason_codes, strike_value_base, strike_value_applied, was_dampened }";

/// Audit-log `reason` JSON schema for `subject_action_revoked`
/// (§F20 / #51). Captures the revoked subject_actions row id and
/// the moderator-supplied rationale.
///
/// ```json
/// {
///   "action_id": <i64>,
///   "revoked_reason": "<free text>" | null
/// }
/// ```
#[doc(alias = "audit_log.reason.subject_action_revoked")]
pub const AUDIT_REASON_REVOKE_ACTION: &str =
    "subject_action_revoked: { action_id, revoked_reason }";

/// Audit-log `reason` JSON schema for `pending_policy_action_confirmed`
/// (§F22 / #74). Single audit row commits with the
/// pending → confirmed transition: the new subject_actions INSERT,
/// label emission, the `pending_policy_actions` resolution UPDATE,
/// and the strike-state cache UPSERT all hash-chain together.
///
/// ```json
/// {
///   "pending_id": <i64>,
///   "action_id": <i64>,
///   "triggered_by_policy_rule": "<rule name>",
///   "action_type": "<warning|note|temp_suspension|indef_suspension|takedown>",
///   "primary_reason": "<identifier>",
///   "reason_codes": ["<id1>", "<id2>"],
///   "strike_value_base": <u32>,
///   "strike_value_applied": <u32>,
///   "was_dampened": <bool>,
///   "emitted_labels": [{"val": "<v>", "uri": "<u>"}, ...],
///   "moderator_note": "<free text>" | null
/// }
/// ```
#[doc(alias = "audit_log.reason.pending_policy_action_confirmed")]
pub const AUDIT_REASON_CONFIRM_PENDING_ACTION: &str = "pending_policy_action_confirmed: { pending_id, action_id, triggered_by_policy_rule, action_type, primary_reason, reason_codes, strike_value_base, strike_value_applied, was_dampened, emitted_labels, moderator_note }";

/// Audit-log `reason` JSON schema for `pending_policy_action_dismissed`
/// (§F22 / #75 + #76). Single audit row per dismissed pending,
/// hash-chained alongside any other writes in the transaction. No
/// subject_actions row is created and no labels emit on the
/// dismiss side; the dismissed pending stays in the table as
/// forensic record.
///
/// Two shapes share the same audit_log.action value
/// (`pending_policy_action_dismissed`), discriminated by the
/// `triggered_by` field in the reason JSON:
///
/// - `triggered_by = "moderator_dismissed"` (#75): explicit
///   moderator dismissal via `tools.cairn.admin.dismissPendingAction`.
///   Carries the moderator's optional rationale on
///   `moderator_reason`.
///
/// - `triggered_by = "takedown_terminal"` (#76): automatic cascade
///   when a takedown row INSERTs against the subject. Carries
///   `takedown_action_id` cross-referencing the triggering
///   `subject_actions` row; `moderator_reason` is omitted.
///
/// ```json
/// {
///   "pending_id": <i64>,
///   "triggered_by_policy_rule": "<rule name>",
///   "action_type": "<warning|note|temp_suspension|indef_suspension|takedown>",
///   "reason_codes": ["<id1>", "<id2>"],
///   "triggered_by": "moderator_dismissed" | "takedown_terminal",
///   "moderator_reason": "<free text>" | null,   // moderator path only
///   "takedown_action_id": <i64>                 // takedown path only
/// }
/// ```
#[doc(alias = "audit_log.reason.pending_policy_action_dismissed")]
pub const AUDIT_REASON_DISMISS_PENDING_ACTION: &str = "pending_policy_action_dismissed: { pending_id, triggered_by_policy_rule, action_type, reason_codes, triggered_by, moderator_reason | takedown_action_id }";

/// `reporter_flagged` / `reporter_unflagged` audit reason JSON —
/// see [`AUDIT_REASON_FLAG_REPORTER`]. Shared with the flagReporter
/// handler (not the writer — flagReporter is a direct handler txn
/// per the #15 criteria).
pub(crate) fn build_flag_reporter_audit_reason(
    did: &str,
    suppressed: bool,
    moderator_reason: Option<&str>,
) -> String {
    serde_json::json!({
        "did": did,
        "suppressed": suppressed,
        "moderator_reason": moderator_reason,
    })
    .to_string()
}

/// Idempotency guard for the recorder's action-label emission
/// step (#64). Returns `true` when a row already carries an
/// emitted action-label `val`, signalling the emission loop
/// should skip producing a duplicate (src, uri, val) record.
///
/// v1.5's [`Writer::handle_record_action`] always passes `None`
/// here in production (the row was just INSERTed and nothing
/// else has touched it inside the same transaction). The
/// function exists so future paths that operate on existing
/// rows — backfill migrations, retry helpers — can call into
/// the same gate logic, and so the gate's behavior is testable
/// without DB scaffolding.
fn should_skip_action_label_emission(existing_emitted_label_uri: Option<&str>) -> bool {
    existing_emitted_label_uri.is_some()
}

/// Idempotency guard for the recorder's reason-label emission
/// step (#64). Returns `true` when a `subject_action_reason_labels`
/// row already exists for `(action_id, reason_code)`, signalling
/// the per-reason emission loop should skip this draft.
///
/// Same v1.5 production posture as
/// [`should_skip_action_label_emission`]: `existing` is always
/// empty when called from [`Writer::handle_record_action`]; the
/// function is the gate logic future paths can reuse and tests
/// can exercise.
fn should_skip_reason_emission(reason_code: &str, existing: &HashSet<&str>) -> bool {
    existing.contains(reason_code)
}

/// `subject_action_recorded` audit reason JSON — see
/// [`AUDIT_REASON_RECORD_ACTION`] for the schema.
#[allow(clippy::too_many_arguments)]
fn build_record_action_audit_reason(
    action_id: i64,
    action_type: ActionType,
    primary_reason: &str,
    reason_codes: &[String],
    strike_value_base: u32,
    strike_value_applied: u32,
    was_dampened: bool,
    emitted_labels: &[serde_json::Value],
    actor_kind: &str,
    triggered_by_policy_rule: Option<&str>,
    policy_consequence: Option<serde_json::Value>,
) -> String {
    let mut obj = serde_json::json!({
        "action_id": action_id,
        "action_type": action_type.as_db_str(),
        "primary_reason": primary_reason,
        "reason_codes": reason_codes,
        "strike_value_base": strike_value_base,
        "strike_value_applied": strike_value_applied,
        "was_dampened": was_dampened,
        // v1.5 (#60): every emitted label as `{val, uri}`. Empty
        // when [label_emission].enabled = false, when the action
        // type is `note`, or when `warning` with the default
        // suppression gate. Captured pre-INSERT so the audit
        // hash chain locks the entire (action, labels) bundle
        // even though the actual label INSERTs land later in the
        // same tx.
        "emitted_labels": emitted_labels,
        // v1.6 (#73): provenance discriminator for the recorder
        // (moderator vs policy engine). Mirrors
        // subject_actions.actor_kind.
        "actor_kind": actor_kind,
    });
    if let Some(rule_name) = triggered_by_policy_rule {
        obj["triggered_by_policy_rule"] = serde_json::Value::String(rule_name.to_string());
    }
    // v1.6 (#73): when the recorded action crosses a
    // [policy_automation] threshold, the audit row's reason JSON
    // gains a `policy_consequence` field cross-referencing the
    // resulting auto-recorded action OR pending row. Omitted
    // when no rule fires.
    if let Some(pc) = policy_consequence {
        obj["policy_consequence"] = pc;
    }
    obj.to_string()
}

/// `subject_action_revoked` audit reason JSON — see
/// [`AUDIT_REASON_REVOKE_ACTION`] for the schema.
///
/// `negated_labels` mirrors the emission-side `emitted_labels`
/// shape from [`build_record_action_audit_reason`]: an array of
/// `{val, uri}` entries, action label first followed by reason
/// labels in alphabetical order. Empty when the revoked action
/// had no emitted labels (note, suppressed warning, emission
/// disabled at record time, action recorded pre-v1.5).
fn build_revoke_action_audit_reason(
    action_id: i64,
    revoked_reason: Option<&str>,
    negated_labels: &[serde_json::Value],
) -> String {
    serde_json::json!({
        "action_id": action_id,
        "revoked_reason": revoked_reason,
        "negated_labels": negated_labels,
    })
    .to_string()
}

/// `pending_policy_action_confirmed` audit reason JSON — see
/// [`AUDIT_REASON_CONFIRM_PENDING_ACTION`] for the schema. Cross-
/// references the originating pending row (`pending_id`,
/// `triggered_by_policy_rule`) and the materialized action
/// (`action_id`); echoes the moderator's optional `note` so
/// forensic readers can reconstruct the rationale without joining
/// to subject_actions.notes.
#[allow(clippy::too_many_arguments)]
fn build_pending_confirmed_audit_reason(
    pending_id: i64,
    triggered_by_policy_rule: &str,
    action_id: i64,
    action_type: ActionType,
    primary_reason: &str,
    reason_codes: &[String],
    strike_value_base: u32,
    strike_value_applied: u32,
    was_dampened: bool,
    emitted_labels: &[serde_json::Value],
    moderator_note: Option<&str>,
) -> String {
    serde_json::json!({
        "pending_id": pending_id,
        "action_id": action_id,
        "triggered_by_policy_rule": triggered_by_policy_rule,
        "action_type": action_type.as_db_str(),
        "primary_reason": primary_reason,
        "reason_codes": reason_codes,
        "strike_value_base": strike_value_base,
        "strike_value_applied": strike_value_applied,
        "was_dampened": was_dampened,
        "emitted_labels": emitted_labels,
        "moderator_note": moderator_note,
    })
    .to_string()
}

/// `pending_policy_action_dismissed` audit reason JSON for the
/// explicit moderator-dismiss path (#75). Cross-references the
/// originating pending row (`pending_id`, `triggered_by_policy_rule`)
/// and echoes the proposed-action shape so forensic readers can
/// reconstruct "moderator dismissed proposed action X" without
/// joining back to `pending_policy_actions`. The `triggered_by`
/// field discriminates this shape from the takedown-cascade
/// dismissal (#76) — same audit_log.action value
/// (`pending_policy_action_dismissed`), different reason JSON
/// shapes.
///
/// `reason_codes_json` is the parsed JSON value from the pending
/// row's `reason_codes` column (already a JSON array of strings);
/// callers pass [`serde_json::Value::Null`] when the column is
/// somehow unparseable, which preserves the audit row rather
/// than failing the dismissal.
fn build_pending_dismissed_audit_reason(
    pending_id: i64,
    triggered_by_policy_rule: &str,
    action_type: &str,
    reason_codes_json: serde_json::Value,
    moderator_reason: Option<&str>,
) -> String {
    serde_json::json!({
        "pending_id": pending_id,
        "triggered_by_policy_rule": triggered_by_policy_rule,
        "action_type": action_type,
        "reason_codes": reason_codes_json,
        "moderator_reason": moderator_reason,
        "triggered_by": "moderator_dismissed",
    })
    .to_string()
}

/// `pending_policy_action_dismissed` audit reason JSON for the
/// takedown-cascade auto-dismissal path (§F22 / #76). Same
/// audit_log.action value as the explicit moderator dismiss
/// (#75), discriminated via the `triggered_by` field. Cross-
/// references both the originating pending row (`pending_id`,
/// `triggered_by_policy_rule`) and the takedown that caused the
/// cascade (`takedown_action_id`); a forensic reader can walk
/// either direction.
///
/// `reason_codes_json` is the parsed JSON value from the pending
/// row's `reason_codes` column (already a JSON array of strings);
/// callers pass [`serde_json::Value::Null`] when the column is
/// somehow unparseable, which preserves the audit row rather
/// than failing the cascade.
fn build_pending_dismissed_on_takedown_audit_reason(
    pending_id: i64,
    triggered_by_policy_rule: &str,
    action_type: &str,
    reason_codes_json: serde_json::Value,
    takedown_action_id: i64,
) -> String {
    serde_json::json!({
        "pending_id": pending_id,
        "triggered_by_policy_rule": triggered_by_policy_rule,
        "action_type": action_type,
        "reason_codes": reason_codes_json,
        "triggered_by": "takedown_terminal",
        "takedown_action_id": takedown_action_id,
    })
    .to_string()
}

/// Convert epoch-ms (i64) to [`SystemTime`]. The v1.4 calculators
/// take SystemTime; the schema stores epoch-ms; this is the
/// boundary helper. Negative values clamp to UNIX_EPOCH (defense:
/// schema columns are non-negative in practice).
fn epoch_ms_to_systemtime(ms: i64) -> SystemTime {
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        UNIX_EPOCH
    }
}

/// Inverse of [`epoch_ms_to_systemtime`]. Used by the emission
/// path (#60) to translate a [`LabelDraft`]'s `exp: SystemTime`
/// into the i64 ms that [`rfc3339_from_epoch_ms`] formats. Errors
/// when the value pre-dates UNIX_EPOCH — the emission core never
/// produces such a value (caller-supplied `expires_at` is
/// epoch-ms-derived), so this should be unreachable in practice.
fn systemtime_to_epoch_ms(st: SystemTime) -> Result<i64> {
    st.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .map_err(|e| Error::Signing(format!("SystemTime before unix epoch: {e}")))
}

/// Route a subject string into (subject_did, subject_uri) per the
/// recorder's contract. DIDs go to subject_did with no URI; AT-URIs
/// extract the repo DID as subject_did and keep the full URI as
/// subject_uri. Anything else is rejected.
fn route_subject(subject: &str) -> Result<(String, Option<String>)> {
    if let Some(rest) = subject.strip_prefix("at://") {
        let repo = rest.split('/').next().unwrap_or("");
        if repo.is_empty() || !repo.starts_with("did:") {
            return Err(Error::Signing(format!(
                "subject at://-URI must start at://did:.../...; got {subject:?}"
            )));
        }
        Ok((repo.to_string(), Some(subject.to_string())))
    } else if subject.starts_with("did:") && subject.len() > "did:".len() {
        Ok((subject.to_string(), None))
    } else {
        Err(Error::Signing(format!(
            "subject must be a DID (`did:...`) or AT-URI (`at://did:...`); got {subject:?}"
        )))
    }
}

/// Parse a narrow ISO-8601 duration subset into a [`Duration`].
/// Supports `P{n}D` (days), `P{n}W` (weeks), `PT{n}H` (hours),
/// `PT{n}M` (minutes), `PT{n}S` (seconds), and combinations like
/// `P1DT12H`. Years and months are NOT supported — moderation
/// suspensions are bounded enough that day/hour granularity covers
/// real cases without the calendar-arithmetic complexity of Y/M.
///
/// Returns the duration in seconds.
///
/// `pub(crate)` so [`crate::policy::automation`] (#71) can validate
/// `[policy_automation.rules.<name>].duration` at config-load time
/// against the same parser the recorder uses on its input
/// boundary — single source of truth for the supported duration
/// shape across the moderator-recorded path and the policy-engine
/// path.
pub(crate) fn parse_iso8601_duration(s: &str) -> Result<u64> {
    let body = s.strip_prefix('P').ok_or_else(|| {
        Error::Signing(format!(
            "duration {s:?} must start with 'P' (ISO-8601 duration form, e.g. P7D)"
        ))
    })?;
    if body.is_empty() {
        return Err(Error::Signing(format!(
            "duration {s:?} has no components after 'P'"
        )));
    }

    // Split into date part (before T, if any) and time part.
    let (date_part, time_part) = match body.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (body, None),
    };

    let mut total_secs: u64 = 0;
    let mut buf = String::new();
    for c in date_part.chars() {
        if c.is_ascii_digit() {
            buf.push(c);
            continue;
        }
        let n: u64 = buf
            .parse()
            .map_err(|_| Error::Signing(format!("duration {s:?}: malformed numeric run")))?;
        buf.clear();
        let mult = match c {
            'D' => 86_400u64,
            'W' => 7 * 86_400u64,
            'Y' | 'M' => {
                return Err(Error::Signing(format!(
                    "duration {s:?}: years (Y) and months (M, without T prefix) not supported in v1.4"
                )));
            }
            other => {
                return Err(Error::Signing(format!(
                    "duration {s:?}: unknown date-part unit {other:?}"
                )));
            }
        };
        total_secs = total_secs.saturating_add(n.saturating_mul(mult));
    }
    if !buf.is_empty() {
        return Err(Error::Signing(format!(
            "duration {s:?}: trailing digits without unit in date part"
        )));
    }

    if let Some(time_body) = time_part {
        if time_body.is_empty() {
            return Err(Error::Signing(format!(
                "duration {s:?}: 'T' separator with no time components"
            )));
        }
        for c in time_body.chars() {
            if c.is_ascii_digit() {
                buf.push(c);
                continue;
            }
            let n: u64 = buf.parse().map_err(|_| {
                Error::Signing(format!(
                    "duration {s:?}: malformed numeric run in time part"
                ))
            })?;
            buf.clear();
            let mult = match c {
                'H' => 3600u64,
                'M' => 60u64,
                'S' => 1u64,
                other => {
                    return Err(Error::Signing(format!(
                        "duration {s:?}: unknown time-part unit {other:?}"
                    )));
                }
            };
            total_secs = total_secs.saturating_add(n.saturating_mul(mult));
        }
        if !buf.is_empty() {
            return Err(Error::Signing(format!(
                "duration {s:?}: trailing digits without unit in time part"
            )));
        }
    }

    if total_secs == 0 {
        return Err(Error::Signing(format!(
            "duration {s:?}: parsed to zero — must be at least one second"
        )));
    }
    Ok(total_secs)
}

/// Predict the next AUTOINCREMENT id for `subject_actions`. SQLite's
/// AUTOINCREMENT columns are backed by `sqlite_sequence`; the next
/// value is `max(seq, max(rowid)) + 1`. With BEGIN DEFERRED + the
/// writer task being the only in-process appender, the predict
/// step is racy only against external processes — and the ROLLBACK
/// path catches mismatch via the inserted_id check in
/// handle_record_action.
async fn predict_next_subject_action_id(tx: &mut sqlx::Transaction<'_, Sqlite>) -> Result<i64> {
    // sqlite_sequence.seq has no NOT NULL constraint; the type
    // override forces a non-nullable i64 because the column is
    // populated for every AUTOINCREMENT table that has had at
    // least one row inserted (NULL only happens if the row
    // doesn't exist, which fetch_optional handles).
    let row = sqlx::query!(
        r#"SELECT seq AS "seq!: i64" FROM sqlite_sequence WHERE name = 'subject_actions'"#
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|r| r.seq + 1).unwrap_or(1))
}

/// Predict the next AUTOINCREMENT id for `pending_policy_actions`
/// (#73, v1.6). Same posture as
/// [`predict_next_subject_action_id`]: writer task is sole
/// appender; the predict-then-verify dance catches any race.
async fn predict_next_pending_action_id(tx: &mut sqlx::Transaction<'_, Sqlite>) -> Result<i64> {
    let row = sqlx::query!(
        r#"SELECT seq AS "seq!: i64" FROM sqlite_sequence WHERE name = 'pending_policy_actions'"#
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|r| r.seq + 1).unwrap_or(1))
}

/// Load subject_actions rows for a subject, oldest-first, projecting
/// to [`ActionRecord`] for the v1.4 calculators (decay #50,
/// window #51). Filters to the columns the calculators consume —
/// the rest stay in the DB.
async fn load_subject_actions_for_calc(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    subject_did: &str,
) -> Result<Vec<ActionRecord>> {
    let rows = sqlx::query!(
        "SELECT action_type, strike_value_applied, was_dampened,
                effective_at, expires_at, revoked_at
         FROM subject_actions
         WHERE subject_did = ?1
         ORDER BY id ASC",
        subject_did,
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let action_type = ActionType::from_db_str(&r.action_type).ok_or_else(|| {
            Error::Signing(format!(
                "subject_actions row has invalid action_type {:?}",
                r.action_type
            ))
        })?;
        let strike_value_applied = u32::try_from(r.strike_value_applied).map_err(|_| {
            Error::Signing(format!(
                "subject_actions row strike_value_applied {} out of u32 range",
                r.strike_value_applied
            ))
        })?;
        out.push(ActionRecord {
            strike_value_applied,
            effective_at: epoch_ms_to_systemtime(r.effective_at),
            revoked_at: r.revoked_at.map(epoch_ms_to_systemtime),
            action_type,
            expires_at: r.expires_at.map(epoch_ms_to_systemtime),
            was_dampened: r.was_dampened != 0,
        });
    }
    Ok(out)
}

/// Load subject_actions rows for a subject, oldest-first,
/// projecting to [`crate::policy::evaluator::ActionForPolicyEval`]
/// — the policy evaluator (#72) needs `triggered_by_policy_rule`
/// for idempotency detection but the v1.4 calculators don't.
/// Separate loader rather than extending [`ActionRecord`] to keep
/// the calculator-input projection narrow per the §F20 contract.
async fn load_subject_actions_for_policy_eval(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    subject_did: &str,
) -> Result<Vec<crate::policy::evaluator::ActionForPolicyEval>> {
    let rows = sqlx::query!(
        r#"SELECT
             action_type AS "action_type!: String",
             effective_at AS "effective_at!: i64",
             revoked_at,
             triggered_by_policy_rule
           FROM subject_actions
           WHERE subject_did = ?1
           ORDER BY id ASC"#,
        subject_did,
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let action_type = ActionType::from_db_str(&r.action_type).ok_or_else(|| {
            Error::Signing(format!(
                "subject_actions row has invalid action_type {:?}",
                r.action_type
            ))
        })?;
        out.push(crate::policy::evaluator::ActionForPolicyEval {
            effective_at: epoch_ms_to_systemtime(r.effective_at),
            action_type,
            revoked_at: r.revoked_at.map(epoch_ms_to_systemtime),
            triggered_by_policy_rule: r.triggered_by_policy_rule,
        });
    }
    Ok(out)
}

/// Load pending_policy_actions rows for a subject (oldest-first
/// by triggered_at), projecting to
/// [`crate::policy::evaluator::PendingActionForPolicyEval`].
/// Includes resolved rows so the evaluator's idempotency check
/// can distinguish unresolved-vs-confirmed-vs-dismissed per
/// #72's contract.
async fn load_pending_for_policy_eval(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    subject_did: &str,
) -> Result<Vec<crate::policy::evaluator::PendingActionForPolicyEval>> {
    let rows = sqlx::query!(
        r#"SELECT
             triggered_by_policy_rule AS "triggered_by_policy_rule!: String",
             resolution
           FROM pending_policy_actions
           WHERE subject_did = ?1
           ORDER BY triggered_at ASC"#,
        subject_did,
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let resolution = match r.resolution.as_deref() {
            None => None,
            Some("confirmed") => Some(crate::policy::evaluator::PendingResolution::Confirmed),
            Some("dismissed") => Some(crate::policy::evaluator::PendingResolution::Dismissed),
            Some(other) => {
                return Err(Error::Signing(format!(
                    "pending_policy_actions row has invalid resolution {:?}",
                    other
                )));
            }
        };
        out.push(crate::policy::evaluator::PendingActionForPolicyEval {
            triggered_by_policy_rule: r.triggered_by_policy_rule,
            resolution,
        });
    }
    Ok(out)
}

/// Auto-dismiss every unresolved `pending_policy_actions` row for
/// a subject when a takedown lands against them (§F22 / #76). The
/// caller is the takedown's INSERT site (one of three: moderator-
/// recorded via [`Writer::handle_record_action`], policy-auto-
/// recorded via [`Writer::insert_policy_auto_action`], or pending-
/// confirmed via [`Writer::handle_confirm_pending_action`]) — each
/// invokes this helper inside its open transaction so the cascade
/// commits atomically with the takedown.
///
/// For each unresolved pending: append a hash-chained
/// `pending_policy_action_dismissed` audit row (with
/// `triggered_by: "takedown_terminal"` and a `takedown_action_id`
/// back-pointer to the triggering subject_actions row), then
/// UPDATE the pending's resolution columns to 'dismissed'. The
/// audit row is appended BEFORE the UPDATE so a forensic reader
/// cannot observe a dismissed pending without an audit row
/// explaining why.
///
/// Per the chainlink scope (#76):
/// - The pending row's `confirmed_action_id` stays NULL —
///   cascaded dismissals are not "confirmations under another
///   name."
/// - The pending row's `resolved_by_did` is the takedown's
///   actor_did — moderator DID for moderator-recorded /
///   confirm-flow takedowns; the synthetic policy DID for
///   policy-auto-recorded takedowns.
/// - Revoking the takedown later does NOT un-dismiss these
///   cascaded pendings; they stay dismissed as forensic record.
///   If the subject decay-and-recrosses post-revocation, the rule
///   re-fires through normal threshold-crossing logic per #72.
///
/// Returns the ids of dismissed pendings (possibly empty when the
/// subject had no unresolved pendings) so the caller can surface
/// the count in tracing or its own audit context.
async fn auto_dismiss_pendings_on_takedown(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    subject_did: &str,
    subject_uri: Option<&str>,
    triggering_takedown_id: i64,
    actor_did: &str,
    now_ms: i64,
) -> Result<Vec<i64>> {
    let rows = sqlx::query!(
        r#"SELECT
             id                       AS "id!: i64",
             triggered_by_policy_rule AS "triggered_by_policy_rule!: String",
             action_type              AS "action_type!: String",
             reason_codes             AS "reason_codes!: String"
           FROM pending_policy_actions
           WHERE subject_did = ?1 AND resolution IS NULL
           ORDER BY id ASC"#,
        subject_did,
    )
    .fetch_all(&mut **tx)
    .await?;

    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let audit_target = subject_uri
        .map(str::to_string)
        .unwrap_or_else(|| subject_did.to_string());
    let dismissed_resolution = "dismissed";
    let mut dismissed_ids = Vec::with_capacity(rows.len());

    for r in rows {
        let reason_codes_json: serde_json::Value =
            serde_json::from_str(&r.reason_codes).unwrap_or(serde_json::Value::Null);
        let audit_reason = build_pending_dismissed_on_takedown_audit_reason(
            r.id,
            &r.triggered_by_policy_rule,
            &r.action_type,
            reason_codes_json,
            triggering_takedown_id,
        );
        crate::audit::append::append_in_tx(
            tx,
            &crate::audit::append::AuditRowForAppend {
                created_at: now_ms,
                action: "pending_policy_action_dismissed".into(),
                actor_did: actor_did.to_string(),
                target: Some(audit_target.clone()),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await?;

        sqlx::query!(
            "UPDATE pending_policy_actions
             SET resolution = ?1,
                 resolved_at = ?2,
                 resolved_by_did = ?3
             WHERE id = ?4",
            dismissed_resolution,
            now_ms,
            actor_did,
            r.id,
        )
        .execute(&mut **tx)
        .await?;

        dismissed_ids.push(r.id);
    }

    Ok(dismissed_ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1_715_000_000_000 ms since epoch = 2024-05-06T12:53:20.000Z UTC.
    // The four tests below pin every branch of the clamp: no prior,
    // wall-ahead, wall-behind (use prev+1ms), wall-equal (advance anyway).

    #[test]
    fn clamp_cts_uses_wall_clock_when_no_prior() {
        let out = clamp_cts(1_715_000_000_000, None).expect("clamp");
        assert_eq!(out, "2024-05-06T12:53:20.000Z");
    }

    #[test]
    fn clamp_cts_advances_one_ms_past_prior_when_wall_clock_lags() {
        // wall_clock one second behind prev: result is prev + 1ms, not wall.
        let prev = "2024-05-06T12:53:20.500Z";
        let out = clamp_cts(1_715_000_000_000 - 1000, Some(prev)).expect("clamp");
        assert_eq!(out, "2024-05-06T12:53:20.501Z");
    }

    #[test]
    fn clamp_cts_uses_wall_clock_when_ahead_of_prior() {
        let prev = "2024-05-06T12:53:20.500Z";
        let out = clamp_cts(1_715_000_000_000 + 2000, Some(prev)).expect("clamp");
        assert_eq!(out, "2024-05-06T12:53:22.000Z");
    }

    #[test]
    fn clamp_cts_handles_equal_wall_and_prior_by_advancing() {
        // wall_clock == prev exactly: must advance by 1ms (strictly greater).
        let prev = "2024-05-06T12:53:20.500Z";
        let out = clamp_cts(1_715_000_000_500, Some(prev)).expect("clamp");
        assert_eq!(out, "2024-05-06T12:53:20.501Z");
    }

    #[test]
    fn build_audit_reason_shape_matches_documented_schema() {
        let json = build_audit_reason("spam", false, Some("user reported"));
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["val"], "spam");
        assert_eq!(v["neg"], false);
        assert_eq!(v["moderator_reason"], "user reported");
    }

    #[test]
    fn build_audit_reason_null_when_moderator_reason_absent() {
        let json = build_audit_reason("spam", true, None);
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert!(v["moderator_reason"].is_null());
    }

    #[test]
    fn rfc3339_roundtrip() {
        let s = "2026-04-22T12:00:00.938Z";
        let ms = parse_rfc3339_ms(s).expect("parse");
        let back = rfc3339_from_epoch_ms(ms).expect("format");
        assert_eq!(back, s);
    }

    // ---------- route_subject (#51) ----------

    #[test]
    fn route_subject_did_only_returns_did_no_uri() {
        let (did, uri) = route_subject("did:plc:abc123").unwrap();
        assert_eq!(did, "did:plc:abc123");
        assert!(uri.is_none());
    }

    #[test]
    fn route_subject_at_uri_extracts_repo_did_and_keeps_full_uri() {
        let (did, uri) = route_subject("at://did:plc:abc/app.bsky.feed.post/3xx").unwrap();
        assert_eq!(did, "did:plc:abc");
        assert_eq!(
            uri.as_deref(),
            Some("at://did:plc:abc/app.bsky.feed.post/3xx")
        );
    }

    #[test]
    fn route_subject_rejects_at_uri_with_non_did_repo() {
        let err = route_subject("at://handle.example/app.bsky.feed.post/3xx").unwrap_err();
        assert!(matches!(err, Error::Signing(_)));
    }

    #[test]
    fn route_subject_rejects_arbitrary_string() {
        assert!(route_subject("not a subject").is_err());
        assert!(route_subject("did:").is_err());
        assert!(route_subject("").is_err());
    }

    // ---------- parse_iso8601_duration (#51) ----------

    #[test]
    fn duration_p7d_is_seven_days() {
        assert_eq!(parse_iso8601_duration("P7D").unwrap(), 7 * 86_400);
    }

    #[test]
    fn duration_p1w_is_seven_days() {
        assert_eq!(parse_iso8601_duration("P1W").unwrap(), 7 * 86_400);
    }

    #[test]
    fn duration_pt12h_is_twelve_hours() {
        assert_eq!(parse_iso8601_duration("PT12H").unwrap(), 12 * 3600);
    }

    #[test]
    fn duration_pt30m_is_thirty_minutes() {
        assert_eq!(parse_iso8601_duration("PT30M").unwrap(), 30 * 60);
    }

    #[test]
    fn duration_pt45s_is_forty_five_seconds() {
        assert_eq!(parse_iso8601_duration("PT45S").unwrap(), 45);
    }

    #[test]
    fn duration_p1d_t12h_combines() {
        assert_eq!(
            parse_iso8601_duration("P1DT12H").unwrap(),
            86_400 + 12 * 3600
        );
    }

    #[test]
    fn duration_no_p_prefix_rejected() {
        assert!(parse_iso8601_duration("7D").is_err());
        assert!(parse_iso8601_duration("").is_err());
    }

    #[test]
    fn duration_p_alone_rejected() {
        assert!(parse_iso8601_duration("P").is_err());
    }

    #[test]
    fn duration_year_rejected_in_v14() {
        let err = parse_iso8601_duration("P1Y").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not supported"));
    }

    #[test]
    fn duration_unknown_unit_rejected() {
        assert!(parse_iso8601_duration("P5X").is_err());
        assert!(parse_iso8601_duration("PT5X").is_err());
    }

    #[test]
    fn duration_zero_rejected() {
        assert!(parse_iso8601_duration("P0D").is_err());
    }

    #[test]
    fn duration_trailing_digits_without_unit_rejected() {
        assert!(parse_iso8601_duration("P5").is_err());
        assert!(parse_iso8601_duration("PT12").is_err());
    }

    #[test]
    fn duration_t_separator_with_no_time_rejected() {
        assert!(parse_iso8601_duration("P1DT").is_err());
    }

    // ---------- audit reason builders (#51) ----------

    #[test]
    fn record_action_audit_reason_shape() {
        let emitted = vec![
            serde_json::json!({"val": "!hide", "uri": "did:plc:subject0000000000000000"}),
            serde_json::json!({"val": "reason-spam", "uri": "did:plc:subject0000000000000000"}),
        ];
        let json = build_record_action_audit_reason(
            42,
            ActionType::TempSuspension,
            "spam",
            &["spam".to_string(), "harassment".to_string()],
            4,
            2,
            true,
            &emitted,
            "moderator",
            None,
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["action_id"], 42);
        assert_eq!(v["action_type"], "temp_suspension");
        assert_eq!(v["primary_reason"], "spam");
        assert_eq!(v["reason_codes"], serde_json::json!(["spam", "harassment"]));
        assert_eq!(v["strike_value_base"], 4);
        assert_eq!(v["strike_value_applied"], 2);
        assert_eq!(v["was_dampened"], true);
        assert_eq!(v["emitted_labels"][0]["val"], "!hide");
        assert_eq!(v["emitted_labels"][1]["val"], "reason-spam");
        assert_eq!(v["actor_kind"], "moderator");
        assert!(v.get("triggered_by_policy_rule").is_none());
        assert!(v.get("policy_consequence").is_none());
    }

    #[test]
    fn record_action_audit_reason_empty_emitted_labels() {
        let json = build_record_action_audit_reason(
            7,
            ActionType::Note,
            "spam",
            &["spam".to_string()],
            0,
            0,
            false,
            &[],
            "moderator",
            None,
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["emitted_labels"], serde_json::json!([]));
    }

    #[test]
    fn record_action_audit_reason_with_policy_consequence_auto() {
        let pc = serde_json::json!({
            "rule_fired": "warn_at_5",
            "mode": "auto",
            "auto_action_id": 43,
        });
        let json = build_record_action_audit_reason(
            42,
            ActionType::Warning,
            "spam",
            &["spam".to_string()],
            0,
            0,
            false,
            &[],
            "moderator",
            None,
            Some(pc),
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["policy_consequence"]["rule_fired"], "warn_at_5");
        assert_eq!(v["policy_consequence"]["mode"], "auto");
        assert_eq!(v["policy_consequence"]["auto_action_id"], 43);
    }

    #[test]
    fn record_action_audit_reason_for_policy_recorded_action() {
        let json = build_record_action_audit_reason(
            43,
            ActionType::Warning,
            "policy-threshold",
            &["policy-threshold".to_string()],
            0,
            0,
            false,
            &[],
            "policy",
            Some("warn_at_5"),
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["actor_kind"], "policy");
        assert_eq!(v["triggered_by_policy_rule"], "warn_at_5");
    }

    #[test]
    fn revoke_action_audit_reason_with_reason() {
        let json = build_revoke_action_audit_reason(7, Some("appeal granted"), &[]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["action_id"], 7);
        assert_eq!(v["revoked_reason"], "appeal granted");
        assert_eq!(v["negated_labels"], serde_json::json!([]));
    }

    #[test]
    fn revoke_action_audit_reason_without_reason_is_null() {
        let json = build_revoke_action_audit_reason(7, None, &[]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["revoked_reason"].is_null());
    }

    #[test]
    fn revoke_action_audit_reason_with_negated_labels() {
        let labels = vec![
            serde_json::json!({"val": "!takedown", "uri": "did:plc:subject0000000000000000"}),
            serde_json::json!({"val": "reason-spam", "uri": "did:plc:subject0000000000000000"}),
        ];
        let json = build_revoke_action_audit_reason(11, None, &labels);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["negated_labels"][0]["val"], "!takedown");
        assert_eq!(v["negated_labels"][1]["val"], "reason-spam");
    }

    // ---------- emission idempotency guards (#64) ----------

    #[test]
    fn skip_action_label_when_row_already_carries_an_emitted_val() {
        // The defense-in-depth case the guard exists for: an
        // existing emitted_label_uri value means the action label
        // was already produced on the wire; the emission loop
        // must skip to avoid a duplicate (src, uri, val) record.
        assert!(should_skip_action_label_emission(Some("!takedown")));
    }

    #[test]
    fn emit_action_label_when_row_has_no_emitted_val() {
        // v1.5's recordAction always reaches this branch in
        // production (fresh INSERT, NULL column). Pin the
        // happy-path so a future refactor that flips the
        // sense of the check breaks here.
        assert!(!should_skip_action_label_emission(None));
    }

    #[test]
    fn skip_reason_emission_when_already_linked() {
        let existing: HashSet<&str> = ["spam", "harassment"].into_iter().collect();
        assert!(should_skip_reason_emission("spam", &existing));
        assert!(should_skip_reason_emission("harassment", &existing));
    }

    #[test]
    fn emit_reason_when_not_already_linked() {
        let existing: HashSet<&str> = ["spam"].into_iter().collect();
        assert!(!should_skip_reason_emission("hate-speech", &existing));
        // Empty existing set (the v1.5 production case): never skip.
        let empty: HashSet<&str> = HashSet::new();
        assert!(!should_skip_reason_emission("anything", &empty));
    }

    #[test]
    fn reason_emission_skip_check_is_case_sensitive() {
        // Reason codes are operator-vocabulary identifiers from
        // [moderation_reasons] (#47). Case sensitivity matches
        // SQLite's default text comparison and the recorder's
        // primary-reason resolution; pinning here defends
        // against an accidental case-fold in the guard during
        // refactoring.
        let existing: HashSet<&str> = ["SPAM"].into_iter().collect();
        assert!(!should_skip_reason_emission("spam", &existing));
    }
}
