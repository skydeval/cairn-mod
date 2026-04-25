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
    "report_resolved",
    "reporter_flagged",
    "reporter_unflagged",
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

/// Request to resolve a report (§F12 `resolveReport`). The optional
/// `apply_label` is applied **in the same transaction** as the report
/// status update and both audit rows — §F5 single-writer invariant
/// plus §F12 atomicity requirement documented in the `resolveReport`
/// lexicon.
#[derive(Debug, Clone)]
pub struct ResolveReportRequest {
    /// Moderator DID issuing the resolution. Becomes
    /// `audit_log.actor_did` on both the label-applied (if any) and
    /// report_resolved rows.
    pub actor_did: String,
    /// Primary key of the report being resolved.
    pub report_id: i64,
    /// Optional label to emit atomically with the resolution. When
    /// `None`, the resolution only updates report state + writes
    /// the audit row.
    pub apply_label: Option<ApplyLabelInline>,
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
pub async fn spawn(
    pool: Pool<Sqlite>,
    key: SigningKey,
    service_did: String,
    retention_days: Option<u32>,
    retention: RetentionConfig,
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
        let seq = reserve_seq(tx).await?;
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
        .fetch_one(&mut **tx)
        .await?;

        let cts = clamp_cts(created_at_ms, prev_cts.as_deref())?;

        let mut label = Label {
            ver: 1,
            src: self.service_did.clone(),
            uri: req.uri.clone(),
            cid: req.cid.clone(),
            val: req.val.clone(),
            neg: false,
            cts: cts.clone(),
            exp: req.exp.clone(),
            sig: None,
        };
        label.sig = Some(sign_label(&self.key, &label)?);
        let sig_bytes = label.sig.expect("just set").to_vec();

        let neg_int: i64 = 0;
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

        let audit_reason = build_audit_reason(&req.val, false, req.moderator_reason.as_deref());
        let action = "label_applied";
        let outcome = "success";
        sqlx::query!(
            "INSERT INTO audit_log (created_at, action, actor_did, target, target_cid, outcome, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            created_at_ms,
            action,
            req.actor_did,
            req.uri,
            req.cid,
            outcome,
            audit_reason,
        )
        .execute(&mut **tx)
        .await?;

        Ok(LabelEvent { seq, label })
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
        let action = "label_negated";
        let outcome = "success";
        sqlx::query!(
            "INSERT INTO audit_log (created_at, action, actor_did, target, target_cid, outcome, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            created_at,
            action,
            req.actor_did,
            req.uri,
            cid,
            outcome,
            audit_reason,
        )
        .execute(&mut *tx)
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
                 status             AS "status!: String",
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
        if report.status != "pending" {
            return Err(Error::ReportAlreadyResolved { id: req.report_id });
        }

        let created_at = epoch_ms_now();

        // 2. Optional label-apply BEFORE the report UPDATE so audit
        // row insertion order reflects logical sequence
        // (label_applied, then report_resolved — §G per #15 criteria).
        let label_event = if let Some(apply) = &req.apply_label {
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
        let resolution_label = req.apply_label.as_ref().map(|a| a.val.clone());
        sqlx::query!(
            "UPDATE reports SET
                status = 'resolved',
                resolved_at = ?1,
                resolved_by = ?2,
                resolution_label = ?3,
                resolution_reason = ?4
             WHERE id = ?5",
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
            req.apply_label.as_ref().map(|a| a.val.as_str()),
            req.resolution_reason.as_deref(),
        );
        let report_id_str = req.report_id.to_string();
        let action = "report_resolved";
        let outcome = "success";
        sqlx::query!(
            "INSERT INTO audit_log (created_at, action, actor_did, target, target_cid, outcome, reason)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)",
            created_at,
            action,
            req.actor_did,
            report_id_str,
            outcome,
            audit_reason,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // 5. Broadcast (post-commit, per §F5 broadcast-after-commit rule).
        if let Some(event) = &label_event {
            let _ = self.broadcast_tx.send(event.clone());
        }

        // 6. Mutate the loaded report struct to reflect the committed
        // state and return it. Avoids a re-fetch round-trip since we
        // know exactly what changed.
        report.status = "resolved".to_string();
        report.resolved_at = Some(resolved_at_rfc);
        report.resolved_by = Some(req.actor_did);
        report.resolution_label = resolution_label;
        report.resolution_reason = req.resolution_reason;

        Ok(ResolvedReport {
            report,
            label_event,
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

async fn acquire_lease(pool: &Pool<Sqlite>) -> Result<String> {
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
}
