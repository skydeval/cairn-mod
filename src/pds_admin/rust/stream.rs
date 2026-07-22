//! Realtime consumer task + reconnect state machine (v1.8.8,
//! v2 §5, chainlink #147).
//!
//! Long-lived tokio task following the capability-refresh
//! pattern (`Weak`-held backend; drop-at-shutdown ends the task)
//! with the writer task's panic-the-process crash policy for
//! genuinely-unreachable states. Cursor persistence follows the
//! F10 discipline: **persist BEFORE processing** — a crash
//! between persist and ingest loses the frame (at-most-once by
//! design); persisting after would regress to at-least-once with
//! duplicate ingestion. Heartbeats and hellos never advance
//! persisted cursors (their `sequence` echoes, not delivers) —
//! except the hello on a cursor-less connect, which SEEDS the
//! position so the first persisted state exists before any event.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::StreamExt as _;
use sqlx::{Pool, Sqlite};

use super::super::backend::{BackendError, PdsAdminBackend};
use super::read_types::{QueryEventsFilter, ReadSubject};
use super::stream_ingest::{IngestSource, RustStreamIngestor, StreamIngestor, classify_origin};
use super::stream_types::{StreamFrame, UpstreamEvent};
use crate::pds_admin::config::RustStreamConfig;

/// Reconciliation page size (shipped `query_events` cap is 100
/// upstream; 50 keeps pages modest).
const RECONCILE_PAGE_LIMIT: u32 = 50;

/// Reconnect backoff floor.
const BACKOFF_FLOOR_MS: u64 = 1_000;

/// Shared operational counters surfaced by `cairn stream status`
/// (in-process; the DB-backed cursor rows survive restarts).
#[derive(Debug, Default)]
pub struct StreamStatus {
    /// Frames received (all types).
    pub frames: AtomicU64,
    /// Events suppressed as local echoes.
    pub echoes_suppressed: AtomicU64,
    /// Ingestion failures (frame lost, at-most-once).
    pub ingest_failures: AtomicU64,
    /// Streamed audit entries failing Path A (verified_local=0).
    pub tampered_entries: AtomicU64,
    /// Completed reconciliation passes.
    pub reconciliations: AtomicU64,
}

/// Cursor row helpers (shared with the CLI).
pub async fn read_cursor(pool: &Pool<Sqlite>, kind: &str) -> Option<(i64, Option<String>)> {
    sqlx::query_as::<_, (i64, Option<String>)>(
        "SELECT position, last_created_at FROM stream_cursors WHERE kind = ?1",
    )
    .bind(kind)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

async fn persist_cursor(
    pool: &Pool<Sqlite>,
    kind: &str,
    position: i64,
    last_created_at: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO stream_cursors (kind, position, last_created_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT (kind) DO UPDATE SET
             position = excluded.position,
             last_created_at = COALESCE(excluded.last_created_at, last_created_at),
             updated_at = datetime('now')",
    )
    .bind(kind)
    .bind(position)
    .bind(last_created_at)
    .execute(pool)
    .await
    .map(|_| ())
}

/// One consumer over one backend. Constructed at server startup
/// when `[pds_admin.rust.stream].enabled = true`; the capability
/// + pin gate is enforced per connection attempt by
/// `subscribe_mod_events` itself (advertisement can change with
/// the background refresh).
pub struct StreamConsumer {
    backend: Arc<dyn PdsAdminBackend>,
    pool: Pool<Sqlite>,
    config: RustStreamConfig,
    ingestor: RustStreamIngestor,
    status: Arc<StreamStatus>,
}

/// Loop directive from one connection's lifetime.
enum Next {
    /// Transient path — reconnect with backoff.
    Backoff,
    /// Healthy frames flowed — reset backoff before reconnect.
    BackoffReset,
    /// outdatedCursor received — reconcile, then reconnect
    /// cursor-less.
    Reconcile,
    /// Auth/role rejection at upgrade — park (operator-actionable;
    /// never hot-loop on Auth).
    HardStop,
    /// Capability unadvertised or unpinned — dormant; retry on the
    /// backoff cap (advertisement can legitimately come and go).
    Dormant,
    /// Clean close with reconnect_on_normal_close = false.
    Stop,
}

impl StreamConsumer {
    /// Construct over shared handles.
    pub fn new(
        backend: Arc<dyn PdsAdminBackend>,
        pool: Pool<Sqlite>,
        config: RustStreamConfig,
        status: Arc<StreamStatus>,
    ) -> Self {
        let ingestor = RustStreamIngestor::new(pool.clone());
        Self {
            backend,
            pool,
            config,
            ingestor,
            status,
        }
    }

    /// Run until Stop/HardStop. Spawn with `tokio::spawn`; the
    /// caller holds the `JoinHandle`.
    pub async fn run(self) {
        let mut backoff_ms = BACKOFF_FLOOR_MS;
        let cap_ms = self.config.reconnect_max_backoff.as_millis() as u64;
        loop {
            let next = self.run_one_connection().await;
            match next {
                Next::BackoffReset => {
                    backoff_ms = BACKOFF_FLOOR_MS;
                }
                Next::Backoff => {}
                Next::Reconcile => {
                    if let Err(e) = self.reconcile().await {
                        tracing::error!(
                            target: "cairn_mod::pds_admin::rust::stream",
                            error = %e,
                            "reconciliation failed; will retry after backoff"
                        );
                    } else {
                        self.status.reconciliations.fetch_add(1, Ordering::Relaxed);
                        backoff_ms = BACKOFF_FLOOR_MS;
                    }
                }
                Next::Dormant => {
                    backoff_ms = cap_ms.max(BACKOFF_FLOOR_MS);
                }
                Next::HardStop => {
                    tracing::error!(
                        target: "cairn_mod::pds_admin::rust::stream",
                        "stream consumer HARD-STOP: upgrade rejected with an auth/role \
                         error; not reconnecting (operator action required — check the \
                         service DID's Aurora-side role grant, then restart)"
                    );
                    return;
                }
                Next::Stop => {
                    tracing::info!(
                        target: "cairn_mod::pds_admin::rust::stream",
                        "stream closed cleanly and reconnect_on_normal_close is off; stopping"
                    );
                    return;
                }
            }
            // ±25% jitter without an RNG dependency: derive from
            // the wall clock's low bits.
            let jitter_span = backoff_ms / 4;
            let jitter = if jitter_span > 0 {
                (crate::writer::epoch_ms_now() as u64) % (jitter_span * 2)
            } else {
                0
            };
            let sleep_ms = backoff_ms + jitter - jitter_span.min(jitter);
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            backoff_ms = (backoff_ms * 2).min(cap_ms.max(BACKOFF_FLOOR_MS));
        }
    }

    /// One connection lifetime: Connecting → (hello) → Connected
    /// frame loop. Hello-wait and every subsequent read share the
    /// `silence_timeout` bound (M-4).
    async fn run_one_connection(&self) -> Next {
        let event_cursor = read_cursor(&self.pool, "mod_events").await.map(|c| c.0);
        let chain_cursor = if self.config.include_audit_chain {
            read_cursor(&self.pool, "audit_chain").await.map(|c| c.0)
        } else {
            None
        };

        let mut frames = match self
            .backend
            .subscribe_mod_events(event_cursor, chain_cursor, self.config.include_audit_chain)
            .await
        {
            Ok(s) => s,
            Err(BackendError::Auth(e)) => {
                tracing::error!(
                    target: "cairn_mod::pds_admin::rust::stream",
                    error = %e, "upgrade auth failure");
                return Next::HardStop;
            }
            Err(BackendError::CapabilityNotAdvertised(cap)) => {
                tracing::info!(
                    target: "cairn_mod::pds_admin::rust::stream",
                    capability = %cap,
                    "stream dormant (capability unadvertised or unpinned)"
                );
                return Next::Dormant;
            }
            Err(e) => {
                tracing::warn!(
                    target: "cairn_mod::pds_admin::rust::stream",
                    error = %e, "stream connect failed");
                return Next::Backoff;
            }
        };

        let mut healthy = false;
        let started_with_cursor = event_cursor.is_some();
        loop {
            let frame = match tokio::time::timeout(self.config.silence_timeout, frames.next()).await
            {
                Err(_) => {
                    tracing::warn!(
                        target: "cairn_mod::pds_admin::rust::stream",
                        "silence timeout ({}s) — treating connection as dead",
                        self.config.silence_timeout.as_secs()
                    );
                    return if healthy {
                        Next::BackoffReset
                    } else {
                        Next::Backoff
                    };
                }
                Ok(None) => {
                    // Stream ended: clean close or post-error drop.
                    return if self.config.reconnect_on_normal_close {
                        if healthy {
                            Next::BackoffReset
                        } else {
                            Next::Backoff
                        }
                    } else if healthy {
                        Next::Stop
                    } else {
                        Next::Backoff
                    };
                }
                Ok(Some(Err(e))) => {
                    tracing::warn!(
                        target: "cairn_mod::pds_admin::rust::stream",
                        error = %e, "transport error");
                    return if healthy {
                        Next::BackoffReset
                    } else {
                        Next::Backoff
                    };
                }
                Ok(Some(Ok(frame))) => frame,
            };
            self.status.frames.fetch_add(1, Ordering::Relaxed);

            match frame {
                StreamFrame::Hello { sequence, .. } => {
                    healthy = true;
                    // Seed the position on cursor-less connects so
                    // persisted state exists before the first
                    // event; never rewind an existing cursor.
                    if !started_with_cursor
                        && let Err(e) =
                            persist_cursor(&self.pool, "mod_events", sequence, None).await
                    {
                        tracing::error!(
                            target: "cairn_mod::pds_admin::rust::stream",
                            error = %e, "hello cursor seed failed");
                    }
                }
                StreamFrame::Heartbeat { .. } => {
                    healthy = true; // feeds the silence timer only
                }
                StreamFrame::Event { event, sequence } => {
                    healthy = true;
                    // F10: persist BEFORE processing.
                    if let Err(e) = persist_cursor(
                        &self.pool,
                        "mod_events",
                        sequence,
                        Some(event.created_at.as_str()),
                    )
                    .await
                    {
                        tracing::error!(
                            target: "cairn_mod::pds_admin::rust::stream",
                            error = %e, "cursor persist failed; dropping connection");
                        return Next::Backoff;
                    }
                    let origin =
                        classify_origin(&self.pool, event.id, crate::writer::epoch_ms_now()).await;
                    if origin == super::stream_ingest::Origin::Local {
                        self.status
                            .echoes_suppressed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    if let Err(e) = self
                        .ingestor
                        .ingest_event(&event, origin, Some(sequence), IngestSource::Stream)
                        .await
                    {
                        self.status.ingest_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            target: "cairn_mod::pds_admin::rust::stream",
                            error = %e,
                            frame = %serde_json::to_string(&event).unwrap_or_default(),
                            "event ingestion failed; frame lost (at-most-once by design)"
                        );
                    }
                }
                StreamFrame::AuditEntry { entry, sequence } => {
                    healthy = true;
                    if let Err(e) = persist_cursor(&self.pool, "audit_chain", sequence, None).await
                    {
                        tracing::error!(
                            target: "cairn_mod::pds_admin::rust::stream",
                            error = %e, "chain cursor persist failed; dropping connection");
                        return Next::Backoff;
                    }
                    if !entry.verified {
                        // Aurora's own recompute disagreeing is
                        // tracked via the mirror columns too.
                        tracing::warn!(
                            target: "cairn_mod::pds_admin::rust::stream",
                            sequence, "upstream reports its own entry unverified");
                    }
                    match self.ingestor.ingest_audit_entry(&entry).await {
                        Ok(()) => {}
                        Err(e) => {
                            self.status.ingest_failures.fetch_add(1, Ordering::Relaxed);
                            tracing::error!(
                                target: "cairn_mod::pds_admin::rust::stream",
                                error = %e, "audit-entry ingestion failed; frame lost");
                        }
                    }
                }
                StreamFrame::OutdatedCursor {
                    oldest_available_seq,
                    message,
                } => {
                    tracing::warn!(
                        target: "cairn_mod::pds_admin::rust::stream",
                        oldest_available_seq,
                        message = %message,
                        "outdated cursor — entering reconciliation"
                    );
                    return Next::Reconcile;
                }
                StreamFrame::Error { code, message } => {
                    tracing::error!(
                        target: "cairn_mod::pds_admin::rust::stream",
                        code = %code, message = %message, "server error frame");
                    // Server drops the socket after this; loop to
                    // observe the end-of-stream and classify there.
                }
            }
        }
    }

    /// Consumer-side reconciliation (v2 §5.5, S-1): page loop over
    /// the shipped `query_events`, per-page ingestion, watermark
    /// advance only after exhaustion. Post-reconciliation the next
    /// connect is cursor-less (the mod_events row is deleted so
    /// the hello re-seeds from the live tail; the overlap is
    /// absorbed by `upstream_events.event_id UNIQUE`).
    async fn reconcile(&self) -> Result<(), BackendError> {
        let last_created_at = read_cursor(&self.pool, "mod_events")
            .await
            .and_then(|(_, t)| t);
        let now_ms = crate::writer::epoch_ms_now();
        if let Some(after) = last_created_at {
            let filter_base = QueryEventsFilter {
                after: Some(after.clone()),
                ..Default::default()
            };
            let mut cursor: Option<String> = None;
            loop {
                let page = self
                    .backend
                    .query_events(
                        filter_base.clone(),
                        cursor.as_deref(),
                        Some(RECONCILE_PAGE_LIMIT),
                    )
                    .await?;
                for item in &page.items {
                    let event = project_event(item);
                    let origin = classify_origin(&self.pool, event.id, now_ms).await;
                    if let Err(e) = self
                        .ingestor
                        .ingest_event(&event, origin, None, IngestSource::Reconciliation)
                        .await
                    {
                        self.status.ingest_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            target: "cairn_mod::pds_admin::rust::stream",
                            error = %e, event_id = event.id, "reconciliation ingest failed");
                    }
                }
                match page.cursor {
                    Some(c) if !page.items.is_empty() => cursor = Some(c),
                    _ => break,
                }
            }
        }
        // Full exhaustion (or nothing ever ingested): resubscribe
        // cursor-less. Deleting the row makes the next hello
        // re-seed from the live tail.
        sqlx::query("DELETE FROM stream_cursors WHERE kind = 'mod_events'")
            .execute(&self.pool)
            .await
            .map_err(|e| BackendError::Transient(format!("cursor reset: {e}")))?;
        Ok(())
    }
}

/// Project a v1.8.3 `EventWithContext` into the flat stream shape
/// (handles dropped, subject union flattened) so reconciliation
/// and live frames ingest through one path.
fn project_event(item: &super::read_types::EventWithContext) -> UpstreamEvent {
    let (subject_did, subject_uri, subject_cid) = match &item.subject {
        Some(ReadSubject::Account { did }) => (Some(did.clone()), None, None),
        Some(ReadSubject::Record { uri, cid }) => (None, Some(uri.clone()), Some(cid.clone())),
        Some(ReadSubject::Blob {
            did,
            cid,
            record_uri,
        }) => (Some(did.clone()), record_uri.clone(), Some(cid.clone())),
        None => (None, None, None),
    };
    UpstreamEvent {
        id: item.id,
        event_type: item.event_type.clone(),
        actor_did: item.actor_did.clone(),
        subject_did,
        subject_uri,
        subject_cid,
        details: item.details.clone(),
        created_at: item.created_at.clone(),
    }
}
