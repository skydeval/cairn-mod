//! Ingestion sink for subscribeModEvents frames + reconciliation
//! events (v1.8.8, v2 §6, chainlink #147).
//!
//! One entry point shared by live stream frames and
//! reconciliation-fetched events (S-1): idempotency comes from
//! `upstream_events.event_id UNIQUE` (INSERT OR IGNORE), so
//! re-runs after a pre-exhaustion crash and stream/reconciliation
//! overlap are both absorbed. Echo suppression (v2 §6.3) joins the
//! incoming event's id against `pds_admin_audit.backend_action_id`
//! — the bare `PerEvent`/`PerBatch` payload stored via the
//! variant-agnostic `as_str` (v1.8.7 LB-5), which is exactly what
//! makes batch echoes joinable.
//!
//! Cascade-event echoes are ingested by design (R1 S-2): a
//! cairn-mod-approved appeal's cascaded reversal id lands in
//! `cascading_actions_json`, not `backend_action_id`, so the join
//! classifies it `Origin::Upstream`. Cascade rows are identifiable
//! via `details.cascadeOf` + cairn-mod's own actor DID; extending
//! the join to per-frame JSON-array containment is deliberately
//! NOT done. The same fail-open direction covers the
//! audit-insert-failure self-echo edge (R1 M-6): a dispatch whose
//! local audit row never landed echoes back as `Upstream` — one
//! harmless observational row, reconciled via cross-verify.

use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

use super::audit_types::AuroraAuditEntry;
use super::read_types::ReadSubject;
use super::stream_types::{EventVerb, UpstreamEvent, disambiguate_event_verb};
use super::upstream_verify::{UpstreamEntryVerdict, verify_upstream_entry};

/// Echo-suppression lookback bound (24h). Module-top const, not
/// config: the join key is time-independent, but the DB scan
/// shouldn't be — 24h covers dispatch→echo latency (≤5s poll +
/// reconciliation windows) with orders-of-magnitude margin.
pub const LOOKBACK_MS: i64 = 86_400_000;

/// Classification of an incoming event frame (v2 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The event's id matches a recent cairn-mod-dispatched
    /// `backend_action_id` — our own action echoing back.
    /// Acknowledged (cursor advances) but not mirrored: the action
    /// is already first-class in `subject_actions` +
    /// `pds_admin_audit`.
    Local,
    /// Genuinely upstream (or fail-open on a check error).
    Upstream,
}

/// Delivery provenance for the `upstream_events.source` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestSource {
    /// Delivered live on the WebSocket.
    Stream,
    /// Fetched via queryEvents reconciliation.
    Reconciliation,
}

impl IngestSource {
    fn as_db_str(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Reconciliation => "reconciliation",
        }
    }
}

/// Thin local ingestion error — never leaves the consumer task
/// except as logs and `stream status` counters (v2 §6.1); NOT a
/// `BackendError`.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// Database failure during ingestion.
    #[error("ingest db failure: {0}")]
    Db(String),
}

/// Ingestion sink (v2 §6.1). Trait-shaped so tests inject
/// recording sinks and future releases can layer consumers
/// without touching the consumer task. NOT a `PdsAdminBackend`
/// extension — ingestion is local persistence, not dispatch.
#[async_trait]
pub trait StreamIngestor: Send + Sync {
    /// Ingest one event (live frame or reconciliation row).
    /// `stream_seq` is the envelope sequence for live frames,
    /// `None` for reconciliation rows.
    async fn ingest_event(
        &self,
        event: &UpstreamEvent,
        origin: Origin,
        stream_seq: Option<i64>,
        source: IngestSource,
    ) -> Result<(), IngestError>;

    /// Ingest one audit-chain entry frame: independent Path A
    /// re-verification, then mirror.
    async fn ingest_audit_entry(&self, entry: &AuroraAuditEntry) -> Result<(), IngestError>;
}

/// Classify an incoming event against cairn-mod's dispatch ledger
/// (v2 §6.3). Fail-open: a check error logs WARN and classifies
/// `Upstream` — the failure mode of a broken echo check must be a
/// duplicate observational row (harmless, dedup-able), never a
/// silently dropped upstream event.
pub async fn classify_origin(pool: &Pool<Sqlite>, event_id: i64, now_ms: i64) -> Origin {
    let key = event_id.to_string();
    let floor = now_ms - LOOKBACK_MS;
    let found: Result<Option<i64>, sqlx::Error> = sqlx::query_scalar(
        "SELECT id FROM pds_admin_audit
         WHERE backend_action_id = ?1 AND call_completed_at >= ?2
         LIMIT 1",
    )
    .bind(&key)
    .bind(floor)
    .fetch_optional(pool)
    .await;
    match found {
        Ok(Some(_)) => Origin::Local,
        Ok(None) => Origin::Upstream,
        Err(e) => {
            tracing::warn!(
                target: "cairn_mod::pds_admin::rust::stream",
                event_id,
                error = %e,
                "echo-suppression check failed; classifying Upstream (fail-open)"
            );
            Origin::Upstream
        }
    }
}

/// Default ingestor (v2 §6.4): all upstream action events → one
/// `upstream_events` row; `report_review` events additionally
/// annotate matching pending local reports (subject-coordinate
/// match — report ids do not ride the stream, A3); audit entries
/// → Path A verification + `upstream_audit_mirror`.
pub struct RustStreamIngestor {
    pool: Pool<Sqlite>,
}

impl RustStreamIngestor {
    /// Construct over the shared pool. Writes deliberately bypass
    /// the writer task: every table this touches is unchained
    /// advisory state (the `cross_verify_outcomes` precedent),
    /// plus the annotation-only `reports.upstream_resolution`.
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    /// Write-once report annotation (v2 §6.4). Matches pending
    /// local reports by subject coordinates; multiple matches all
    /// annotate (honest: Aurora resolved *a* report about this
    /// subject; the wire doesn't say which). Local `status` stays
    /// operator-owned.
    async fn annotate_reports(
        &self,
        event: &UpstreamEvent,
        resolution: &str,
    ) -> Result<u64, IngestError> {
        let result = sqlx::query(
            "UPDATE reports SET upstream_resolution = ?1
             WHERE status = 'pending'
               AND subject_did = ?2
               AND (subject_uri IS ?3)
               AND upstream_resolution IS NULL",
        )
        .bind(resolution)
        .bind(event.subject_did.as_deref().unwrap_or(""))
        .bind(event.subject_uri.as_deref())
        .execute(&self.pool)
        .await
        .map_err(|e| IngestError::Db(format!("reports annotation: {e}")))?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl StreamIngestor for RustStreamIngestor {
    async fn ingest_event(
        &self,
        event: &UpstreamEvent,
        origin: Origin,
        stream_seq: Option<i64>,
        source: IngestSource,
    ) -> Result<(), IngestError> {
        if origin == Origin::Local {
            // Echo: already first-class locally. Cursor was
            // advanced by the consumer before this call; nothing
            // to mirror.
            return Ok(());
        }

        let details_json = if event.details.is_null() {
            None
        } else {
            Some(event.details.to_string())
        };
        let now_ms = crate::writer::epoch_ms_now();
        sqlx::query(
            "INSERT INTO upstream_events (
                event_id, stream_seq, event_type, actor_did,
                subject_did, subject_uri, subject_cid, details,
                created_at, source, ingested_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(event.id)
        .bind(stream_seq)
        .bind(&event.event_type)
        .bind(&event.actor_did)
        .bind(event.subject_did.as_deref())
        .bind(event.subject_uri.as_deref())
        .bind(event.subject_cid.as_deref())
        .bind(details_json.as_deref())
        .bind(&event.created_at)
        .bind(source.as_db_str())
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| IngestError::Db(format!("upstream_events insert: {e}")))?;

        // Report-resolution annotation: the one write-side
        // coupling (v2 §6.4). Wire-derivable states only (A3).
        if event.event_type == "report_review" {
            match disambiguate_event_verb(event) {
                EventVerb::EmitEvent(kind) if kind == "ResolveReport" => {
                    self.annotate_reports(event, "resolved").await?;
                }
                EventVerb::EmitEvent(kind) if kind == "DismissReport" => {
                    self.annotate_reports(event, "dismissed").await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn ingest_audit_entry(&self, entry: &AuroraAuditEntry) -> Result<(), IngestError> {
        // Independent Path A verification (v1.8.6 pipeline,
        // reused directly — v2 §6.5). Tampered entries are still
        // mirrored (verified_local = 0): the mirror row IS the
        // evidence, the cursor advances (at-most-once holds), and
        // `cairn audit cross-verify` remains the authoritative
        // whole-chain verdict / exit-15 surface.
        let verdict = verify_upstream_entry(entry);
        let verified_local = !matches!(verdict, UpstreamEntryVerdict::Tampered);
        if !verified_local {
            tracing::error!(
                target: "cairn_mod::pds_admin::rust::stream",
                sequence = entry.sequence,
                entry_id = %entry.id,
                "streamed audit entry FAILED independent Path A verification \
                 (audit-divergence signal); mirroring with verified_local = 0"
            );
        }

        let (subject_did, subject_uri, subject_cid) = flatten_subject(entry.subject_ref.as_ref());
        let cascade_subjects = if entry.cascade_subjects.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&entry.cascade_subjects)
                    .map_err(|e| IngestError::Db(format!("cascade serialize: {e}")))?,
            )
        };
        let cascade_snapshot_ids = if entry.cascade_snapshot_ids.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&entry.cascade_snapshot_ids)
                    .map_err(|e| IngestError::Db(format!("cascade ids serialize: {e}")))?,
            )
        };
        let payload = entry.payload.as_ref().map(|p| p.get().to_string());
        let now_ms = crate::writer::epoch_ms_now();

        sqlx::query(
            "INSERT INTO upstream_audit_mirror (
                entry_id, sequence, timestamp, actor_did, action,
                subject_did, subject_uri, subject_cid, rationale,
                snapshot_id, event_id, current_hash, previous_hash,
                cascade_subjects, cascade_snapshot_ids, source,
                payload, verified_upstream, verified_local,
                ingested_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                       ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
             ON CONFLICT (sequence) DO NOTHING",
        )
        .bind(&entry.id)
        .bind(entry.sequence)
        .bind(&entry.timestamp)
        .bind(&entry.actor_did)
        .bind(&entry.action)
        .bind(subject_did)
        .bind(subject_uri)
        .bind(subject_cid)
        .bind(&entry.rationale)
        .bind(entry.snapshot_id.as_deref())
        .bind(entry.event_id.as_deref())
        .bind(&entry.current_hash)
        .bind(entry.previous_hash.as_deref())
        .bind(cascade_subjects.as_deref())
        .bind(cascade_snapshot_ids.as_deref())
        .bind(&entry.source)
        .bind(payload.as_deref())
        .bind(i64::from(entry.verified))
        .bind(i64::from(verified_local))
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| IngestError::Db(format!("upstream_audit_mirror insert: {e}")))?;
        Ok(())
    }
}

/// Flatten the wire subject union into the mirror's nullable
/// columns (Aurora's own from_columns precedence, inverted).
fn flatten_subject(subject: Option<&ReadSubject>) -> (Option<&str>, Option<&str>, Option<&str>) {
    match subject {
        Some(ReadSubject::Account { did }) => (Some(did), None, None),
        Some(ReadSubject::Record { uri, cid }) => (None, Some(uri), Some(cid)),
        Some(ReadSubject::Blob {
            did,
            cid,
            record_uri,
        }) => (Some(did), record_uri.as_deref(), Some(cid)),
        None => (None, None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pds_admin::rust::stream_types::UpstreamEvent;
    use serde_json::json;
    use sqlx::Row as _;

    async fn fresh_pool() -> Pool<Sqlite> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stream-ingest-test.db");
        let pool = crate::storage::open(&path).await.unwrap();
        Box::leak(Box::new(dir));
        pool
    }

    fn event(id: i64, event_type: &str, details: serde_json::Value) -> UpstreamEvent {
        UpstreamEvent {
            id,
            event_type: event_type.to_string(),
            actor_did: "did:plc:mod".to_string(),
            subject_did: Some("did:plc:subject".to_string()),
            subject_uri: None,
            subject_cid: None,
            details,
            created_at: "2026-07-21T00:00:00Z".to_string(),
        }
    }

    async fn upstream_event_count(pool: &Pool<Sqlite>) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM upstream_events")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Land a local dispatch audit row whose backend_action_id is
    /// `event_id` via the production path (subject_actions fixture
    /// + record_pds_admin_call) so classify_origin joins it.
    async fn land_local_dispatch(pool: &Pool<Sqlite>, event_id: i64, completed_at: i64) {
        let action_id: i64 = sqlx::query_scalar(
            r#"INSERT INTO subject_actions (
                subject_did, actor_did, action_type, reason_codes,
                effective_at, strike_value_base, strike_value_applied,
                was_dampened, strikes_at_time_of_action, created_at, actor_kind
             ) VALUES ('did:plc:subject', 'did:plc:mod', 'takedown', '["spam"]',
                       1000, 0, 0, 0, 0, 1000, 'moderator')
             RETURNING id"#,
        )
        .fetch_one(pool)
        .await
        .unwrap();
        crate::pds_admin::record_pds_admin_call(
            pool,
            action_id,
            crate::pds_admin::BackendMethod::TakedownAccount,
            Ok(Some(crate::pds_admin::BackendActionId::PerBatch(
                event_id.to_string(),
            ))),
            None,
            completed_at - 100,
            completed_at,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn echo_suppression_classifies_and_skips_local_dispatches() {
        let pool = fresh_pool().await;
        let now = crate::writer::epoch_ms_now();
        land_local_dispatch(&pool, 42, now - 1_000).await;

        // PerBatch payload joins (variant-agnostic bare storage).
        assert_eq!(classify_origin(&pool, 42, now).await, Origin::Local);
        // Unknown id → Upstream.
        assert_eq!(classify_origin(&pool, 43, now).await, Origin::Upstream);
        // Outside the lookback window → Upstream (bound respected).
        assert_eq!(
            classify_origin(&pool, 42, now + LOOKBACK_MS + 200).await,
            Origin::Upstream
        );

        // Local origin: acknowledged, not mirrored.
        let ingestor = RustStreamIngestor::new(pool.clone());
        ingestor
            .ingest_event(
                &event(42, "account_takedown", json!({"action": "TakedownAccount"})),
                Origin::Local,
                Some(7),
                IngestSource::Stream,
            )
            .await
            .unwrap();
        assert_eq!(upstream_event_count(&pool).await, 0);
    }

    #[tokio::test]
    async fn upstream_event_ingests_once_and_dedups_on_event_id() {
        let pool = fresh_pool().await;
        let ingestor = RustStreamIngestor::new(pool.clone());
        let e = event(100, "account_takedown", json!({"action": "DeleteAccount"}));
        ingestor
            .ingest_event(&e, Origin::Upstream, Some(5), IngestSource::Stream)
            .await
            .unwrap();
        // Reconciliation overlap: same event_id, different source.
        ingestor
            .ingest_event(&e, Origin::Upstream, None, IngestSource::Reconciliation)
            .await
            .unwrap();
        assert_eq!(upstream_event_count(&pool).await, 1);

        let row = sqlx::query(
            "SELECT stream_seq, source, details FROM upstream_events WHERE event_id = 100",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<Option<i64>, _>("stream_seq"), Some(5));
        assert_eq!(row.get::<String, _>("source"), "stream");
        assert!(
            row.get::<Option<String>, _>("details")
                .unwrap()
                .contains("DeleteAccount")
        );
    }

    #[tokio::test]
    async fn cascade_echo_ingests_as_upstream_by_design() {
        // S-2 pin: cascade reversals of cairn-mod-approved appeals
        // classify Upstream (their id is in cascading_actions_json,
        // not backend_action_id) and ingest with the identifying
        // markers queryable.
        let pool = fresh_pool().await;
        let now = crate::writer::epoch_ms_now();
        // Root appeal-resolution event was dispatched locally...
        land_local_dispatch(&pool, 200, now - 1_000).await;
        assert_eq!(classify_origin(&pool, 200, now).await, Origin::Local);
        // ...but the cascade event (id 201) doesn't join.
        assert_eq!(classify_origin(&pool, 201, now).await, Origin::Upstream);

        let ingestor = RustStreamIngestor::new(pool.clone());
        let cascade = event(
            201,
            "account_restore",
            json!({
                "rationale": "cascade from appeal 9 approval",
                "action": "RestoreAccount",
                "cascadeOf": 9
            }),
        );
        ingestor
            .ingest_event(&cascade, Origin::Upstream, Some(8), IngestSource::Stream)
            .await
            .unwrap();
        let details: String =
            sqlx::query_scalar("SELECT details FROM upstream_events WHERE event_id = 201")
                .fetch_one(&pool)
                .await
                .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&details).unwrap();
        assert_eq!(parsed["cascadeOf"], 9);
    }

    #[tokio::test]
    async fn report_review_annotates_matching_pending_reports_write_once() {
        let pool = fresh_pool().await;
        // Two pending reports: one matching subject, one other.
        for did in ["did:plc:subject", "did:plc:other"] {
            sqlx::query(
                "INSERT INTO reports (
                    created_at, reported_by, reason_type, subject_type,
                    subject_did, status
                 ) VALUES ('2026-07-20T00:00:00Z', 'did:plc:reporter',
                           'com.atproto.moderation.defs#reasonSpam', 'account', ?1, 'pending')",
            )
            .bind(did)
            .execute(&pool)
            .await
            .unwrap();
        }

        let ingestor = RustStreamIngestor::new(pool.clone());
        ingestor
            .ingest_event(
                &event(
                    300,
                    "report_review",
                    json!({"rationale": "r", "action": "ResolveReport"}),
                ),
                Origin::Upstream,
                Some(9),
                IngestSource::Stream,
            )
            .await
            .unwrap();

        let annotated: Option<String> = sqlx::query_scalar(
            "SELECT upstream_resolution FROM reports WHERE subject_did = 'did:plc:subject'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(annotated.as_deref(), Some("resolved"));
        let other: Option<String> = sqlx::query_scalar(
            "SELECT upstream_resolution FROM reports WHERE subject_did = 'did:plc:other'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(other.is_none(), "non-matching subject untouched");

        // Write-once: a later DismissReport can't overwrite.
        ingestor
            .ingest_event(
                &event(
                    301,
                    "report_review",
                    json!({"rationale": "r2", "action": "DismissReport"}),
                ),
                Origin::Upstream,
                Some(10),
                IngestSource::Stream,
            )
            .await
            .unwrap();
        let still: Option<String> = sqlx::query_scalar(
            "SELECT upstream_resolution FROM reports WHERE subject_did = 'did:plc:subject'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(still.as_deref(), Some("resolved"));
    }

    fn sentinel_entry(sequence: i64) -> AuroraAuditEntry {
        // PRE_CHAIN_SENTINEL current_hash → Sentinel verdict
        // (verified_local = 1) without needing a real recompute.
        serde_json::from_value(json!({
            "id": sequence.to_string(),
            "sequence": sequence,
            "timestamp": "2026-07-21T00:00:00+00:00",
            "actorDid": "did:plc:m1",
            "action": "TakedownAccount",
            "subjectRef": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:s"},
            "rationale": "spam",
            "currentHash": super::super::upstream_verify::PRE_CHAIN_SENTINEL,
            "previousHash": null,
            "verified": true,
            "cascadeSubjects": [],
            "cascadeSnapshotIds": [],
            "source": "manual"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn audit_entries_mirror_with_dual_verdicts_and_dedup() {
        let pool = fresh_pool().await;
        let ingestor = RustStreamIngestor::new(pool.clone());

        // Sentinel entry → verified_local = 1.
        ingestor
            .ingest_audit_entry(&sentinel_entry(1))
            .await
            .unwrap();
        // Tampered entry (junk hash) → mirrored with
        // verified_local = 0; ingestion does NOT error (cursor
        // advance is the caller's, at-most-once holds).
        let mut tampered = sentinel_entry(2);
        tampered.current_hash = "not-a-real-hash".to_string();
        ingestor.ingest_audit_entry(&tampered).await.unwrap();
        // Reconnect re-delivery of sequence 1 dedups.
        ingestor
            .ingest_audit_entry(&sentinel_entry(1))
            .await
            .unwrap();

        let rows = sqlx::query(
            "SELECT sequence, verified_upstream, verified_local
             FROM upstream_audit_mirror ORDER BY sequence",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<i64, _>("verified_local"), 1);
        assert_eq!(rows[1].get::<i64, _>("verified_local"), 0);
        assert_eq!(rows[1].get::<i64, _>("verified_upstream"), 1);
    }
}
