//! v1.8.8 stream-consumer integration (v2 §10, chainlink #147):
//! mock-WS Aurora lifecycle — hello seeding, F10
//! persist-before-process, echo suppression, audit-entry
//! mirroring, outdatedCursor → queryEvents reconciliation →
//! cursor-less resubscribe with UNIQUE-absorbed overlap.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use serde_json::json;
use sqlx::{Pool, Sqlite};
use tokio::net::TcpListener;

use cairn_mod::pds_admin::config::{RustBackendConfig, RustStreamConfig};
use cairn_mod::pds_admin::rust::RustBackend;
use cairn_mod::pds_admin::rust::stream::{StreamConsumer, StreamStatus, read_cursor};
use cairn_mod::pds_admin::{BackendActionId, PdsAdminBackend, record_pds_admin_call};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

const TEST_KEY_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";

struct MockState {
    /// WS connection counter — the frame script branches on it.
    connections: AtomicUsize,
}

fn frame(v: serde_json::Value) -> Message {
    Message::Text(v.to_string().into())
}

fn event_frame(seq: i64, id: i64, created_at: &str) -> Message {
    frame(json!({
        "$type": "event",
        "event": {
            "id": id,
            "eventType": "account_takedown",
            "actorDid": "did:plc:upstream-mod",
            "subjectDid": "did:plc:subject",
            "subjectUri": null,
            "subjectCid": null,
            "details": {"rationale": "spam", "action": "TakedownAccount"},
            "createdAt": created_at
        },
        "sequence": seq
    }))
}

async fn ws_handler(
    State(state): State<Arc<MockState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let conn = state.connections.fetch_add(1, Ordering::SeqCst) + 1;
    ws.on_upgrade(move |mut socket| async move {
        if conn == 1 {
            // hello → upstream event → echo event → sentinel audit
            // entry → outdatedCursor → clean close.
            let frames = vec![
                frame(json!({"$type": "hello", "instanceVersion": "0.10.0", "sequence": 10})),
                // Unknown frame type: must be skipped, not fatal.
                frame(json!({"$type": "futureThing", "sequence": 999})),
                event_frame(11, 100, "2026-07-21T10:00:00+00:00"),
                event_frame(12, 101, "2026-07-21T10:00:01+00:00"),
                frame(json!({
                    "$type": "auditEntry",
                    "entry": {
                        "id": "1",
                        "sequence": 1,
                        "timestamp": "2026-07-21T10:00:01+00:00",
                        "actorDid": "did:plc:upstream-mod",
                        "action": "TakedownAccount",
                        "subjectRef": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:subject"},
                        "rationale": "spam",
                        "currentHash": "pre-chain",
                        "previousHash": null,
                        "verified": true,
                        "cascadeSubjects": [],
                        "cascadeSnapshotIds": [],
                        "source": "manual"
                    },
                    "sequence": 1
                })),
                frame(json!({
                    "$type": "outdatedCursor",
                    "oldestAvailableSeq": 50,
                    "message": "cursor is older than the retention window"
                })),
            ];
            for f in frames {
                if socket.send(f).await.is_err() {
                    return;
                }
            }
            let _ = socket
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1000,
                    reason: "outdated cursor".into(),
                })))
                .await;
        } else {
            // Post-reconciliation cursor-less resubscribe: hello
            // re-seeds, then hold the connection open.
            let _ = socket
                .send(frame(
                    json!({"$type": "hello", "instanceVersion": "0.10.0", "sequence": 60}),
                ))
                .await;
            // Keep alive long enough for the test to assert.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    })
}

async fn spawn_mock_aurora() -> (SocketAddr, Arc<MockState>) {
    let state = Arc::new(MockState {
        connections: AtomicUsize::new(0),
    });

    async fn describe() -> impl IntoResponse {
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            json!({
                "families": {"tools.aurora.admin": ["emitEvent"]},
                "extensions": [
                    {"name": "mod-events-emit-v1"},
                    {"name": "moderator-activity-v1"},
                    {"name": "mod-events-stream-v1"}
                ],
                "implementation": "aurora-locus",
                "version": "0.10.0"
            })
            .to_string(),
        )
    }

    async fn query_events() -> impl IntoResponse {
        // Reconciliation page: one overlap item (id 100, already
        // ingested live) + one gap item (id 102). Single page.
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            json!({
                "items": [
                    {
                        "id": 102,
                        "eventType": "account_takedown",
                        "actorDid": "did:plc:upstream-mod",
                        "actorHandle": null,
                        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:gap"},
                        "subjectHandle": null,
                        "details": {"rationale": "gap event", "action": "TakedownAccount"},
                        "createdAt": "2026-07-21T10:00:05+00:00"
                    },
                    {
                        "id": 100,
                        "eventType": "account_takedown",
                        "actorDid": "did:plc:upstream-mod",
                        "actorHandle": null,
                        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:subject"},
                        "subjectHandle": null,
                        "details": {"rationale": "spam", "action": "TakedownAccount"},
                        "createdAt": "2026-07-21T10:00:00+00:00"
                    }
                ],
                "cursor": null
            })
            .to_string(),
        )
    }

    let router = Router::new()
        .route("/xrpc/tools.aurora.describeCapabilities", get(describe))
        .route(
            "/xrpc/tools.aurora.moderator.queryEvents",
            get(query_events),
        )
        .route(
            "/xrpc/tools.aurora.admin.subscribeModEvents",
            get(ws_handler).with_state(state.clone()),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    (addr, state)
}

fn stream_config() -> RustStreamConfig {
    RustStreamConfig {
        enabled: true,
        include_audit_chain: true,
        reconnect_max_backoff: Duration::from_secs(2),
        // Constructed directly (config validation enforces >30s
        // for real deployments; tests need speed).
        silence_timeout: Duration::from_secs(3),
        reconnect_on_normal_close: false,
    }
}

async fn pinned_backend(addr: SocketAddr) -> Arc<RustBackend> {
    let config = RustBackendConfig {
        pds_url: url::Url::parse(&format!("http://{addr}")).unwrap(),
        service_did: "did:web:cairn-mod.example.test".into(),
        service_signing_key_env: "CAIRN_TEST_STREAM_KEY".into(),
        service_did_document_url: None,
        target_service_did: "did:web:aurora.example.test".into(),
        request_timeout: Duration::from_secs(5),
        capability_refresh_interval: Duration::from_secs(3600),
        required_capabilities: Vec::new(),
        pinned_versions: std::collections::BTreeMap::from([(
            "mod-events-stream".to_string(),
            "v1".to_string(),
        )]),
        verification_persist: true,
        stream: stream_config(),
    };
    let backend =
        RustBackend::new_with_key_source(&config, &|_| Ok(TEST_KEY_HEX.to_string())).unwrap();
    backend.probe().await.expect("probe succeeds");
    Arc::new(backend)
}

async fn fresh_pool() -> Pool<Sqlite> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stream-consumer.db");
    let pool = cairn_mod::storage::open(&path).await.unwrap();
    Box::leak(Box::new(dir));
    pool
}

/// Land a local dispatch whose backend_action_id is `event_id` so
/// the echo-suppression join fires for it.
async fn land_local_dispatch(pool: &Pool<Sqlite>, event_id: i64) {
    let action_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO subject_actions (
            subject_did, actor_did, action_type, reason_codes,
            effective_at, strike_value_base, strike_value_applied,
            was_dampened, strikes_at_time_of_action, created_at, actor_kind
         ) VALUES ('did:plc:subject', 'did:plc:self', 'takedown', '["spam"]',
                   1000, 0, 0, 0, 0, 1000, 'moderator')
         RETURNING id"#,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    record_pds_admin_call(
        pool,
        action_id,
        cairn_mod::pds_admin::BackendMethod::TakedownAccount,
        Ok(Some(BackendActionId::PerEvent(event_id.to_string()))),
        None,
        now_ms() - 200,
        now_ms() - 100,
    )
    .await
    .unwrap();
}

/// Poll until `check` passes or ~10s elapse.
async fn wait_for<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..100 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition not reached within 10s");
}

#[tokio::test]
async fn full_lifecycle_echo_suppression_reconciliation_and_reseed() {
    let (addr, mock) = spawn_mock_aurora().await;
    let backend = pinned_backend(addr).await;
    let pool = fresh_pool().await;
    land_local_dispatch(&pool, 101).await;

    let status = Arc::new(StreamStatus::default());
    let consumer = StreamConsumer::new(
        backend.clone() as Arc<dyn PdsAdminBackend>,
        pool.clone(),
        stream_config(),
        status.clone(),
    );
    let handle = tokio::spawn(consumer.run());

    // Reconciliation completed + second connection established.
    wait_for(|| {
        let status = status.clone();
        let mock = &mock.connections;
        let n = mock.load(Ordering::SeqCst);
        let r = status.reconciliations.load(Ordering::SeqCst);
        async move { r >= 1 && n >= 2 }
    })
    .await;
    // Second-connection hello re-seeded the cursor from the tail.
    wait_for(|| {
        let pool = pool.clone();
        async move { read_cursor(&pool, "mod_events").await.map(|c| c.0) == Some(60) }
    })
    .await;

    // Upstream event 100 ingested live; echo 101 suppressed; gap
    // event 102 arrived via reconciliation; overlap 100 deduped.
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT event_id, source FROM upstream_events ORDER BY event_id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![
            (100, "stream".to_string()),
            (102, "reconciliation".to_string()),
        ],
        "echo suppressed, overlap deduped, gap reconciled"
    );
    assert_eq!(status.echoes_suppressed.load(Ordering::SeqCst), 1);

    // Sentinel audit entry mirrored with verified_local = 1 and
    // the chain cursor persisted.
    let (vu, vl): (i64, i64) = sqlx::query_as(
        "SELECT verified_upstream, verified_local FROM upstream_audit_mirror WHERE sequence = 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((vu, vl), (1, 1));
    assert_eq!(
        read_cursor(&pool, "audit_chain").await.map(|c| c.0),
        Some(1)
    );

    // last_created_at cleared with the mod_events row at
    // reconciliation, then re-seeded WITHOUT a timestamp (hello
    // carries none).
    let (_, last) = read_cursor(&pool, "mod_events").await.unwrap();
    assert!(last.is_none());

    handle.abort();
}

#[tokio::test]
async fn f10_cursor_persists_before_failed_ingestion() {
    // Drop the ingestion target: every event ingest fails, but the
    // cursor must already be persisted (persist-BEFORE-process) —
    // the frame is lost by design, not re-deliverable.
    let (addr, _mock) = spawn_mock_aurora().await;
    let backend = pinned_backend(addr).await;
    let pool = fresh_pool().await;
    sqlx::query("DROP TABLE upstream_events")
        .execute(&pool)
        .await
        .unwrap();

    let status = Arc::new(StreamStatus::default());
    let consumer = StreamConsumer::new(
        backend.clone() as Arc<dyn PdsAdminBackend>,
        pool.clone(),
        stream_config(),
        status.clone(),
    );
    let handle = tokio::spawn(consumer.run());

    // End state: both conn-1 events failed ingestion (frames
    // lost — no re-delivery: the cursor advanced BEFORE each
    // ingest attempt) and reconciliation's re-fetch of the same
    // window failed too, yet the consumer progressed all the way
    // to the cursor-less resubscribe whose hello re-seeded the
    // position. At-most-once end to end: nothing ever retried a
    // lost frame.
    wait_for(|| {
        let pool = pool.clone();
        async move { read_cursor(&pool, "mod_events").await.map(|c| c.0) == Some(60) }
    })
    .await;
    assert!(
        status.ingest_failures.load(Ordering::SeqCst) >= 2,
        "both live events should have failed ingestion"
    );
    assert_eq!(status.echoes_suppressed.load(Ordering::SeqCst), 0);

    handle.abort();
}

#[tokio::test]
async fn unpinned_family_parks_dormant_without_wire_traffic() {
    let (addr, mock) = spawn_mock_aurora().await;
    // Advertised but NOT pinned → subscribe refuses → Dormant.
    let config = RustBackendConfig {
        pds_url: url::Url::parse(&format!("http://{addr}")).unwrap(),
        service_did: "did:web:cairn-mod.example.test".into(),
        service_signing_key_env: "CAIRN_TEST_STREAM_KEY2".into(),
        service_did_document_url: None,
        target_service_did: "did:web:aurora.example.test".into(),
        request_timeout: Duration::from_secs(5),
        capability_refresh_interval: Duration::from_secs(3600),
        required_capabilities: Vec::new(),
        pinned_versions: std::collections::BTreeMap::new(),
        verification_persist: true,
        stream: stream_config(),
    };
    let backend = Arc::new(
        RustBackend::new_with_key_source(&config, &|_| Ok(TEST_KEY_HEX.to_string())).unwrap(),
    );
    backend.probe().await.expect("probe succeeds");
    let pool = fresh_pool().await;

    let status = Arc::new(StreamStatus::default());
    let consumer = StreamConsumer::new(
        backend.clone() as Arc<dyn PdsAdminBackend>,
        pool.clone(),
        stream_config(),
        status.clone(),
    );
    let handle = tokio::spawn(consumer.run());
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert_eq!(
        mock.connections.load(Ordering::SeqCst),
        0,
        "no WS connection attempted while unpinned (OperatorOptIn gate)"
    );
    assert!(read_cursor(&pool, "mod_events").await.is_none());
    handle.abort();
}
