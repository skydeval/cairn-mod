//! Integration tests for `health_router` — `/health` and `/ready` (#23).
//!
//! These tests construct `health_router` directly against a test-owned
//! pool + writer rather than going through the full `serve::run`
//! lifecycle. Rationale:
//!
//! - /ready's failure paths need controlled DB-state manipulation
//!   (close the pool, DELETE from signing_keys, UPDATE the lease's
//!   last_heartbeat). Owning the pool handle makes each of those a
//!   single SQL statement in the test. Going through serve::run would
//!   mean reaching over a process boundary.
//! - The writer's own heartbeat timer races a "set lease stale"
//!   UPDATE if we don't freeze tokio time; using `tokio::time::pause`
//!   mid-test is cleaner when the test owns the writer directly.
//!
//! Coverage:
//! - /health always 200 while the server responds.
//! - /ready 200 with all-ok body when every check passes.
//! - /ready 503 with checks.database=failed when pool is closed.
//! - /ready 503 with checks.signing_key=failed when signing_keys is
//!   empty.
//! - /ready 503 with checks.label_stream=degraded when
//!   server_instance_lease.last_heartbeat is older than
//!   `LEASE_STALE_MS`.
//! - /health and /ready are reachable without an Authorization header
//!   (implicit: the tests never send one and expect 2xx/5xx, not 401).
//! - Response body shape conforms in both success and failure cases
//!   (typed struct deserialization, not string-contains).
//!
//! Not covered here (deliberate):
//! - Shutdown-signal path. The writer's shutdown flipping is inherently
//!   racy to observe mid-test (the drain window is short, and the
//!   signal isn't externally triggerable from here). The stale-
//!   heartbeat test exercises the same check branch — any regression
//!   in the label_stream logic would surface there.

use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use cairn_mod::signing_key::SigningKey;
use cairn_mod::{health_router, spawn_writer, storage};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const TEST_SERVICE_DID: &str = "did:web:labeler.test";

fn write_signing_key(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("signing-key.hex");
    fs::write(&path, TEST_PRIV_HEX).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn free_port() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// Spin up a minimal test harness: pool + writer + a locally-served
/// `health_router`. Returns everything the caller needs to manipulate
/// DB state and probe the endpoints.
async fn harness(dir: &TempDir) -> (Pool<Sqlite>, SocketAddr, tokio::task::JoinHandle<()>) {
    let db_path = dir.path().join("cairn.db");
    let pool = storage::open(&db_path).await.unwrap();
    let key_path = write_signing_key(dir);
    let key = SigningKey::load_from_file(&key_path).unwrap();
    let writer = spawn_writer(
        pool.clone(),
        key,
        TEST_SERVICE_DID.into(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();
    let router = health_router(pool.clone(), writer);

    let bind_addr = free_port();
    let listener = TcpListener::bind(bind_addr).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    // Give axum a tick to start accepting.
    tokio::task::yield_now().await;
    (pool, addr, server)
}

async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
    let (mut send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "127.0.0.1")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), send.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[derive(Debug, serde::Deserialize)]
struct HealthBody {
    status: String,
    version: String,
}

#[derive(Debug, serde::Deserialize)]
struct ReadyBody {
    status: String,
    version: String,
    checks: ReadyChecks,
}

#[derive(Debug, serde::Deserialize)]
struct ReadyChecks {
    database: String,
    signing_key: String,
    label_stream: String,
}

// ---------- /health ----------

#[tokio::test]
async fn health_returns_200_with_ok_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let (_pool, addr, _server) = harness(&dir).await;

    let (status, body) = http_get(addr, "/health").await;
    assert_eq!(status, 200);

    let parsed: HealthBody = serde_json::from_str(&body).expect("health body parses");
    assert_eq!(parsed.status, "ok");
    assert_eq!(parsed.version, env!("CARGO_PKG_VERSION"));
}

// ---------- /ready happy path ----------

#[tokio::test]
async fn ready_returns_200_and_all_ok_when_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let (_pool, addr, _server) = harness(&dir).await;

    let (status, body) = http_get(addr, "/ready").await;
    assert_eq!(status, 200, "body: {body}");

    let parsed: ReadyBody = serde_json::from_str(&body).expect("ready body parses");
    assert_eq!(parsed.status, "ok");
    assert_eq!(parsed.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(parsed.checks.database, "ok");
    assert_eq!(parsed.checks.signing_key, "ok");
    assert_eq!(parsed.checks.label_stream, "ok");
}

// ---------- /ready failures ----------

#[tokio::test]
async fn ready_returns_503_with_database_failed_when_pool_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, addr, _server) = harness(&dir).await;

    // close() marks the shared pool state as closed; both our handle
    // and the router's clone see subsequent queries error out.
    pool.close().await;

    let (status, body) = http_get(addr, "/ready").await;
    assert_eq!(status, 503, "body: {body}");

    let parsed: ReadyBody = serde_json::from_str(&body).expect("ready body parses on failure");
    assert_eq!(parsed.status, "degraded");
    assert_eq!(parsed.checks.database, "failed");
    // The other checks may be "failed"/"degraded" because they also
    // query the closed pool; assert the shape is preserved rather
    // than spelling each variant.
    assert!(
        matches!(parsed.checks.signing_key.as_str(), "ok" | "failed"),
        "signing_key should be a OkOrFailed variant, got {:?}",
        parsed.checks.signing_key
    );
    assert!(
        matches!(parsed.checks.label_stream.as_str(), "ok" | "degraded"),
        "label_stream should be a OkOrDegraded variant, got {:?}",
        parsed.checks.label_stream
    );
}

#[tokio::test]
async fn ready_returns_503_with_signing_key_failed_when_row_absent() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, addr, _server) = harness(&dir).await;

    // Wipe the signing_keys row the writer bootstrapped. The /ready
    // signing_key check mirrors did_document_router's 503 semantics
    // on this exact state.
    sqlx::query!("DELETE FROM signing_keys")
        .execute(&pool)
        .await
        .unwrap();

    let (status, body) = http_get(addr, "/ready").await;
    assert_eq!(status, 503, "body: {body}");

    let parsed: ReadyBody = serde_json::from_str(&body).expect("ready body parses on failure");
    assert_eq!(parsed.status, "degraded");
    assert_eq!(parsed.checks.signing_key, "failed");
    assert_eq!(parsed.checks.database, "ok", "DB itself is still reachable");
}

#[tokio::test]
async fn ready_returns_503_with_label_stream_degraded_when_heartbeat_stale() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, addr, _server) = harness(&dir).await;

    // Backdate the lease's heartbeat well past LEASE_STALE_MS (60s).
    // Using a value far beyond the threshold leaves no room for the
    // writer's own periodic heartbeat to refresh it between the
    // UPDATE and the probe — we race-proof by picking an absurdly
    // old timestamp so the writer would need a full tick (10s) to
    // restore health.
    let stale_ms = now_ms() - 10 * 60 * 1000; // 10 minutes old
    sqlx::query!(
        "UPDATE server_instance_lease SET last_heartbeat = ?1 WHERE id = 1",
        stale_ms
    )
    .execute(&pool)
    .await
    .unwrap();

    let (status, body) = http_get(addr, "/ready").await;
    assert_eq!(status, 503, "body: {body}");

    let parsed: ReadyBody = serde_json::from_str(&body).expect("ready body parses on failure");
    assert_eq!(parsed.status, "degraded");
    assert_eq!(parsed.checks.label_stream, "degraded");
    assert_eq!(parsed.checks.database, "ok");
    assert_eq!(parsed.checks.signing_key, "ok");
}

// ---------- Body-shape round-trip ----------

#[tokio::test]
async fn ready_body_is_well_formed_json_with_expected_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (_pool, addr, _server) = harness(&dir).await;

    let (_, body) = http_get(addr, "/ready").await;

    // Round-trip through a generic JSON Value too, so a typo in a
    // key name (which would deserialize fine into ReadyBody via the
    // struct layout but fail a direct key check) surfaces here.
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v.get("status").is_some(), "missing status: {body}");
    assert!(v.get("version").is_some(), "missing version: {body}");
    let checks = v.get("checks").expect("missing checks");
    assert!(checks.get("database").is_some(), "missing checks.database");
    assert!(
        checks.get("signing_key").is_some(),
        "missing checks.signing_key"
    );
    assert!(
        checks.get("label_stream").is_some(),
        "missing checks.label_stream"
    );
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
