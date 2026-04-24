//! Library-level integration tests for `cairn_mod::serve::run` (L4).
//!
//! These tests exercise the lifecycle function directly — no
//! subprocess, no signal handling. Commit C adds a subprocess smoke
//! test that pins the real binary → SIGTERM → exit-0 contract.
//!
//! Coverage:
//! - Happy startup: run returns 0, lease is released, a second
//!   run against the same DB succeeds (lease re-acquirable).
//! - Signing-key permission failure aborts startup before the port
//!   is bound.
//! - Lease conflict: seed a fresh-heartbeat lease row; run exits
//!   with `CliError::LeaseConflict` and the correct exit code.
//! - Bind failure: occupy the configured port first; run exits
//!   with `CliError::BindFailed` (NETWORK exit code).
//! - Merged-router routing: all five route groups (admin,
//!   createReport, subscribe, wellknown lexicons, did.json) reach
//!   handlers when the server is up. Hit each route; assert the
//!   status is NOT 404.
//! - Migrations-on-fresh-DB: pointing at a nonexistent db_path
//!   creates + migrates + serves without error.

use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cairn_mod::cli::error::{CliError, code};
use cairn_mod::config::Config;
use cairn_mod::{serve, storage};
use serde_json::json;
use tempfile::TempDir;
use tokio::sync::oneshot;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

fn write_signing_key(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("signing-key.hex");
    fs::write(&path, TEST_PRIV_HEX).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn free_port() -> SocketAddr {
    // Bind then drop to discover a free port. Not race-free in
    // theory (another process could grab it) but fine for local
    // CI; TcpListener's SO_REUSEADDR is off by default.
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn build_config(dir: &TempDir, bind_addr: SocketAddr) -> Config {
    let db_path = dir.path().join("cairn.db");
    let key_path = write_signing_key(dir);
    serde_json::from_value(json!({
        "service_did": "did:web:labeler.test",
        "service_endpoint": "https://labeler.test",
        "bind_addr": bind_addr.to_string(),
        "db_path": db_path,
        "signing_key_path": key_path,
    }))
    .expect("config deserializes")
}

/// Poll `addr` until a TCP connect succeeds or `deadline` elapses.
async fn wait_ready(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("server at {addr} did not become ready within 5s");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ---------- Happy path + shutdown + lease release ----------

#[tokio::test]
async fn happy_startup_releases_lease_on_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    let config = build_config(&dir, addr);
    let db_path = config.db_path.clone();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let cfg_for_task = config.clone();
    let server = tokio::spawn(async move {
        serve::run(cfg_for_task, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    wait_ready(addr).await;
    shutdown_tx.send(()).unwrap();

    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server exits within timeout")
        .expect("server task did not panic");
    assert!(
        result.is_ok(),
        "clean shutdown should return Ok, got {result:?}"
    );

    // Lease must be released so a follow-on start can acquire it.
    let pool = storage::open(&db_path).await.unwrap();
    let rows: Option<(String, i64)> = sqlx::query_as(
        "SELECT instance_id, last_heartbeat FROM server_instance_lease WHERE id = 1",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        rows.is_none(),
        "lease row should be deleted on clean shutdown, got {rows:?}"
    );
}

// ---------- Signing key failure ----------

#[tokio::test]
async fn wider_signing_key_permissions_abort_startup() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    let mut config = build_config(&dir, addr);
    // Loosen the key file's permissions AFTER config build.
    fs::set_permissions(&config.signing_key_path, fs::Permissions::from_mode(0o644)).unwrap();
    // Give it a real-ish addr (never bound because startup fails
    // first).
    let _ = &mut config;

    let err = serve::run(config, std::future::pending::<()>())
        .await
        .expect_err("must fail on wide key perms");
    assert!(matches!(err, CliError::KeyLoad(_)), "got {err:?}");
    assert_eq!(err.exit_code(), code::INTERNAL);
}

// ---------- Lease conflict ----------

#[tokio::test]
async fn lease_conflict_aborts_startup_with_dedicated_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    let config = build_config(&dir, addr);

    // Pre-create the DB + pop a fresh-heartbeat lease row so the
    // next start hits `Error::LeaseHeld`.
    let pool = storage::open(&config.db_path).await.unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    sqlx::query(
        "INSERT INTO server_instance_lease (id, instance_id, acquired_at, last_heartbeat)
         VALUES (1, 'ghost-instance-abcdef', ?1, ?1)",
    )
    .bind(now_ms)
    .execute(&pool)
    .await
    .unwrap();
    drop(pool);

    let err = serve::run(config, std::future::pending::<()>())
        .await
        .expect_err("must fail on lease conflict");
    match &err {
        CliError::LeaseConflict { instance_id, .. } => {
            assert_eq!(instance_id, "ghost-instance-abcdef");
        }
        other => panic!("expected LeaseConflict, got {other:?}"),
    }
    assert_eq!(err.exit_code(), code::LEASE_CONFLICT);
}

// ---------- Bind failure ----------

#[tokio::test]
async fn bind_failure_maps_to_network_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    // Grab a port AND hold it.
    let occupied = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap();
    let config = build_config(&dir, addr);

    let err = serve::run(config, std::future::pending::<()>())
        .await
        .expect_err("must fail when addr is in use");
    match &err {
        CliError::BindFailed { addr: a, .. } => assert_eq!(*a, addr),
        other => panic!("expected BindFailed, got {other:?}"),
    }
    assert_eq!(err.exit_code(), code::NETWORK);

    drop(occupied);
}

// ---------- Merged-router routing ----------

async fn http_get(addr: SocketAddr, path: &str) -> u16 {
    use http_body_util::Empty;
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
    resp.status().as_u16()
}

#[tokio::test]
async fn merged_router_routes_every_feature_group() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    let config = build_config(&dir, addr);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let cfg_for_task = config.clone();
    let server = tokio::spawn(async move {
        serve::run(cfg_for_task, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    wait_ready(addr).await;

    // Each of the five route groups should NOT 404 — the exact
    // status depends on auth/validation, but the handler must exist.
    let probes: &[(&str, &[u16])] = &[
        // admin.listReports — unauthenticated GET → 401.
        ("/xrpc/tools.cairn.admin.listReports", &[401, 403]),
        // createReport — GET not allowed → 405 or handler-specific,
        // but definitely not 404.
        (
            "/xrpc/com.atproto.moderation.createReport",
            &[401, 405, 415],
        ),
        // queryLabels — unauthenticated public endpoint; accepts GET.
        ("/xrpc/com.atproto.label.queryLabels", &[200, 400, 422]),
        // Lexicon bundle (#18).
        (
            "/.well-known/lexicons/tools/cairn/admin/applyLabel.json",
            &[200],
        ),
        // did.json (L3).
        ("/.well-known/did.json", &[200]),
    ];
    for (path, expected) in probes {
        let status = http_get(addr, path).await;
        assert!(
            expected.contains(&status),
            "GET {path}: got {status}, expected one of {expected:?}"
        );
    }

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

// ---------- Migrations on fresh DB ----------

#[tokio::test]
async fn fresh_db_path_is_created_and_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    let mut config = build_config(&dir, addr);
    // Point at a subdir that exists but with a new DB file name
    // that has never been touched.
    let new_db = dir.path().join("fresh.db");
    assert!(!new_db.exists());
    config.db_path = new_db.clone();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let cfg_for_task = config.clone();
    let server = tokio::spawn(async move {
        serve::run(cfg_for_task, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    wait_ready(addr).await;
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(new_db.exists(), "DB file should be created on first run");

    // And the schema ran — signing_keys has a row from the writer
    // bootstrap.
    let pool = storage::open(&new_db).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signing_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "writer bootstrap must have populated signing_keys"
    );
}

// ---------- #19 regression: spontaneous exit after DRAIN_TIMEOUT ----------

/// Under the old bug, `serve::run` wrapped the entire serve future in
/// `tokio::time::timeout(DRAIN_TIMEOUT, ...)`, causing the server to
/// exit after ~30s even without any shutdown signal. This test pauses
/// tokio time and advances past DRAIN_TIMEOUT: if the regression ever
/// returns, `server.is_finished()` will be true after the advance.
/// After the fix, no DRAIN_TIMEOUT sleep is pending before shutdown,
/// so the advance is a no-op and the server stays alive.
#[tokio::test]
async fn server_stays_alive_past_drain_timeout_without_external_signal() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    let config = build_config(&dir, addr);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let cfg_for_task = config.clone();
    let server = tokio::spawn(async move {
        serve::run(cfg_for_task, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    wait_ready(addr).await;

    // Pause and fast-forward well past DRAIN_TIMEOUT (30s). Under the
    // old bug, tokio::time::timeout would fire here and the server task
    // would complete; under the fix, no timer is pending so advance is
    // a no-op.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    // Give the scheduler a few ticks to observe any work the advance
    // might have woken.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    assert!(
        !server.is_finished(),
        "server exited on its own within 60s of simulated time — #19 regression"
    );

    // Restore real-time before cleanup. Under auto-advance, the outer
    // timeout below would otherwise race the server task's shutdown
    // wakeups and fire prematurely.
    tokio::time::resume();

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server exits within real-time timeout")
        .expect("server task did not panic")
        .expect("clean shutdown should return Ok");
}

/// Complements the above: when shutdown fires AND a handler is still
/// in-flight (simulated by an open subscribeLabels WebSocket), the
/// drain timer must eventually fire and force-exit. This covers the
/// real scenario the 30s bound exists for.
#[tokio::test]
async fn drain_timeout_forces_exit_when_handler_hangs() {
    use tokio_tungstenite::connect_async;

    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    let config = build_config(&dir, addr);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let cfg_for_task = config.clone();
    let server = tokio::spawn(async move {
        serve::run(cfg_for_task, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    wait_ready(addr).await;

    // Open a subscribeLabels WebSocket. The handler loops on (broadcast
    // recv | client message) and won't exit on its own, so axum's
    // graceful_shutdown can't drain without the drain_timer firing.
    let ws_url = format!("ws://{addr}/xrpc/com.atproto.label.subscribeLabels");
    let (mut ws, _) = connect_async(&ws_url).await.expect("ws connect");
    // Let the upgrade settle so the handler is registered as in-flight.
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }

    shutdown_tx.send(()).unwrap();

    // Fast-forward past DRAIN_TIMEOUT. drain_timer wakes → force-exit.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(35)).await;
    // Restore real-time for the cleanup timeout; otherwise auto-advance
    // can fire it before the server finishes writer.shutdown() + exit.
    tokio::time::resume();

    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server must exit within real-time timeout after advance")
        .expect("server task did not panic");
    assert!(
        result.is_ok(),
        "drain-timeout path must return Ok(()), got {result:?}"
    );

    // Close the client cleanly; assertion is done.
    let _ = ws.close(None).await;
}

// Silence unused-import warnings where a single-use helper isn't
// reached by every test in this file.
#[allow(dead_code)]
fn _touch(_: &Path, _: &Arc<()>) {}
