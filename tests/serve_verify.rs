//! Integration tests for `cairn serve`'s startup verify check
//! (#8 — §F1 verify-only).
//!
//! Each test composes:
//!   - The mock PDS fixture from tests/support/mock_pds.rs
//!     (extended in #8 commit 3 with `getRecord` route + the four
//!     scenario flags).
//!   - A real `serve::run` invocation with a Config that has both
//!     `[labeler]` and `[operator]` sections. The `[operator]`
//!     pds_url points at the mock; `[labeler]` matches what the
//!     mock's seeded record contains (or differs, per scenario).
//!
//! Test surface (matches the #8 design proposal):
//!   - serve_starts_when_pds_record_matches
//!   - serve_fails_with_drift_exit_code_when_records_differ
//!   - serve_fails_with_absent_exit_code_when_record_404s
//!   - serve_fails_with_unreachable_exit_code_on_pds_503
//!   - verify_failure_releases_lease — precise: `COUNT(*) FROM
//!     server_instance_lease = 0` (the table is a singleton at
//!     id=1; the assertion catches any regression where verify
//!     fails but writer.shutdown isn't called)

mod support;

use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use cairn_mod::cli::error::{CliError, code};
use cairn_mod::config::{
    BlursToml, Config, LabelValueDefinitionToml, LabelerConfigToml, LocaleToml, SeverityToml,
};
use cairn_mod::service_record;
use cairn_mod::{serve, storage};
use serde_json::json;
use sqlx::{Pool, Sqlite};
use support::mock_pds;
use tempfile::TempDir;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:web:labeler.test";
const OPERATOR_DID: &str = "did:plc:mockoperator0000000000000000";

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

fn sample_labeler_cfg() -> LabelerConfigToml {
    LabelerConfigToml {
        label_values: vec!["spam".into()],
        label_value_definitions: vec![LabelValueDefinitionToml {
            identifier: "spam".into(),
            severity: SeverityToml::Alert,
            blurs: BlursToml::None,
            default_setting: None,
            adult_only: None,
            locales: vec![LocaleToml {
                lang: "en".into(),
                name: "Spam".into(),
                description: "Unsolicited promotional content.".into(),
            }],
        }],
        reason_types: vec![],
        subject_types: vec!["account".into()],
        subject_collections: vec![],
    }
}

/// Build a Config with the [labeler] block and an [operator] block
/// pointing at the mock PDS. This is the verify-eligible shape.
fn build_config(dir: &TempDir, bind_addr: SocketAddr, pds_base: &str) -> Config {
    let db_path = dir.path().join("cairn.db");
    let key_path = write_signing_key(dir);
    let session_path = dir.path().join("operator-session.json");
    let labeler = serde_json::to_value(sample_labeler_cfg()).unwrap();
    serde_json::from_value(json!({
        "service_did": SERVICE_DID,
        "service_endpoint": "https://labeler.test",
        "bind_addr": bind_addr.to_string(),
        "db_path": db_path,
        "signing_key_path": key_path,
        "labeler": labeler,
        "operator": {
            "pds_url": pds_base,
            "session_path": session_path,
        },
    }))
    .expect("config deserializes")
}

/// Render the local labeler config to a wire-shape JSON Value
/// suitable for seeding `mock_pds.state.get_record_value`. Uses
/// the same `service_record::render` path the verify-side uses,
/// so a "matching" seed is structurally identical to what the
/// local config produces.
fn render_record_value(cfg: &LabelerConfigToml, created_at: &str) -> serde_json::Value {
    let record = service_record::render(cfg, created_at).unwrap();
    serde_json::to_value(&record).unwrap()
}

async fn lease_count(pool: &Pool<Sqlite>) -> i64 {
    sqlx::query_scalar!("SELECT COUNT(*) FROM server_instance_lease")
        .fetch_one(pool)
        .await
        .unwrap()
}

// ============ happy path ============

#[tokio::test]
async fn serve_starts_when_pds_record_matches() {
    let dir = tempfile::tempdir().unwrap();
    let pds = mock_pds::spawn(OPERATOR_DID).await;
    let addr = free_port();
    let config = build_config(&dir, addr, &pds.base_url());

    // Seed the mock with the canonical (matching) record.
    let cfg = sample_labeler_cfg();
    let value = render_record_value(&cfg, "2026-04-23T00:00:00.000Z");
    *pds.state.get_record_value.lock().await = Some(value);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let cfg_for_task = config.clone();
    let server = tokio::spawn(async move {
        serve::run(cfg_for_task, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // Wait for serve to actually bind (verify must have passed).
    poll_until_listening(addr).await;
    shutdown_tx.send(()).unwrap();

    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server exits within timeout")
        .expect("server task did not panic");
    assert!(
        result.is_ok(),
        "verify-success path should reach Ok exit; got {result:?}"
    );
}

// ============ drift ============

#[tokio::test]
async fn serve_fails_with_drift_exit_code_when_records_differ() {
    let dir = tempfile::tempdir().unwrap();
    let pds = mock_pds::spawn(OPERATOR_DID).await;
    let addr = free_port();
    let config = build_config(&dir, addr, &pds.base_url());

    // Seed the mock with a record whose label_values differ from
    // the local config — drift trigger.
    let mut drifted = sample_labeler_cfg();
    drifted.label_values = vec!["other".into()];
    drifted.label_value_definitions[0].identifier = "other".into();
    let value = render_record_value(&drifted, "2026-04-23T00:00:00.000Z");
    *pds.state.get_record_value.lock().await = Some(value);

    let result = serve::run(config.clone(), std::future::pending::<()>()).await;
    let err = result.expect_err("drift must fail-start");
    match &err {
        CliError::ServiceRecordDrift { summary, .. } => {
            assert!(
                summary.contains("label values"),
                "drift summary must name the drifted field; got: {summary}"
            );
        }
        other => panic!("expected ServiceRecordDrift, got {other:?}"),
    }
    assert_eq!(err.exit_code(), code::SERVICE_RECORD_DRIFT);

    let pool = storage::open(&config.db_path).await.unwrap();
    assert_eq!(
        lease_count(&pool).await,
        0,
        "lease must be released after verify-induced drift exit"
    );
}

// ============ absent ============

#[tokio::test]
async fn serve_fails_with_absent_exit_code_when_record_404s() {
    let dir = tempfile::tempdir().unwrap();
    let pds = mock_pds::spawn(OPERATOR_DID).await;
    let addr = free_port();
    let config = build_config(&dir, addr, &pds.base_url());

    // No seed → mock returns 404 / RecordNotFound naturally.
    // Don't even need to set the force_get_record_404 flag.

    let result = serve::run(config.clone(), std::future::pending::<()>()).await;
    let err = result.expect_err("absent must fail-start");
    match &err {
        CliError::ServiceRecordAbsent { service_did, .. } => {
            assert_eq!(service_did, SERVICE_DID);
        }
        other => panic!("expected ServiceRecordAbsent, got {other:?}"),
    }
    assert_eq!(err.exit_code(), code::SERVICE_RECORD_ABSENT);

    let pool = storage::open(&config.db_path).await.unwrap();
    assert_eq!(
        lease_count(&pool).await,
        0,
        "lease must be released after verify-induced absent exit"
    );
}

// ============ unreachable ============

#[tokio::test]
async fn serve_fails_with_unreachable_exit_code_on_pds_503() {
    let dir = tempfile::tempdir().unwrap();
    let pds = mock_pds::spawn(OPERATOR_DID).await;
    let addr = free_port();
    let config = build_config(&dir, addr, &pds.base_url());

    // Force a 503 on the next getRecord call. CLI maps non-404
    // non-2xx to UnexpectedStatus → ServiceRecordUnreachable.
    pds.state
        .force_get_record_503
        .store(1, std::sync::atomic::Ordering::SeqCst);

    let result = serve::run(config.clone(), std::future::pending::<()>()).await;
    let err = result.expect_err("503 must fail-start as unreachable");
    assert!(
        matches!(err, CliError::ServiceRecordUnreachable { .. }),
        "expected ServiceRecordUnreachable, got {err:?}"
    );
    assert_eq!(err.exit_code(), code::SERVICE_RECORD_UNREACHABLE);

    let pool = storage::open(&config.db_path).await.unwrap();
    assert_eq!(
        lease_count(&pool).await,
        0,
        "lease must be released after verify-induced unreachable exit"
    );
}

// ============ true-transport unreachable (no mock at all) ============

#[tokio::test]
async fn serve_fails_with_unreachable_exit_code_on_truly_unreachable_pds() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    // Point operator.pds_url at an unbound port. Connect will
    // refuse → PdsError::Network → ServiceRecordUnreachable.
    let unreachable_pds = "http://127.0.0.1:1";
    let config = build_config(&dir, addr, unreachable_pds);

    let result = serve::run(config.clone(), std::future::pending::<()>()).await;
    let err = result.expect_err("unreachable PDS must fail-start");
    assert!(
        matches!(err, CliError::ServiceRecordUnreachable { .. }),
        "expected ServiceRecordUnreachable, got {err:?}"
    );
    assert_eq!(err.exit_code(), code::SERVICE_RECORD_UNREACHABLE);

    let pool = storage::open(&config.db_path).await.unwrap();
    assert_eq!(
        lease_count(&pool).await,
        0,
        "lease must be released even on transport-level verify failure"
    );
}

// ============ helpers ============

async fn poll_until_listening(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("server at {addr} did not become ready within 10s");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
