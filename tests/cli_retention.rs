//! Integration tests for `cairn retention sweep` (#12).
//!
//! Same fixture pattern as tests/cli_audit.rs and
//! tests/cli_report_admin.rs. Covers:
//! - happy-path admin role: sweep returns SweepResponse with the
//!   right shape; an audit_log row is written by the server.
//! - admin-only role gate: a moderator-role session receives 403.
//! - retention-days=None deployment: server omits
//!   `retentionDaysApplied`; CLI deserializes and surfaces the
//!   "no retention cutoff" hint via `format_sweep_human`.

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::cli::error::CliError;
use cairn_mod::cli::retention::{self, SweepInput};
use cairn_mod::cli::session::SessionFile;
use cairn_mod::{AdminConfig, ApplyLabelRequest, admin_router, spawn_writer, storage};
use sqlx::{Pool, Sqlite};
use support::mock_pds::{self, MOCK_APP_PASSWORD, MOCK_HANDLE};
use tempfile::TempDir;
use tokio::net::TcpListener;

const MODERATOR_DID: &str = "did:plc:mockmoderator0000000000000";
const CAIRN_SERVICE_DID: &str = "did:plc:cairntest00000000000000000";

// ---------- harness ----------

struct MapResolver(Mutex<HashMap<String, DidDocument>>);

#[async_trait]
impl DidResolver for MapResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError> {
        self.0
            .lock()
            .unwrap()
            .get(did)
            .cloned()
            .ok_or(ResolveError::BadStatus(404))
    }
}

struct CairnHarness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    addr: SocketAddr,
    writer: cairn_mod::WriterHandle,
}

async fn spawn_cairn_with_retention(retention_days: Option<u32>) -> CairnHarness {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cairn.db");
    let pool = storage::open(&db_path).await.unwrap();

    let did_doc: DidDocument =
        serde_json::from_value(mock_pds::fixture_did_document(MODERATOR_DID)).unwrap();
    let resolver = Arc::new(MapResolver(Mutex::new(
        [(MODERATOR_DID.to_string(), did_doc)].into(),
    )));
    let auth = Arc::new(AuthContext::with_resolver(
        AuthConfig {
            service_did: CAIRN_SERVICE_DID.to_string(),
            ..AuthConfig::default()
        },
        resolver,
    ));

    let writer = spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(
            hex::decode(mock_pds::MOCK_MODERATOR_PRIV_HEX)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        CAIRN_SERVICE_DID.to_string(),
        retention_days,
        cairn_mod::RetentionConfig {
            sweep_enabled: false,
            sweep_run_at_utc_hour: 4,
            sweep_batch_size: 1000,
        },
    )
    .await
    .unwrap();
    let router = admin_router(
        pool.clone(),
        writer.clone(),
        auth,
        AdminConfig {
            label_values: Some(vec!["spam".into()]),
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    CairnHarness {
        _dir: dir,
        pool,
        addr,
        writer,
    }
}

async fn seed_moderator(pool: &Pool<Sqlite>, did: &str, role: &str) {
    sqlx::query!(
        "INSERT INTO moderators (did, role, added_at)
         VALUES (?1, ?2, strftime('%s', 'now') * 1000)",
        did,
        role
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn seeded_session(
    cairn_addr: SocketAddr,
    pds_base: &str,
    session_path: &std::path::Path,
) -> SessionFile {
    cairn_mod::cli::login::login(
        &format!("http://{cairn_addr}"),
        pds_base,
        MOCK_HANDLE,
        MOCK_APP_PASSWORD,
        Some(CAIRN_SERVICE_DID),
        session_path,
    )
    .await
    .expect("login seeds session")
}

// ============ tests ============

#[tokio::test]
async fn sweep_admin_role_returns_response_and_writes_audit() {
    let cairn = spawn_cairn_with_retention(Some(30)).await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "admin").await;

    // Seed labels and backdate so the sweep has work.
    let req = ApplyLabelRequest {
        actor_did: MODERATOR_DID.to_string(),
        uri: "at://did:plc:s000000000000000000000000/app.bsky.feed.post/x".to_string(),
        cid: None,
        val: "spam".to_string(),
        exp: None,
        moderator_reason: Some("seed".to_string()),
    };
    cairn.writer.apply_label(req).await.unwrap();
    let cutoff_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        - 30 * 86_400_000;
    let too_old: i64 = cutoff_ms - 3_600_000;
    sqlx::query!("UPDATE labels SET created_at = ?1", too_old)
        .execute(&cairn.pool)
        .await
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = retention::sweep(&mut session, &path, SweepInput::default())
        .await
        .expect("sweep");
    assert_eq!(resp.rows_deleted, 1);
    assert!(resp.batches >= 1);
    assert_eq!(resp.retention_days_applied, Some(30));

    // Audit row landed (via the admin endpoint, not the writer).
    let n = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n: i64" FROM audit_log
           WHERE action = 'retention_sweep' AND actor_did = ?1"#,
        MODERATOR_DID,
    )
    .fetch_one(&cairn.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn sweep_mod_role_forbidden() {
    let cairn = spawn_cairn_with_retention(Some(30)).await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "mod").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let err = retention::sweep(&mut session, &path, SweepInput::default())
        .await
        .expect_err("mod role must be 403");
    match err {
        CliError::CairnStatus { status, .. } => assert_eq!(status, 403),
        other => panic!("expected CairnStatus 403, got {other:?}"),
    }
}

#[tokio::test]
async fn sweep_with_no_cutoff_returns_zero_and_omits_field() {
    // Server side: retention_days = None → handle_sweep is a no-op
    // and the JSON omits retentionDaysApplied. CLI deserializes
    // OK and `format_sweep_human` surfaces the "no cutoff" note
    // — this is the load-bearing UX guard against silent zero
    // results.
    let cairn = spawn_cairn_with_retention(None).await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "admin").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = retention::sweep(&mut session, &path, SweepInput::default())
        .await
        .expect("sweep");
    assert_eq!(resp.rows_deleted, 0);
    assert!(resp.retention_days_applied.is_none());
    let human = retention::format_sweep_human(&resp);
    assert!(human.contains("no retention cutoff configured"));
}
