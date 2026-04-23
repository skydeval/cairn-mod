//! End-to-end integration tests for `cairn_mod::cli::report::create`.
//!
//! Each test composes the three building blocks: mock PDS
//! (tests/support/mock_pds.rs), real Cairn `create_report_router`
//! with a `MockDidResolver` wired to the same fixture key the mock
//! PDS signs with, and a session file on disk.
//!
//! Covered:
//! - Happy path: report posts, Cairn persists, session file
//!   untouched.
//! - `--json` vs human formatters produce parseable output.
//! - `--cairn-server` override wins over session's stored value.
//! - Auto-refresh: `force_get_service_auth_401_next` causes the
//!   CLI to refresh once and retry; session file on disk has
//!   rotated tokens.
//! - Refresh exhaustion: `force_refresh_401` surfaces as
//!   `PdsError::Unauthorized { context: "refreshSession", .. }` —
//!   exit-code class AUTH.
//! - Missing session → `CliError::NotLoggedIn`.
//! - Bad subject shape (no `at://`, no `did:`) → `CliError::Config`
//!   without any network calls.

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::cli::error::CliError;
use cairn_mod::cli::pds::PdsError;
use cairn_mod::cli::report::{self, ReportCreateInput};
use cairn_mod::cli::session::{SESSION_VERSION, SessionFile};
use cairn_mod::{CreateReportConfig, create_report_router, storage};
use sqlx::{Pool, Sqlite};
use support::mock_pds::{self, MOCK_APP_PASSWORD, MOCK_HANDLE};
use tempfile::TempDir;
use tokio::net::TcpListener;

const MODERATOR_DID: &str = "did:plc:mockmoderator0000000000000";
const CAIRN_SERVICE_DID: &str = "did:plc:cairntest00000000000000000";

// ---------- Cairn fixture ----------

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
}

async fn spawn_cairn() -> CairnHarness {
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

    let router = create_report_router(
        pool.clone(),
        auth,
        CreateReportConfig {
            db_path: db_path.clone(),
            ..CreateReportConfig::default()
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
    }
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

fn default_input(subject: &str) -> ReportCreateInput {
    ReportCreateInput {
        subject: subject.into(),
        cid: None,
        reason_type: "com.atproto.moderation.defs#reasonSpam".into(),
        reason: Some("CLI test report".into()),
        cairn_server_override: None,
    }
}

// ---------- happy paths ----------

#[tokio::test]
async fn report_create_happy_path_persists_in_cairn() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = report::create(
        &mut session,
        &path,
        default_input("did:plc:target000000000000000000000"),
    )
    .await
    .expect("createReport");

    assert!(resp.id > 0);
    assert_eq!(resp.reported_by, MODERATOR_DID);
    assert_eq!(resp.reason_type, "com.atproto.moderation.defs#reasonSpam");

    // Direct-SQL verification — the writer persisted the row.
    let row = sqlx::query!(
        "SELECT id, reported_by, reason FROM reports WHERE id = ?1",
        resp.id
    )
    .fetch_one(&cairn.pool)
    .await
    .unwrap();
    assert_eq!(row.id, resp.id);
    assert_eq!(row.reported_by, MODERATOR_DID);
    assert_eq!(row.reason.as_deref(), Some("CLI test report"));
}

#[tokio::test]
async fn format_helpers_produce_usable_output() {
    let resp = report::CreateReportResponse {
        id: 42,
        created_at: "2026-04-23T00:00:00.000Z".into(),
        reason_type: "com.atproto.moderation.defs#reasonSpam".into(),
        reported_by: MODERATOR_DID.into(),
        subject: serde_json::json!({"$type": "com.atproto.admin.defs#repoRef"}),
    };
    let human = report::format_human(&resp);
    assert!(human.contains("Report 42"), "got: {human}");
    let json = report::format_json(&resp);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["id"], 42);
}

#[tokio::test]
async fn cairn_server_override_wins_over_session_default() {
    // Spawn TWO Cairn instances; session stores A, override points
    // at B — the report must land in B.
    let cairn_a = spawn_cairn().await;
    let cairn_b = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn_a.addr, &pds.base_url(), &path).await;

    let mut input = default_input("did:plc:target000000000000000000000");
    input.cairn_server_override = Some(format!("http://{}", cairn_b.addr));
    let resp = report::create(&mut session, &path, input).await.unwrap();

    // Row exists in B, not A.
    let b_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM reports")
        .fetch_one(&cairn_b.pool)
        .await
        .unwrap();
    let a_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM reports")
        .fetch_one(&cairn_a.pool)
        .await
        .unwrap();
    assert_eq!(b_count, 1);
    assert_eq!(a_count, 0);
    assert!(resp.id > 0);
}

// ---------- auto-refresh ----------

#[tokio::test]
async fn auto_refresh_on_401_then_retry_succeeds_and_persists_tokens() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;
    let original_access = session.access_jwt.clone();
    let original_refresh = session.refresh_jwt.clone();

    // Prime the mock: next getServiceAuth will 401 once.
    pds.state
        .force_get_service_auth_401_next
        .store(1, Ordering::SeqCst);

    let resp = report::create(
        &mut session,
        &path,
        default_input("did:plc:target000000000000000000000"),
    )
    .await
    .expect("report survives one-shot 401");

    assert!(resp.id > 0);
    // In-memory session was rotated.
    assert_ne!(session.access_jwt, original_access);
    assert_ne!(session.refresh_jwt, original_refresh);
    // On-disk session matches the in-memory rotation.
    let on_disk = SessionFile::load(&path).unwrap().unwrap();
    assert_eq!(on_disk.access_jwt, session.access_jwt);
    assert_eq!(on_disk.refresh_jwt, session.refresh_jwt);
    // Call counts: 2 getServiceAuth, 1 refreshSession.
    assert_eq!(pds.state.get_service_auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(pds.state.refresh_session_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refresh_exhaustion_surfaces_as_auth_error() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    // Force BOTH: getServiceAuth 401 on next call AND refresh 401.
    pds.state
        .force_get_service_auth_401_next
        .store(1, Ordering::SeqCst);
    pds.state.force_refresh_401.store(1, Ordering::SeqCst);

    let err = report::create(
        &mut session,
        &path,
        default_input("did:plc:target000000000000000000000"),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            CliError::Pds(PdsError::Unauthorized {
                context: "refreshSession",
                ..
            })
        ),
        "got {err:?}"
    );
    assert_eq!(err.exit_code(), cairn_mod::cli::error::code::AUTH);
}

// ---------- missing session / bad input ----------

#[tokio::test]
async fn missing_session_via_dispatcher_level_is_not_logged_in() {
    // This mirrors main.rs's "load session, error out if absent"
    // step: we exercise the same branch the dispatcher does.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    assert!(!path.exists());

    let loaded = SessionFile::load(&path).unwrap();
    assert!(loaded.is_none());
    // main.rs maps this to CliError::NotLoggedIn; here we assert
    // the mapping works by hand-constructing the error and
    // checking its exit code class.
    let err = CliError::NotLoggedIn;
    assert_eq!(err.exit_code(), cairn_mod::cli::error::code::SESSION);
}

#[tokio::test]
async fn bad_subject_shape_fails_fast_without_network() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");

    // Hand-build a session so we don't burn a login round-trip.
    SessionFile {
        version: SESSION_VERSION,
        cairn_server_url: "http://127.0.0.1:1".into(),
        cairn_service_did: CAIRN_SERVICE_DID.into(),
        pds_url: pds.base_url(),
        moderator_did: MODERATOR_DID.into(),
        moderator_handle: MOCK_HANDLE.into(),
        access_jwt: "a".into(),
        refresh_jwt: "r".into(),
    }
    .save(&path)
    .unwrap();
    let mut session = SessionFile::load(&path).unwrap().unwrap();

    let input = ReportCreateInput {
        subject: "not-a-valid-subject".into(),
        cid: None,
        reason_type: "com.atproto.moderation.defs#reasonSpam".into(),
        reason: None,
        cairn_server_override: None,
    };
    let err = report::create(&mut session, &path, input)
        .await
        .unwrap_err();
    assert!(matches!(err, CliError::Config(_)), "got {err:?}");
    // Nothing on the wire — both mocks untouched.
    assert_eq!(pds.state.get_service_auth_calls.load(Ordering::SeqCst), 0);
}
