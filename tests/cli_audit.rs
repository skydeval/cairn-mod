//! Integration tests for `cairn audit list` (#6).
//!
//! Same fixture pattern as tests/cli_report_admin.rs (which see
//! for the design notes on the mock_pds + admin_router + MapResolver
//! composition). One test file per CLI sub-area for focused failure
//! reporting; the test binary boundary matches the file boundary.
//!
//! Test surface covers:
//! - happy path: seed rows, list returns them newest-first
//! - filter combinations (actor / action / outcome / since)
//! - admin-only auth contract: a moderator-role session receives
//!   403 (the load-bearing reason this section of the README
//!   spells out the role requirement)
//! - format_* unit tests (pure)

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::cli::audit::{self, AuditEntry, AuditListInput, AuditListResponse};
use cairn_mod::cli::error::CliError;
use cairn_mod::cli::session::SessionFile;
use cairn_mod::{AdminConfig, admin_router, spawn_writer, storage};
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

    let writer = spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(
            hex::decode(mock_pds::MOCK_MODERATOR_PRIV_HEX)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        CAIRN_SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
    )
    .await
    .unwrap();
    let router = admin_router(
        pool.clone(),
        writer,
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
    }
}

// ---------- seeders ----------

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

async fn seed_audit(
    pool: &Pool<Sqlite>,
    created_at: i64,
    action: &str,
    actor: &str,
    outcome: &str,
) -> i64 {
    sqlx::query_scalar!(
        "INSERT INTO audit_log
            (created_at, action, actor_did, outcome, reason)
         VALUES (?1, ?2, ?3, ?4, NULL)
         RETURNING id",
        created_at,
        action,
        actor,
        outcome,
    )
    .fetch_one(pool)
    .await
    .unwrap()
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

// ============ list ============

#[tokio::test]
async fn list_returns_seeded_entries_newest_first() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "admin").await;
    let _id1 = seed_audit(&cairn.pool, 1, "label_applied", "did:plc:m1", "success").await;
    let _id2 = seed_audit(&cairn.pool, 2, "label_negated", "did:plc:m1", "success").await;
    let _id3 = seed_audit(&cairn.pool, 3, "report_resolved", "did:plc:m2", "success").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = audit::list(&mut session, &path, AuditListInput::default())
        .await
        .expect("list");
    assert_eq!(resp.entries.len(), 3);
    // Newest-first ordering: id3 first.
    assert_eq!(resp.entries[0].action, "report_resolved");
    assert_eq!(resp.entries[2].action, "label_applied");
}

#[tokio::test]
async fn list_actor_filter_returns_matching_only() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "admin").await;
    seed_audit(&cairn.pool, 1, "label_applied", "did:plc:m1", "success").await;
    seed_audit(&cairn.pool, 2, "label_applied", "did:plc:m2", "success").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = audit::list(
        &mut session,
        &path,
        AuditListInput {
            actor: Some("did:plc:m1".into()),
            ..AuditListInput::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.entries.len(), 1);
    assert_eq!(resp.entries[0].actor_did, "did:plc:m1");
}

#[tokio::test]
async fn list_action_filter_returns_matching_only() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "admin").await;
    seed_audit(&cairn.pool, 1, "label_applied", "did:plc:m1", "success").await;
    seed_audit(&cairn.pool, 2, "label_negated", "did:plc:m1", "success").await;
    seed_audit(&cairn.pool, 3, "label_applied", "did:plc:m2", "success").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = audit::list(
        &mut session,
        &path,
        AuditListInput {
            action: Some("label_applied".into()),
            ..AuditListInput::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.entries.len(), 2);
    assert!(resp.entries.iter().all(|e| e.action == "label_applied"));
}

#[tokio::test]
async fn list_outcome_filter_returns_matching_only() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "admin").await;
    seed_audit(&cairn.pool, 1, "label_applied", "did:plc:m1", "success").await;
    seed_audit(&cairn.pool, 2, "label_applied", "did:plc:m2", "failure").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = audit::list(
        &mut session,
        &path,
        AuditListInput {
            outcome: Some("failure".into()),
            ..AuditListInput::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.entries.len(), 1);
    assert_eq!(resp.entries[0].outcome, "failure");
}

#[tokio::test]
async fn list_admin_only_moderator_role_receives_403() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    // Seed as moderator (NOT admin) to confirm the admin-only guard.
    seed_moderator(&cairn.pool, MODERATOR_DID, "mod").await;
    seed_audit(&cairn.pool, 1, "label_applied", "did:plc:m1", "success").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let err = audit::list(&mut session, &path, AuditListInput::default())
        .await
        .expect_err("mod role must be 403'd");
    assert!(
        matches!(err, CliError::CairnStatus { status: 403, .. }),
        "expected 403, got {err:?}"
    );
}

// ============ format_* ============

fn fixture() -> AuditListResponse {
    AuditListResponse {
        entries: vec![
            AuditEntry {
                id: 5,
                created_at: "2026-04-23T00:00:00Z".into(),
                action: "label_applied".into(),
                actor_did: "did:plc:moderator".into(),
                target: Some("did:plc:target".into()),
                target_cid: None,
                outcome: "success".into(),
                reason: None,
            },
            AuditEntry {
                id: 4,
                created_at: "2026-04-22T00:00:00Z".into(),
                action: "report_resolved".into(),
                actor_did: "did:plc:moderator".into(),
                target: None,
                target_cid: None,
                outcome: "success".into(),
                reason: Some(r#"{"report_id":42}"#.into()),
            },
        ],
        cursor: Some("c-next".into()),
    }
}

#[test]
fn format_list_human_table_and_cursor() {
    let s = audit::format_list_human(&fixture());
    assert!(s.contains("ID"));
    assert!(s.contains("ACTION"));
    assert!(s.contains("label_applied"));
    assert!(s.contains("next cursor: c-next"), "got: {s}");
}

#[test]
fn format_list_human_empty() {
    let resp = AuditListResponse {
        entries: vec![],
        cursor: None,
    };
    assert_eq!(audit::format_list_human(&resp), "(no audit entries)");
}

#[test]
fn format_list_json_round_trips() {
    let v: serde_json::Value =
        serde_json::from_str(&audit::format_list_json(&fixture())).expect("valid JSON");
    let arr = v["entries"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], 5);
    assert_eq!(arr[0]["action"], "label_applied");
    assert_eq!(arr[1]["reason"], r#"{"report_id":42}"#);
    assert_eq!(v["cursor"], "c-next");
}
