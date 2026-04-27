//! Integration tests for `cairn report {list, view, resolve, flag,
//! unflag}` (#7).
//!
//! Pattern composes the existing `tests/support/mock_pds` fixture
//! (signs `getServiceAuth` JWTs against a known key) with a real
//! Cairn `admin_router` mounted on a tempdir-scoped pool. The
//! moderator DID is wired through a `MapResolver` so the admin
//! handlers' JWT verification can resolve it to the matching pub
//! key.
//!
//! Each subcommand is exercised end-to-end (CLI orchestrator → real
//! Cairn HTTP endpoint → DB state). Pure `format_*` formatters are
//! tested with synthetic typed responses so output-shape regressions
//! land in tight unit tests.
//!
//! Bundled into one test binary because the fixture is shared:
//! splitting per subcommand would re-spin the mock stack five times
//! per `cargo test` run for marginal organizational benefit.

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::cli::error::CliError;
use cairn_mod::cli::report::{
    self, ApplyLabelArg, ReportDetail, ReportFlagInput, ReportFlagResponse, ReportListEntry,
    ReportListInput, ReportListResponse, ReportResolveInput, ReportSubject, ReportViewInput,
};
use cairn_mod::cli::session::SessionFile;
use cairn_mod::{AdminConfig, admin_router, spawn_writer, storage};
use sqlx::{Pool, Sqlite};
use support::mock_pds::{self, MOCK_APP_PASSWORD, MOCK_HANDLE};
use tempfile::TempDir;
use tokio::net::TcpListener;

const MODERATOR_DID: &str = "did:plc:mockmoderator0000000000000";
const CAIRN_SERVICE_DID: &str = "did:plc:cairntest00000000000000000";

// ---------- DID resolver ----------

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

// ---------- Cairn admin harness ----------

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
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();

    // Allowlist used by resolveReport's apply-label validation.
    // Includes "spam" so the with-label test can apply it.
    let admin_cfg = AdminConfig {
        label_values: Some(vec!["spam".into()]),
        ..Default::default()
    };
    let router = admin_router(
        pool.clone(),
        writer,
        auth,
        admin_cfg,
        cairn_mod::StrikePolicy::defaults(),
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

// ---------- Seeders ----------

async fn seed_moderator_admin(pool: &Pool<Sqlite>, did: &str) {
    sqlx::query!(
        "INSERT INTO moderators (did, role, added_at)
         VALUES (?1, 'admin', strftime('%s', 'now') * 1000)",
        did
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_report(
    pool: &Pool<Sqlite>,
    reported_by: &str,
    reason: Option<&str>,
    status: &str,
) -> i64 {
    let created_at = "2026-04-23T00:00:00.000Z";
    let reason_type = "com.atproto.moderation.defs#reasonSpam";
    let subject_type = "account";
    let subject_did = "did:plc:target0000000000000000000";
    sqlx::query_scalar!(
        "INSERT INTO reports
             (created_at, reported_by, reason_type, reason,
              subject_type, subject_did, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         RETURNING id",
        created_at,
        reported_by,
        reason_type,
        reason,
        subject_type,
        subject_did,
        status,
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
async fn list_returns_seeded_reports() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;
    let _id1 = seed_report(&cairn.pool, "did:plc:r1", Some("body1"), "pending").await;
    let _id2 = seed_report(&cairn.pool, "did:plc:r2", Some("body2"), "pending").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = report::list(
        &mut session,
        &path,
        ReportListInput {
            status: None,
            reported_by: None,
            limit: None,
            cursor: None,
            cairn_server_override: None,
        },
    )
    .await
    .expect("list");

    assert_eq!(resp.reports.len(), 2);
    // Reason field MUST be absent in list responses (§F11). Since
    // ReportListEntry has no `reason` field at all, this is enforced
    // structurally — the assertion below is belt-and-suspenders.
    let json = report::format_list_json(&resp);
    assert!(
        !json.contains("body1"),
        "list output must not include reason bodies; got {json}"
    );
}

#[tokio::test]
async fn list_status_filter_works() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;
    let _ = seed_report(&cairn.pool, "did:plc:r1", None, "pending").await;
    let _ = seed_report(&cairn.pool, "did:plc:r2", None, "resolved").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = report::list(
        &mut session,
        &path,
        ReportListInput {
            status: Some("pending".into()),
            reported_by: None,
            limit: None,
            cursor: None,
            cairn_server_override: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.reports.len(), 1);
    assert_eq!(resp.reports[0].status, "pending");
}

// ============ view ============

#[tokio::test]
async fn view_returns_full_body() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;
    let id = seed_report(&cairn.pool, "did:plc:r", Some("full body"), "pending").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = report::view(
        &mut session,
        &path,
        ReportViewInput {
            id,
            cairn_server_override: None,
        },
    )
    .await
    .expect("view");
    assert_eq!(resp.id, id);
    assert_eq!(resp.reason.as_deref(), Some("full body"));
    assert_eq!(resp.status, "pending");
}

#[tokio::test]
async fn view_unknown_id_returns_status_error() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let err = report::view(
        &mut session,
        &path,
        ReportViewInput {
            id: 99999,
            cairn_server_override: None,
        },
    )
    .await
    .expect_err("view of unknown id must error");
    assert!(matches!(err, CliError::CairnStatus { status, .. } if (400..500).contains(&status)));
}

// ============ resolve ============

#[tokio::test]
async fn resolve_without_label_marks_resolved() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;
    let id = seed_report(&cairn.pool, "did:plc:r", None, "pending").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = report::resolve(
        &mut session,
        &path,
        ReportResolveInput {
            id,
            apply_label: None,
            reason: Some("not actionable".into()),
            cairn_server_override: None,
        },
    )
    .await
    .expect("resolve");
    assert_eq!(resp.status, "resolved");
    assert!(resp.resolution_label.is_none());
    assert_eq!(resp.resolved_by.as_deref(), Some(MODERATOR_DID));
}

#[tokio::test]
async fn resolve_with_label_applies_and_resolves() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;
    let id = seed_report(&cairn.pool, "did:plc:r", None, "pending").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = report::resolve(
        &mut session,
        &path,
        ReportResolveInput {
            id,
            apply_label: Some(ApplyLabelArg {
                uri: "did:plc:target0000000000000000000".into(),
                cid: None,
                val: "spam".into(),
                exp: None,
            }),
            reason: Some("definitely spam".into()),
            cairn_server_override: None,
        },
    )
    .await
    .expect("resolve+label");
    assert_eq!(resp.status, "resolved");
    assert_eq!(resp.resolution_label.as_deref(), Some("spam"));
    assert_eq!(resp.resolved_by.as_deref(), Some(MODERATOR_DID));

    // Audit attribution check: the audit_log row for the resolve
    // must carry the moderator DID, not NULL. This is the load-
    // bearing reason for the HTTP-path architecture (vs direct DB).
    let actor: Option<String> = sqlx::query_scalar!(
        "SELECT actor_did FROM audit_log WHERE action = 'report_resolved' ORDER BY id DESC LIMIT 1"
    )
    .fetch_optional(&cairn.pool)
    .await
    .unwrap();
    assert_eq!(actor.as_deref(), Some(MODERATOR_DID));
}

// ============ flag / unflag ============

#[tokio::test]
async fn flag_creates_suppression_row() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let target = "did:plc:reporter0000000000000000000";
    let resp = report::flag(
        &mut session,
        &path,
        ReportFlagInput {
            did: target.into(),
            suppressed: true,
            reason: Some("repeat false reports".into()),
            cairn_server_override: None,
        },
    )
    .await
    .expect("flag");
    assert!(resp.suppressed);
    assert_eq!(resp.did, target);

    let n: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM suppressed_reporters WHERE did = ?1",
        target
    )
    .fetch_one(&cairn.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn unflag_removes_suppression_row() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let target = "did:plc:reporter0000000000000000000";
    // Flag first.
    report::flag(
        &mut session,
        &path,
        ReportFlagInput {
            did: target.into(),
            suppressed: true,
            reason: None,
            cairn_server_override: None,
        },
    )
    .await
    .unwrap();
    // Now unflag.
    let resp = report::flag(
        &mut session,
        &path,
        ReportFlagInput {
            did: target.into(),
            suppressed: false,
            reason: None,
            cairn_server_override: None,
        },
    )
    .await
    .expect("unflag");
    assert!(!resp.suppressed);

    let n: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM suppressed_reporters WHERE did = ?1",
        target
    )
    .fetch_one(&cairn.pool)
    .await
    .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn flag_invalid_did_rejected_before_http() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator_admin(&cairn.pool, MODERATOR_DID).await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let err = report::flag(
        &mut session,
        &path,
        ReportFlagInput {
            did: "not-a-did".into(),
            suppressed: true,
            reason: None,
            cairn_server_override: None,
        },
    )
    .await
    .expect_err("invalid DID must be rejected");
    assert!(matches!(err, CliError::Config(_)));
}

// ============ format_* (pure unit tests) ============

fn list_fixture() -> ReportListResponse {
    ReportListResponse {
        reports: vec![ReportListEntry {
            id: 7,
            created_at: "2026-04-23T00:00:00Z".into(),
            reason_type: "com.atproto.moderation.defs#reasonSpam".into(),
            subject: ReportSubject::Repo {
                did: "did:plc:target".into(),
            },
            reported_by: "did:plc:reporter".into(),
            status: "pending".into(),
            resolved_at: None,
            resolved_by: None,
            resolution_label: None,
            resolution_reason: None,
        }],
        cursor: Some("next-c".into()),
    }
}

#[test]
fn format_list_human_includes_cursor_line() {
    let s = report::format_list_human(&list_fixture());
    assert!(s.contains("ID"));
    assert!(s.contains("did:plc:reporter"));
    assert!(s.contains("next cursor: next-c"), "got: {s}");
}

#[test]
fn format_list_human_empty() {
    let resp = ReportListResponse {
        reports: vec![],
        cursor: None,
    };
    let s = report::format_list_human(&resp);
    assert_eq!(s, "(no reports)");
}

#[test]
fn format_list_json_round_trips() {
    let v: serde_json::Value =
        serde_json::from_str(&report::format_list_json(&list_fixture())).expect("valid JSON");
    assert_eq!(v["reports"][0]["id"], 7);
    assert_eq!(v["reports"][0]["status"], "pending");
    assert!(
        v["reports"][0].get("reason").is_none(),
        "list shape must not carry reason"
    );
    assert_eq!(v["cursor"], "next-c");
}

fn detail_fixture() -> ReportDetail {
    ReportDetail {
        id: 7,
        created_at: "2026-04-23T00:00:00Z".into(),
        reason_type: "com.atproto.moderation.defs#reasonSpam".into(),
        reason: Some("body text".into()),
        subject: ReportSubject::Strong {
            uri: "at://did:plc:target/app.bsky.feed.post/x".into(),
            cid: "bafy".into(),
        },
        reported_by: "did:plc:reporter".into(),
        status: "resolved".into(),
        resolved_at: Some("2026-04-24T00:00:00Z".into()),
        resolved_by: Some("did:plc:moderator".into()),
        resolution_label: Some("spam".into()),
        resolution_reason: Some("acted".into()),
    }
}

#[test]
fn format_view_human_lists_fields() {
    let s = report::format_view_human(&detail_fixture());
    assert!(s.contains("Report 7"));
    assert!(s.contains("body text"));
    assert!(s.contains("status:         resolved"));
}

#[test]
fn format_view_json_round_trips() {
    let v: serde_json::Value =
        serde_json::from_str(&report::format_view_json(&detail_fixture())).unwrap();
    assert_eq!(v["id"], 7);
    assert_eq!(v["reason"], "body text");
    assert_eq!(v["subject"]["$type"], "com.atproto.repo.strongRef");
}

#[test]
fn format_resolve_human_with_and_without_label() {
    let mut d = detail_fixture();
    let with = report::format_resolve_human(&d);
    assert!(with.contains("with label spam"), "got: {with}");
    d.resolution_label = None;
    let without = report::format_resolve_human(&d);
    assert!(!without.contains("with label"), "got: {without}");
    assert!(without.contains("Resolved report 7"));
}

#[test]
fn format_flag_json_includes_action_discriminator() {
    let r1 = ReportFlagResponse {
        did: "did:plc:r".into(),
        suppressed: true,
    };
    let v1: serde_json::Value = serde_json::from_str(&report::format_flag_json(&r1)).unwrap();
    assert_eq!(v1["action"], "flag");
    assert_eq!(v1["suppressed"], true);

    let r2 = ReportFlagResponse {
        did: "did:plc:r".into(),
        suppressed: false,
    };
    let v2: serde_json::Value = serde_json::from_str(&report::format_flag_json(&r2)).unwrap();
    assert_eq!(v2["action"], "unflag");
    assert_eq!(v2["suppressed"], false);
}

#[test]
fn format_flag_human_uses_correct_verb() {
    let r1 = ReportFlagResponse {
        did: "did:plc:r".into(),
        suppressed: true,
    };
    assert!(report::format_flag_human(&r1).starts_with("Flagged"));
    let r2 = ReportFlagResponse {
        did: "did:plc:r".into(),
        suppressed: false,
    };
    assert!(report::format_flag_human(&r2).starts_with("Unflagged"));
}
