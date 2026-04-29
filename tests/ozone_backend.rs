//! Integration tests for `OzoneBackend::takedown_account` (#87)
//! and the recordAction → PDS-admin dispatch pipeline.
//!
//! Two test surfaces:
//!
//! 1. **Wire-protocol** (`OzoneBackend::takedown_account` against
//!    a wiremock-mocked bsky-PDS): exercises the request shape +
//!    response-status mapping. The mock isn't a real bsky-PDS,
//!    so these tests prove the **request we send** is correct
//!    by `bsky-PDS findings §6.1`'s spec but **cannot** prove the
//!    real bsky-PDS will accept that shape. Phase B verification
//!    against a live bsky-PDS will catch any divergence.
//!
//! 2. **End-to-end** (recordAction → writer task → backend call
//!    → audit row): exercises the dispatch wiring through a real
//!    SQLite DB + real writer task + wiremock-backed
//!    `OzoneBackend`. Asserts that successful PDS calls produce a
//!    `pds_admin_audit` row with `outcome = 'success'`; that
//!    failed PDS calls leave the cairn-mod-side `subject_actions`
//!    row committed and produce a `pds_admin_audit` row with the
//!    matching failure outcome; and that recordAction without a
//!    bridge behaves identically to v1.6 builds (no audit rows).
//!
//! # Audit-verify divergence (deferred)
//!
//! These tests write `pds_admin_audit` rows that interleave with
//! `audit_log` in the unified hash chain (#85). `cairn audit-verify`
//! (#41) currently walks `audit_log` only and would report
//! false-positive divergences. Extending verify is a separate
//! issue (next slot in v1.7); these tests do NOT assert against
//! verify output.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use cairn_mod::moderation::types::ActionType;
use cairn_mod::pds_admin::{
    ActionMapEntry, AdminPassword, AuditOutcome, BackendMethod, OzoneBackend, OzoneBackendConfig,
    PdsAdminBackend, PdsAdminBridge, PdsAdminPolicy, list_pds_admin_audit_for_action,
};
use cairn_mod::{RecordActionRequest, spawn_with_pds_admin, storage};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use url::Url;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SUBJECT_DID: &str = "did:plc:subjecttesttesttesttesttest";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";

// ===========================================================================
// Wire-protocol tests
// ===========================================================================

fn ozone_backend_against(server_uri: &str, admin_password: &str) -> OzoneBackend {
    let cfg = OzoneBackendConfig {
        pds_url: Url::parse(server_uri).unwrap(),
        admin_password: AdminPassword::new(admin_password.into()),
        request_timeout: Duration::from_secs(5),
    };
    OzoneBackend::new(&cfg).expect("construct OzoneBackend")
}

#[tokio::test]
async fn takedown_account_sends_correct_wire_shape_and_synthesizes_id() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.admin.updateSubjectStatus"))
        .and(header("authorization", "Basic YWRtaW46aHVudGVyMg=="))
        .respond_with(|req: &Request| {
            // Wiremock can't return assertion failures to the
            // test, so we inline-assert the request shape per
            // bsky-PDS findings §6.1; panics propagate to the
            // test runner as a 500 the test asserts on below.
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("body is JSON");
            let subject = body.get("subject").expect("subject present");
            assert_eq!(
                subject.get("$type").and_then(|v| v.as_str()),
                Some("com.atproto.admin.defs#repoRef")
            );
            assert_eq!(
                subject.get("did").and_then(|v| v.as_str()),
                Some(SUBJECT_DID)
            );
            let takedown = body.get("takedown").expect("takedown present");
            assert_eq!(
                takedown.get("applied").and_then(|v| v.as_bool()),
                Some(true)
            );
            let r = takedown.get("ref").and_then(|v| v.as_str()).unwrap();
            assert!(
                r.starts_with("cairn-mod:action_id=42:reason=spam"),
                "ref={r}"
            );

            ResponseTemplate::new(200).set_body_json(serde_json::json!({}))
        })
        .expect(1)
        .mount(&server)
        .await;

    let backend = ozone_backend_against(&server.uri(), "hunter2");
    let id = backend
        .takedown_account(SUBJECT_DID, "spam", None, 42)
        .await
        .expect("takedown succeeds against the mock 200 response");

    // bsky-PDS returns no id — synthesized format pinned per #87.
    assert_eq!(id.as_str(), format!("ozone:{SUBJECT_DID}:42"));
}

#[tokio::test]
async fn takedown_account_401_maps_to_auth_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.admin.updateSubjectStatus"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "AuthenticationRequired",
            "message": "bad password"
        })))
        .mount(&server)
        .await;

    let backend = ozone_backend_against(&server.uri(), "wrong");
    let err = backend
        .takedown_account(SUBJECT_DID, "spam", None, 1)
        .await
        .expect_err("401 must produce an error");
    match err {
        cairn_mod::pds_admin::BackendError::Auth(msg) => {
            assert!(msg.contains("401"));
            assert!(msg.contains("bad password"));
        }
        other => panic!("expected Auth, got {other:?}"),
    }
}

#[tokio::test]
async fn takedown_account_400_invalid_request_with_subject_message_maps_to_validation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.admin.updateSubjectStatus"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "InvalidRequest",
            "message": "subject DID is malformed"
        })))
        .mount(&server)
        .await;

    let backend = ozone_backend_against(&server.uri(), "hunter2");
    let err = backend
        .takedown_account("did:plc:malformed", "spam", None, 1)
        .await
        .expect_err("400 with subject message must produce Validation");
    assert!(matches!(
        err,
        cairn_mod::pds_admin::BackendError::Validation(_)
    ));
}

#[tokio::test]
async fn takedown_account_429_with_retry_after_carries_hint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.admin.updateSubjectStatus"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "30")
                .set_body_json(serde_json::json!({
                    "error": "RateLimitExceeded",
                    "message": "too many requests"
                })),
        )
        .mount(&server)
        .await;

    let backend = ozone_backend_against(&server.uri(), "hunter2");
    let err = backend
        .takedown_account(SUBJECT_DID, "spam", None, 1)
        .await
        .expect_err("429 must produce an error");
    match err {
        cairn_mod::pds_admin::BackendError::RateLimited {
            retry_after_seconds,
            ..
        } => {
            assert_eq!(retry_after_seconds, Some(30));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[tokio::test]
async fn takedown_account_5xx_maps_to_network() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.admin.updateSubjectStatus"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
        .mount(&server)
        .await;

    let backend = ozone_backend_against(&server.uri(), "hunter2");
    let err = backend
        .takedown_account(SUBJECT_DID, "spam", None, 1)
        .await
        .expect_err("503 must produce an error");
    assert!(matches!(
        err,
        cairn_mod::pds_admin::BackendError::Network(_)
    ));
}

#[tokio::test]
async fn takedown_account_unreachable_pds_maps_to_network() {
    // No MockServer — the URL points at a port that should be
    // closed. reqwest's connect-refused → Network per the helper
    // map_reqwest_error.
    let cfg = OzoneBackendConfig {
        pds_url: Url::parse("http://127.0.0.1:1").unwrap(),
        admin_password: AdminPassword::new("hunter2".into()),
        request_timeout: Duration::from_secs(2),
    };
    let backend = OzoneBackend::new(&cfg).unwrap();
    let err = backend
        .takedown_account(SUBJECT_DID, "spam", None, 1)
        .await
        .expect_err("connect-refused must produce an error");
    assert!(matches!(
        err,
        cairn_mod::pds_admin::BackendError::Network(_)
    ));
}

// ===========================================================================
// End-to-end recordAction → dispatch → audit tests
// ===========================================================================

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    writer: cairn_mod::WriterHandle,
}

fn takedown_action_map() -> BTreeMap<ActionType, ActionMapEntry> {
    let mut m = BTreeMap::new();
    m.insert(
        ActionType::Takedown,
        ActionMapEntry::Method(BackendMethod::TakedownAccount),
    );
    m
}

async fn build_harness(server_uri: Option<&str>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();

    let pds_admin = server_uri.map(|uri| {
        let cfg = OzoneBackendConfig {
            pds_url: Url::parse(uri).unwrap(),
            admin_password: AdminPassword::new("hunter2".into()),
            request_timeout: Duration::from_secs(5),
        };
        let backend: Arc<dyn PdsAdminBackend> = Arc::new(OzoneBackend::new(&cfg).unwrap());

        PdsAdminBridge {
            policy: PdsAdminPolicy {
                enabled: true,
                backend: None,
                action_map: takedown_action_map(),
            },
            backend,
        }
    });

    let writer = spawn_with_pds_admin(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
        cairn_mod::PolicyAutomationPolicy::defaults(),
        pds_admin,
    )
    .await
    .unwrap();

    Harness {
        _dir: dir,
        pool,
        writer,
    }
}

fn takedown_request() -> RecordActionRequest {
    RecordActionRequest {
        subject: SUBJECT_DID.into(),
        actor_did: MODERATOR_DID.into(),
        action_type: ActionType::Takedown,
        reason_codes: vec!["spam".into()],
        duration_iso: None,
        notes: Some("repeat offender".into()),
        report_ids: vec![],
    }
}

#[tokio::test]
async fn recordaction_with_takedown_dispatches_to_backend_and_audits_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.admin.updateSubjectStatus"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let h = build_harness(Some(&server.uri())).await;
    let recorded = h.writer.record_action(takedown_request()).await.unwrap();

    // The subject_actions row was committed.
    let action_id_in_db: i64 = sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM subject_actions WHERE id = ?1"#,
        recorded.action_id
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(action_id_in_db, recorded.action_id);

    // The pds_admin_audit row landed with success outcome.
    let audit_rows = list_pds_admin_audit_for_action(&h.pool, recorded.action_id)
        .await
        .unwrap();
    assert_eq!(audit_rows.len(), 1);
    assert_eq!(audit_rows[0].outcome, AuditOutcome::Success);
    assert_eq!(audit_rows[0].backend_method, BackendMethod::TakedownAccount);
    assert_eq!(
        audit_rows[0].backend_action_id.as_ref().unwrap().as_str(),
        format!("ozone:{SUBJECT_DID}:{}", recorded.action_id)
    );

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn recordaction_with_takedown_records_failure_and_keeps_action_committed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.admin.updateSubjectStatus"))
        .respond_with(ResponseTemplate::new(503).set_body_string("backend down"))
        .expect(1)
        .mount(&server)
        .await;

    let h = build_harness(Some(&server.uri())).await;
    let recorded = h
        .writer
        .record_action(takedown_request())
        .await
        .expect("recordAction succeeds even when backend fails (per §A13)");

    // §A13 invariant: cairn-mod-side action stays committed.
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM subject_actions WHERE id = ?1",
        recorded.action_id
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "subject_actions row stays committed");

    // Audit-row records the failure with Network outcome (503 → Network per #87 mapping).
    let audit_rows = list_pds_admin_audit_for_action(&h.pool, recorded.action_id)
        .await
        .unwrap();
    assert_eq!(audit_rows.len(), 1);
    assert_eq!(audit_rows[0].outcome, AuditOutcome::Network);
    assert!(audit_rows[0].backend_action_id.is_none());

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn recordaction_without_pds_admin_bridge_is_unchanged() {
    // The whole point of `Option<PdsAdminBridge>` — when None, the
    // post-commit dispatch is a no-op and recordAction behaves
    // identically to v1.6 builds.
    let h = build_harness(None).await;
    let recorded = h.writer.record_action(takedown_request()).await.unwrap();
    let audit_rows = list_pds_admin_audit_for_action(&h.pool, recorded.action_id)
        .await
        .unwrap();
    assert!(
        audit_rows.is_empty(),
        "no pds_admin_audit row when bridge is None"
    );
    h.writer.shutdown().await.unwrap();
}
