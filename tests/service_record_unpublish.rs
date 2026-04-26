//! Integration tests for `cairn_mod::cli::unpublish_service_record` (#34).
//!
//! Coverage:
//! - Happy path: publish then unpublish → PDS record removed,
//!   labeler_config cleared, audit row written with content_changed=true.
//! - Idempotent no-op: unpublish on a fresh DB → NoChange outcome,
//!   no PDS round-trip, audit row written with content_changed=false
//!   (the §F10 / #20 invariant: every invocation audits exactly once).
//! - Two-shot idempotency: publish → unpublish → unpublish second
//!   time is also a no-op (mirrors the real operator workflow where
//!   re-running the inverse should not error).
//! - Missing [labeler] / [operator] / operator session: clear Config
//!   error, no PDS call. Symmetric with publish's failure modes so
//!   operators running the inverse hit the same shape.

mod support;

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use cairn_mod::cli::error::CliError;
use cairn_mod::cli::operator_login;
use cairn_mod::cli::publish_service_record;
use cairn_mod::cli::unpublish_service_record::{self, UnpublishOutcome};
use cairn_mod::config::{
    BlursToml, Config, LabelValueDefinitionToml, LabelerConfigToml, LocaleToml, SeverityToml,
};
use cairn_mod::storage;
use serde_json::json;
use sqlx::{Pool, Sqlite};
use support::mock_pds::{self, MOCK_APP_PASSWORD, MOCK_HANDLE};
use tempfile::TempDir;

const OPERATOR_DID: &str = "did:plc:mockmoderator0000000000000";

/// Parsed form of an `audit_log.reason` JSON payload for
/// `service_record_unpublished` actions. Mirrors the schema docblock
/// at `unpublish_service_record::AUDIT_REASON_SERVICE_RECORD_UNPUBLISH`.
/// `cid` and `content_hash_hex` are `Option` because the no-op branch
/// emits JSON null for both.
#[derive(Debug, serde::Deserialize)]
struct UnpublishAuditReason {
    cid: Option<String>,
    content_hash_hex: Option<String>,
    content_changed: bool,
}

async fn setup_pool(dir: &TempDir) -> Pool<Sqlite> {
    let path = dir.path().join("cairn.db");
    storage::open(&path).await.unwrap()
}

fn sample_labeler(values: &[&str]) -> LabelerConfigToml {
    LabelerConfigToml {
        label_values: values.iter().map(|s| (*s).into()).collect(),
        label_value_definitions: values
            .iter()
            .map(|id| LabelValueDefinitionToml {
                identifier: (*id).into(),
                severity: SeverityToml::Alert,
                blurs: BlursToml::None,
                default_setting: None,
                adult_only: None,
                locales: vec![LocaleToml {
                    lang: "en".into(),
                    name: (*id).into(),
                    description: format!("Description for {id}."),
                }],
            })
            .collect(),
        reason_types: vec!["com.atproto.moderation.defs#reasonSpam".into()],
        subject_types: vec!["account".into()],
        subject_collections: vec![],
    }
}

fn sample_config(
    labeler: Option<LabelerConfigToml>,
    pds_url: &str,
    session_path: &std::path::Path,
    db_path: &std::path::Path,
    signing_key_path: &std::path::Path,
) -> Config {
    let mut v = json!({
        "service_did": "did:web:labeler.test",
        "service_endpoint": "https://labeler.test",
        "db_path": db_path,
        "signing_key_path": signing_key_path,
        "operator": {
            "pds_url": pds_url,
            "session_path": session_path,
        },
    });
    if let Some(l) = labeler {
        v["labeler"] = serde_json::to_value(l).unwrap();
    }
    serde_json::from_value(v).expect("config deserializes")
}

fn placeholder_key_path(dir: &TempDir) -> PathBuf {
    let p = dir.path().join("unused-signing-key.hex");
    fs::write(&p, "00".repeat(32)).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    p
}

async fn seed_operator_session(pds_url: &str, session_path: &std::path::Path) {
    operator_login::login(pds_url, MOCK_HANDLE, MOCK_APP_PASSWORD, session_path)
        .await
        .expect("operator login seeds session");
}

async fn harness() -> (TempDir, Pool<Sqlite>, Config, SocketAddr, mock_pds::MockPds) {
    let dir = tempfile::tempdir().unwrap();
    let pool = setup_pool(&dir).await;
    let pds = mock_pds::spawn(OPERATOR_DID).await;
    let session_path = dir.path().join("operator-session.json");
    seed_operator_session(&pds.base_url(), &session_path).await;
    let key_path = placeholder_key_path(&dir);
    let db_path = dir.path().join("cairn.db");
    let config = sample_config(
        Some(sample_labeler(&["spam"])),
        &pds.base_url(),
        &session_path,
        &db_path,
        &key_path,
    );
    let addr = pds.addr;
    (dir, pool, config, addr, pds)
}

// ---------- Happy path ----------

#[tokio::test]
async fn publish_then_unpublish_clears_state_and_audits() {
    let (dir, pool, config, _addr, pds) = harness().await;
    let session_path = config.operator.as_ref().unwrap().session_path.clone();

    // Publish first to establish PDS + labeler_config state.
    publish_service_record::publish(&pool, &config, &session_path)
        .await
        .expect("publish");
    let published_cid: String =
        sqlx::query_scalar!("SELECT value FROM labeler_config WHERE key = 'service_record_cid'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let published_hash: String = sqlx::query_scalar!(
        "SELECT value FROM labeler_config WHERE key = 'service_record_content_hash'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pds.state.delete_record_calls.load(Ordering::SeqCst), 0);

    // Now unpublish.
    let outcome = unpublish_service_record::unpublish(&pool, &config, &session_path)
        .await
        .expect("unpublish");
    let returned_cid = match outcome {
        UnpublishOutcome::Unpublished { cid } => cid,
        other => panic!("expected Unpublished, got {other:?}"),
    };
    assert_eq!(returned_cid, published_cid);

    // Exactly one deleteRecord call.
    assert_eq!(pds.state.delete_record_calls.load(Ordering::SeqCst), 1);

    // Mock PDS state: current_service_record_cid cleared.
    let stored = pds.state.current_service_record_cid.lock().await.clone();
    assert!(
        stored.is_none(),
        "mock PDS still holds a record after unpublish: {stored:?}"
    );

    // labeler_config: all three keys gone.
    for key in [
        "service_record_cid",
        "service_record_content_hash",
        "service_record_created_at",
    ] {
        let count: i64 =
            sqlx::query_scalar!("SELECT COUNT(*) FROM labeler_config WHERE key = ?1", key)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 0, "labeler_config row for {key} still present");
    }

    // Exactly one audit row for the unpublish (separate from publish's row).
    let unpub_audit_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'service_record_unpublished'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unpub_audit_count, 1);

    let audit = sqlx::query!(
        "SELECT actor_did, outcome, target_cid, reason
         FROM audit_log
         WHERE action = 'service_record_unpublished'
         ORDER BY id DESC LIMIT 1"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit.actor_did, OPERATOR_DID);
    assert_eq!(audit.outcome, "success");
    assert_eq!(audit.target_cid.as_deref(), Some(published_cid.as_str()));

    let reason: UnpublishAuditReason =
        serde_json::from_str(audit.reason.as_deref().expect("reason json present"))
            .expect("reason parses per AUDIT_REASON_SERVICE_RECORD_UNPUBLISH docblock");
    assert!(
        reason.content_changed,
        "real-delete branch records content_changed=true"
    );
    assert_eq!(reason.cid.as_deref(), Some(published_cid.as_str()));
    assert_eq!(
        reason.content_hash_hex.as_deref(),
        Some(published_hash.as_str())
    );

    drop(dir);
}

// ---------- Idempotency: nothing-to-unpublish ----------

#[tokio::test]
async fn unpublish_with_no_prior_state_is_noop() {
    let (dir, pool, config, _addr, pds) = harness().await;
    let session_path = config.operator.as_ref().unwrap().session_path.clone();

    // No prior publish — unpublish on a fresh DB.
    let outcome = unpublish_service_record::unpublish(&pool, &config, &session_path)
        .await
        .expect("unpublish");
    assert!(
        matches!(outcome, UnpublishOutcome::NoChange),
        "fresh DB unpublish must be NoChange"
    );

    // No PDS round-trip on the no-op branch.
    assert_eq!(
        pds.state.delete_record_calls.load(Ordering::SeqCst),
        0,
        "no PDS call when there is no prior state to remove"
    );

    // Audit row was still written: per the publish-skip pattern,
    // every invocation produces exactly one audit_log row (#20).
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'service_record_unpublished'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);

    let audit = sqlx::query!(
        "SELECT target_cid, reason FROM audit_log
         WHERE action = 'service_record_unpublished'
         ORDER BY id DESC LIMIT 1"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // No-op branch: target_cid is NULL (no record to point at).
    assert!(audit.target_cid.is_none());
    let reason: UnpublishAuditReason =
        serde_json::from_str(audit.reason.as_deref().expect("reason json present"))
            .expect("reason parses per AUDIT_REASON_SERVICE_RECORD_UNPUBLISH docblock");
    assert!(
        !reason.content_changed,
        "no-op records content_changed=false"
    );
    assert!(reason.cid.is_none(), "no-op reason carries cid: null");
    assert!(
        reason.content_hash_hex.is_none(),
        "no-op reason carries content_hash_hex: null"
    );

    drop(dir);
}

// ---------- Idempotency: unpublish twice ----------

#[tokio::test]
async fn unpublish_twice_after_publish_is_idempotent() {
    let (dir, pool, config, _addr, pds) = harness().await;
    let session_path = config.operator.as_ref().unwrap().session_path.clone();

    publish_service_record::publish(&pool, &config, &session_path)
        .await
        .unwrap();

    // First unpublish: real delete.
    let first = unpublish_service_record::unpublish(&pool, &config, &session_path)
        .await
        .unwrap();
    assert!(matches!(first, UnpublishOutcome::Unpublished { .. }));
    assert_eq!(pds.state.delete_record_calls.load(Ordering::SeqCst), 1);

    // Second unpublish: no-op. labeler_config is empty so we don't
    // touch the PDS again.
    let second = unpublish_service_record::unpublish(&pool, &config, &session_path)
        .await
        .unwrap();
    assert!(matches!(second, UnpublishOutcome::NoChange));
    assert_eq!(
        pds.state.delete_record_calls.load(Ordering::SeqCst),
        1,
        "second unpublish must not contact the PDS"
    );

    // Audit: one real-delete + one no-op = two unpublish rows.
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'service_record_unpublished'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2);

    drop(dir);
}

// ---------- Missing config ----------

#[tokio::test]
async fn missing_labeler_section_fails_fast_without_pds_call() {
    let dir = tempfile::tempdir().unwrap();
    let pool = setup_pool(&dir).await;
    let pds = mock_pds::spawn(OPERATOR_DID).await;
    let session_path = dir.path().join("operator-session.json");
    seed_operator_session(&pds.base_url(), &session_path).await;
    let key_path = placeholder_key_path(&dir);
    let db_path = dir.path().join("cairn.db");
    let config = sample_config(
        None, // no [labeler]
        &pds.base_url(),
        &session_path,
        &db_path,
        &key_path,
    );

    let err = unpublish_service_record::unpublish(&pool, &config, &session_path)
        .await
        .unwrap_err();
    assert!(matches!(err, CliError::Config(_)));
    assert_eq!(
        pds.state.delete_record_calls.load(Ordering::SeqCst),
        0,
        "no PDS round-trip on config error"
    );
}

#[tokio::test]
async fn missing_operator_session_fails_fast_without_pds_call() {
    let dir = tempfile::tempdir().unwrap();
    let pool = setup_pool(&dir).await;
    let pds = mock_pds::spawn(OPERATOR_DID).await;
    let session_path = dir.path().join("operator-session.json");
    // Do NOT seed the session.
    let key_path = placeholder_key_path(&dir);
    let db_path = dir.path().join("cairn.db");
    let config = sample_config(
        Some(sample_labeler(&["spam"])),
        &pds.base_url(),
        &session_path,
        &db_path,
        &key_path,
    );

    let err = unpublish_service_record::unpublish(&pool, &config, &session_path)
        .await
        .unwrap_err();
    assert!(matches!(err, CliError::Config(_)));
    assert_eq!(pds.state.delete_record_calls.load(Ordering::SeqCst), 0);
}
