//! Integration tests for `cairn_mod::cli::publish_service_record` (#8).
//!
//! Coverage:
//! - Happy path: fresh DB, publish succeeds, putRecord called with
//!   no swap, state persisted, audit row written.
//! - Idempotent re-publish: second call with identical config → no
//!   PDS round-trip, NoChange outcome.
//! - Content change: second call with different config → putRecord
//!   called WITH swap_record = prior CID, state updated.
//! - Swap-race: mock PDS rejects with InvalidSwap → CliError maps to
//!   PdsError::SwapRace, local state NOT updated.
//! - Missing [labeler] section: clear Config error, no PDS call.
//! - Missing operator session: clear Config error, no PDS call.

mod support;

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use cairn_mod::cli::error::CliError;
use cairn_mod::cli::operator_login;
use cairn_mod::cli::pds::PdsError;
use cairn_mod::cli::publish_service_record::{self, PublishOutcome};
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
/// `service_record_published` actions. Mirrors the schema docblock
/// at `publish_service_record::AUDIT_REASON_SERVICE_RECORD`.
/// Tests parse via serde so `content_changed` asserts land on the
/// literal boolean rather than a string-contains check.
#[derive(Debug, serde::Deserialize)]
struct AuditReason {
    cid: String,
    content_hash_hex: String,
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
    // publish-service-record doesn't read the signing key; just need
    // the config field to deserialize.
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
async fn first_publish_writes_record_and_persists_state() {
    let (dir, pool, config, _addr, pds) = harness().await;
    let session_path = config.operator.as_ref().unwrap().session_path.clone();

    let outcome = publish_service_record::publish(&pool, &config, &session_path)
        .await
        .expect("publish");
    let published_cid = match outcome {
        PublishOutcome::Published { cid, .. } => {
            assert!(cid.starts_with("bafy-mock-"), "got {cid}");
            cid
        }
        other => panic!("expected Published, got {other:?}"),
    };

    // Exactly one putRecord call.
    assert_eq!(pds.state.put_record_calls.load(Ordering::SeqCst), 1);

    // labeler_config populated with the published CID and a hash.
    let cid: String =
        sqlx::query_scalar!("SELECT value FROM labeler_config WHERE key = 'service_record_cid'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cid, published_cid);
    let stored_hash: String = sqlx::query_scalar!(
        "SELECT value FROM labeler_config WHERE key = 'service_record_content_hash'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    // #20 invariant: every invocation writes exactly one audit row.
    let audit_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'service_record_published'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1, "one audit row per publish invocation");

    // Audit row shape + reason-JSON contents.
    let audit = sqlx::query!(
        "SELECT action, actor_did, outcome, target_cid, reason
         FROM audit_log
         WHERE action = 'service_record_published'
         ORDER BY id DESC LIMIT 1"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit.action, "service_record_published");
    assert_eq!(audit.actor_did, OPERATOR_DID);
    assert_eq!(audit.outcome, "success");
    assert_eq!(audit.target_cid.as_deref(), Some(published_cid.as_str()));

    // Parse reason JSON via serde — literal boolean match per #20 note.
    let reason: AuditReason =
        serde_json::from_str(audit.reason.as_deref().expect("reason json present"))
            .expect("reason parses per AUDIT_REASON_SERVICE_RECORD docblock");
    assert!(
        reason.content_changed,
        "first publish is content_changed=true by construction of the publish-path branch"
    );
    assert_eq!(
        reason.cid, published_cid,
        "audit reason cid matches published cid"
    );
    assert_eq!(
        reason.content_hash_hex, stored_hash,
        "audit reason hash matches stored hash"
    );

    drop(dir);
}

// ---------- Idempotency ----------

#[tokio::test]
async fn republish_with_identical_config_is_noop() {
    let (dir, pool, config, _addr, pds) = harness().await;
    let session_path = config.operator.as_ref().unwrap().session_path.clone();

    // First publish.
    publish_service_record::publish(&pool, &config, &session_path)
        .await
        .unwrap();
    assert_eq!(pds.state.put_record_calls.load(Ordering::SeqCst), 1);
    let first_cid: String =
        sqlx::query_scalar!("SELECT value FROM labeler_config WHERE key = 'service_record_cid'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let first_hash: String = sqlx::query_scalar!(
        "SELECT value FROM labeler_config WHERE key = 'service_record_content_hash'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    // Second publish with same config → NoChange, no extra putRecord.
    let outcome = publish_service_record::publish(&pool, &config, &session_path)
        .await
        .unwrap();
    assert!(matches!(outcome, PublishOutcome::NoChange));
    assert_eq!(
        pds.state.put_record_calls.load(Ordering::SeqCst),
        1,
        "no extra PDS round-trip on idempotent republish"
    );

    // #20 invariant: skip path audits too — two invocations → two rows.
    let audit_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'service_record_published'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit_count, 2,
        "each invocation writes one audit row (publish + skip both audit)"
    );

    // Most recent row is the skip's. Assert target_cid, reason shape,
    // and content_changed=false as a literal boolean.
    let skip_audit = sqlx::query!(
        "SELECT target_cid, reason
         FROM audit_log
         WHERE action = 'service_record_published'
         ORDER BY id DESC LIMIT 1"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        skip_audit.target_cid.as_deref(),
        Some(first_cid.as_str()),
        "skip audit echoes prior cid in target_cid, not null"
    );
    let reason: AuditReason =
        serde_json::from_str(skip_audit.reason.as_deref().expect("reason json present"))
            .expect("skip reason parses per AUDIT_REASON_SERVICE_RECORD docblock");
    assert!(
        !reason.content_changed,
        "skip path records content_changed=false (literal bool)"
    );
    assert_eq!(
        reason.cid, first_cid,
        "skip audit reason echoes prior cid, not empty/null — audit integrity"
    );
    assert_eq!(
        reason.content_hash_hex, first_hash,
        "skip audit reason echoes the matched hash"
    );

    drop(dir);
}

// ---------- Content change with swap ----------

#[tokio::test]
async fn republish_with_changed_labels_uses_swap() {
    let (dir, pool, config, _addr, pds) = harness().await;
    let session_path = config.operator.as_ref().unwrap().session_path.clone();

    // First publish.
    publish_service_record::publish(&pool, &config, &session_path)
        .await
        .unwrap();

    // Second publish with a different labeler.
    let mut updated = config.clone();
    updated.labeler = Some(sample_labeler(&["spam", "abuse"]));
    let outcome = publish_service_record::publish(&pool, &updated, &session_path)
        .await
        .expect("second publish");
    assert!(matches!(outcome, PublishOutcome::Published { .. }));
    assert_eq!(pds.state.put_record_calls.load(Ordering::SeqCst), 2);

    drop(dir);
}

// ---------- Swap-race ----------

#[tokio::test]
async fn swap_race_surfaces_as_dedicated_error_and_preserves_local_state() {
    let (dir, pool, config, _addr, pds) = harness().await;
    let session_path = config.operator.as_ref().unwrap().session_path.clone();

    // First publish establishes state.
    publish_service_record::publish(&pool, &config, &session_path)
        .await
        .unwrap();
    let cid_before: String =
        sqlx::query_scalar!("SELECT value FROM labeler_config WHERE key = 'service_record_cid'")
            .fetch_one(&pool)
            .await
            .unwrap();

    // Simulate an out-of-band write to the PDS by overwriting the
    // mock's stored current CID. The next publish's swap guard
    // (= our locally-cached cid_before) won't match.
    *pds.state.current_service_record_cid.lock().await = Some("external-cid".into());

    // Second publish with changed config → putRecord with stale
    // swap → InvalidSwap → PdsError::SwapRace.
    let mut updated = config.clone();
    updated.labeler = Some(sample_labeler(&["spam", "abuse"]));
    let err = publish_service_record::publish(&pool, &updated, &session_path)
        .await
        .unwrap_err();
    match err {
        CliError::Pds(PdsError::SwapRace { .. }) => {}
        other => panic!("expected SwapRace, got {other:?}"),
    }

    // Local state unchanged — the stale cid remains, no audit row
    // added for the failed publish.
    let cid_after: String =
        sqlx::query_scalar!("SELECT value FROM labeler_config WHERE key = 'service_record_cid'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        cid_before, cid_after,
        "failed publish must not overwrite labeler_config"
    );
    let audit_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'service_record_published'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1, "only the successful first publish audited");

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
        None, // <-- no [labeler] section
        &pds.base_url(),
        &session_path,
        &db_path,
        &key_path,
    );

    let err = publish_service_record::publish(&pool, &config, &session_path)
        .await
        .unwrap_err();
    assert!(matches!(err, CliError::Config(_)));
    assert_eq!(
        pds.state.put_record_calls.load(Ordering::SeqCst),
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

    let err = publish_service_record::publish(&pool, &config, &session_path)
        .await
        .unwrap_err();
    assert!(matches!(err, CliError::Config(_)));
    assert_eq!(pds.state.put_record_calls.load(Ordering::SeqCst), 0);
}
