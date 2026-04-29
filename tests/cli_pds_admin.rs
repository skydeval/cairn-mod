//! Integration tests for `cairn pds-admin` (#99) — covers the
//! direct-DB helpers and config preflight. The full HTTP-routed
//! happy path (recordAction → writer post-commit dispatch →
//! pds_admin_audit row) is exercised by the writer's own
//! integration tests in `tests/admin_subject_actions.rs` plus the
//! `tests/ozone_backend.rs` mock-server suite; this file
//! verifies the CLI-side glue.

use cairn_mod::cli::pds_admin::{
    PDS_ADMIN_DEFAULT_REASON_CODE, find_active_suspension_action_id,
    find_pds_admin_audit_for_action, verify_pds_admin_enabled,
};
use cairn_mod::storage;
use serde_json::json;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

const ALICE: &str = "did:plc:alice00000000000000000000";
const MOD_DID: &str = "did:plc:m00000000000000000000000000";

async fn fresh_pool() -> (TempDir, Pool<Sqlite>) {
    let dir = tempfile::tempdir().unwrap();
    let pool = storage::open(&dir.path().join("cairn.db")).await.unwrap();
    (dir, pool)
}

/// Build a `Config` from a JSON value that round-trips through
/// serde — same pattern as `tests/cli_moderator.rs` and the
/// strike calculator's `vocab_with` test helper.
fn config_from_json(v: serde_json::Value) -> cairn_mod::config::Config {
    serde_json::from_value(v).expect("config deserializes")
}

#[test]
fn verify_pds_admin_enabled_succeeds_when_configured() {
    // Set the env var the [pds_admin.ozone].admin_password_env
    // config field references; from_config reads it at policy-build
    // time. SAFETY: tests run in the same process; setting env vars
    // is a known anti-pattern but acceptable for a single-test
    // exercise of the config surface.
    // SAFETY: single-threaded test process; env is read by the
    // sync from_config call below.
    unsafe {
        std::env::set_var("CAIRN_TEST_PDS_ADMIN_PW", "secret");
    }
    let cfg = config_from_json(json!({
        "service_did": "did:web:cairn.example.com",
        "service_endpoint": "https://cairn.example.com",
        "db_path": "/tmp/cairn.db",
        "signing_key_path": "/tmp/key.hex",
        "pds_admin": {
            "enabled": true,
            "ozone": {
                "pds_url": "https://pds.example.com",
                "admin_user": "admin",
                "admin_password_env": "CAIRN_TEST_PDS_ADMIN_PW",
            },
            "action_map": {
                "warning": "skip",
                "note": "skip",
                "temp_suspension": "suspend_account",
                "indef_suspension": "suspend_account",
                "takedown": "takedown_account",
            },
        },
    }));
    let res = verify_pds_admin_enabled(&cfg);
    assert!(res.is_ok(), "verify_pds_admin_enabled: {res:?}");
}

#[test]
fn verify_pds_admin_enabled_errors_when_disabled() {
    let cfg = config_from_json(json!({
        "service_did": "did:web:cairn.example.com",
        "service_endpoint": "https://cairn.example.com",
        "db_path": "/tmp/cairn.db",
        "signing_key_path": "/tmp/key.hex",
    }));
    let err = verify_pds_admin_enabled(&cfg).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("[pds_admin]") || msg.contains("disabled"),
        "{msg}"
    );
}

#[test]
fn pds_admin_default_reason_code_constant() {
    // Operators must declare this in [moderation_reasons] for
    // `cairn pds-admin` to succeed without a --reason override.
    assert_eq!(PDS_ADMIN_DEFAULT_REASON_CODE, "pds-admin-cli");
}

#[tokio::test]
async fn find_active_suspension_returns_none_when_no_actions() {
    let (_d, pool) = fresh_pool().await;
    let r = find_active_suspension_action_id(&pool, ALICE)
        .await
        .unwrap();
    assert!(r.is_none());
}

/// Insert a subject_actions row directly. Tests the find/lookup
/// helpers without needing the full writer pipeline.
async fn seed_action(
    pool: &Pool<Sqlite>,
    subject_did: &str,
    action_type: &str,
    revoked_at: Option<i64>,
) -> i64 {
    let revoked_by = revoked_at.map(|_| MOD_DID.to_string());
    let revoked_reason = revoked_at.map(|_| "test revoke".to_string());
    let id: i64 = sqlx::query_scalar!(
        r#"INSERT INTO subject_actions (
             subject_did, actor_did, action_type, reason_codes,
             effective_at, strike_value_base, strike_value_applied,
             was_dampened, strikes_at_time_of_action, created_at,
             revoked_at, revoked_by_did, revoked_reason
           )
           VALUES (?1, ?2, ?3, '["spam"]', ?4, 0, 0, 0, 0, ?4, ?5, ?6, ?7)
           RETURNING id as "id!: i64""#,
        subject_did,
        MOD_DID,
        action_type,
        1_700_000_000_000i64,
        revoked_at,
        revoked_by,
        revoked_reason,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn find_active_suspension_finds_unrevoked_takedown() {
    let (_d, pool) = fresh_pool().await;
    let id = seed_action(&pool, ALICE, "takedown", None).await;
    let found = find_active_suspension_action_id(&pool, ALICE)
        .await
        .unwrap();
    assert_eq!(found, Some(id));
}

#[tokio::test]
async fn find_active_suspension_skips_revoked_takedown() {
    let (_d, pool) = fresh_pool().await;
    seed_action(&pool, ALICE, "takedown", Some(1_700_000_001_000)).await;
    let found = find_active_suspension_action_id(&pool, ALICE)
        .await
        .unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn find_active_suspension_picks_most_recent() {
    let (_d, pool) = fresh_pool().await;
    let _old = seed_action(&pool, ALICE, "takedown", Some(1_700_000_001_000)).await;
    let new = seed_action(&pool, ALICE, "indef_suspension", None).await;
    let found = find_active_suspension_action_id(&pool, ALICE)
        .await
        .unwrap();
    assert_eq!(found, Some(new));
}

#[tokio::test]
async fn find_active_suspension_includes_temp_and_indef() {
    let (_d, pool) = fresh_pool().await;
    let id = seed_action(&pool, ALICE, "temp_suspension", None).await;
    let found = find_active_suspension_action_id(&pool, ALICE)
        .await
        .unwrap();
    assert_eq!(found, Some(id));
}

#[tokio::test]
async fn find_active_suspension_ignores_warning_and_note() {
    let (_d, pool) = fresh_pool().await;
    seed_action(&pool, ALICE, "warning", None).await;
    seed_action(&pool, ALICE, "note", None).await;
    let found = find_active_suspension_action_id(&pool, ALICE)
        .await
        .unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn find_pds_admin_audit_returns_none_when_no_dispatch() {
    let (_d, pool) = fresh_pool().await;
    let r = find_pds_admin_audit_for_action(&pool, 1).await.unwrap();
    assert!(r.is_none());
}

#[tokio::test]
async fn find_pds_admin_audit_finds_matching_row() {
    let (_d, pool) = fresh_pool().await;
    let action_id = seed_action(&pool, ALICE, "takedown", None).await;
    // Seed a pds_admin_audit row pointing at the action. Use
    // dummy zero-bytes for prev_hash / row_hash since the read
    // helper doesn't validate the chain (audit-verify does).
    let prev_hash: Vec<u8> = vec![0u8];
    let row_hash: Vec<u8> = vec![1u8];
    sqlx::query!(
        r#"INSERT INTO pds_admin_audit (
             precipitating_action_id, backend_method, backend_action_id,
             outcome, error_code, error_message, retry_after_seconds,
             prev_hash, row_hash, call_started_at, call_completed_at
           )
           VALUES (?1, 'takedown_account', 'backend-id-42', 'success',
                   NULL, NULL, NULL, ?2, ?3, ?4, ?5)"#,
        action_id,
        prev_hash,
        row_hash,
        1_700_000_001_000i64,
        1_700_000_001_500i64,
    )
    .execute(&pool)
    .await
    .unwrap();

    let view = find_pds_admin_audit_for_action(&pool, action_id)
        .await
        .unwrap()
        .expect("found");
    assert_eq!(view.precipitating_action_id, action_id);
    assert_eq!(view.backend_method, "takedown_account");
    assert_eq!(view.backend_action_id.as_deref(), Some("backend-id-42"));
    assert_eq!(view.outcome, "success");
}
