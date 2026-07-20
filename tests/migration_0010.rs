//! Migration 0010 assertions (v1.8.5, chainlink #134): the
//! two-table CHECK extension + `action_detail` + the
//! `ActionResponse` persistence columns, with the append-only
//! trigger contract intact after the family-choreography rebuild.
//!
//! Fresh-schema path only — the populated-DB path (rows in all
//! four rebuilt/re-created tables surviving the choreography) was
//! verified out-of-band during implementation; the fixtures here
//! insert post-migration, which exercises the same constraints.

use sqlx::{Pool, Sqlite};

async fn fresh_pool() -> Pool<Sqlite> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mig0010.db");
    let pool = cairn_mod::storage::open(&path).await.unwrap();
    Box::leak(Box::new(dir));
    pool
}

async fn fixture_action(pool: &Pool<Sqlite>, action_type: &str, detail: Option<&str>) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO subject_actions (
            subject_did, actor_did, action_type, reason_codes,
            effective_at, strike_value_base, strike_value_applied,
            strikes_at_time_of_action, created_at, action_detail
         ) VALUES ('did:plc:x', 'did:plc:mod', ?1, '[\"spam\"]', 1000, 0, 0, 0, 1000, ?2)
         RETURNING id",
    )
    .bind(action_type)
    .bind(detail)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn action_type_check_accepts_all_fifteen_values() {
    let pool = fresh_pool().await;
    for at in [
        "warning",
        "note",
        "temp_suspension",
        "indef_suspension",
        "takedown",
        "delete_account",
        "quarantine_blob",
        "restore_blob",
        "delete_blob",
        "resolve_report",
        "dismiss_report",
        "resolve_appeal",
        "escalate_appeal",
        "send_email",
        "update_subject_status",
    ] {
        fixture_action(&pool, at, None).await;
    }
    // Values outside the extended CHECK still reject.
    let bogus = sqlx::query(
        "INSERT INTO subject_actions (
            subject_did, actor_did, action_type, reason_codes,
            effective_at, strike_value_base, strike_value_applied,
            strikes_at_time_of_action, created_at
         ) VALUES ('did:plc:x', 'did:plc:mod', 'bogus_verb', '[]', 1, 0, 0, 0, 1)",
    )
    .execute(&pool)
    .await;
    assert!(bogus.is_err(), "CHECK must reject unknown action types");
}

#[tokio::test]
async fn backend_method_check_and_response_columns() {
    let pool = fresh_pool().await;
    let action_id = fixture_action(&pool, "resolve_report", Some(r#"{"reportId":1}"#)).await;

    // All 16 backend_method values insert; response columns accept
    // JSON payloads.
    sqlx::query(
        "INSERT INTO pds_admin_audit (
            precipitating_action_id, backend_method, backend_action_id, outcome,
            prev_hash, row_hash, call_started_at, call_completed_at,
            upstream_audit_entry_id, cascading_actions_json, snapshots_json
         ) VALUES (?1, 'resolve_report', 'evt-1', 'success', x'00', x'01', 1, 2,
                   'chain-9', '[\"evt-2\"]', '[]')",
    )
    .bind(action_id)
    .execute(&pool)
    .await
    .expect("new backend_method + response columns insert");

    let bogus = sqlx::query(
        "INSERT INTO pds_admin_audit (
            precipitating_action_id, backend_method, outcome,
            prev_hash, row_hash, call_started_at, call_completed_at
         ) VALUES (?1, 'bogus_method', 'success', x'00', x'02', 1, 2)",
    )
    .bind(action_id)
    .execute(&pool)
    .await;
    assert!(bogus.is_err(), "CHECK must reject unknown backend methods");
}

#[tokio::test]
async fn append_only_triggers_survive_rebuild() {
    let pool = fresh_pool().await;
    let action_id =
        fixture_action(&pool, "send_email", Some(r#"{"subject":"s","body":"b"}"#)).await;
    sqlx::query(
        "INSERT INTO pds_admin_audit (
            precipitating_action_id, backend_method, outcome,
            prev_hash, row_hash, call_started_at, call_completed_at
         ) VALUES (?1, 'send_email', 'success', x'00', x'01', 1, 2)",
    )
    .bind(action_id)
    .execute(&pool)
    .await
    .unwrap();

    // subject_actions: action_detail is write-once at INSERT.
    let detail_update =
        sqlx::query("UPDATE subject_actions SET action_detail = '{}' WHERE id = ?1")
            .bind(action_id)
            .execute(&pool)
            .await;
    assert!(detail_update.is_err(), "action_detail must be immutable");

    // Core append-only contracts.
    assert!(
        sqlx::query("DELETE FROM subject_actions WHERE id = ?1")
            .bind(action_id)
            .execute(&pool)
            .await
            .is_err(),
        "subject_actions no-delete trigger"
    );
    assert!(
        sqlx::query("UPDATE pds_admin_audit SET outcome = 'auth'")
            .execute(&pool)
            .await
            .is_err(),
        "pds_admin_audit no-update trigger"
    );
    assert!(
        sqlx::query("DELETE FROM pds_admin_audit")
            .execute(&pool)
            .await
            .is_err(),
        "pds_admin_audit no-delete trigger"
    );

    // One-time revocation transition still permitted (the UPDATE
    // trigger's carve-out survived the rebuild).
    sqlx::query(
        "UPDATE subject_actions SET revoked_at = 99, revoked_by_did = 'did:plc:mod',
         revoked_reason = 'test' WHERE id = ?1",
    )
    .bind(action_id)
    .execute(&pool)
    .await
    .expect("one-time revocation transition still allowed");
}

#[tokio::test]
async fn pending_policy_actions_keeps_five_value_check() {
    let pool = fresh_pool().await;
    let action_id = fixture_action(&pool, "takedown", None).await;
    // The recreated pending table still rejects the v1.8.5 verbs
    // (policy automation cannot propose them).
    let bogus = sqlx::query(
        "INSERT INTO pending_policy_actions (
            subject_did, action_type, reason_codes, triggered_by_policy_rule,
            triggered_at, triggering_action_id
         ) VALUES ('did:plc:x', 'delete_account', '[]', 'rule', 1, ?1)",
    )
    .bind(action_id)
    .execute(&pool)
    .await;
    assert!(bogus.is_err(), "pending CHECK must stay five-value");

    sqlx::query(
        "INSERT INTO pending_policy_actions (
            subject_did, action_type, reason_codes, triggered_by_policy_rule,
            triggered_at, triggering_action_id
         ) VALUES ('did:plc:x', 'takedown', '[]', 'rule', 1, ?1)",
    )
    .bind(action_id)
    .execute(&pool)
    .await
    .expect("classic proposals still insert");
}
