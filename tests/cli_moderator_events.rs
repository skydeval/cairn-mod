//! Integration tests for `cairn moderator events` (#99). Same
//! pattern as `tests/cli_moderator.rs`: calls the orchestrator
//! function directly rather than shelling out to the binary.

use cairn_mod::cli::moderator_events::{EventRow, EventsInput, format_human, format_json, list};
use cairn_mod::storage;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

const ALICE: &str = "did:plc:alice00000000000000000000";
const BOB: &str = "did:plc:bob000000000000000000000000";
const MOD_DID: &str = "did:plc:m00000000000000000000000000";

async fn fresh_pool() -> (TempDir, Pool<Sqlite>) {
    let dir = tempfile::tempdir().unwrap();
    let pool = storage::open(&dir.path().join("cairn.db")).await.unwrap();
    (dir, pool)
}

/// Insert a `subject_action_recorded` audit row + matching
/// subject_actions row directly. Bypasses the writer task because
/// these tests are exercising the read path (`cairn moderator
/// events`); the writer's full pipeline (strike calc, label
/// emission, etc.) is covered elsewhere.
#[allow(clippy::too_many_arguments)]
async fn seed_recorded_action(
    pool: &Pool<Sqlite>,
    audit_id_hint: i64,
    subject_did: &str,
    subject_uri: Option<&str>,
    action_type: &str,
    notes: Option<&str>,
    duration: Option<&str>,
    reason_codes_json: &str,
) -> i64 {
    let _ = audit_id_hint; // SQLite assigns; hint is for test-readability.
    let target = subject_uri.unwrap_or(subject_did);
    let audit_reason = format!(
        r#"{{"action_id": 0, "action_type": "{action_type}", "primary_reason": "spam", "reason_codes": {reason_codes_json}, "strike_value_base": 0, "strike_value_applied": 0, "was_dampened": false}}"#
    );
    let audit_id: i64 = sqlx::query_scalar!(
        r#"INSERT INTO audit_log (created_at, action, actor_did, target, outcome, reason)
           VALUES (?1, 'subject_action_recorded', ?2, ?3, 'success', ?4)
           RETURNING id as "id!: i64""#,
        1_700_000_000_000i64,
        MOD_DID,
        target,
        audit_reason,
    )
    .fetch_one(pool)
    .await
    .unwrap();

    sqlx::query!(
        r#"INSERT INTO subject_actions (
             subject_did, subject_uri, actor_did, action_type, reason_codes,
             duration, effective_at, notes, strike_value_base, strike_value_applied,
             was_dampened, strikes_at_time_of_action, audit_log_id, created_at
           )
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, 0, 0, ?9, ?10)"#,
        subject_did,
        subject_uri,
        MOD_DID,
        action_type,
        reason_codes_json,
        duration,
        1_700_000_000_000i64,
        notes,
        audit_id,
        1_700_000_000_000i64,
    )
    .execute(pool)
    .await
    .unwrap();
    audit_id
}

/// Insert a cairn-mod-internal audit row (no subject_actions
/// link). Used to verify the filter-out policy.
async fn seed_internal_audit(pool: &Pool<Sqlite>, action: &str) -> i64 {
    sqlx::query_scalar!(
        r#"INSERT INTO audit_log (created_at, action, actor_did, outcome)
           VALUES (?1, ?2, ?3, 'success')
           RETURNING id as "id!: i64""#,
        1_700_000_000_000i64,
        action,
        MOD_DID,
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn empty_db_returns_no_events() {
    let (_d, pool) = fresh_pool().await;
    let resp = list(&pool, EventsInput::default()).await.unwrap();
    assert_eq!(resp.events.len(), 0);
    assert!(resp.cursor.is_none());
}

#[tokio::test]
async fn ozone_only_surfaces_only_eligible_actions() {
    let (_d, pool) = fresh_pool().await;
    seed_recorded_action(&pool, 1, ALICE, None, "warning", None, None, r#"["spam"]"#).await;
    seed_internal_audit(&pool, "retention_sweep").await;
    seed_internal_audit(&pool, "report_resolved").await;
    seed_internal_audit(&pool, "label_applied").await;

    let resp = list(
        &pool,
        EventsInput {
            ozone_only: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Only the warning event surfaces.
    assert_eq!(resp.events.len(), 1);
    assert!(matches!(resp.events[0], EventRow::Ozone(_)));
}

#[tokio::test]
async fn full_mode_surfaces_internal_rows_too() {
    let (_d, pool) = fresh_pool().await;
    seed_recorded_action(&pool, 1, ALICE, None, "warning", None, None, r#"["spam"]"#).await;
    seed_internal_audit(&pool, "retention_sweep").await;
    seed_internal_audit(&pool, "report_resolved").await;

    let resp = list(&pool, EventsInput::default()).await.unwrap();
    assert_eq!(resp.events.len(), 3);
    // One ozone, two internal.
    let ozone_count = resp
        .events
        .iter()
        .filter(|e| matches!(e, EventRow::Ozone(_)))
        .count();
    let internal_count = resp
        .events
        .iter()
        .filter(|e| matches!(e, EventRow::Internal(_)))
        .count();
    assert_eq!(ozone_count, 1);
    assert_eq!(internal_count, 2);
}

#[tokio::test]
async fn full_mode_surfaces_revoked_warning_as_internal() {
    let (_d, pool) = fresh_pool().await;
    let _ = seed_recorded_action(&pool, 1, ALICE, None, "warning", None, None, r#"["spam"]"#).await;
    // Insert a subject_action_revoked audit row pointing at action_id=1 (the warning).
    sqlx::query!(
        r#"INSERT INTO audit_log (created_at, action, actor_did, target, outcome, reason)
           VALUES (?1, 'subject_action_revoked', ?2, '1', 'success', '{"action_id": 1, "revoked_reason": "mistake"}')"#,
        1_700_000_001_000i64,
        MOD_DID,
    )
    .execute(&pool)
    .await
    .unwrap();

    // Full mode: both rows surface; the revoked-warning is
    // Internal-shaped because the projection filtered it out.
    let resp = list(&pool, EventsInput::default()).await.unwrap();
    assert_eq!(resp.events.len(), 2);
    let ozone_count = resp
        .events
        .iter()
        .filter(|e| matches!(e, EventRow::Ozone(_)))
        .count();
    let internal_count = resp
        .events
        .iter()
        .filter(|e| matches!(e, EventRow::Internal(_)))
        .count();
    assert_eq!(ozone_count, 1);
    assert_eq!(internal_count, 1);

    // Ozone-only mode: only the original warning surfaces.
    let resp = list(
        &pool,
        EventsInput {
            ozone_only: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.events.len(), 1);
}

#[tokio::test]
async fn subject_filter_narrows_to_one_did() {
    let (_d, pool) = fresh_pool().await;
    seed_recorded_action(&pool, 1, ALICE, None, "warning", None, None, r#"["spam"]"#).await;
    seed_recorded_action(&pool, 2, BOB, None, "note", None, None, r#"["spam"]"#).await;

    let resp = list(
        &pool,
        EventsInput {
            subject: Some(ALICE.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.events.len(), 1);
    if let EventRow::Ozone(o) = &resp.events[0] {
        assert_eq!(o.subject["did"].as_str(), Some(ALICE));
    } else {
        panic!("expected Ozone variant");
    }
}

#[tokio::test]
async fn actor_filter_narrows() {
    let (_d, pool) = fresh_pool().await;
    seed_recorded_action(&pool, 1, ALICE, None, "warning", None, None, r#"["spam"]"#).await;
    // Insert an internal row by a different actor.
    let other_actor = "did:plc:other00000000000000000000";
    sqlx::query!(
        r#"INSERT INTO audit_log (created_at, action, actor_did, outcome)
           VALUES (?1, 'retention_sweep', ?2, 'success')"#,
        1_700_000_000_000i64,
        other_actor,
    )
    .execute(&pool)
    .await
    .unwrap();

    let resp = list(
        &pool,
        EventsInput {
            actor: Some(other_actor.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.events.len(), 1);
    assert!(matches!(resp.events[0], EventRow::Internal(_)));
}

#[tokio::test]
async fn type_filter_narrows() {
    let (_d, pool) = fresh_pool().await;
    seed_recorded_action(&pool, 1, ALICE, None, "warning", None, None, r#"["spam"]"#).await;
    seed_internal_audit(&pool, "retention_sweep").await;
    seed_internal_audit(&pool, "report_resolved").await;

    let resp = list(
        &pool,
        EventsInput {
            action_type: Some("retention_sweep".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.events.len(), 1);
    if let EventRow::Internal(i) = &resp.events[0] {
        assert_eq!(i.action, "retention_sweep");
    } else {
        panic!("expected Internal variant");
    }
}

#[tokio::test]
async fn pagination_round_trip() {
    let (_d, pool) = fresh_pool().await;
    for _ in 0..5 {
        seed_internal_audit(&pool, "retention_sweep").await;
    }

    // Page 1: limit=2 → 2 events + cursor.
    let resp = list(
        &pool,
        EventsInput {
            limit: Some(2),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.events.len(), 2);
    let cursor = resp.cursor.expect("cursor present");

    // Page 2 + page 3 walk the rest.
    let resp = list(
        &pool,
        EventsInput {
            limit: Some(2),
            cursor: Some(cursor),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.events.len(), 2);
    let cursor = resp.cursor.expect("cursor present");

    let resp = list(
        &pool,
        EventsInput {
            limit: Some(2),
            cursor: Some(cursor),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.events.len(), 1);
    assert!(resp.cursor.is_none());
}

#[tokio::test]
async fn format_renders_mixed_shapes() {
    let (_d, pool) = fresh_pool().await;
    seed_recorded_action(
        &pool,
        1,
        ALICE,
        None,
        "warning",
        Some("warned"),
        None,
        r#"["spam"]"#,
    )
    .await;
    seed_internal_audit(&pool, "retention_sweep").await;

    let resp = list(&pool, EventsInput::default()).await.unwrap();
    let human = format_human(&resp);
    assert!(human.contains("ozone"));
    assert!(human.contains("internal"));
    assert!(human.contains("retention_sweep"));

    let json = format_json(&resp);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let arr = v["events"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
}
