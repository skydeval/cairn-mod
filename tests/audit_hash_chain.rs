//! End-to-end integration tests for audit-log hash-chaining (#39).
//!
//! Coverage:
//! - Writer-internal append (via apply_label) populates prev_hash +
//!   row_hash; chain links across successive writer-task writes.
//! - Cross-process append (via append_via_pool) produces hashes that
//!   match what a recomputation from the stored content would yield.
//! - Tampering detection: altering the stored row content makes the
//!   recomputed hash diverge from the stored row_hash.
//! - Pool-direct vs writer-task parity: identical row content + same
//!   prev_hash produce identical row_hash, regardless of which append
//!   path wrote it. Pins the no-drift contract from #39's design.

use cairn_mod::audit::append::{AuditRowForAppend, append_via_pool};
use cairn_mod::audit::hash::{
    AuditRowForHashing, GENESIS_PREV_HASH, compute_audit_row_hash, parse_stored_hash,
};
use cairn_mod::{ApplyLabelRequest, NegateLabelRequest, SigningKey, spawn_writer, storage};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

const SERVICE_DID: &str = "did:plc:3jzfcijpj2z2a4pdagfkktq6";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";
const TEST_KEY_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

struct TestDb {
    _dir: TempDir,
    pool: Pool<Sqlite>,
}

async fn fresh_db() -> TestDb {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();
    TestDb { _dir: dir, pool }
}

fn test_key() -> SigningKey {
    let bytes: [u8; 32] = hex::decode(TEST_KEY_HEX).unwrap().try_into().unwrap();
    SigningKey::from_bytes(bytes)
}

#[tokio::test]
async fn apply_label_writes_genesis_chained_audit_row() {
    let db = fresh_db().await;
    let handle = spawn_writer(
        db.pool.clone(),
        test_key(),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();

    handle
        .apply_label(ApplyLabelRequest {
            actor_did: MODERATOR_DID.into(),
            uri: "at://did:plc:subject/col/r".into(),
            cid: None,
            val: "spam".into(),
            exp: None,
            moderator_reason: Some("test".into()),
        })
        .await
        .unwrap();

    let row = sqlx::query!(
        "SELECT created_at, action, actor_did, target, target_cid, outcome, reason,
                prev_hash, row_hash
         FROM audit_log ORDER BY id DESC LIMIT 1"
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();

    let prev = row.prev_hash.expect("prev_hash present on v1.3 row");
    let stored_row_hash = row.row_hash.expect("row_hash present on v1.3 row");
    assert_eq!(
        prev.as_slice(),
        GENESIS_PREV_HASH,
        "first row's prev_hash must be GENESIS"
    );

    // Recompute from the stored content; must match stored row_hash.
    let prev_arr = parse_stored_hash(&prev).unwrap();
    let recomputed = compute_audit_row_hash(
        &prev_arr,
        &AuditRowForHashing {
            created_at: row.created_at,
            action: &row.action,
            actor_did: &row.actor_did,
            target: row.target.as_deref(),
            target_cid: row.target_cid.as_deref(),
            outcome: &row.outcome,
            reason: row.reason.as_deref(),
        },
    )
    .unwrap();
    assert_eq!(
        recomputed.to_vec(),
        stored_row_hash,
        "stored row_hash must match recomputation from stored content"
    );

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn successive_writer_writes_chain_via_prev_hash() {
    let db = fresh_db().await;
    let handle = spawn_writer(
        db.pool.clone(),
        test_key(),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();

    handle
        .apply_label(ApplyLabelRequest {
            actor_did: MODERATOR_DID.into(),
            uri: "at://did:plc:subject/col/r".into(),
            cid: None,
            val: "spam".into(),
            exp: None,
            moderator_reason: None,
        })
        .await
        .unwrap();
    handle
        .negate_label(NegateLabelRequest {
            actor_did: MODERATOR_DID.into(),
            uri: "at://did:plc:subject/col/r".into(),
            val: "spam".into(),
            moderator_reason: None,
        })
        .await
        .unwrap();

    let rows = sqlx::query!(
        r#"SELECT id, prev_hash AS "prev_hash!", row_hash AS "row_hash!"
           FROM audit_log ORDER BY id ASC"#
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].prev_hash, GENESIS_PREV_HASH);
    assert_eq!(
        rows[1].prev_hash, rows[0].row_hash,
        "row 2's prev_hash must equal row 1's row_hash"
    );

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn tampered_row_recomputation_diverges_from_stored_hash() {
    // The chain's integrity property: if an attacker (with DB file
    // access, post-trigger-drop) modifies a row's content, recomputing
    // the row_hash from the new content yields a different hash than
    // what's stored. The verify path (#41) uses exactly this check.
    let db = fresh_db().await;
    let handle = spawn_writer(
        db.pool.clone(),
        test_key(),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();

    handle
        .apply_label(ApplyLabelRequest {
            actor_did: MODERATOR_DID.into(),
            uri: "at://did:plc:subject/col/r".into(),
            cid: None,
            val: "spam".into(),
            exp: None,
            moderator_reason: None,
        })
        .await
        .unwrap();

    let row = sqlx::query!(
        "SELECT created_at, action, actor_did, target, target_cid, outcome, reason,
                prev_hash, row_hash
         FROM audit_log ORDER BY id DESC LIMIT 1"
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();

    let stored_row_hash = row.row_hash.unwrap();
    let prev_arr = parse_stored_hash(&row.prev_hash.unwrap()).unwrap();

    // Recompute with the action altered — simulates a tampering edit.
    let tampered = compute_audit_row_hash(
        &prev_arr,
        &AuditRowForHashing {
            created_at: row.created_at,
            action: "label_negated", // <- altered from "label_applied"
            actor_did: &row.actor_did,
            target: row.target.as_deref(),
            target_cid: row.target_cid.as_deref(),
            outcome: &row.outcome,
            reason: row.reason.as_deref(),
        },
    )
    .unwrap();
    assert_ne!(
        tampered.to_vec(),
        stored_row_hash,
        "altered content must produce a different hash than stored"
    );

    // Recompute with the actor altered — same property.
    let tampered2 = compute_audit_row_hash(
        &prev_arr,
        &AuditRowForHashing {
            created_at: row.created_at,
            action: &row.action,
            actor_did: "did:plc:attacker0000000000000000000",
            target: row.target.as_deref(),
            target_cid: row.target_cid.as_deref(),
            outcome: &row.outcome,
            reason: row.reason.as_deref(),
        },
    )
    .unwrap();
    assert_ne!(tampered2.to_vec(), stored_row_hash);

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn writer_task_and_pool_direct_paths_produce_identical_row_hash() {
    // The no-drift contract from #39's design: append_via_pool and
    // append_in_tx (used internally by the writer task and other
    // in-process callers) must compute the same row_hash for the same
    // input. Both paths route through compute_audit_row_hash, so a
    // divergence here means the hash implementation has split between
    // the two call sites.
    let row = AuditRowForAppend {
        created_at: 1_776_902_400_000,
        action: "service_record_published".into(),
        actor_did: "did:plc:operator00000000000000000".into(),
        target: None,
        target_cid: Some("bafytest".into()),
        outcome: "success".into(),
        reason: Some(
            r#"{"cid":"bafytest","content_hash_hex":"deadbeef","content_changed":true}"#.into(),
        ),
    };

    // Path A: pool-direct (cross-process CLI shape).
    let db_a = fresh_db().await;
    let id_a = append_via_pool(&db_a.pool, &row).await.unwrap();
    let hash_a: Vec<u8> = sqlx::query_scalar!(
        r#"SELECT row_hash AS "row_hash!" FROM audit_log WHERE id = ?1"#,
        id_a
    )
    .fetch_one(&db_a.pool)
    .await
    .unwrap();

    // Path B: writer-task (sends WriteCommand::AppendAudit). The
    // writer's handle_append_audit opens its own tx and calls the
    // same append_in_tx the pool-direct path uses.
    let db_b = fresh_db().await;
    let handle = spawn_writer(
        db_b.pool.clone(),
        test_key(),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();
    let id_b = handle.append_audit(row.clone()).await.unwrap();
    let hash_b: Vec<u8> = sqlx::query_scalar!(
        r#"SELECT row_hash AS "row_hash!" FROM audit_log WHERE id = ?1"#,
        id_b
    )
    .fetch_one(&db_b.pool)
    .await
    .unwrap();

    assert_eq!(
        hash_a, hash_b,
        "pool-direct and writer-task paths must produce identical row_hash for identical input"
    );

    handle.shutdown().await.unwrap();
}
