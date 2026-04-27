//! Integration tests for the single-writer task (§F5, §F6).
//!
//! Each test uses a fresh tempfile-backed SQLite database so instance-lease
//! and sequence invariants are exercised against real WAL + migrations,
//! not mocked. `storage::open` runs migrations; `writer::spawn` acquires
//! the lease and bootstraps the `signing_keys` row.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cairn_mod::{
    ApplyLabelRequest, Error, NegateLabelRequest, SigningKey, spawn_writer, storage, verify_label,
};
use proto_blue_crypto::{K256Keypair, Keypair as _, format_multikey};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::task::JoinSet;

const SERVICE_DID: &str = "did:plc:3jzfcijpj2z2a4pdagfkktq6";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";
const TEST_KEY_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

struct TestDb {
    // Keep the TempDir alive for the pool's lifetime; dropping it early
    // removes the SQLite file out from under the pool and produces
    // confusing "disk I/O error" failures.
    _dir: TempDir,
    pool: Pool<Sqlite>,
}

async fn fresh_db() -> TestDb {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.expect("open pool");
    TestDb { _dir: dir, pool }
}

fn test_key() -> SigningKey {
    let bytes: [u8; 32] = hex::decode(TEST_KEY_HEX)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    SigningKey::from_bytes(bytes)
}

fn test_key_multibase() -> String {
    let bytes = hex::decode(TEST_KEY_HEX).expect("hex");
    let kp = K256Keypair::from_private_key(&bytes).expect("keypair");
    format_multikey("ES256K", &kp.public_key_compressed())
}

fn apply_req(uri: &str, val: &str) -> ApplyLabelRequest {
    ApplyLabelRequest {
        actor_did: MODERATOR_DID.to_string(),
        uri: uri.to_string(),
        cid: None,
        val: val.to_string(),
        exp: None,
        moderator_reason: Some("test".to_string()),
    }
}

fn negate_req(uri: &str, val: &str) -> NegateLabelRequest {
    NegateLabelRequest {
        actor_did: MODERATOR_DID.to_string(),
        uri: uri.to_string(),
        val: val.to_string(),
        moderator_reason: None,
    }
}

#[tokio::test]
async fn apply_writes_label_and_audit_and_sig_verifies() {
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
    .expect("spawn");

    let uri = "at://did:plc:subject000000000000000000/app.bsky.feed.post/aaa";
    let event = handle
        .apply_label(apply_req(uri, "spam"))
        .await
        .expect("apply");

    // 1. Sequence is the first row in label_sequence.
    assert_eq!(event.seq, 1);

    // 2. labels row exists and matches the event.
    let row = sqlx::query!(
        "SELECT seq, src, uri, val, neg, cts, sig, signing_key_id FROM labels WHERE seq = ?1",
        event.seq
    )
    .fetch_one(&db.pool)
    .await
    .expect("fetch label");
    assert_eq!(row.src, SERVICE_DID);
    assert_eq!(row.uri, uri);
    assert_eq!(row.val, "spam");
    assert_eq!(row.neg, 0);
    assert_eq!(row.cts, event.label.cts);
    assert_eq!(row.sig.len(), 64);
    assert_eq!(row.signing_key_id, 1);

    // 3. Exactly one audit row, action=label_applied, well-formed reason JSON.
    let audit = sqlx::query!("SELECT action, actor_did, target, outcome, reason FROM audit_log")
        .fetch_all(&db.pool)
        .await
        .expect("fetch audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "label_applied");
    assert_eq!(audit[0].actor_did, MODERATOR_DID);
    assert_eq!(audit[0].target, Some(uri.to_string()));
    assert_eq!(audit[0].outcome, "success");
    let reason_json: serde_json::Value =
        serde_json::from_str(audit[0].reason.as_deref().unwrap()).expect("parse reason json");
    assert_eq!(reason_json["val"], "spam");
    assert_eq!(reason_json["neg"], false);
    assert_eq!(reason_json["moderator_reason"], "test");

    // 4. The signed bytes verify under the key's multibase.
    verify_label(&test_key_multibase(), &event.label).expect("sig verifies");

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn concurrent_applies_produce_contiguous_unique_seqs() {
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
    .expect("spawn");
    let handle = Arc::new(handle);

    const N: usize = 100;
    let mut set = JoinSet::new();
    for i in 0..N {
        let h = handle.clone();
        set.spawn(async move {
            h.apply_label(apply_req(
                &format!("at://did:plc:subject{i:026}/app.bsky.feed.post/x"),
                "spam",
            ))
            .await
        });
    }

    let mut seqs: Vec<i64> = Vec::with_capacity(N);
    while let Some(res) = set.join_next().await {
        seqs.push(res.expect("task").expect("apply").seq);
    }

    seqs.sort_unstable();
    assert_eq!(seqs.len(), N);
    assert_eq!(seqs, (1..=N as i64).collect::<Vec<_>>());

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn rapid_same_tuple_emissions_have_strictly_increasing_cts() {
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
    .expect("spawn");

    let uri = "at://did:plc:subjectX0000000000000000000/app.bsky.feed.post/yyy";
    let e1 = handle.apply_label(apply_req(uri, "spam")).await.unwrap();
    let e2 = handle.apply_label(apply_req(uri, "spam")).await.unwrap();
    let e3 = handle.apply_label(apply_req(uri, "spam")).await.unwrap();

    // cts is a lex-comparable Z-form RFC-3339, so string compare is
    // equivalent to semantic compare here.
    assert!(
        e2.label.cts > e1.label.cts,
        "{} !> {}",
        e2.label.cts,
        e1.label.cts
    );
    assert!(
        e3.label.cts > e2.label.cts,
        "{} !> {}",
        e3.label.cts,
        e2.label.cts
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn negate_flow_and_reapply() {
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
    .expect("spawn");

    let uri = "at://did:plc:subjectZ0000000000000000000/app.bsky.feed.post/zzz";

    // apply, then negate, then negating again must fail.
    let applied = handle.apply_label(apply_req(uri, "spam")).await.unwrap();
    let negated = handle.negate_label(negate_req(uri, "spam")).await.unwrap();

    assert!(negated.seq > applied.seq);
    assert!(negated.label.neg);
    assert!(negated.label.cts > applied.label.cts);
    // Each event has its own signature — not reused from the apply.
    assert_ne!(applied.label.sig, negated.label.sig);
    // Both signatures must verify against the service key.
    verify_label(&test_key_multibase(), &applied.label).expect("apply sig");
    verify_label(&test_key_multibase(), &negated.label).expect("negate sig");

    // Second negate: no currently-applied label for the tuple.
    let err = handle
        .negate_label(negate_req(uri, "spam"))
        .await
        .expect_err("second negate should fail");
    assert!(matches!(err, Error::LabelNotFound { .. }), "got {err:?}");

    // Re-apply after negation produces a fresh event with new seq + cts.
    let reapplied = handle.apply_label(apply_req(uri, "spam")).await.unwrap();
    assert!(reapplied.seq > negated.seq);
    assert!(reapplied.label.cts > negated.label.cts);
    assert!(!reapplied.label.neg);

    // audit_log has 3 rows: apply, negate, re-apply (second-negate failed
    // before the transaction, so no row).
    let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 3);

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn negate_without_prior_apply_returns_label_not_found() {
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
    .expect("spawn");

    let err = handle
        .negate_label(negate_req(
            "at://did:plc:never0000000000000000000000/app.bsky.feed.post/x",
            "spam",
        ))
        .await
        .expect_err("must fail");
    assert!(matches!(err, Error::LabelNotFound { .. }), "got {err:?}");

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn second_spawn_against_live_lease_returns_lease_held() {
    let db = fresh_db().await;
    let first = spawn_writer(
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
    .expect("first spawn");

    // Second spawn against the same pool must fail — the first writer's
    // lease is fresh (we literally just acquired it).
    let err = spawn_writer(
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
    .expect_err("second spawn must fail");
    assert!(matches!(err, Error::LeaseHeld { .. }), "got {err:?}");

    first.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn stale_lease_is_taken_over_on_next_spawn() {
    let db = fresh_db().await;

    // Plant a lease row with a heartbeat older than the 60s staleness
    // threshold. No prior writer — we're setting up the condition that
    // would exist after an unclean shutdown (crashed instance never
    // releasing its lease).
    let stale_heartbeat = (SystemTime::now() - Duration::from_secs(120))
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    sqlx::query!(
        "INSERT INTO server_instance_lease (id, instance_id, acquired_at, last_heartbeat)
         VALUES (1, 'stale-zombie-id', ?1, ?1)",
        stale_heartbeat
    )
    .execute(&db.pool)
    .await
    .unwrap();

    // Spawn should take over the stale lease (INSERT OR REPLACE path).
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
    .expect("spawn must succeed against stale lease");

    let holder: String =
        sqlx::query_scalar!("SELECT instance_id FROM server_instance_lease WHERE id = 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_ne!(holder, "stale-zombie-id");

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn shutdown_releases_lease_row() {
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
    .expect("spawn");

    // Pre-shutdown: row exists.
    let n: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM server_instance_lease")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);

    handle.shutdown().await.expect("shutdown");

    let n: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM server_instance_lease")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn first_spawn_bootstraps_signing_keys_row() {
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
    .expect("spawn");

    let row = sqlx::query!("SELECT public_key_multibase, valid_to FROM signing_keys WHERE id = 1")
        .fetch_one(&db.pool)
        .await
        .expect("fetch signing_key row");
    assert_eq!(row.public_key_multibase, test_key_multibase());
    assert!(row.valid_to.is_none());

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn second_spawn_with_different_key_errors() {
    let db = fresh_db().await;
    let first = spawn_writer(
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
    .expect("first spawn");
    first.shutdown().await.expect("shutdown");

    // Different 32-byte key.
    let other_key = SigningKey::from_bytes([0x11; 32]);
    let err = spawn_writer(
        db.pool.clone(),
        other_key,
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .expect_err("mismatched key must error");

    // Swapping the signing key without going through the (deferred)
    // rotation path is explicitly rejected — §F8.
    match err {
        Error::Signing(msg) => assert!(msg.contains("does not match"), "unexpected msg: {msg}"),
        other => panic!("expected Signing, got {other:?}"),
    }
}

#[tokio::test]
async fn broadcast_delivers_events_to_subscribers() {
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
    .expect("spawn");

    let mut rx = handle.subscribe();
    let event = handle
        .apply_label(apply_req(
            "at://did:plc:bcastSubject00000000000000/app.bsky.feed.post/x",
            "spam",
        ))
        .await
        .unwrap();

    let delivered = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("broadcast timeout")
        .expect("broadcast recv");
    assert_eq!(delivered.seq, event.seq);
    assert_eq!(delivered.label.uri, event.label.uri);

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn apply_with_no_broadcast_receiver_still_succeeds() {
    // Verifies the documented rule that `broadcast::send` returning Err
    // when no receivers exist is NOT a write failure.
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
    .expect("spawn");

    // Nobody has called .subscribe(). The initial receiver created inside
    // spawn is dropped on function return, so there are zero live
    // receivers when this apply fires.
    let event = handle
        .apply_label(apply_req(
            "at://did:plc:nobcast0000000000000000/app.bsky.feed.post/x",
            "spam",
        ))
        .await
        .expect("apply must succeed with no subscribers");
    assert_eq!(event.seq, 1);

    handle.shutdown().await.expect("shutdown");
}

// Heartbeat liveness (`last_heartbeat` actually advances) would require
// sleeping past the 10s interval. That's too slow for the default suite;
// the heartbeat's correctness is indirectly covered by the stale-lease
// takeover test (same code path for insertion) and the shutdown test
// (same DB machinery). When the heartbeat interval becomes configurable,
// add a fast-interval integration test.

// ============ Retention sweep (#12, §F4) ============

/// Helper: spawn a writer with manual-only sweep semantics. Disables the
/// scheduled timer so tests don't race the daily fire and never trigger
/// log noise via the log-and-exit error path; sweeps still run through
/// `WriterHandle::sweep` for test-driven coverage.
async fn spawn_writer_for_sweep_test(
    db: &TestDb,
    retention_days: Option<u32>,
    sweep_batch_size: i64,
) -> cairn_mod::WriterHandle {
    spawn_writer(
        db.pool.clone(),
        test_key(),
        SERVICE_DID.to_string(),
        retention_days,
        cairn_mod::RetentionConfig {
            sweep_enabled: false,
            sweep_run_at_utc_hour: 4,
            sweep_batch_size,
        },
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .expect("spawn writer for sweep test")
}

/// Backdate the `created_at` of label rows by setting it to a fixed
/// epoch-ms value. Used to manufacture "old" rows the sweep should
/// delete without waiting wall-clock time.
async fn backdate_labels(pool: &Pool<Sqlite>, seq_max_inclusive: i64, new_created_at_ms: i64) {
    sqlx::query!(
        "UPDATE labels SET created_at = ?1 WHERE seq <= ?2",
        new_created_at_ms,
        seq_max_inclusive,
    )
    .execute(pool)
    .await
    .expect("backdate UPDATE");
}

async fn count_labels(pool: &Pool<Sqlite>) -> i64 {
    sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n: i64" FROM labels"#)
        .fetch_one(pool)
        .await
        .expect("count")
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_millis() as i64
}

#[tokio::test]
async fn sweep_with_retention_none_is_noop() {
    let db = fresh_db().await;
    let handle = spawn_writer_for_sweep_test(&db, None, 1000).await;

    // Apply a few labels — sweep MUST NOT delete them when
    // retention_days is None (sweep is disabled at the cutoff layer).
    for i in 0..3 {
        let uri = format!("at://did:plc:test{i:05}000000000000000/app.bsky.feed.post/aaa");
        handle.apply_label(apply_req(&uri, "spam")).await.unwrap();
    }
    assert_eq!(count_labels(&db.pool).await, 3);

    let result = handle.sweep(cairn_mod::SweepRequest).await.unwrap();
    assert_eq!(result.rows_deleted, 0, "no-op sweep deletes nothing");
    assert_eq!(result.retention_days_applied, None);
    // One round-trip even on the no-op path; the handle loop counts it.
    assert_eq!(result.batches, 1);

    assert_eq!(count_labels(&db.pool).await, 3, "labels untouched");
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn sweep_empty_table_is_noop() {
    let db = fresh_db().await;
    let handle = spawn_writer_for_sweep_test(&db, Some(30), 1000).await;

    let result = handle.sweep(cairn_mod::SweepRequest).await.unwrap();
    assert_eq!(result.rows_deleted, 0);
    assert_eq!(result.retention_days_applied, Some(30));
    assert_eq!(result.batches, 1, "single empty batch ends the sweep");
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn sweep_deletes_only_old_labels() {
    let db = fresh_db().await;
    let retention_days: u32 = 30;
    let handle = spawn_writer_for_sweep_test(&db, Some(retention_days), 1000).await;

    // Five labels — all created "now" by the writer.
    for i in 0..5 {
        let uri = format!("at://did:plc:test{i:05}000000000000000/app.bsky.feed.post/aaa");
        handle.apply_label(apply_req(&uri, "spam")).await.unwrap();
    }
    assert_eq!(count_labels(&db.pool).await, 5);

    // Backdate seq=1..=3 to older than the cutoff. Pick "cutoff - 1
    // hour" so they're unambiguously beyond retention.
    let cutoff_ms = current_time_ms() - (retention_days as i64) * 86_400_000;
    backdate_labels(&db.pool, 3, cutoff_ms - 3_600_000).await;

    let result = handle.sweep(cairn_mod::SweepRequest).await.unwrap();
    assert_eq!(result.rows_deleted, 3, "exactly the backdated rows");
    assert_eq!(result.retention_days_applied, Some(retention_days));

    // Only seq=4..=5 remain.
    let remaining = sqlx::query_scalar!(r#"SELECT seq AS "seq!: i64" FROM labels ORDER BY seq"#)
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert_eq!(remaining, vec![4, 5]);
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn sweep_completes_full_run_across_multiple_batches() {
    let db = fresh_db().await;
    let retention_days: u32 = 30;
    // Tiny batch_size forces multi-batch execution.
    let handle = spawn_writer_for_sweep_test(&db, Some(retention_days), 3).await;

    // Seven labels, all backdated → sweep deletes them across
    // ceil(7/3) = 3 batches (3 + 3 + 1).
    for i in 0..7 {
        let uri = format!("at://did:plc:test{i:05}000000000000000/app.bsky.feed.post/aaa");
        handle.apply_label(apply_req(&uri, "spam")).await.unwrap();
    }
    let cutoff_ms = current_time_ms() - (retention_days as i64) * 86_400_000;
    backdate_labels(&db.pool, 7, cutoff_ms - 3_600_000).await;

    let result = handle.sweep(cairn_mod::SweepRequest).await.unwrap();
    assert_eq!(result.rows_deleted, 7);
    // Three full deletion batches + one terminating partial-batch
    // round-trip that sees rows_deleted == 0 OR < limit. The handle
    // counts it, so total is 3 (last batch returns 1 row, < limit=3,
    // so has_more=false on that batch — total 3 batches).
    assert_eq!(result.batches, 3);
    assert_eq!(count_labels(&db.pool).await, 0);
    handle.shutdown().await.unwrap();
}

/// LOAD-BEARING TEST per #12 verification requirements: the
/// subscribeLabels retention floor (`current_retention_floor`)
/// must return the SAME value before and after a sweep, for the
/// same `retention_days` config. The floor is computed by SQL
/// filter (`WHERE created_at >= cutoff`), so deleting rows that
/// would have been excluded anyway must not move the floor.
///
/// If a future "optimization" switches floor computation from
/// live SQL to a stored value (e.g., a `last_swept_seq` column),
/// this test catches the regression — the floor would shift to
/// the stored sweep marker and the assertion fails.
#[tokio::test]
async fn sweep_does_not_change_subscriber_visible_floor() {
    let db = fresh_db().await;
    let retention_days: u32 = 30;
    let handle = spawn_writer_for_sweep_test(&db, Some(retention_days), 1000).await;

    // Five labels: backdate the first three, leave seq=4..=5 fresh.
    for i in 0..5 {
        let uri = format!("at://did:plc:test{i:05}000000000000000/app.bsky.feed.post/aaa");
        handle.apply_label(apply_req(&uri, "spam")).await.unwrap();
    }
    let cutoff_ms = current_time_ms() - (retention_days as i64) * 86_400_000;
    backdate_labels(&db.pool, 3, cutoff_ms - 3_600_000).await;

    let floor_pre = cairn_mod::current_retention_floor(&db.pool, Some(retention_days))
        .await
        .unwrap();
    assert_eq!(
        floor_pre,
        Some(4),
        "floor before sweep must be the oldest visible (non-expired) seq"
    );

    let result = handle.sweep(cairn_mod::SweepRequest).await.unwrap();
    assert_eq!(result.rows_deleted, 3, "sweep deleted the backdated rows");

    let floor_post = cairn_mod::current_retention_floor(&db.pool, Some(retention_days))
        .await
        .unwrap();
    assert_eq!(
        floor_pre, floor_post,
        "the live retention floor MUST be invariant under sweep — \
         this is the §F4 contract that makes the cursor-floor protocol \
         work without a sweep-aware coordination step"
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn concurrent_apply_and_sweep_serialize_through_writer() {
    let db = fresh_db().await;
    let retention_days: u32 = 30;
    // Tiny batch forces multi-batch sweep so the inter-batch yield
    // window is non-trivial.
    let handle = spawn_writer_for_sweep_test(&db, Some(retention_days), 2).await;
    let handle = Arc::new(handle);

    // Seed: ten labels, backdated so the sweep will delete them.
    for i in 0..10 {
        let uri = format!("at://did:plc:seed{i:05}0000000000000000/app.bsky.feed.post/aaa");
        handle.apply_label(apply_req(&uri, "spam")).await.unwrap();
    }
    let cutoff_ms = current_time_ms() - (retention_days as i64) * 86_400_000;
    backdate_labels(&db.pool, 10, cutoff_ms - 3_600_000).await;

    // Run sweep + a parallel stream of fresh apply calls. Both
    // futures must complete; ordering is whatever the writer's
    // biased select decides (Apply preferred over Sweep batches).
    let sweep_handle = handle.clone();
    let sweep_fut = tokio::spawn(async move { sweep_handle.sweep(cairn_mod::SweepRequest).await });

    let mut apply_set = JoinSet::new();
    for i in 0..5 {
        let h = handle.clone();
        apply_set.spawn(async move {
            let uri = format!("at://did:plc:fresh{i:05}000000000000000/app.bsky.feed.post/bbb");
            h.apply_label(apply_req(&uri, "abuse")).await
        });
    }

    let sweep_result = sweep_fut.await.unwrap().unwrap();
    while let Some(res) = apply_set.join_next().await {
        let event = res.unwrap().unwrap();
        // Each fresh apply must succeed and produce a label event.
        assert!(event.seq > 0);
    }

    // Sweep deleted the ten backdated rows.
    assert_eq!(sweep_result.rows_deleted, 10);

    // Five fresh labels remain (the seq counter never reuses values,
    // so even if the seq numbers are interleaved with the sweep, the
    // count of remaining rows is exactly the five fresh ones).
    let remaining = count_labels(&db.pool).await;
    assert_eq!(
        remaining, 5,
        "fresh applies survived alongside the in-flight sweep"
    );
    Arc::try_unwrap(handle)
        .expect("only one handle ref remains")
        .shutdown()
        .await
        .unwrap();
}
