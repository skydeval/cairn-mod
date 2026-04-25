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
