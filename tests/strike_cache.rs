//! Integration tests for the subject-strike-state cache management
//! module (`crate::moderation::cache`, #55).
//!
//! Coverage:
//! - The recorder's existing write-through path populates the
//!   cache on every `recordAction` (already true from #51; pinned
//!   here as an explicit end-to-end test).
//! - `get_or_recompute_strike_count` against a real SQLite DB
//!   matches what the decay calculator (#50) produces from the
//!   same history.
//! - Stale cache triggers a recompute + write-back; fresh cache
//!   returns without recomputing (last_recompute_at unchanged).
//! - Missing cache (never-actioned subject) returns
//!   `Error::StrikeCacheMissing`.

use std::time::{Duration, SystemTime};

use cairn_mod::error::Error;
use cairn_mod::labels::policy::LabelEmissionPolicy;
use cairn_mod::moderation::cache::{
    cache_is_fresh, get_or_recompute_strike_count, load_cache, update_cache,
};
use cairn_mod::moderation::policy::StrikePolicy;
use cairn_mod::moderation::reasons::ReasonVocabulary;
use cairn_mod::moderation::types::ActionType;
use cairn_mod::policy::automation::PolicyAutomationPolicy;
use cairn_mod::{ApplyLabelRequest, RecordActionRequest, SigningKey, spawn_writer, storage};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const ACTOR_DID: &str = "did:plc:moderator0000000000000000";
const SUBJECT_DID: &str = "did:plc:subject000000000000000000";

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    writer: cairn_mod::WriterHandle,
}

async fn spawn() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();
    let writer = spawn_writer(
        pool.clone(),
        SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        ReasonVocabulary::defaults(),
        StrikePolicy::defaults(),
        LabelEmissionPolicy::defaults(),
        PolicyAutomationPolicy::defaults(),
    )
    .await
    .unwrap();
    Harness {
        _dir: dir,
        pool,
        writer,
    }
}

/// Send a takedown via the writer's `RecordAction` path. Returns
/// the inserted action_id.
async fn record_takedown(h: &Harness, reasons: &[&str]) -> i64 {
    let req = RecordActionRequest {
        subject: SUBJECT_DID.to_string(),
        actor_did: ACTOR_DID.to_string(),
        action_type: ActionType::Takedown,
        reason_codes: reasons.iter().map(|s| s.to_string()).collect(),
        duration_iso: None,
        notes: None,
        report_ids: vec![],
    };
    let resp = h.writer.record_action(req).await.unwrap();
    resp.action_id
}

#[tokio::test]
async fn record_action_writes_through_to_cache() {
    let h = spawn().await;
    record_takedown(&h, &["hate-speech"]).await;

    // After the recorder's UPSERT, the cache row exists.
    let cache = load_cache(&h.pool, SUBJECT_DID)
        .await
        .unwrap()
        .expect("cache row present after recordAction");
    assert_eq!(cache.subject_did, SUBJECT_DID);
    // First offense in good standing → curve[0] = 1 (default policy).
    assert_eq!(cache.current_strike_count, 1);
    assert!(cache.last_action_at.is_some());
}

#[tokio::test]
async fn missing_cache_returns_strike_cache_missing() {
    let h = spawn().await;
    let policy = StrikePolicy::defaults();
    let now = SystemTime::now();
    let err = get_or_recompute_strike_count(&h.pool, SUBJECT_DID, &policy, now)
        .await
        .expect_err("never-actioned subject must error");
    match err {
        Error::StrikeCacheMissing(did) => assert_eq!(did, SUBJECT_DID),
        other => panic!("expected StrikeCacheMissing, got {other:?}"),
    }
}

#[tokio::test]
async fn fresh_cache_returns_cached_count_without_recomputing() {
    let h = spawn().await;
    record_takedown(&h, &["hate-speech"]).await;

    // Sanity: cache row holds count=1 (curve[0] for the first
    // offense). Capture last_recompute_at before the read.
    let before = load_cache(&h.pool, SUBJECT_DID).await.unwrap().unwrap();
    let original_recompute = before.last_recompute_at;

    let policy = StrikePolicy::defaults();
    // Use the writer's just-written timestamp as `now` so the cache
    // is freshly within the window.
    let count = get_or_recompute_strike_count(
        &h.pool,
        SUBJECT_DID,
        &policy,
        original_recompute + Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(count, 1);

    // last_recompute_at unchanged → no recompute fired.
    let after = load_cache(&h.pool, SUBJECT_DID).await.unwrap().unwrap();
    assert_eq!(
        after.last_recompute_at, original_recompute,
        "fresh-cache path must not write back"
    );
}

#[tokio::test]
async fn stale_cache_triggers_recompute_and_writeback() {
    let h = spawn().await;
    record_takedown(&h, &["hate-speech"]).await;

    let before = load_cache(&h.pool, SUBJECT_DID).await.unwrap().unwrap();
    let original_recompute = before.last_recompute_at;

    let mut policy = StrikePolicy::defaults();
    policy.cache_freshness_window_seconds = 60;
    // Move `now` 2 hours past last_recompute → stale.
    let now = original_recompute + Duration::from_secs(7200);

    let count = get_or_recompute_strike_count(&h.pool, SUBJECT_DID, &policy, now)
        .await
        .unwrap();
    // Default decay: linear, 90-day window. 2 hours of decay on a
    // 1-strike count yields essentially 1 still (1 * (1 - tiny)
    // rounds to 1).
    assert_eq!(count, 1);

    // last_recompute_at advanced → write-back fired.
    let after = load_cache(&h.pool, SUBJECT_DID).await.unwrap().unwrap();
    assert!(
        after.last_recompute_at > original_recompute,
        "stale-cache path must write back"
    );
}

#[tokio::test]
async fn stale_cache_recompute_matches_calculator_after_decay() {
    let h = spawn().await;
    record_takedown(&h, &["hate-speech"]).await;

    let before = load_cache(&h.pool, SUBJECT_DID).await.unwrap().unwrap();
    let original_recompute = before.last_recompute_at;

    // Move `now` 45 days past last_recompute → halfway through the
    // 90-day linear decay window. count = round(1 * 0.5) = 1
    // (rounding up; ties to even on .round()). A 1-strike row
    // halfway through decay still rounds to 1 because round(0.5)
    // → 1 in IEEE 754 ties-to-even when the value is exactly 0.5
    // … but `1.0 * (1.0 - 45.0/90.0)` is exactly 0.5, and Rust's
    // f64::round() rounds half away from zero (returns 1.0). So
    // we expect 1.
    //
    // Pick 60 days instead — clearly past the half: 1 * (1 -
    // 60/90) = 0.333 → rounds to 0.
    let mut policy = StrikePolicy::defaults();
    policy.cache_freshness_window_seconds = 60;
    let now = original_recompute + Duration::from_secs(60 * 86_400);

    let count = get_or_recompute_strike_count(&h.pool, SUBJECT_DID, &policy, now)
        .await
        .unwrap();
    assert_eq!(count, 0, "60 days into 90-day linear decay rounds to 0");

    let after = load_cache(&h.pool, SUBJECT_DID).await.unwrap().unwrap();
    assert_eq!(after.current_strike_count, 0);
}

#[tokio::test]
async fn update_cache_creates_row_if_absent() {
    // Defense-in-depth: the public surface forbids calling
    // get_or_recompute_strike_count on a never-actioned subject
    // (StrikeCacheMissing error), but update_cache() itself is
    // also exposed and must do the right thing on a fresh insert.
    let h = spawn().await;
    let now = SystemTime::now();
    update_cache(&h.pool, SUBJECT_DID, 4, now).await.unwrap();
    let row = load_cache(&h.pool, SUBJECT_DID).await.unwrap().unwrap();
    assert_eq!(row.current_strike_count, 4);
    // Insert path leaves last_action_at NULL (this isn't an action).
    assert!(row.last_action_at.is_none());
}

#[tokio::test]
async fn cache_is_fresh_against_real_cache_row() {
    // Pin that cache_is_fresh works on a real loaded cache row,
    // not just the unit-test struct fixture.
    let h = spawn().await;
    record_takedown(&h, &["hate-speech"]).await;
    let cache = load_cache(&h.pool, SUBJECT_DID).await.unwrap().unwrap();

    // 30 minutes in the future from last_recompute → still fresh
    // under the default 1-hour window.
    let now = cache.last_recompute_at + Duration::from_secs(1800);
    assert!(cache_is_fresh(&cache, Duration::from_secs(3600), now));

    // 2 hours in the future → stale.
    let now = cache.last_recompute_at + Duration::from_secs(7200);
    assert!(!cache_is_fresh(&cache, Duration::from_secs(3600), now));
}

// `_apply_label_unused` placates the `unused_imports` lint —
// `ApplyLabelRequest` is imported alongside the other writer types
// so future tests in this file (e.g., interaction between label
// writes + strike cache) can use it without re-adding the import.
#[allow(dead_code)]
fn _apply_label_unused() -> ApplyLabelRequest {
    ApplyLabelRequest {
        actor_did: ACTOR_DID.into(),
        uri: "at://did:plc:x/c/r".into(),
        cid: None,
        val: "spam".into(),
        exp: None,
        moderator_reason: None,
    }
}
