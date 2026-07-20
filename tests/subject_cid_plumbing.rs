//! v1.8.3 Workstream B integration tests: `subject_cid` plumbing
//! (per-release doc §4.5, §8).
//!
//! - Migration 0009: column exists post-migration; the rebuilt
//!   append-only trigger guards `subject_cid` AND preserves the
//!   one-time revocation carve-out and the 0004/0005 clauses.
//! - Dual CID sourcing at the recordAction writer: request-level
//!   CID wins; report-join fallback fires only for reports whose
//!   `subject_uri` matches; neither source → NULL.
//! - Legacy-shape regression: record-targeted rows without a CID
//!   keep rejecting at dispatch (v1.8.2's no-fallback routing) —
//!   covered by the dispatch unit tests; here we pin the row-level
//!   NULL that drives that path.

use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

const SERVICE_DID: &str = "did:plc:3jzfcijpj2z2a4pdagfkktq6";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";
const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    writer: cairn_mod::WriterHandle,
}

async fn spawn() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = cairn_mod::storage::open(&path).await.unwrap();
    let writer = cairn_mod::spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
        cairn_mod::PolicyAutomationPolicy::defaults(),
    )
    .await
    .unwrap();
    Harness {
        _dir: dir,
        pool,
        writer,
    }
}

fn record_req(subject: &str) -> cairn_mod::writer::RecordActionRequest {
    cairn_mod::writer::RecordActionRequest {
        subject: subject.to_string(),
        actor_did: MODERATOR_DID.to_string(),
        action_type: cairn_mod::moderation::types::ActionType::Takedown,
        reason_codes: vec!["spam".into()],
        duration_iso: None,
        notes: None,
        report_ids: Vec::new(),
        subject_cid: None,
        detail: None,
    }
}

async fn stored_cid(pool: &Pool<Sqlite>, action_id: i64) -> Option<String> {
    sqlx::query_scalar("SELECT subject_cid FROM subject_actions WHERE id = ?1")
        .bind(action_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn insert_report(
    pool: &Pool<Sqlite>,
    subject_did: &str,
    subject_uri: Option<&str>,
    subject_cid: Option<&str>,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO reports (
            created_at, reported_by, reason_type, reason, subject_type,
            subject_did, subject_uri, subject_cid, status
         ) VALUES ('2026-07-20T00:00:00Z', 'did:plc:reporter', 'com.atproto.moderation.defs#reasonSpam',
                   NULL, ?1, ?2, ?3, ?4, 'pending')
         RETURNING id",
    )
    .bind(if subject_uri.is_some() { "record" } else { "account" })
    .bind(subject_did)
    .bind(subject_uri)
    .bind(subject_cid)
    .fetch_one(pool)
    .await
    .unwrap()
}

// =========================================================================
// Dual CID sourcing (§4.5)
// =========================================================================

#[tokio::test]
async fn request_level_cid_is_stored() {
    let h = spawn().await;
    let uri = "at://did:plc:subject000000000000000000/app.bsky.feed.post/r1";
    let mut req = record_req(uri);
    req.subject_cid = Some("bafyreq".to_string());
    let recorded = h.writer.record_action(req).await.unwrap();
    assert_eq!(
        stored_cid(&h.pool, recorded.action_id).await.as_deref(),
        Some("bafyreq")
    );
}

#[tokio::test]
async fn report_join_fallback_populates_cid_for_matching_uri() {
    let h = spawn().await;
    let did = "did:plc:subject000000000000000000";
    let uri = format!("at://{did}/app.bsky.feed.post/r2");
    let report_id = insert_report(&h.pool, did, Some(&uri), Some("bafyjoined")).await;

    let mut req = record_req(&uri);
    req.report_ids = vec![report_id];
    let recorded = h.writer.record_action(req).await.unwrap();
    assert_eq!(
        stored_cid(&h.pool, recorded.action_id).await.as_deref(),
        Some("bafyjoined")
    );
}

#[tokio::test]
async fn report_join_ignores_reports_about_other_records() {
    // A referenced report about a DIFFERENT record must never
    // donate its CID (URI-match guard in the join).
    let h = spawn().await;
    let did = "did:plc:subject000000000000000000";
    let action_uri = format!("at://{did}/app.bsky.feed.post/target");
    let other_uri = format!("at://{did}/app.bsky.feed.post/other");
    let report_id = insert_report(&h.pool, did, Some(&other_uri), Some("bafywrong")).await;

    let mut req = record_req(&action_uri);
    req.report_ids = vec![report_id];
    let recorded = h.writer.record_action(req).await.unwrap();
    assert_eq!(stored_cid(&h.pool, recorded.action_id).await, None);
}

#[tokio::test]
async fn request_cid_wins_over_report_join() {
    let h = spawn().await;
    let did = "did:plc:subject000000000000000000";
    let uri = format!("at://{did}/app.bsky.feed.post/r3");
    let report_id = insert_report(&h.pool, did, Some(&uri), Some("bafyreport")).await;

    let mut req = record_req(&uri);
    req.subject_cid = Some("bafyrequest".to_string());
    req.report_ids = vec![report_id];
    let recorded = h.writer.record_action(req).await.unwrap();
    assert_eq!(
        stored_cid(&h.pool, recorded.action_id).await.as_deref(),
        Some("bafyrequest")
    );
}

#[tokio::test]
async fn no_cid_source_stores_null_legacy_shape_regression() {
    // Row-level NULL is what keeps v1.8.2's partial-shape
    // Validation rejection firing for record-targeted rows with
    // no CID source (dispatch routing regression anchor).
    let h = spawn().await;
    let uri = "at://did:plc:subject000000000000000000/app.bsky.feed.post/r4";
    let recorded = h.writer.record_action(record_req(uri)).await.unwrap();
    assert_eq!(stored_cid(&h.pool, recorded.action_id).await, None);

    // Account-level rows also NULL, trivially.
    let recorded = h
        .writer
        .record_action(record_req("did:plc:subject000000000000000000"))
        .await
        .unwrap();
    assert_eq!(stored_cid(&h.pool, recorded.action_id).await, None);
}

// =========================================================================
// Migration 0009 — trigger rebuild (§4.5, §8)
// =========================================================================

#[tokio::test]
async fn trigger_guards_subject_cid_mutation() {
    let h = spawn().await;
    let uri = "at://did:plc:subject000000000000000000/app.bsky.feed.post/r5";
    let mut req = record_req(uri);
    req.subject_cid = Some("bafyimmutable".to_string());
    let recorded = h.writer.record_action(req).await.unwrap();

    let attempt =
        sqlx::query("UPDATE subject_actions SET subject_cid = 'bafyaltered' WHERE id = ?1")
            .bind(recorded.action_id)
            .execute(&h.pool)
            .await;
    let err = attempt.expect_err("subject_cid mutation must abort");
    assert!(
        err.to_string().contains("append-only"),
        "rebuilt trigger enforces subject_cid immutability: {err}"
    );
}

#[tokio::test]
async fn trigger_preserves_one_time_revocation_carve_out() {
    let h = spawn().await;
    let recorded = h
        .writer
        .record_action(record_req("did:plc:subject000000000000000000"))
        .await
        .unwrap();

    // First revocation transition (NULL → non-NULL): allowed.
    h.writer
        .revoke_action(cairn_mod::writer::RevokeActionRequest {
            action_id: recorded.action_id,
            revoked_by_did: MODERATOR_DID.to_string(),
            revoked_reason: Some("resolved".to_string()),
        })
        .await
        .expect("one-time revocation succeeds post-0009");

    // Second transition (non-NULL → different non-NULL): aborts at
    // the trigger (defense-in-depth below the writer's own state
    // checks — exercise the trigger directly).
    let attempt =
        sqlx::query("UPDATE subject_actions SET revoked_reason = 'rewritten' WHERE id = ?1")
            .bind(recorded.action_id)
            .execute(&h.pool)
            .await;
    let err = attempt.expect_err("re-revocation must abort");
    assert!(err.to_string().contains("append-only"), "{err}");
}

#[tokio::test]
async fn trigger_preserves_0004_0005_clauses() {
    // actor_kind is write-once per 0005's clauses — verify the
    // 0009 rebuild kept them.
    let h = spawn().await;
    let recorded = h
        .writer
        .record_action(record_req("did:plc:subject000000000000000000"))
        .await
        .unwrap();
    let attempt = sqlx::query("UPDATE subject_actions SET actor_kind = 'policy' WHERE id = ?1")
        .bind(recorded.action_id)
        .execute(&h.pool)
        .await;
    assert!(attempt.is_err(), "actor_kind write-once clause preserved");
}
