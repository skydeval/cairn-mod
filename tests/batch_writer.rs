//! v1.8.7 batch intent-row shape at the recordAction writer
//! (v2 §5.1/§5.2.1, chainlink #143).
//!
//! - One `subject_actions` row per batch: first-subject-primary
//!   flat columns (`subject_did` = first DID, `subject_uri`/
//!   `subject_cid` NULL), authoritative subjects list in
//!   `action_detail` with the `batch: true` marker.
//! - Strike-exemption (M-B): batch rows record
//!   `strike_value_base = strike_value_applied = 0` even under a
//!   strike-bearing `action_type` — one-subject-one-strike doesn't
//!   compose with N-subject aggregation. The exemption keys on the
//!   marker being exactly `true`.

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

fn takedown_req(
    subject: &str,
    detail: Option<serde_json::Value>,
) -> cairn_mod::writer::RecordActionRequest {
    cairn_mod::writer::RecordActionRequest {
        subject: subject.to_string(),
        actor_did: MODERATOR_DID.to_string(),
        action_type: cairn_mod::moderation::types::ActionType::Takedown,
        reason_codes: vec!["spam".into()],
        duration_iso: None,
        notes: None,
        report_ids: Vec::new(),
        subject_cid: None,
        detail,
    }
}

#[derive(Debug)]
struct RowShape {
    subject_did: String,
    subject_uri: Option<String>,
    subject_cid: Option<String>,
    strike_value_base: i64,
    strike_value_applied: i64,
    action_detail: Option<String>,
}

async fn row_shape(pool: &Pool<Sqlite>, action_id: i64) -> RowShape {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT subject_did, subject_uri, subject_cid,
                strike_value_base, strike_value_applied, action_detail
         FROM subject_actions WHERE id = ?1",
    )
    .bind(action_id)
    .fetch_one(pool)
    .await
    .unwrap();
    RowShape {
        subject_did: row.get("subject_did"),
        subject_uri: row.get("subject_uri"),
        subject_cid: row.get("subject_cid"),
        strike_value_base: row.get("strike_value_base"),
        strike_value_applied: row.get("strike_value_applied"),
        action_detail: row.get("action_detail"),
    }
}

#[tokio::test]
async fn batch_row_is_first_subject_primary_and_strike_exempt() {
    let h = spawn().await;
    let detail = serde_json::json!({
        "batch": true,
        "dids": ["did:plc:primary0000000000000000", "did:plc:second00000000000000000"]
    });
    let recorded = h
        .writer
        .record_action(takedown_req(
            "did:plc:primary0000000000000000",
            Some(detail.clone()),
        ))
        .await
        .unwrap();

    let row = row_shape(&h.pool, recorded.action_id).await;
    assert_eq!(row.subject_did, "did:plc:primary0000000000000000");
    assert!(row.subject_uri.is_none());
    assert!(row.subject_cid.is_none());
    // M-B: strike-exempt despite the strike-bearing takedown verb.
    assert_eq!(row.strike_value_base, 0);
    assert_eq!(row.strike_value_applied, 0);
    // Authoritative subjects list round-trips through the
    // write-once action_detail column.
    let stored: serde_json::Value =
        serde_json::from_str(row.action_detail.as_deref().unwrap()).unwrap();
    assert_eq!(stored, detail);

    // Exactly ONE intent row for the whole batch.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subject_actions")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn non_batch_takedown_still_accrues_strikes() {
    // Contrast pin: the exemption is batch-specific — the same
    // verb/reason without the marker keeps the shipped strike
    // accrual (so nobody "fixes" M-B by zeroing everything).
    let h = spawn().await;
    let recorded = h
        .writer
        .record_action(takedown_req("did:plc:primary0000000000000000", None))
        .await
        .unwrap();
    let row = row_shape(&h.pool, recorded.action_id).await;
    assert!(
        row.strike_value_applied > 0,
        "singular takedown with a strike-bearing reason accrues strikes; got {row:?}"
    );
}

#[tokio::test]
async fn batch_marker_must_be_exactly_true() {
    // detail.batch = false (or non-bool) is NOT a batch row: the
    // strike path stays on the singular semantics.
    let h = spawn().await;
    let recorded = h
        .writer
        .record_action(takedown_req(
            "did:plc:primary0000000000000000",
            Some(serde_json::json!({"batch": false, "dids": ["did:plc:x"]})),
        ))
        .await
        .unwrap();
    let row = row_shape(&h.pool, recorded.action_id).await;
    assert!(row.strike_value_applied > 0, "{row:?}");
}
