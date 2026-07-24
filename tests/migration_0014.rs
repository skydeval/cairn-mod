//! Migration 0014 assertions (v1.8.13, chainlink #167): the reports
//! table rebuild that extends the `subject_type` CHECK with
//! `kryphocron_record` and adds the `decode_source` + `decoded_plaintext`
//! columns for the report-flow decode path.
//!
//! `storage::open` runs all migrations (0001..0014) including the rebuild,
//! so these fixtures exercise the post-rebuild schema. The two load-bearing
//! properties: the extended CHECK, and the preserved column set + CHECKs
//! (`status`, `upstream_resolution`) that the rebuild had to carry forward.

use sqlx::{Pool, Sqlite};

async fn fresh_pool() -> Pool<Sqlite> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mig0014.db");
    let pool = cairn_mod::storage::open(&path).await.unwrap();
    Box::leak(Box::new(dir));
    pool
}

#[tokio::test]
async fn subject_type_check_accepts_kryphocron_record() {
    let pool = fresh_pool().await;
    for st in ["account", "record", "kryphocron_record"] {
        sqlx::query(
            "INSERT INTO reports (created_at, reported_by, reason_type, subject_type, subject_did)
             VALUES ('2026-07-24T00:00:00Z', 'did:plc:r', 'spam', ?1, 'did:plc:s')",
        )
        .bind(st)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("subject_type {st} must insert: {e}"));
    }
    let bogus = sqlx::query(
        "INSERT INTO reports (created_at, reported_by, reason_type, subject_type, subject_did)
         VALUES ('2026-07-24T00:00:00Z', 'did:plc:r', 'spam', 'bogus', 'did:plc:s')",
    )
    .execute(&pool)
    .await;
    assert!(
        bogus.is_err(),
        "extended CHECK must reject unknown subject_type"
    );
}

#[tokio::test]
async fn decode_source_check_and_plaintext_column() {
    let pool = fresh_pool().await;
    // Both valid decode_source values + decoded_plaintext insert.
    for src in ["aurora_server", "cairn_client"] {
        sqlx::query(
            "INSERT INTO reports (
                created_at, reported_by, reason_type, subject_type, subject_did,
                decode_source, decoded_plaintext
             ) VALUES ('t', 'did:plc:r', 'spam', 'kryphocron_record', 'did:plc:s', ?1, 'hello')",
        )
        .bind(src)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("decode_source {src} must insert: {e}"));
    }
    // NULL decode_source is allowed (non-kryphocron subjects).
    sqlx::query(
        "INSERT INTO reports (created_at, reported_by, reason_type, subject_type, subject_did)
         VALUES ('t', 'did:plc:r', 'spam', 'account', 'did:plc:s')",
    )
    .execute(&pool)
    .await
    .expect("NULL decode_source allowed");
    // A bogus decode_source rejects.
    let bogus = sqlx::query(
        "INSERT INTO reports (
            created_at, reported_by, reason_type, subject_type, subject_did, decode_source
         ) VALUES ('t', 'did:plc:r', 'spam', 'account', 'did:plc:s', 'bogus_source')",
    )
    .execute(&pool)
    .await;
    assert!(
        bogus.is_err(),
        "decode_source CHECK must reject unknown values"
    );
}

#[tokio::test]
async fn preserved_checks_and_columns_survive_rebuild() {
    let pool = fresh_pool().await;
    // status CHECK (0001) survives.
    let bad_status = sqlx::query(
        "INSERT INTO reports (created_at, reported_by, reason_type, subject_type, subject_did, status)
         VALUES ('t', 'did:plc:r', 'spam', 'account', 'did:plc:s', 'bogus_status')",
    )
    .execute(&pool)
    .await;
    assert!(bad_status.is_err(), "status CHECK survived the rebuild");

    // upstream_resolution CHECK (0012 ALTER — the easy-to-miss one) survives.
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO reports (created_at, reported_by, reason_type, subject_type, subject_did)
         VALUES ('t', 'did:plc:r', 'spam', 'account', 'did:plc:s') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let ok = sqlx::query("UPDATE reports SET upstream_resolution = 'resolved' WHERE id = ?1")
        .bind(id)
        .execute(&pool)
        .await;
    assert!(ok.is_ok(), "upstream_resolution accepts 'resolved'");
    let bad = sqlx::query("UPDATE reports SET upstream_resolution = 'bogus' WHERE id = ?1")
        .bind(id)
        .execute(&pool)
        .await;
    assert!(
        bad.is_err(),
        "upstream_resolution CHECK survived the rebuild"
    );
}

#[tokio::test]
async fn autoincrement_ids_are_monotonic_after_rebuild() {
    // subject_actions.report_ids stores report ids BY VALUE (JSON array),
    // so id continuity across the rebuild is load-bearing. On a fresh DB the
    // rebuild copies zero rows, but AUTOINCREMENT must still allocate
    // strictly increasing ids (never reuse) after the rebuilt table exists.
    let pool = fresh_pool().await;
    let mut last = 0i64;
    for _ in 0..3 {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO reports (created_at, reported_by, reason_type, subject_type, subject_did)
             VALUES ('t', 'did:plc:r', 'spam', 'account', 'did:plc:s') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            id > last,
            "AUTOINCREMENT ids strictly increase: {id} > {last}"
        );
        last = id;
    }
}
