//! `cairn audit verify` (#41, v1.3) — operator command for verifying
//! the audit_log hash chain.
//!
//! Walks audit_log in id order, recomputes each attested row's
//! row_hash from the running prev_hash + the row's stored content
//! using [`crate::audit::hash::compute_audit_row_hash`] (the same
//! function the v1.3+ append paths use), and compares against the
//! stored row_hash. Reports the **first** divergence and stops.
//!
//! Continuing past first divergence would cascade — every row after
//! a tampered row would also report mismatch, since the chain link
//! is broken from there forward. The first divergence is the
//! actionable signal; later rows are downstream noise.
//!
//! Read-only. No lease acquired (unlike `cairn audit-rebuild`); safe
//! to run while `cairn serve` is live. Concurrent writes during
//! verify are fine — SQLite's WAL gives us a consistent snapshot,
//! and any new rows arriving mid-walk are either fully included or
//! not at all.
//!
//! Pre-attestation rows (NULL `row_hash`) are **skipped, not flagged**.
//! Pre-v1.3 rows that haven't been backfilled by `cairn audit-rebuild`
//! (#40) are the documented trust horizon; verify counts them so the
//! operator sees exactly how much of their audit log is unattested.
//! When the first attested row's id is > 1 (i.e., rows 1..N-1 are
//! NULL because rebuild was never run), `attestation_starts_at_row`
//! reports the horizon row id.
//!
//! Tampering detection model: this catches any modification that
//! changes a row's hash-relevant content without recomputing the
//! whole forward chain. A "smart" attacker who tampers a row AND
//! re-derives the entire downstream chain is **not** caught by this
//! command alone — that requires external attestation (signed
//! Merkle root, transparency log) which is v1.x+ scope. The
//! README's Trust-chain disclosure #2 stays honest about this.
//!
//! Output: typed `VerifyOutcome` (Empty / Verified / Divergence)
//! with `serde(tag = "outcome")` for stable JSON. The dispatcher in
//! `main.rs` prints the outcome to stdout and, on Divergence, also
//! returns [`crate::cli::error::CliError::AuditDivergence`] so the
//! process exits with [`crate::cli::error::code::AUDIT_DIVERGENCE`]
//! (15). Operators can branch on the exit code in monitoring;
//! `--json` consumers get the structured report on stdout.

use serde::Serialize;
use sqlx::{Pool, Sqlite};

use super::error::CliError;
use crate::audit::hash::{
    AuditRowForHashing, GENESIS_PREV_HASH, compute_audit_row_hash, parse_stored_hash,
};

/// Outcome of a verify run. Tests + the formatters branch on this
/// rather than on stdout text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// audit_log was empty; nothing to verify.
    Empty,
    /// Chain verified successfully.
    Verified {
        /// Total rows in audit_log (attested + pre-attestation).
        total_rows: i64,
        /// Rows whose stored row_hash matched the recomputed hash.
        attested_rows: i64,
        /// Rows with NULL row_hash that were skipped (pre-v1.3 rows
        /// that haven't been backfilled by `cairn audit-rebuild`).
        pre_attestation_rows: i64,
        /// `Some(N)` when rows 1..N-1 are pre-attestation and the
        /// attested chain begins at row N — the trust horizon.
        /// `None` when the first attested row's id is 1 (pure
        /// post-v1.3 deployment OR a fully-rebuilt deployment;
        /// either way, the chain is rooted at genesis with no
        /// horizon to call out).
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_starts_at_row: Option<i64>,
    },
    /// First-divergence report. Walking halts once this is detected.
    Divergence {
        /// `audit_log.id` of the row whose recomputed hash did not
        /// match the stored row_hash.
        row_id: i64,
        /// Hex-encoded SHA-256 the chain says this row's row_hash
        /// should be.
        expected_hash: String,
        /// Hex-encoded SHA-256 actually stored in the row.
        actual_hash: String,
        /// Number of rows whose hashes verified before this one —
        /// the truncation point operators reconcile from.
        attested_rows_before_divergence: i64,
    },
}

/// Walk audit_log in id order and verify every attested row's hash.
/// Returns Ok(VerifyOutcome) regardless of whether the chain is
/// intact; CliError is reserved for genuine errors (DB unreachable,
/// row_hash blob with wrong length, etc.). The dispatcher in
/// `main.rs` lifts `VerifyOutcome::Divergence` into
/// `CliError::AuditDivergence` for exit-code mapping.
///
/// Read-only. No lease, no transaction (a single SELECT is its own
/// implicit transaction in SQLite WAL mode). Concurrent appends
/// during the walk are tolerated — they either appear in our
/// snapshot or don't, but the chain integrity property holds for
/// whatever subset we read.
pub async fn verify(pool: &Pool<Sqlite>) -> Result<VerifyOutcome, CliError> {
    let rows = sqlx::query!(
        "SELECT id, created_at, action, actor_did, target, target_cid, outcome, reason,
                prev_hash, row_hash
         FROM audit_log
         ORDER BY id ASC"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| CliError::Startup(format!("audit verify scan: {e}")))?;

    if rows.is_empty() {
        return Ok(VerifyOutcome::Empty);
    }

    let total_rows = rows.len() as i64;
    let mut running_prev_hash: [u8; 32] = GENESIS_PREV_HASH;
    let mut attested_rows: i64 = 0;
    let mut pre_attestation_rows: i64 = 0;
    let mut attestation_starts_at_row: Option<i64> = None;
    let mut seen_attested = false;

    for row in &rows {
        let Some(stored_row_hash_blob) = &row.row_hash else {
            // Pre-attestation row: skip, don't update running_prev_hash.
            pre_attestation_rows += 1;
            continue;
        };

        if !seen_attested {
            seen_attested = true;
            // Trust horizon: only set the field when there's actually
            // a horizon to call out (first attested row's id > 1).
            if row.id != 1 {
                attestation_starts_at_row = Some(row.id);
            }
        }

        let stored_row_hash = parse_stored_hash(stored_row_hash_blob).map_err(|e| {
            CliError::Startup(format!(
                "audit verify: row id={} stored row_hash malformed: {e}",
                row.id
            ))
        })?;

        let recomputed = compute_audit_row_hash(
            &running_prev_hash,
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
        .map_err(|e| {
            CliError::Startup(format!("audit verify: row id={} hash compute: {e}", row.id))
        })?;

        if recomputed != stored_row_hash {
            // First-divergence: bail with a structured report. The
            // recomputed hash is what the chain dictates this row's
            // row_hash should be (using the running prev_hash from
            // our walk + the row's stored content). The stored hash
            // is what's actually in the row.
            return Ok(VerifyOutcome::Divergence {
                row_id: row.id,
                expected_hash: hex::encode(recomputed),
                actual_hash: hex::encode(stored_row_hash),
                attested_rows_before_divergence: attested_rows,
            });
        }

        attested_rows += 1;
        running_prev_hash = stored_row_hash;
    }

    Ok(VerifyOutcome::Verified {
        total_rows,
        attested_rows,
        pre_attestation_rows,
        attestation_starts_at_row,
    })
}

/// Human-readable summary. Multi-line for `Verified` (one line per
/// fact the operator wants to see) and `Divergence` (id + hashes).
/// Trailing newline is left for the dispatcher's `println!`.
pub fn format_human(outcome: &VerifyOutcome) -> String {
    use std::fmt::Write;
    match outcome {
        VerifyOutcome::Empty => "audit_log is empty; nothing to verify".to_string(),
        VerifyOutcome::Verified {
            total_rows,
            attested_rows,
            pre_attestation_rows,
            attestation_starts_at_row,
        } => {
            let mut s = String::new();
            let _ = writeln!(
                s,
                "audit chain verified: {attested_rows} attested row(s) of {total_rows} total"
            );
            if *pre_attestation_rows > 0 {
                let _ = writeln!(
                    s,
                    "  skipped {pre_attestation_rows} row(s) pre-dating audit chain attestation"
                );
            }
            if let Some(n) = attestation_starts_at_row {
                let _ = write!(s, "  attestation starts at row {n} (trust horizon)");
            } else if s.ends_with('\n') {
                s.pop();
            }
            s
        }
        VerifyOutcome::Divergence {
            row_id,
            expected_hash,
            actual_hash,
            attested_rows_before_divergence,
        } => {
            let mut s = String::new();
            let _ = writeln!(s, "audit chain divergence at row {row_id}");
            let _ = writeln!(s, "  expected: {expected_hash}");
            let _ = writeln!(s, "  actual:   {actual_hash}");
            let _ = write!(
                s,
                "  {attested_rows_before_divergence} row(s) verified before divergence"
            );
            s
        }
    }
}

/// JSON one-line summary. The serde discriminator (`outcome`) lets
/// downstream tools branch on a stable enum tag rather than parsing
/// the human string.
pub fn format_json(outcome: &VerifyOutcome) -> String {
    serde_json::to_string(outcome).expect("VerifyOutcome serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::append::{AuditRowForAppend, append_via_pool};
    use crate::storage;
    use tempfile::tempdir;

    async fn fresh_pool() -> Pool<Sqlite> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-verify-test.db");
        let pool = storage::open(&path).await.unwrap();
        Box::leak(Box::new(dir));
        pool
    }

    fn sample_row(action: &str, actor_did: &str, created_at: i64) -> AuditRowForAppend {
        AuditRowForAppend {
            created_at,
            action: action.into(),
            actor_did: actor_did.into(),
            target: None,
            target_cid: None,
            outcome: "success".into(),
            reason: None,
        }
    }

    /// Manually insert a pre-v1.3-style row (NULL hashes) for fixtures
    /// that simulate a v1.2-upgrade DB before `cairn audit-rebuild`
    /// has run.
    async fn insert_pre_v13_row(
        pool: &Pool<Sqlite>,
        action: &str,
        actor_did: &str,
        created_at: i64,
    ) {
        sqlx::query!(
            "INSERT INTO audit_log (created_at, action, actor_did, outcome) VALUES (?1, ?2, ?3, ?4)",
            created_at,
            action,
            actor_did,
            "success",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    /// Drop the audit_log_no_update trigger so a test can simulate
    /// tampering. Production paths don't do this — only operator
    /// commands like `cairn audit-rebuild` (which restores the
    /// trigger before commit). Tests need this to forge mismatches.
    async fn drop_no_update_trigger(pool: &Pool<Sqlite>) {
        sqlx::query("DROP TRIGGER IF EXISTS audit_log_no_update")
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn empty_audit_log_returns_empty() {
        let pool = fresh_pool().await;
        let outcome = verify(&pool).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Empty);
    }

    #[tokio::test]
    async fn all_attested_chain_from_row_one_returns_verified_no_horizon() {
        let pool = fresh_pool().await;
        append_via_pool(&pool, &sample_row("label_applied", "did:plc:m1", 1))
            .await
            .unwrap();
        append_via_pool(&pool, &sample_row("label_negated", "did:plc:m1", 2))
            .await
            .unwrap();
        append_via_pool(&pool, &sample_row("report_resolved", "did:plc:m2", 3))
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        assert_eq!(
            outcome,
            VerifyOutcome::Verified {
                total_rows: 3,
                attested_rows: 3,
                pre_attestation_rows: 0,
                attestation_starts_at_row: None,
            }
        );
    }

    #[tokio::test]
    async fn all_pre_attestation_returns_verified_with_zero_attested() {
        let pool = fresh_pool().await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 1).await;
        insert_pre_v13_row(&pool, "label_negated", "did:plc:m1", 2).await;
        insert_pre_v13_row(&pool, "report_resolved", "did:plc:m2", 3).await;

        let outcome = verify(&pool).await.unwrap();
        assert_eq!(
            outcome,
            VerifyOutcome::Verified {
                total_rows: 3,
                attested_rows: 0,
                pre_attestation_rows: 3,
                attestation_starts_at_row: None,
            }
        );
    }

    #[tokio::test]
    async fn mixed_pre_then_attested_returns_horizon_at_first_attested_row() {
        // Three pre-v1.3 NULL rows, then two v1.3 attested rows.
        // The trust horizon is row 4.
        let pool = fresh_pool().await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 1).await;
        insert_pre_v13_row(&pool, "label_negated", "did:plc:m1", 2).await;
        insert_pre_v13_row(&pool, "report_resolved", "did:plc:m2", 3).await;
        append_via_pool(&pool, &sample_row("label_applied", "did:plc:m3", 4))
            .await
            .unwrap();
        append_via_pool(&pool, &sample_row("label_negated", "did:plc:m3", 5))
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        assert_eq!(
            outcome,
            VerifyOutcome::Verified {
                total_rows: 5,
                attested_rows: 2,
                pre_attestation_rows: 3,
                attestation_starts_at_row: Some(4),
            }
        );
    }

    #[tokio::test]
    async fn post_rebuild_chain_starts_at_genesis_no_horizon() {
        // Pre-v1.3 rows + audit-rebuild → all rows attested, chain
        // rooted at row 1. attestation_starts_at_row should be None,
        // not Some(1).
        let pool = fresh_pool().await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 1).await;
        insert_pre_v13_row(&pool, "label_negated", "did:plc:m1", 2).await;
        crate::cli::audit_rebuild::rebuild(&pool).await.unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Verified {
                attested_rows,
                pre_attestation_rows,
                attestation_starts_at_row,
                ..
            } => {
                assert_eq!(attested_rows, 2);
                assert_eq!(pre_attestation_rows, 0);
                assert_eq!(
                    attestation_starts_at_row, None,
                    "post-rebuild chain rooted at row 1 should report no horizon"
                );
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampered_row_content_produces_divergence_at_that_row() {
        // The load-bearing integrity proof: modify a row's content
        // (without recomputing row_hash) and confirm verify catches
        // it at exactly that row, not before, not after.
        let pool = fresh_pool().await;
        append_via_pool(&pool, &sample_row("label_applied", "did:plc:m1", 1))
            .await
            .unwrap();
        append_via_pool(&pool, &sample_row("label_negated", "did:plc:m1", 2))
            .await
            .unwrap();
        append_via_pool(&pool, &sample_row("report_resolved", "did:plc:m2", 3))
            .await
            .unwrap();

        // Tamper row 2's actor_did.
        drop_no_update_trigger(&pool).await;
        sqlx::query!("UPDATE audit_log SET actor_did = 'did:plc:attacker' WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Divergence {
                row_id,
                expected_hash,
                actual_hash,
                attested_rows_before_divergence,
            } => {
                assert_eq!(row_id, 2, "divergence must point at the tampered row");
                assert_eq!(
                    attested_rows_before_divergence, 1,
                    "row 1 was verified before the divergence at row 2"
                );
                assert_ne!(
                    expected_hash, actual_hash,
                    "expected and actual must differ for a real divergence"
                );
                assert_eq!(expected_hash.len(), 64, "hex-encoded SHA-256 is 64 chars");
                assert_eq!(actual_hash.len(), 64);
            }
            other => panic!("expected Divergence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampered_row_hash_alone_produces_divergence_at_that_row() {
        // Mirror of the content-tampering test: leave row content
        // untouched, modify only the stored row_hash. Verify catches
        // the same way (recomputation from running prev + content
        // ≠ stored).
        let pool = fresh_pool().await;
        append_via_pool(&pool, &sample_row("label_applied", "did:plc:m1", 1))
            .await
            .unwrap();
        append_via_pool(&pool, &sample_row("label_negated", "did:plc:m1", 2))
            .await
            .unwrap();

        drop_no_update_trigger(&pool).await;
        // Replace row 2's row_hash with 32 bytes of 0xAA.
        let bogus: Vec<u8> = vec![0xAA; 32];
        sqlx::query!("UPDATE audit_log SET row_hash = ?1 WHERE id = 2", bogus)
            .execute(&pool)
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Divergence {
                row_id,
                actual_hash,
                ..
            } => {
                assert_eq!(row_id, 2);
                assert_eq!(actual_hash, hex::encode([0xAAu8; 32]));
            }
            other => panic!("expected Divergence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampering_at_first_row_reports_zero_attested_before_divergence() {
        // Edge case: attested_rows_before_divergence = 0 when the
        // very first row is tampered. Pin this so a future off-by-
        // one in counting surfaces here.
        let pool = fresh_pool().await;
        append_via_pool(&pool, &sample_row("label_applied", "did:plc:m1", 1))
            .await
            .unwrap();

        drop_no_update_trigger(&pool).await;
        sqlx::query!("UPDATE audit_log SET action = 'label_negated' WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Divergence {
                row_id,
                attested_rows_before_divergence,
                ..
            } => {
                assert_eq!(row_id, 1);
                assert_eq!(attested_rows_before_divergence, 0);
            }
            other => panic!("expected Divergence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn divergence_after_pre_attestation_tail_reports_correct_row() {
        // Mixed state: rows 1-2 pre-attestation (NULL), rows 3-4
        // attested, row 4 tampered. Verify should skip 1-2, attest
        // 3, and diverge at 4.
        let pool = fresh_pool().await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 1).await;
        insert_pre_v13_row(&pool, "label_negated", "did:plc:m1", 2).await;
        append_via_pool(&pool, &sample_row("report_resolved", "did:plc:m2", 3))
            .await
            .unwrap();
        append_via_pool(&pool, &sample_row("reporter_flagged", "did:plc:m2", 4))
            .await
            .unwrap();

        drop_no_update_trigger(&pool).await;
        sqlx::query!("UPDATE audit_log SET action = 'tampered' WHERE id = 4")
            .execute(&pool)
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Divergence {
                row_id,
                attested_rows_before_divergence,
                ..
            } => {
                assert_eq!(row_id, 4);
                assert_eq!(
                    attested_rows_before_divergence, 1,
                    "row 3 attested; rows 1-2 skipped as pre-attestation"
                );
            }
            other => panic!("expected Divergence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_does_not_acquire_lease_safe_during_serve() {
        // Verify is read-only; it must NOT touch server_instance_lease.
        // Plant a fresh-heartbeat lease (simulating cairn serve running)
        // and confirm verify still works without LeaseConflict.
        let pool = fresh_pool().await;
        let now_ms = crate::writer::epoch_ms_now();
        sqlx::query!(
            "INSERT INTO server_instance_lease (id, instance_id, acquired_at, last_heartbeat)
             VALUES (1, ?1, ?2, ?2)",
            "rival-writer",
            now_ms,
        )
        .execute(&pool)
        .await
        .unwrap();
        append_via_pool(&pool, &sample_row("label_applied", "did:plc:m1", 1))
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        assert!(
            matches!(outcome, VerifyOutcome::Verified { .. }),
            "verify must run while a lease is held; got {outcome:?}"
        );

        // Confirm the lease is unchanged after verify ran.
        let row = sqlx::query!("SELECT instance_id FROM server_instance_lease WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.instance_id, "rival-writer");
    }

    #[test]
    fn format_human_renders_each_outcome_shape() {
        assert!(format_human(&VerifyOutcome::Empty).contains("empty"));

        let verified = format_human(&VerifyOutcome::Verified {
            total_rows: 10,
            attested_rows: 7,
            pre_attestation_rows: 3,
            attestation_starts_at_row: Some(4),
        });
        assert!(verified.contains("7 attested"));
        assert!(verified.contains("of 10"));
        assert!(verified.contains("skipped 3"));
        assert!(verified.contains("trust horizon"));
        assert!(verified.contains("row 4"));

        let no_horizon = format_human(&VerifyOutcome::Verified {
            total_rows: 5,
            attested_rows: 5,
            pre_attestation_rows: 0,
            attestation_starts_at_row: None,
        });
        assert!(!no_horizon.contains("horizon"), "no horizon line when None");
        assert!(!no_horizon.contains("skipped"), "no skipped line when 0");

        let divergence = format_human(&VerifyOutcome::Divergence {
            row_id: 42,
            expected_hash: "abc123".into(),
            actual_hash: "def456".into(),
            attested_rows_before_divergence: 41,
        });
        assert!(divergence.contains("row 42"));
        assert!(divergence.contains("expected: abc123"));
        assert!(divergence.contains("actual:   def456"));
        assert!(divergence.contains("41 row"));
    }

    #[test]
    fn format_json_uses_outcome_discriminator() {
        let s = format_json(&VerifyOutcome::Verified {
            total_rows: 5,
            attested_rows: 5,
            pre_attestation_rows: 0,
            attestation_starts_at_row: None,
        });
        assert!(s.contains(r#""outcome":"verified""#), "got: {s}");
        assert!(
            !s.contains("attestation_starts_at_row"),
            "None should be skipped"
        );

        let div = format_json(&VerifyOutcome::Divergence {
            row_id: 5,
            expected_hash: "aa".into(),
            actual_hash: "bb".into(),
            attested_rows_before_divergence: 4,
        });
        assert!(div.contains(r#""outcome":"divergence""#));
        assert!(div.contains(r#""row_id":5"#));
        assert!(div.contains(r#""expected_hash":"aa""#));
    }
}
