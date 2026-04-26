//! `cairn audit-rebuild` (#40, v1.3) — one-shot operator command for
//! backfilling `prev_hash` + `row_hash` on pre-v1.3 audit_log rows.
//!
//! Operator runs once per cairn-mod instance after upgrading from v1.2
//! to v1.3. Pre-v1.3 audit rows have NULL hashes (the migration in #39
//! makes both columns nullable); rebuild walks them in id order and
//! fills both columns using the same canonical hash function the v1.3+
//! append paths use ([`crate::audit::hash::compute_audit_row_hash`]).
//!
//! Rebuild does NOT write an audit_log row of its own — it's a
//! one-time data migration, not a moderation action. Stderr carries
//! progress; stdout carries the final outcome (so `--json` is
//! pipe-friendly).
//!
//! Trust-horizon caveat: rebuild's hashes attest to whatever's stored
//! at the time it runs. An attacker who modified rows before rebuild
//! has those modifications canonicalized into the chain. The integrity
//! claim covers post-migration writes; pre-rebuild rows are hashed but
//! unattested. Documented at the call site (#43 reconciles this in the
//! design doc).
//!
//! Concurrency contract: refuses to run while a `cairn serve` writer
//! is live. Acquires the same `server_instance_lease` row the writer
//! task uses (§F5), runs the rebuild, releases the lease. Lease
//! conflict surfaces as [`CliError::LeaseConflict`] (exit code
//! [`code::LEASE_CONFLICT`](crate::cli::error::code::LEASE_CONFLICT))
//! — the operator stops `cairn serve` and re-runs.
//!
//! Trigger handling: §F10's `audit_log_no_update` trigger blocks every
//! UPDATE. Rebuild drops the trigger inside the same transaction as
//! the backfill UPDATEs, then recreates it before COMMIT. The trigger
//! reappears atomically with the rebuilt rows; a partial-failure
//! ROLLBACK restores the trigger via the same transaction's undo log.

use serde::Serialize;
use sqlx::{Pool, Sqlite, sqlite::SqliteConnection};

use super::error::CliError;
use crate::audit::hash::{
    AuditRowForHashing, GENESIS_PREV_HASH, compute_audit_row_hash, parse_stored_hash,
};
use crate::error::Error;

/// Outcome of a rebuild run. Tests + the formatters branch on this
/// rather than on stdout text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RebuildOutcome {
    /// audit_log was empty; nothing to do.
    Empty,
    /// All existing rows already had hashes (re-run after a prior
    /// rebuild, or a v1.3-from-scratch deployment whose rows were all
    /// written by post-#39 append paths). No DB writes were issued.
    AlreadyRebuilt {
        /// Total rows in audit_log at the time of the no-op check.
        total_rows: i64,
    },
    /// Filled in `rows_filled` previously-NULL rows out of
    /// `total_rows` total.
    Rebuilt {
        /// Number of rows whose `prev_hash` + `row_hash` were
        /// populated by this run.
        rows_filled: i64,
        /// Total rows in audit_log.
        total_rows: i64,
    },
}

/// Trigger DDL — duplicated here from `migrations/0001_init.sql` so
/// rebuild can recreate the trigger after dropping it for the
/// backfill window. The two MUST stay byte-identical; a regression
/// test pins this.
const RECREATE_NO_UPDATE_TRIGGER: &str =
    "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END";

/// Run the rebuild end-to-end: acquire the lease, perform the
/// backfill inside `BEGIN IMMEDIATE`, release the lease.
///
/// Lease release happens unconditionally (a panic-and-drop wouldn't
/// restore it cleanly — the operator would have to wait
/// `LEASE_STALE_MS` or hand-delete the row). On a propagating error
/// from the inner rebuild, we still release before returning so the
/// next `cairn serve` start isn't blocked.
pub async fn rebuild(pool: &Pool<Sqlite>) -> Result<RebuildOutcome, CliError> {
    let instance_id = crate::writer::acquire_lease(pool)
        .await
        .map_err(map_lease_error)?;

    let result = run_with_lease_held(pool).await;

    if let Err(e) = crate::writer::release_lease_by_id(pool, &instance_id).await {
        // Lease release failure is observable but not the operator's
        // primary signal; surface as a stderr warning. The original
        // result still flows up; if it was Ok, the rebuild succeeded
        // and the orphan-lease ages out via LEASE_STALE_MS.
        eprintln!("warning: audit-rebuild lease release failed (instance_id={instance_id}): {e}");
    }

    result
}

/// Translate the writer's [`Error::LeaseHeld`] into the CLI's typed
/// [`CliError::LeaseConflict`] — same mapping as
/// `serve::map_spawn_writer_error` so operators see one consistent
/// error shape across `cairn serve` and `cairn audit-rebuild`.
fn map_lease_error(e: Error) -> CliError {
    match e {
        Error::LeaseHeld {
            instance_id,
            age_secs,
        } => CliError::LeaseConflict {
            instance_id,
            age_secs,
        },
        other => CliError::Startup(format!("audit-rebuild lease: {other}")),
    }
}

/// Inner rebuild path. Runs inside `BEGIN IMMEDIATE` so the trigger
/// drop, the UPDATEs, and the trigger recreate either all commit
/// together or all roll back together.
async fn run_with_lease_held(pool: &Pool<Sqlite>) -> Result<RebuildOutcome, CliError> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| CliError::Startup(format!("audit-rebuild acquire: {e}")))?;

    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .map_err(|e| CliError::Startup(format!("audit-rebuild begin: {e}")))?;

    match perform_rebuild(&mut conn).await {
        Ok(outcome) => {
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .map_err(|e| CliError::Startup(format!("audit-rebuild commit: {e}")))?;
            Ok(outcome)
        }
        Err(e) => {
            // ROLLBACK undoes the trigger DROP and any UPDATEs we
            // landed pre-failure. Best-effort — if rollback fails too,
            // the original error is what surfaces.
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

/// Walk the table, fill NULLs, restore the trigger. Caller frames
/// the BEGIN IMMEDIATE / COMMIT.
async fn perform_rebuild(conn: &mut SqliteConnection) -> Result<RebuildOutcome, CliError> {
    let total_rows: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| CliError::Startup(format!("audit-rebuild count: {e}")))?;

    if total_rows == 0 {
        return Ok(RebuildOutcome::Empty);
    }

    let null_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM audit_log WHERE row_hash IS NULL")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| CliError::Startup(format!("audit-rebuild null-count: {e}")))?;

    if null_count == 0 {
        // Fast path: nothing to do. Skip the trigger DROP/CREATE
        // entirely so the no-op case doesn't churn the schema.
        return Ok(RebuildOutcome::AlreadyRebuilt { total_rows });
    }

    sqlx::query("DROP TRIGGER IF EXISTS audit_log_no_update")
        .execute(&mut *conn)
        .await
        .map_err(|e| CliError::Startup(format!("audit-rebuild drop trigger: {e}")))?;

    let rows_filled = walk_and_fill(conn).await?;

    sqlx::query(RECREATE_NO_UPDATE_TRIGGER)
        .execute(&mut *conn)
        .await
        .map_err(|e| CliError::Startup(format!("audit-rebuild restore trigger: {e}")))?;

    Ok(RebuildOutcome::Rebuilt {
        rows_filled,
        total_rows,
    })
}

/// Walk audit_log in id order, filling rows whose `row_hash` is NULL.
/// Tracks the running prev_hash in memory so we don't hit the DB once
/// per row for the previous-row lookup; the lease invariant guarantees
/// we're the only writer.
///
/// Mixed-state handling: rows with non-NULL `row_hash` are kept (their
/// stored hash becomes the prev_hash for the next row) — this lets a
/// partial prior rebuild be resumed cleanly. Mixed state shouldn't
/// arise in practice but the algorithm tolerates it without special-
/// casing.
async fn walk_and_fill(conn: &mut SqliteConnection) -> Result<i64, CliError> {
    let rows = sqlx::query!(
        "SELECT id, created_at, action, actor_did, target, target_cid, outcome, reason, row_hash
         FROM audit_log
         ORDER BY id ASC"
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| CliError::Startup(format!("audit-rebuild scan: {e}")))?;

    let mut prev_hash = GENESIS_PREV_HASH;
    let mut rows_filled: i64 = 0;

    for row in rows {
        if let Some(stored) = &row.row_hash {
            // Already-hashed row: trust the stored hash and chain
            // forward from it.
            prev_hash = parse_stored_hash(stored)
                .map_err(|e| CliError::Startup(format!("audit-rebuild parse stored hash: {e}")))?;
            continue;
        }

        let new_hash = compute_audit_row_hash(
            &prev_hash,
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
        .map_err(|e| CliError::Startup(format!("audit-rebuild hash: {e}")))?;

        let prev_slice: &[u8] = &prev_hash;
        let new_slice: &[u8] = &new_hash;
        sqlx::query!(
            "UPDATE audit_log SET prev_hash = ?1, row_hash = ?2 WHERE id = ?3",
            prev_slice,
            new_slice,
            row.id,
        )
        .execute(&mut *conn)
        .await
        .map_err(|e| CliError::Startup(format!("audit-rebuild update id={}: {e}", row.id)))?;

        rows_filled += 1;
        prev_hash = new_hash;
    }

    Ok(rows_filled)
}

/// Human one-line summary. Goes to stdout via the dispatcher's
/// `println!`; progress messages during the walk would go to stderr,
/// but in practice the rebuild is fast enough that we don't emit
/// per-row progress.
pub fn format_human(outcome: &RebuildOutcome) -> String {
    match outcome {
        RebuildOutcome::Empty => "audit_log is empty; nothing to rebuild".to_string(),
        RebuildOutcome::AlreadyRebuilt { total_rows } => {
            format!("audit_log already rebuilt; {total_rows} row(s) already have hashes")
        }
        RebuildOutcome::Rebuilt {
            rows_filled,
            total_rows,
        } => format!("audit-rebuild complete: filled {rows_filled} row(s) of {total_rows} total"),
    }
}

/// JSON one-line summary. The serde discriminator (`outcome`) makes
/// downstream tools branch on a stable enum tag rather than parsing
/// the human string.
pub fn format_json(outcome: &RebuildOutcome) -> String {
    serde_json::to_string(outcome).expect("RebuildOutcome serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage;
    use tempfile::tempdir;

    async fn fresh_pool() -> Pool<Sqlite> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-rebuild-test.db");
        let pool = storage::open(&path).await.unwrap();
        Box::leak(Box::new(dir));
        pool
    }

    /// Manually insert a pre-v1.3-style row (NULL hashes). Bypasses
    /// the audit::append helpers because those would populate hashes;
    /// we want the v1.2-upgrade fixture state.
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

    #[tokio::test]
    async fn empty_audit_log_returns_empty() {
        let pool = fresh_pool().await;
        let outcome = rebuild(&pool).await.unwrap();
        assert_eq!(outcome, RebuildOutcome::Empty);
    }

    #[tokio::test]
    async fn already_rebuilt_no_op_is_fast_path() {
        // Use append_via_pool to insert v1.3-style rows (already
        // hashed at INSERT time). Re-running rebuild on those rows
        // should hit the null_count==0 fast path.
        let pool = fresh_pool().await;
        crate::audit::append::append_via_pool(
            &pool,
            &crate::audit::append::AuditRowForAppend {
                created_at: 1,
                action: "label_applied".into(),
                actor_did: "did:plc:m1".into(),
                target: None,
                target_cid: None,
                outcome: "success".into(),
                reason: None,
            },
        )
        .await
        .unwrap();
        crate::audit::append::append_via_pool(
            &pool,
            &crate::audit::append::AuditRowForAppend {
                created_at: 2,
                action: "label_negated".into(),
                actor_did: "did:plc:m1".into(),
                target: None,
                target_cid: None,
                outcome: "success".into(),
                reason: None,
            },
        )
        .await
        .unwrap();

        let outcome = rebuild(&pool).await.unwrap();
        assert_eq!(outcome, RebuildOutcome::AlreadyRebuilt { total_rows: 2 });
    }

    #[tokio::test]
    async fn fills_all_null_rows_chained_from_genesis() {
        let pool = fresh_pool().await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 100).await;
        insert_pre_v13_row(&pool, "label_negated", "did:plc:m1", 200).await;
        insert_pre_v13_row(&pool, "report_resolved", "did:plc:m2", 300).await;

        let outcome = rebuild(&pool).await.unwrap();
        assert_eq!(
            outcome,
            RebuildOutcome::Rebuilt {
                rows_filled: 3,
                total_rows: 3,
            }
        );

        // Verify chain: row 1's prev_hash is GENESIS, row 2's
        // prev_hash equals row 1's row_hash, row 3's prev_hash
        // equals row 2's row_hash.
        let rows = sqlx::query!(
            r#"SELECT id, prev_hash AS "prev_hash!", row_hash AS "row_hash!"
               FROM audit_log ORDER BY id ASC"#
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].prev_hash, GENESIS_PREV_HASH);
        assert_eq!(rows[1].prev_hash, rows[0].row_hash);
        assert_eq!(rows[2].prev_hash, rows[1].row_hash);
    }

    #[tokio::test]
    async fn mixed_state_fills_only_null_rows() {
        // Construct a half-rebuilt state: rows 1-2 already hashed
        // (via append_via_pool), rows 3-4 NULL (manual insert). Run
        // rebuild and confirm rows 3-4 chain from row 2's row_hash.
        let pool = fresh_pool().await;
        crate::audit::append::append_via_pool(
            &pool,
            &crate::audit::append::AuditRowForAppend {
                created_at: 1,
                action: "label_applied".into(),
                actor_did: "did:plc:m1".into(),
                target: None,
                target_cid: None,
                outcome: "success".into(),
                reason: None,
            },
        )
        .await
        .unwrap();
        crate::audit::append::append_via_pool(
            &pool,
            &crate::audit::append::AuditRowForAppend {
                created_at: 2,
                action: "label_negated".into(),
                actor_did: "did:plc:m1".into(),
                target: None,
                target_cid: None,
                outcome: "success".into(),
                reason: None,
            },
        )
        .await
        .unwrap();
        insert_pre_v13_row(&pool, "report_resolved", "did:plc:m2", 300).await;
        insert_pre_v13_row(&pool, "reporter_flagged", "did:plc:m2", 400).await;

        let outcome = rebuild(&pool).await.unwrap();
        assert_eq!(
            outcome,
            RebuildOutcome::Rebuilt {
                rows_filled: 2,
                total_rows: 4,
            }
        );

        let rows = sqlx::query!(
            r#"SELECT id, prev_hash AS "prev_hash!", row_hash AS "row_hash!"
               FROM audit_log ORDER BY id ASC"#
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows[2].prev_hash, rows[1].row_hash);
        assert_eq!(rows[3].prev_hash, rows[2].row_hash);
    }

    #[tokio::test]
    async fn rebuild_restores_no_update_trigger_after_run() {
        // After rebuild, the audit_log_no_update trigger is back in
        // place — subsequent UPDATE attempts must abort. Pin this
        // because the rebuild path drops + recreates the trigger;
        // a regression that forgets the recreate would silently
        // leave audit_log mutable.
        let pool = fresh_pool().await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 100).await;
        rebuild(&pool).await.unwrap();

        let err = sqlx::query!("UPDATE audit_log SET action = 'tampered' WHERE id = 1")
            .execute(&pool)
            .await
            .expect_err("audit_log_no_update trigger must abort UPDATE");
        let msg = err.to_string();
        assert!(
            msg.contains("audit_log is append-only"),
            "expected trigger message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn rebuild_rejects_when_lease_held_by_other_writer() {
        let pool = fresh_pool().await;
        // Plant a fresh-heartbeat lease — simulates a running cairn
        // serve in another process.
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
        // Plant a NULL-hashed row so rebuild has work it would do
        // if the lease check didn't gate it.
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 100).await;

        let err = rebuild(&pool).await.expect_err("lease must block rebuild");
        match err {
            CliError::LeaseConflict { instance_id, .. } => {
                assert_eq!(instance_id, "rival-writer");
            }
            other => panic!("expected LeaseConflict, got: {other:?}"),
        }

        // Row was not touched.
        let row_hash: Option<Vec<u8>> =
            sqlx::query_scalar!("SELECT row_hash FROM audit_log WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            row_hash.is_none(),
            "rebuild must not write rows when lease is held"
        );
    }

    #[tokio::test]
    async fn rebuild_releases_lease_on_success_so_next_run_works() {
        // Two consecutive rebuild calls must both succeed — first
        // one fills, second one is AlreadyRebuilt. If the first
        // didn't release the lease, the second would LeaseConflict.
        let pool = fresh_pool().await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 100).await;

        let first = rebuild(&pool).await.unwrap();
        assert!(matches!(first, RebuildOutcome::Rebuilt { .. }));

        let second = rebuild(&pool).await.unwrap();
        assert!(matches!(second, RebuildOutcome::AlreadyRebuilt { .. }));
    }

    #[tokio::test]
    async fn rebuilt_hashes_recompute_correctly() {
        // Forward-compatibility check for #41 (cairn audit verify):
        // every row's stored row_hash must equal compute_audit_row_hash
        // applied to its stored content + the previous row's row_hash.
        let pool = fresh_pool().await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 100).await;
        insert_pre_v13_row(&pool, "label_negated", "did:plc:m1", 200).await;
        rebuild(&pool).await.unwrap();

        let rows = sqlx::query!(
            r#"SELECT id, created_at, action, actor_did, target, target_cid, outcome, reason,
                      prev_hash AS "prev_hash!", row_hash AS "row_hash!"
               FROM audit_log ORDER BY id ASC"#
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        for row in &rows {
            let prev = parse_stored_hash(&row.prev_hash).unwrap();
            let recomputed = compute_audit_row_hash(
                &prev,
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
                row.row_hash,
                "row id={} hash recomputation mismatch",
                row.id
            );
        }
    }

    #[test]
    fn recreate_trigger_ddl_matches_initial_migration() {
        // Pin the DDL drift contract: the rebuild's recreate string
        // must match what migrations/0001_init.sql declares for the
        // no_update trigger. If the migration's trigger body changes,
        // this constant has to change too — the test catches the
        // disconnect.
        let init_sql = include_str!("../../migrations/0001_init.sql");
        // Find the CREATE TRIGGER block for audit_log_no_update.
        let needle = "CREATE TRIGGER audit_log_no_update";
        let start = init_sql
            .find(needle)
            .expect("0001_init.sql contains audit_log_no_update trigger");
        // Slice from the start of the CREATE through the END.
        let end = init_sql[start..].find("END;").expect("trigger has END;") + start + "END".len(); // exclude the trailing semicolon (we don't include it in the const)
        let init_trigger = &init_sql[start..end];
        assert_eq!(
            init_trigger, RECREATE_NO_UPDATE_TRIGGER,
            "RECREATE_NO_UPDATE_TRIGGER must match the body in 0001_init.sql"
        );
    }

    #[test]
    fn format_human_renders_each_outcome() {
        assert!(format_human(&RebuildOutcome::Empty).contains("empty"));
        assert!(
            format_human(&RebuildOutcome::AlreadyRebuilt { total_rows: 5 })
                .contains("already rebuilt")
        );
        let s = format_human(&RebuildOutcome::Rebuilt {
            rows_filled: 3,
            total_rows: 5,
        });
        assert!(s.contains("filled 3"));
        assert!(s.contains("of 5"));
    }

    #[test]
    fn format_json_uses_outcome_discriminator() {
        let s = format_json(&RebuildOutcome::Rebuilt {
            rows_filled: 3,
            total_rows: 5,
        });
        assert!(s.contains(r#""outcome":"rebuilt""#), "got: {s}");
        assert!(s.contains(r#""rows_filled":3"#), "got: {s}");
        assert!(s.contains(r#""total_rows":5"#), "got: {s}");
    }
}
