//! Audit-log append helpers (#39, v1.3; chain extended to span
//! `pds_admin_audit` in #85, v1.7).
//!
//! Two public entry points + one shared connection-level helper. All
//! three route through [`crate::audit::hash::compute_audit_row_hash`]
//! so the chain has a single canonical hash implementation.
//!
//! ```text
//!   in-process call sites with their own tx        →  append_in_tx (writer-internal,
//!                                                                   flag_reporter)
//!   in-process callers without an existing tx      →  WriterHandle::append_audit
//!                                                     (retention_sweep)
//!   cross-process CLI callers (no writer task)     →  append_via_pool (publish,
//!                                                                      unpublish)
//! ```
//!
//! `prev_hash` is the **most recent chain link across both tables** —
//! `audit_log.row_hash` (latest non-NULL by id) and
//! `pds_admin_audit.row_hash` (latest by id). Tie-broken on insertion
//! timestamp (`audit_log.created_at` vs.
//! `pds_admin_audit.call_completed_at`); falls back to
//! [`crate::audit::hash::GENESIS_PREV_HASH`] when both tables are empty
//! or audit_log only contains pre-v1.3 rows. The unified-chain semantics
//! live in the crate-internal `read_latest_chain_hash` helper below.
//!
//! The chain-integrity invariant is enforced at the SQLite write-lock
//! layer. [`append_via_pool`] explicitly issues `BEGIN IMMEDIATE` so the
//! latest-row read + INSERT pair is atomic against any concurrent
//! appender — including a `cairn serve` writer task running in another
//! process. [`append_in_tx`] inherits the lock from its caller's already-
//! open transaction.

use sqlx::sqlite::SqliteConnection;
use sqlx::{Pool, Sqlite, Transaction};

use super::hash::{
    AuditRowForHashing, GENESIS_PREV_HASH, compute_audit_row_hash, parse_stored_hash,
};
use crate::error::{Error, Result};

/// Owned audit-row payload used as input to the append helpers.
/// Mirrors [`crate::audit::hash::AuditRowForHashing`] but holds owned
/// data so it can travel across futures + writer-task message boundaries.
#[derive(Debug, Clone)]
pub struct AuditRowForAppend {
    /// Internal wall-clock epoch-ms.
    pub created_at: i64,
    /// Audit-action discriminator.
    pub action: String,
    /// Actor DID.
    pub actor_did: String,
    /// Optional target identifier.
    pub target: Option<String>,
    /// Optional CID pin on the target.
    pub target_cid: Option<String>,
    /// `"success"` or `"failure"`.
    pub outcome: String,
    /// Optional structured-JSON or free-text payload.
    pub reason: Option<String>,
}

impl AuditRowForAppend {
    /// Borrowed view for hashing — no ownership transfer.
    fn as_hashing(&self) -> AuditRowForHashing<'_> {
        AuditRowForHashing {
            created_at: self.created_at,
            action: &self.action,
            actor_did: &self.actor_did,
            target: self.target.as_deref(),
            target_cid: self.target_cid.as_deref(),
            outcome: &self.outcome,
            reason: self.reason.as_deref(),
        }
    }
}

/// Append an audit row inside an existing transaction. Used by callers
/// that need to combine the audit row with other writes in the same
/// commit — writer-internal handlers (apply / negate / resolve_report)
/// and `flag_reporter` (suppression update + audit row atomically).
///
/// The transaction itself is the serialization point: SQLite's
/// `BEGIN IMMEDIATE` (or any write-acquiring tx) holds the database
/// write lock, so the latest-row-hash read + INSERT pair is atomic
/// against any concurrent appender.
///
/// Returns the inserted `audit_log.id`.
pub async fn append_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    row: &AuditRowForAppend,
) -> Result<i64> {
    perform_append(tx, row).await
}

/// Append an audit row in its own transaction. Used by cross-process
/// CLI callers that don't have a writer task in their address space —
/// `cairn publish-service-record` and `cairn unpublish-service-record`
/// run as one-shot CLIs and write to the same SQLite file as a running
/// `cairn serve`, so the SQLite write lock is what serializes them
/// against the writer's appends.
///
/// `BEGIN IMMEDIATE` is the load-bearing primitive: it acquires the
/// write lock at transaction-start instead of first-write-statement,
/// closing the read-then-modify race that would otherwise let two
/// processes both observe the same `prev_hash` and write rows that
/// fork the chain. sqlx 0.8's `Pool::begin` issues `BEGIN DEFERRED`
/// with no override hook, so we reach for `Pool::acquire` + raw SQL.
pub async fn append_via_pool(pool: &Pool<Sqlite>, row: &AuditRowForAppend) -> Result<i64> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| Error::Signing(format!("audit acquire: {e}")))?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .map_err(|e| Error::Signing(format!("audit begin: {e}")))?;

    match perform_append(&mut conn, row).await {
        Ok(id) => {
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .map_err(|e| Error::Signing(format!("audit commit: {e}")))?;
            Ok(id)
        }
        Err(e) => {
            // Best-effort rollback — if the rollback itself fails the
            // connection is in a degraded state but the original error
            // is what the caller cares about.
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

/// Connection-level append: reads `prev_hash`, computes `row_hash`,
/// INSERTs the row. The caller is responsible for transactional
/// framing (either inheriting one via [`append_in_tx`] or issuing
/// `BEGIN IMMEDIATE` via [`append_via_pool`]).
async fn perform_append(conn: &mut SqliteConnection, row: &AuditRowForAppend) -> Result<i64> {
    let prev_hash = read_latest_chain_hash(&mut *conn).await?;
    let row_hash = compute_audit_row_hash(&prev_hash, &row.as_hashing())?;

    let prev_hash_slice: &[u8] = &prev_hash;
    let row_hash_slice: &[u8] = &row_hash;
    let id = sqlx::query_scalar!(
        "INSERT INTO audit_log
             (created_at, action, actor_did, target, target_cid, outcome, reason,
              prev_hash, row_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         RETURNING id",
        row.created_at,
        row.action,
        row.actor_did,
        row.target,
        row.target_cid,
        row.outcome,
        row.reason,
        prev_hash_slice,
        row_hash_slice,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| Error::Signing(format!("audit append: {e}")))?;
    Ok(id)
}

/// Read the latest stored `row_hash` across the unified chain.
///
/// Walks four tables since #94 / v1.7: `audit_log` (#39),
/// `pds_admin_audit` (#85 / §F23), `xrpc_known_callers` and
/// `xrpc_trusted_pdses` (#94 / §F23 inbound). Skips pre-v1.3
/// `audit_log` rows that have NULL hashes. Returns
/// [`GENESIS_PREV_HASH`] when all four tables are empty (or
/// `audit_log` only contains pre-v1.3 NULL rows and the other
/// three are empty).
///
/// # Tie-break
///
/// When multiple candidate rows share the latest timestamp, the
/// chain tip is the one with the highest **table priority**:
///
/// | Table | Priority |
/// |-------|----------|
/// | `audit_log` | 0 |
/// | `pds_admin_audit` | 1 |
/// | `xrpc_known_callers` | 2 |
/// | `xrpc_trusted_pdses` | 3 |
///
/// Higher priority = "newer in the chain" on ties. Mirrored by
/// `cairn audit verify`'s walker (#88, extended in #94). The
/// pairing keeps the read and the walker consistent so the
/// chain has a single canonical ordering.
///
/// **Monotonicity caveat:** if a low-priority row inserts AFTER
/// a high-priority row at the same millisecond timestamp, the
/// priority-based tie-break treats the high-priority row as the
/// chain tip (not the actually-most-recently-inserted low-
/// priority row), and the next chained row would skip the low-
/// priority one. The `xrpc_*` write paths in #94 enforce
/// strict-monotonic timestamps to sidestep this; the existing
/// `audit_log` + `pds_admin_audit` paths rely on the writer task's
/// natural sub-millisecond gap between writes (ms-resolution
/// timestamps tied across these two tables are rare in practice).
///
/// `pub(crate)` so the `pds_admin_audit` (#85) and `xrpc_*`
/// (#94) append helpers can share the same chain-tip read.
pub(crate) async fn read_latest_chain_hash(conn: &mut SqliteConnection) -> Result<[u8; 32]> {
    let candidates = read_chain_tip_candidates(&mut *conn).await?;
    Ok(select_chain_tip(&candidates).unwrap_or(GENESIS_PREV_HASH))
}

/// Borrowed candidate row across the four chain tables. Each
/// variant carries the row's chain-ordering timestamp and the
/// stored `row_hash` (or `None` for pre-v1.3 audit_log rows that
/// haven't been backfilled by `cairn audit-rebuild`).
#[derive(Debug, Clone)]
struct ChainTipCandidate {
    /// Chain-ordering timestamp (epoch-ms).
    timestamp: i64,
    /// Stable per-table priority (see `read_latest_chain_hash`).
    priority: u8,
    /// Stored row_hash. `None` only for pre-v1.3 audit_log rows.
    row_hash: Option<Vec<u8>>,
}

async fn read_chain_tip_candidates(conn: &mut SqliteConnection) -> Result<Vec<ChainTipCandidate>> {
    let mut out = Vec::with_capacity(4);

    let audit_log = sqlx::query!(
        "SELECT row_hash, created_at FROM audit_log
         WHERE row_hash IS NOT NULL
         ORDER BY id DESC LIMIT 1"
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| Error::Signing(format!("audit_log prev_hash read: {e}")))?;
    if let Some(r) = audit_log {
        out.push(ChainTipCandidate {
            timestamp: r.created_at,
            priority: 0,
            row_hash: r.row_hash,
        });
    }

    let pds_admin = sqlx::query!(
        "SELECT row_hash, call_completed_at FROM pds_admin_audit
         ORDER BY id DESC LIMIT 1"
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| Error::Signing(format!("pds_admin_audit prev_hash read: {e}")))?;
    if let Some(r) = pds_admin {
        out.push(ChainTipCandidate {
            timestamp: r.call_completed_at,
            priority: 1,
            row_hash: Some(r.row_hash),
        });
    }

    let known_callers = sqlx::query!(
        "SELECT row_hash, added_at FROM xrpc_known_callers
         ORDER BY added_at DESC LIMIT 1"
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| Error::Signing(format!("xrpc_known_callers prev_hash read: {e}")))?;
    if let Some(r) = known_callers {
        out.push(ChainTipCandidate {
            timestamp: r.added_at,
            priority: 2,
            row_hash: Some(r.row_hash),
        });
    }

    let trusted_pdses = sqlx::query!(
        "SELECT row_hash, added_at FROM xrpc_trusted_pdses
         ORDER BY added_at DESC LIMIT 1"
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| Error::Signing(format!("xrpc_trusted_pdses prev_hash read: {e}")))?;
    if let Some(r) = trusted_pdses {
        out.push(ChainTipCandidate {
            timestamp: r.added_at,
            priority: 3,
            row_hash: Some(r.row_hash),
        });
    }

    Ok(out)
}

/// Read the maximum chain-ordering timestamp across all four
/// chain tables, in epoch-ms. Returns `None` when all four are
/// empty.
///
/// Used by the #94 `xrpc_*` write paths to enforce strict-
/// monotonic chain timestamps:
/// `added_at = max(epoch_ms_now(), max_existing + 1)`. This
/// sidesteps the priority-tie-break monotonicity caveat
/// documented on [`read_latest_chain_hash`] for chain extensions
/// that originate outside the writer task (CLI inserts).
pub(crate) async fn read_latest_chain_timestamp_ms(
    conn: &mut SqliteConnection,
) -> Result<Option<i64>> {
    let candidates = read_chain_tip_candidates(&mut *conn).await?;
    Ok(candidates.iter().map(|c| c.timestamp).max())
}

/// Pick the chain tip from a set of candidates, applying the
/// `(timestamp DESC, priority DESC)` rule. Returns `None` if no
/// candidate has a non-NULL `row_hash` (caller defaults to
/// `GENESIS_PREV_HASH`).
fn select_chain_tip(candidates: &[ChainTipCandidate]) -> Option<[u8; 32]> {
    let mut best: Option<&ChainTipCandidate> = None;
    for c in candidates {
        if c.row_hash.is_none() {
            continue;
        }
        match best {
            None => best = Some(c),
            Some(b) => {
                if c.timestamp > b.timestamp
                    || (c.timestamp == b.timestamp && c.priority > b.priority)
                {
                    best = Some(c);
                }
            }
        }
    }
    let bytes = best?.row_hash.as_ref()?;
    parse_stored_hash(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage;
    use tempfile::tempdir;

    async fn fresh_pool() -> Pool<Sqlite> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-test.db");
        let pool = storage::open(&path).await.unwrap();
        // Hold the tempdir for the pool's lifetime via Box::leak —
        // the pool's connections reference the on-disk file. Test-only
        // pattern; production paths own their TempDir explicitly.
        Box::leak(Box::new(dir));
        pool
    }

    fn sample_row(action: &str, actor_did: &str) -> AuditRowForAppend {
        AuditRowForAppend {
            created_at: 1_776_902_400_000,
            action: action.into(),
            actor_did: actor_did.into(),
            target: Some("at://did:plc:target/col/r".into()),
            target_cid: None,
            outcome: "success".into(),
            reason: None,
        }
    }

    #[tokio::test]
    async fn first_append_uses_genesis_prev_hash() {
        let pool = fresh_pool().await;
        let id = append_via_pool(&pool, &sample_row("label_applied", "did:plc:m1"))
            .await
            .unwrap();

        let stored = sqlx::query!(
            "SELECT prev_hash, row_hash FROM audit_log WHERE id = ?1",
            id
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let prev: &[u8] = stored.prev_hash.as_deref().expect("prev_hash present");
        assert_eq!(prev, GENESIS_PREV_HASH);
        assert!(stored.row_hash.is_some());
    }

    #[tokio::test]
    async fn second_append_chains_to_first_row_hash() {
        let pool = fresh_pool().await;
        let id1 = append_via_pool(&pool, &sample_row("label_applied", "did:plc:m1"))
            .await
            .unwrap();
        let id2 = append_via_pool(&pool, &sample_row("label_negated", "did:plc:m1"))
            .await
            .unwrap();

        let row1_hash: Vec<u8> = sqlx::query_scalar!(
            r#"SELECT row_hash AS "row_hash!" FROM audit_log WHERE id = ?1"#,
            id1
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let row2_prev: Vec<u8> = sqlx::query_scalar!(
            r#"SELECT prev_hash AS "prev_hash!" FROM audit_log WHERE id = ?1"#,
            id2
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row1_hash, row2_prev,
            "row 2's prev_hash must match row 1's row_hash"
        );
    }

    #[tokio::test]
    async fn pre_v13_null_rows_are_skipped_for_prev_hash_lookup() {
        let pool = fresh_pool().await;
        // Manually insert a pre-v1.3 row (NULL hashes), then append
        // a v1.3 row and confirm the v1.3 row's prev_hash is GENESIS,
        // not the NULL value of the previous row.
        sqlx::query!(
            "INSERT INTO audit_log (created_at, action, actor_did, outcome)
             VALUES (?1, ?2, ?3, ?4)",
            1_i64,
            "label_applied",
            "did:plc:m1",
            "success"
        )
        .execute(&pool)
        .await
        .unwrap();

        let v13_id = append_via_pool(&pool, &sample_row("label_negated", "did:plc:m1"))
            .await
            .unwrap();

        let prev: Option<Vec<u8>> =
            sqlx::query_scalar!("SELECT prev_hash FROM audit_log WHERE id = ?1", v13_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let prev_bytes = prev.expect("prev_hash present on v1.3 row");
        assert_eq!(
            prev_bytes.as_slice(),
            GENESIS_PREV_HASH,
            "v1.3 row must use GENESIS_PREV_HASH when latest row has NULL row_hash"
        );
    }

    #[tokio::test]
    async fn append_in_tx_and_append_via_pool_produce_same_row_hash() {
        // Pin the no-drift contract from #39's design: both append
        // paths must compute the same row_hash for the same row
        // content + prev_hash. If this test ever fails, the hash
        // implementation has split between the two paths.
        let pool_a = fresh_pool().await;
        let pool_b = fresh_pool().await;
        let row = sample_row("label_applied", "did:plc:m1");

        // Path 1: append_via_pool on its own.
        let id_a = append_via_pool(&pool_a, &row).await.unwrap();
        let hash_a: Vec<u8> = sqlx::query_scalar!(
            r#"SELECT row_hash AS "row_hash!" FROM audit_log WHERE id = ?1"#,
            id_a
        )
        .fetch_one(&pool_a)
        .await
        .unwrap();

        // Path 2: append_in_tx via an explicit BEGIN IMMEDIATE on a
        // raw connection (matches the production tx pattern that
        // writer-internal callers and flag_reporter exercise).
        let mut tx = pool_b.begin().await.unwrap();
        let id_b = append_in_tx(&mut tx, &row).await.unwrap();
        tx.commit().await.unwrap();
        let hash_b: Vec<u8> = sqlx::query_scalar!(
            r#"SELECT row_hash AS "row_hash!" FROM audit_log WHERE id = ?1"#,
            id_b
        )
        .fetch_one(&pool_b)
        .await
        .unwrap();

        assert_eq!(
            hash_a, hash_b,
            "append_via_pool and append_in_tx must agree on row_hash for identical input"
        );
    }
}
