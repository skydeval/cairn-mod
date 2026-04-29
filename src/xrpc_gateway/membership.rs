//! Membership tables for the inbound XRPC gateway (#94, v1.7).
//!
//! Two append-only-except-revoke SQLite tables that gate per-NSID
//! authorization for the gateway's request path. Per §A9 / §A10:
//!
//! - [`xrpc_known_callers`](crate) — moderator DIDs whose proxied
//!   `tools.ozone.moderation.*` calls are accepted. The JWT
//!   issuer is the user (a moderator) attesting to themselves.
//! - [`xrpc_trusted_pdses`](crate) — PDS DIDs whose forwarded
//!   `com.atproto.moderation.createReport` calls are accepted.
//!   The JWT issuer is the PDS itself attesting to who
//!   `reportedBy` is.
//!
//! These answer **cryptographically distinct** authorization
//! questions; conflating them creates a confused trust model.
//! Two tables, two read APIs, two CLI surfaces.
//!
//! # Hash-chain integration
//!
//! ADD writes a chained INSERT — the row's `prev_hash` /
//! `row_hash` link into the unified §F23 audit chain alongside
//! `audit_log` and `pds_admin_audit`. REVOKE updates the existing
//! row's `revoked_at` + `revoked_by_moderator` (the migration's
//! trigger allows only that update shape) AND writes a sibling
//! `audit_log` row recording the revocation. The chain reflects
//! both events: the original ADD in chain order; the REVOKE as
//! a downstream `audit_log` row.
//!
//! # Strict-monotonic timestamps
//!
//! Membership writes can come from CLI processes (separate from
//! the writer task), so the chain head's priority-based tie-break
//! could in principle put a low-priority row before the actually-
//! most-recent high-priority row at the same millisecond. Sidestep
//! the corner case by enforcing
//! `added_at = max(epoch_ms_now(), max_existing_chain_ts + 1)`
//! at insert time. The CLI's writes are then guaranteed to extend
//! the chain monotonically regardless of timestamp ties with the
//! writer task.

use std::collections::BTreeMap;

use proto_blue_lex_cbor::encode;
use proto_blue_lex_data::LexValue;
use sqlx::sqlite::SqliteConnection;
use sqlx::{Pool, Sqlite};

use crate::audit::append::{
    AuditRowForAppend, append_in_tx, read_latest_chain_hash, read_latest_chain_timestamp_ms,
};
use crate::audit::hash::compute_chain_hash;
use crate::error::{Error, Result};
use crate::writer::epoch_ms_now;

/// A row from `xrpc_known_callers` or `xrpc_trusted_pdses` (the
/// shape is identical between the two tables).
#[derive(Debug, Clone)]
pub struct MembershipRow {
    /// Subject DID.
    pub did: String,
    /// Operator-supplied label.
    pub note: Option<String>,
    /// DID of the moderator who added this row.
    pub added_by_moderator: String,
    /// Wall-clock epoch-ms at INSERT time (chain-ordering
    /// timestamp).
    pub added_at: i64,
    /// `Some(_)` when the row has been revoked; `None` for
    /// active rows. The active-only read APIs filter on
    /// `revoked_at IS NULL` via the partial index.
    pub revoked_at: Option<i64>,
    /// DID of the moderator who revoked this row, set
    /// alongside `revoked_at`.
    pub revoked_by_moderator: Option<String>,
}

// ===========================================================================
// Read API
// ===========================================================================

/// Whether `did` is currently an active known caller (i.e. has a
/// row in `xrpc_known_callers` with `revoked_at IS NULL`).
///
/// Used by the membership middleware (#94) to gate proxied
/// `tools.ozone.moderation.*` calls.
pub async fn is_known_caller(pool: &Pool<Sqlite>, did: &str) -> Result<bool> {
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM xrpc_known_callers
         WHERE did = ?1 AND revoked_at IS NULL",
        did
    )
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// Whether `did` is currently an active trusted PDS.
///
/// Used by the membership middleware to gate forwarded
/// `com.atproto.moderation.createReport` calls.
pub async fn is_trusted_pds(pool: &Pool<Sqlite>, did: &str) -> Result<bool> {
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM xrpc_trusted_pdses
         WHERE did = ?1 AND revoked_at IS NULL",
        did
    )
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// List `xrpc_known_callers` rows.
///
/// `include_revoked = false` returns only active rows (the
/// production runtime cares only about active membership).
/// `include_revoked = true` returns all rows including revoked
/// ones (for the CLI's `list --include-revoked` and audit-
/// forensic queries).
pub async fn list_known_callers(
    pool: &Pool<Sqlite>,
    include_revoked: bool,
) -> Result<Vec<MembershipRow>> {
    let rows = if include_revoked {
        sqlx::query!(
            "SELECT did, note, added_by_moderator, added_at, revoked_at, revoked_by_moderator
             FROM xrpc_known_callers ORDER BY added_at ASC"
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| MembershipRow {
            did: r.did,
            note: r.note,
            added_by_moderator: r.added_by_moderator,
            added_at: r.added_at,
            revoked_at: r.revoked_at,
            revoked_by_moderator: r.revoked_by_moderator,
        })
        .collect()
    } else {
        sqlx::query!(
            "SELECT did, note, added_by_moderator, added_at, revoked_at, revoked_by_moderator
             FROM xrpc_known_callers
             WHERE revoked_at IS NULL
             ORDER BY added_at ASC"
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| MembershipRow {
            did: r.did,
            note: r.note,
            added_by_moderator: r.added_by_moderator,
            added_at: r.added_at,
            revoked_at: r.revoked_at,
            revoked_by_moderator: r.revoked_by_moderator,
        })
        .collect()
    };
    Ok(rows)
}

/// List `xrpc_trusted_pdses` rows. Mirror of [`list_known_callers`].
pub async fn list_trusted_pdses(
    pool: &Pool<Sqlite>,
    include_revoked: bool,
) -> Result<Vec<MembershipRow>> {
    let rows = if include_revoked {
        sqlx::query!(
            "SELECT did, note, added_by_moderator, added_at, revoked_at, revoked_by_moderator
             FROM xrpc_trusted_pdses ORDER BY added_at ASC"
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| MembershipRow {
            did: r.did,
            note: r.note,
            added_by_moderator: r.added_by_moderator,
            added_at: r.added_at,
            revoked_at: r.revoked_at,
            revoked_by_moderator: r.revoked_by_moderator,
        })
        .collect()
    } else {
        sqlx::query!(
            "SELECT did, note, added_by_moderator, added_at, revoked_at, revoked_by_moderator
             FROM xrpc_trusted_pdses
             WHERE revoked_at IS NULL
             ORDER BY added_at ASC"
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| MembershipRow {
            did: r.did,
            note: r.note,
            added_by_moderator: r.added_by_moderator,
            added_at: r.added_at,
            revoked_at: r.revoked_at,
            revoked_by_moderator: r.revoked_by_moderator,
        })
        .collect()
    };
    Ok(rows)
}

// ===========================================================================
// Write API
// ===========================================================================

/// Which membership table a write targets. Internal — the public
/// API exposes `add_known_caller` / `add_trusted_pds` etc.
#[derive(Debug, Clone, Copy)]
enum MembershipTable {
    KnownCallers,
    TrustedPdses,
}

impl MembershipTable {
    fn name(self) -> &'static str {
        match self {
            Self::KnownCallers => "xrpc_known_callers",
            Self::TrustedPdses => "xrpc_trusted_pdses",
        }
    }
}

/// Add a row to `xrpc_known_callers`. Errors if the DID is
/// already present and active.
pub async fn add_known_caller(
    pool: &Pool<Sqlite>,
    did: &str,
    note: Option<&str>,
    added_by_moderator: &str,
) -> Result<MembershipRow> {
    add_membership_row(
        pool,
        MembershipTable::KnownCallers,
        did,
        note,
        added_by_moderator,
    )
    .await
}

/// Add a row to `xrpc_trusted_pdses`. Mirror of
/// [`add_known_caller`].
pub async fn add_trusted_pds(
    pool: &Pool<Sqlite>,
    did: &str,
    note: Option<&str>,
    added_by_moderator: &str,
) -> Result<MembershipRow> {
    add_membership_row(
        pool,
        MembershipTable::TrustedPdses,
        did,
        note,
        added_by_moderator,
    )
    .await
}

/// Revoke a known caller. Sets `revoked_at` + `revoked_by_moderator`
/// on the row (one-way transition; the trigger forbids further
/// updates) AND writes a sibling `audit_log` row so the revocation
/// appears in chain order alongside other administrative events.
pub async fn revoke_known_caller(
    pool: &Pool<Sqlite>,
    did: &str,
    revoked_by_moderator: &str,
) -> Result<()> {
    revoke_membership_row(
        pool,
        MembershipTable::KnownCallers,
        did,
        revoked_by_moderator,
    )
    .await
}

/// Revoke a trusted PDS. Mirror of [`revoke_known_caller`].
pub async fn revoke_trusted_pds(
    pool: &Pool<Sqlite>,
    did: &str,
    revoked_by_moderator: &str,
) -> Result<()> {
    revoke_membership_row(
        pool,
        MembershipTable::TrustedPdses,
        did,
        revoked_by_moderator,
    )
    .await
}

async fn add_membership_row(
    pool: &Pool<Sqlite>,
    table: MembershipTable,
    did: &str,
    note: Option<&str>,
    added_by_moderator: &str,
) -> Result<MembershipRow> {
    // BEGIN IMMEDIATE for the read-then-modify pair: chain-tip
    // read (timestamp + hash) + INSERT must be atomic against any
    // concurrent appender. Same primitive `pds_admin_audit::record_pds_admin_call`
    // uses (#85). sqlx's `Pool::begin` issues `BEGIN DEFERRED`
    // which doesn't acquire the write lock until the first write —
    // a concurrent writer-task append could squeeze in between
    // our read and INSERT. `BEGIN IMMEDIATE` closes that race.
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| Error::Signing(format!("membership acquire: {e}")))?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .map_err(|e| Error::Signing(format!("membership begin: {e}")))?;

    let result = perform_add(&mut conn, table, did, note, added_by_moderator).await;

    match result {
        Ok(row) => {
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .map_err(|e| Error::Signing(format!("membership commit: {e}")))?;
            Ok(row)
        }
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

async fn perform_add(
    conn: &mut SqliteConnection,
    table: MembershipTable,
    did: &str,
    note: Option<&str>,
    added_by_moderator: &str,
) -> Result<MembershipRow> {
    // Strict-monotonic timestamp (see module docs).
    let now_ms = epoch_ms_now();
    let max_existing = read_latest_chain_timestamp_ms(&mut *conn)
        .await?
        .unwrap_or(0);
    let added_at = now_ms.max(max_existing.saturating_add(1));

    let prev_hash = read_latest_chain_hash(&mut *conn).await?;
    let row_hash = compute_membership_row_hash(
        &prev_hash,
        &MembershipRowForHashing {
            did,
            note,
            added_by_moderator,
            added_at,
        },
    )?;

    let prev_hash_slice: &[u8] = &prev_hash;
    let row_hash_slice: &[u8] = &row_hash;

    let sql = match table {
        MembershipTable::KnownCallers => {
            "INSERT INTO xrpc_known_callers
                 (did, note, added_by_moderator, added_at, prev_hash, row_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        }
        MembershipTable::TrustedPdses => {
            "INSERT INTO xrpc_trusted_pdses
                 (did, note, added_by_moderator, added_at, prev_hash, row_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        }
    };

    sqlx::query(sql)
        .bind(did)
        .bind(note)
        .bind(added_by_moderator)
        .bind(added_at)
        .bind(prev_hash_slice)
        .bind(row_hash_slice)
        .execute(&mut *conn)
        .await
        .map_err(|e| Error::Signing(format!("{} insert: {e}", table.name())))?;

    Ok(MembershipRow {
        did: did.to_string(),
        note: note.map(str::to_string),
        added_by_moderator: added_by_moderator.to_string(),
        added_at,
        revoked_at: None,
        revoked_by_moderator: None,
    })
}

async fn revoke_membership_row(
    pool: &Pool<Sqlite>,
    table: MembershipTable,
    did: &str,
    revoked_by_moderator: &str,
) -> Result<()> {
    let mut tx = pool.begin().await?;

    // Verify the row exists and isn't already revoked. Pull the
    // pre-existing fields so the audit-log entry can carry the
    // original add-time metadata.
    let existing = match table {
        MembershipTable::KnownCallers => sqlx::query!(
            "SELECT added_by_moderator, added_at, revoked_at FROM xrpc_known_callers
             WHERE did = ?1",
            did
        )
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| (r.added_by_moderator, r.added_at, r.revoked_at)),
        MembershipTable::TrustedPdses => sqlx::query!(
            "SELECT added_by_moderator, added_at, revoked_at FROM xrpc_trusted_pdses
             WHERE did = ?1",
            did
        )
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| (r.added_by_moderator, r.added_at, r.revoked_at)),
    };
    let Some((_added_by, _added_at, revoked_at)) = existing else {
        return Err(Error::Signing(format!(
            "{} row not found for did {did:?}",
            table.name()
        )));
    };
    if revoked_at.is_some() {
        return Err(Error::Signing(format!(
            "{} row for did {did:?} is already revoked",
            table.name()
        )));
    }

    let now_ms = epoch_ms_now();

    let update_sql = match table {
        MembershipTable::KnownCallers => {
            "UPDATE xrpc_known_callers
             SET revoked_at = ?1, revoked_by_moderator = ?2
             WHERE did = ?3"
        }
        MembershipTable::TrustedPdses => {
            "UPDATE xrpc_trusted_pdses
             SET revoked_at = ?1, revoked_by_moderator = ?2
             WHERE did = ?3"
        }
    };

    sqlx::query(update_sql)
        .bind(now_ms)
        .bind(revoked_by_moderator)
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::Signing(format!("{} revoke: {e}", table.name())))?;

    // Sibling audit_log row so the revocation appears in chain
    // order. Reuses #85's chain-extending append_in_tx.
    let audit_action = match table {
        MembershipTable::KnownCallers => "xrpc_known_caller_revoked",
        MembershipTable::TrustedPdses => "xrpc_trusted_pds_revoked",
    };
    append_in_tx(
        &mut tx,
        &AuditRowForAppend {
            created_at: now_ms,
            action: audit_action.to_string(),
            actor_did: revoked_by_moderator.to_string(),
            target: Some(did.to_string()),
            target_cid: None,
            outcome: "success".to_string(),
            reason: None,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

// ===========================================================================
// Chain hashing for membership rows
// ===========================================================================

struct MembershipRowForHashing<'a> {
    did: &'a str,
    note: Option<&'a str>,
    added_by_moderator: &'a str,
    added_at: i64,
}

fn compute_membership_row_hash(
    prev_hash: &[u8; 32],
    row: &MembershipRowForHashing<'_>,
) -> Result<[u8; 32]> {
    let canonical = encode(&row_to_lex_value(row))?;
    Ok(compute_chain_hash(prev_hash, &canonical))
}

fn row_to_lex_value(row: &MembershipRowForHashing<'_>) -> LexValue {
    let mut m = BTreeMap::new();
    m.insert("did".to_string(), LexValue::String(row.did.to_string()));
    if let Some(note) = row.note {
        m.insert("note".to_string(), LexValue::String(note.to_string()));
    }
    m.insert(
        "added_by_moderator".to_string(),
        LexValue::String(row.added_by_moderator.to_string()),
    );
    m.insert("added_at".to_string(), LexValue::Integer(row.added_at));
    LexValue::Map(m)
}

/// `pub(crate)` projection of the membership row's hash inputs.
/// Used by `cairn audit verify` (#88, extended in #94) to walk
/// the unified chain across all four tables — the verifier
/// recomputes each row's `row_hash` against its stored content
/// using this same canonicalization.
pub(crate) fn recompute_membership_row_hash(
    prev_hash: &[u8; 32],
    did: &str,
    note: Option<&str>,
    added_by_moderator: &str,
    added_at: i64,
) -> Result<[u8; 32]> {
    compute_membership_row_hash(
        prev_hash,
        &MembershipRowForHashing {
            did,
            note,
            added_by_moderator,
            added_at,
        },
    )
}

#[cfg(test)]
#[allow(unused_imports, dead_code)]
mod tests {
    use super::*;
    use crate::storage;
    use tempfile::tempdir;

    async fn fresh_pool() -> Pool<Sqlite> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("membership-test.db");
        let pool = storage::open(&path).await.unwrap();
        Box::leak(Box::new(dir));
        pool
    }

    const M_DID: &str = "did:plc:moderator0000000000000000";

    // ===== Known-callers =====

    #[tokio::test]
    async fn add_known_caller_persists_active_row() {
        let pool = fresh_pool().await;
        add_known_caller(&pool, "did:plc:alice", Some("alice"), M_DID)
            .await
            .unwrap();
        assert!(is_known_caller(&pool, "did:plc:alice").await.unwrap());
        assert!(!is_known_caller(&pool, "did:plc:bob").await.unwrap());
    }

    #[tokio::test]
    async fn list_known_callers_active_only_excludes_revoked() {
        let pool = fresh_pool().await;
        add_known_caller(&pool, "did:plc:alice", None, M_DID)
            .await
            .unwrap();
        add_known_caller(&pool, "did:plc:bob", None, M_DID)
            .await
            .unwrap();
        revoke_known_caller(&pool, "did:plc:alice", M_DID)
            .await
            .unwrap();

        let active = list_known_callers(&pool, false).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].did, "did:plc:bob");

        let all = list_known_callers(&pool, true).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn revoke_known_caller_marks_inactive_and_writes_audit_log() {
        let pool = fresh_pool().await;
        add_known_caller(&pool, "did:plc:alice", Some("alice"), M_DID)
            .await
            .unwrap();
        revoke_known_caller(&pool, "did:plc:alice", M_DID)
            .await
            .unwrap();
        assert!(!is_known_caller(&pool, "did:plc:alice").await.unwrap());

        // Sibling audit_log row recorded.
        let audit_count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM audit_log
             WHERE action = 'xrpc_known_caller_revoked' AND target = 'did:plc:alice'"
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);
    }

    #[tokio::test]
    async fn revoke_unknown_did_errors() {
        let pool = fresh_pool().await;
        let res = revoke_known_caller(&pool, "did:plc:nope", M_DID).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn double_revoke_errors() {
        let pool = fresh_pool().await;
        add_known_caller(&pool, "did:plc:alice", None, M_DID)
            .await
            .unwrap();
        revoke_known_caller(&pool, "did:plc:alice", M_DID)
            .await
            .unwrap();
        let res = revoke_known_caller(&pool, "did:plc:alice", M_DID).await;
        assert!(res.is_err(), "double-revoke must fail");
    }

    // ===== Trusted-PDSes (mirror) =====

    #[tokio::test]
    async fn add_trusted_pds_persists_active_row() {
        let pool = fresh_pool().await;
        add_trusted_pds(&pool, "did:web:bsky.example.com", None, M_DID)
            .await
            .unwrap();
        assert!(
            is_trusted_pds(&pool, "did:web:bsky.example.com")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn revoke_trusted_pds_marks_inactive() {
        let pool = fresh_pool().await;
        add_trusted_pds(&pool, "did:web:bsky.example.com", None, M_DID)
            .await
            .unwrap();
        revoke_trusted_pds(&pool, "did:web:bsky.example.com", M_DID)
            .await
            .unwrap();
        assert!(
            !is_trusted_pds(&pool, "did:web:bsky.example.com")
                .await
                .unwrap()
        );
    }

    // ===== Cross-table independence =====

    #[tokio::test]
    async fn known_caller_membership_does_not_imply_trusted_pds() {
        // Different security domains: a moderator DID being a
        // known caller doesn't make their (hypothetical) PDS a
        // trusted PDS. The two tables answer different
        // authorization questions.
        let pool = fresh_pool().await;
        add_known_caller(&pool, "did:plc:alice", None, M_DID)
            .await
            .unwrap();
        assert!(is_known_caller(&pool, "did:plc:alice").await.unwrap());
        assert!(!is_trusted_pds(&pool, "did:plc:alice").await.unwrap());
    }

    // ===== Hash-chain integration =====

    #[tokio::test]
    async fn membership_rows_chain_with_audit_log() {
        // Insert an audit_log row, then a membership row, then
        // another audit_log row. Each subsequent row's prev_hash
        // must equal the prior row's row_hash — proving the
        // chain extends across the new tables.
        let pool = fresh_pool().await;

        crate::audit::append::append_via_pool(
            &pool,
            &AuditRowForAppend {
                created_at: 100,
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

        let m_row = add_known_caller(&pool, "did:plc:alice", None, M_DID)
            .await
            .unwrap();
        // Membership row's added_at is strict-monotonically > 100.
        assert!(m_row.added_at > 100);

        // The membership row's prev_hash equals the audit_log
        // row's row_hash. Verify by reading the stored prev_hash.
        let stored_prev: Vec<u8> = sqlx::query_scalar!(
            "SELECT prev_hash FROM xrpc_known_callers WHERE did = 'did:plc:alice'"
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let audit_row_hash: Vec<u8> =
            sqlx::query_scalar!(r#"SELECT row_hash AS "row_hash!" FROM audit_log WHERE id = 1"#)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_prev, audit_row_hash);
    }
}
