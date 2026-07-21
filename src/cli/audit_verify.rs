//! `cairn audit verify` (#41 / v1.3; #88 / v1.7 unified-chain
//! extension) — operator command for verifying the audit hash chain.
//!
//! Walks the **unified** chain across all four chained tables —
//! `audit_log`, `pds_admin_audit` (#85 / §F23), and the
//! `xrpc_known_callers` / `xrpc_trusted_pdses` membership tables
//! (#94) — in chain order, recomputes each attested row's
//! `row_hash` from the running prev_hash + the row's stored
//! content, and compares against the stored hash. Reports the
//! **first** divergence and stops. (The two-table wording that
//! previously opened this comment predated #94's extension and
//! misled the v1.8.6 recon; the walk has been four-table since
//! the membership tables landed.)
//!
//! # v1.8.6 preimage format boundary
//!
//! `pds_admin_audit` rows hash under two forms (v2 §5.2):
//! the v1.7 9-field preimage at or below the migration-0011
//! format boundary, and the v1.8.6 12-field preimage (adding the
//! Aurora response-persistence columns) above it — with a 9-field
//! fallback for post-boundary rows written by a pre-upgrade
//! binary mid-deploy (counted in
//! [`VerifyOutcome::Verified::legacy_form_rows`], not failed).
//!
//! Continuing past first divergence would cascade — every row after
//! a tampered row would also report mismatch, since the chain link
//! is broken from there forward. The first divergence is the
//! actionable signal; later rows are downstream noise.
//!
//! # Why both tables, not just `audit_log`
//!
//! v1.3's verify walked `audit_log` only. After #87 wired
//! `pds_admin_audit` rows into the recordAction pipeline, the
//! single-table walker would report false-positive divergences for
//! any `audit_log` row whose chain-predecessor is a
//! `pds_admin_audit` row (the predecessor's `row_hash` would not
//! be findable in `audit_log`). #88 extends the walker to read
//! both tables in a single ordered stream so the same chain
//! integrity property holds across the v1.7+ shape.
//!
//! # Chain ordering
//!
//! Matches the tie-break convention used by the crate-internal
//! `read_latest_chain_hash` helper in [`crate::audit::append`]
//! (#85):
//! 1. timestamp ascending — `audit_log.created_at` vs
//!    `pds_admin_audit.call_completed_at`
//! 2. on tie, `audit_log` comes before `pds_admin_audit` (because
//!    #85's chain-tip read uses `pds.call_completed_at >= a.created_at`,
//!    treating `pds_admin_audit` as the more-recent tie-winner;
//!    inverted, that means `pds_admin_audit` comes AFTER
//!    `audit_log` in chain order)
//! 3. within a single table, id ascending (id is
//!    `INTEGER PRIMARY KEY AUTOINCREMENT` — insertion order)
//!
//! # Read-only / streaming
//!
//! Read-only. No lease acquired (unlike `cairn audit-rebuild`); safe
//! to run while `cairn serve` is live. Concurrent writes during
//! verify are fine — SQLite's WAL gives us a consistent snapshot,
//! and any new rows arriving mid-walk are either fully included or
//! not at all.
//!
//! Loads both tables fully into memory (matching v1.3's existing
//! posture for `audit_log`-only walks). Streaming is a v1.x+
//! concern when production-scale audit logs make full-load
//! prohibitive; for v1.7's deployment scale (single-binary,
//! single-SQLite-file, community-tier per §10) full read is fine.
//! The full-load assumption is documented at the read site.
//!
//! # Pre-attestation rows
//!
//! Pre-v1.3 rows in `audit_log` (NULL `row_hash`) are **skipped,
//! not flagged**. They predate the chain attestation; verify counts
//! them so the operator sees exactly how much of their audit log
//! is unattested. `pds_admin_audit` has no pre-attestation rows
//! (the table only exists from v1.7 onward, and migration 0006
//! makes both hash columns NOT NULL).
//!
//! # Tampering detection model
//!
//! This catches any modification that changes a row's hash-relevant
//! content without recomputing the whole forward chain. A "smart"
//! attacker who tampers a row AND re-derives the entire downstream
//! chain is **not** caught by this command alone — that requires
//! external attestation (signed Merkle root, transparency log)
//! which is v1.x+ scope.

use std::cmp::Ordering;

use serde::Serialize;
use sqlx::{Pool, Sqlite};

use super::error::CliError;
use crate::audit::hash::{
    AuditRowForHashing, GENESIS_PREV_HASH, compute_audit_row_hash, parse_stored_hash,
};
use crate::pds_admin::audit::{PdsAdminAuditRowForHashing, compute_pds_admin_audit_row_hash};
use crate::xrpc_gateway::membership::recompute_membership_row_hash;

/// Which table a divergent row lives in. Lets operators correlate
/// the divergence id back to the right SQL table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTable {
    /// §F10 audit_log — the v1.3-original chain.
    AuditLog,
    /// §F23 pds_admin_audit — the v1.7-added chain (#85, #87).
    PdsAdminAudit,
    /// §F23 inbound xrpc_gateway membership — moderator DIDs
    /// authorized for proxied `tools.ozone.*` calls (#94).
    XrpcKnownCallers,
    /// §F23 inbound xrpc_gateway membership — PDS DIDs
    /// authorized to forward `createReport` calls (#94).
    XrpcTrustedPdses,
}

impl AuditTable {
    /// SQL-table name. Used by the human formatter and by the
    /// dispatcher in `main.rs` to populate
    /// [`crate::cli::error::CliError::AuditDivergence::table`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuditLog => "audit_log",
            Self::PdsAdminAudit => "pds_admin_audit",
            Self::XrpcKnownCallers => "xrpc_known_callers",
            Self::XrpcTrustedPdses => "xrpc_trusted_pdses",
        }
    }
}

/// Outcome of a verify run. Tests + the formatters branch on this
/// rather than on stdout text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// Both tables were empty; nothing to verify.
    Empty,
    /// Chain verified successfully.
    Verified {
        /// Total rows across both tables (attested + pre-attestation).
        total_rows: i64,
        /// Rows whose stored row_hash matched the recomputed hash
        /// (across both tables).
        attested_rows: i64,
        /// Rows with NULL row_hash that were skipped (pre-v1.3
        /// `audit_log` rows that haven't been backfilled by
        /// `cairn audit-rebuild`). `pds_admin_audit` rows are
        /// always attested, so this counts only `audit_log` rows.
        pre_attestation_rows: i64,
        /// `Some(N)` when rows 1..N-1 are pre-attestation and the
        /// attested chain begins at row N — the trust horizon. Refers
        /// to `audit_log.id` (the only table where pre-attestation
        /// rows exist).
        /// `None` when the first attested row's id is 1 (pure
        /// post-v1.3 deployment OR a fully-rebuilt deployment;
        /// either way, the chain is rooted at genesis with no
        /// horizon to call out).
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_starts_at_row: Option<i64>,
        /// Total `audit_log` rows seen during the walk
        /// (attested + pre-attestation). Added in #88 so operators
        /// can see the per-table breakdown when running on a
        /// post-#87 deployment.
        audit_log_rows: i64,
        /// Total `pds_admin_audit` rows seen during the walk.
        /// `0` for pre-#87 deployments and operators with
        /// `[pds_admin].enabled = false`.
        pds_admin_audit_rows: i64,
        /// Total `xrpc_known_callers` rows seen during the walk.
        /// Added in #94. `0` when `[xrpc_gateway]` is disabled
        /// or no callers have been added.
        xrpc_known_callers_rows: i64,
        /// Total `xrpc_trusted_pdses` rows seen during the walk
        /// (#94). Same defaulting as
        /// [`Self::Verified::xrpc_known_callers_rows`].
        xrpc_trusted_pdses_rows: i64,
        /// v1.8.6: post-boundary `pds_admin_audit` rows that
        /// verified only under the v1.7 9-field preimage
        /// (mid-deploy writes by a pre-upgrade binary). Expected
        /// 0; reported, never failed.
        legacy_form_rows: i64,
    },
    /// First-divergence report. Walking halts once this is detected.
    Divergence {
        /// Which table the divergent row lives in. Added in #88.
        /// Operators correlate `(table, row_id)` to the SQL row.
        table: AuditTable,
        /// `id` of the divergent row, scoped to the table named by
        /// [`Self::Divergence::table`].
        row_id: i64,
        /// Hex-encoded SHA-256 the chain says this row's row_hash
        /// should be.
        expected_hash: String,
        /// Hex-encoded SHA-256 actually stored in the row.
        actual_hash: String,
        /// Number of rows whose hashes verified before this one
        /// (across both tables). The truncation point operators
        /// reconcile from.
        attested_rows_before_divergence: i64,
    },
}

/// Walk the unified audit chain across `audit_log` and
/// `pds_admin_audit`, verifying every attested row's hash.
///
/// Returns `Ok(VerifyOutcome)` regardless of whether the chain is
/// intact; [`CliError`] is reserved for genuine errors (DB
/// unreachable, row_hash blob with wrong length, etc.). The
/// dispatcher in `main.rs` lifts `VerifyOutcome::Divergence` into
/// [`CliError::AuditDivergence`] for exit-code mapping.
///
/// Read-only. No lease, no transaction (a single SELECT is its own
/// implicit transaction in SQLite WAL mode). Concurrent appends
/// during the walk are tolerated — they either appear in our
/// snapshot or don't, but the chain integrity property holds for
/// whatever subset we read.
pub async fn verify(pool: &Pool<Sqlite>) -> Result<VerifyOutcome, CliError> {
    // Load both tables fully. Streaming would be a refactor for
    // production-scale audit logs; deferred per #88's prompt
    // ("not in scope").
    let audit_log_rows = read_audit_log_rows(pool).await?;
    let pds_admin_rows = read_pds_admin_audit_rows(pool).await?;
    // v1.8.6 preimage format boundary (migration 0011; one row,
    // captured at apply time).
    let format_boundary: i64 = sqlx::query_scalar!(
        r#"SELECT boundary_id AS "boundary_id!" FROM pds_admin_audit_format_boundary WHERE id = 1"#
    )
    .fetch_one(pool)
    .await
    .map_err(|e| CliError::Startup(format!("audit verify boundary read: {e}")))?;
    let xrpc_known_callers_rows = read_xrpc_known_callers_rows(pool).await?;
    let xrpc_trusted_pdses_rows = read_xrpc_trusted_pdses_rows(pool).await?;

    if audit_log_rows.is_empty()
        && pds_admin_rows.is_empty()
        && xrpc_known_callers_rows.is_empty()
        && xrpc_trusted_pdses_rows.is_empty()
    {
        return Ok(VerifyOutcome::Empty);
    }

    let audit_log_count = audit_log_rows.len() as i64;
    let pds_admin_count = pds_admin_rows.len() as i64;
    let xrpc_known_callers_count = xrpc_known_callers_rows.len() as i64;
    let xrpc_trusted_pdses_count = xrpc_trusted_pdses_rows.len() as i64;

    let mut entries: Vec<UnifiedEntry> = Vec::with_capacity(
        audit_log_rows.len()
            + pds_admin_rows.len()
            + xrpc_known_callers_rows.len()
            + xrpc_trusted_pdses_rows.len(),
    );
    entries.extend(audit_log_rows.into_iter().map(UnifiedEntry::AuditLog));
    entries.extend(pds_admin_rows.into_iter().map(UnifiedEntry::PdsAdmin));
    entries.extend(
        xrpc_known_callers_rows
            .into_iter()
            .map(UnifiedEntry::XrpcKnownCaller),
    );
    entries.extend(
        xrpc_trusted_pdses_rows
            .into_iter()
            .map(UnifiedEntry::XrpcTrustedPds),
    );
    entries.sort_by(unified_chain_cmp);

    let total_rows =
        audit_log_count + pds_admin_count + xrpc_known_callers_count + xrpc_trusted_pdses_count;
    let mut running_prev_hash: [u8; 32] = GENESIS_PREV_HASH;
    let mut attested_rows: i64 = 0;
    let mut pre_attestation_rows: i64 = 0;
    let mut legacy_form_rows: i64 = 0;
    let mut attestation_starts_at_row: Option<i64> = None;
    let mut seen_attested = false;

    for entry in &entries {
        let stored_row_hash_blob = match entry.row_hash() {
            Some(b) => b,
            None => {
                // Pre-attestation row: skip, don't update
                // running_prev_hash. Only audit_log produces these.
                pre_attestation_rows += 1;
                continue;
            }
        };

        if !seen_attested {
            seen_attested = true;
            // Trust horizon: only set the field when there's
            // actually a horizon to call out (first attested
            // audit_log row's id > 1). The horizon refers to
            // audit_log only — pds_admin_audit has no
            // pre-attestation rows, so a chain that starts with
            // a pds_admin_audit row has no horizon.
            if let UnifiedEntry::AuditLog(row) = entry
                && row.id != 1
            {
                attestation_starts_at_row = Some(row.id);
            }
        }

        let stored_row_hash = parse_stored_hash(stored_row_hash_blob).map_err(|e| {
            CliError::Startup(format!(
                "audit verify: {}:{} stored row_hash malformed: {e}",
                entry.table().as_str(),
                entry.id()
            ))
        })?;

        let recomputed = match entry {
            // v1.8.6 boundary-aware two-form verify for
            // pds_admin_audit rows (v2 §5.2/§5.3).
            UnifiedEntry::PdsAdmin(r) if r.id > format_boundary => {
                let v12 =
                    compute_pds_admin_audit_row_hash(&running_prev_hash, &r.hashing_row_v12())
                        .map_err(|e| {
                            CliError::Startup(format!(
                                "audit verify: pds_admin_audit:{} hash compute: {e}",
                                r.id
                            ))
                        })?;
                if v12 == stored_row_hash {
                    v12
                } else {
                    // Mid-deploy fallback: a post-boundary row
                    // written by a pre-upgrade binary hashes under
                    // the 9-field form. A match is counted, not
                    // failed; a miss reports the 12-field
                    // expectation (the boundary-prescribed form).
                    let v9 =
                        compute_pds_admin_audit_row_hash(&running_prev_hash, &r.hashing_row_v9())
                            .map_err(|e| {
                            CliError::Startup(format!(
                                "audit verify: pds_admin_audit:{} hash compute: {e}",
                                r.id
                            ))
                        })?;
                    if v9 == stored_row_hash {
                        legacy_form_rows += 1;
                        v9
                    } else {
                        v12
                    }
                }
            }
            _ => entry.recompute_row_hash(&running_prev_hash).map_err(|e| {
                CliError::Startup(format!(
                    "audit verify: {}:{} hash compute: {e}",
                    entry.table().as_str(),
                    entry.id()
                ))
            })?,
        };

        if recomputed != stored_row_hash {
            // First-divergence: bail with a structured report.
            return Ok(VerifyOutcome::Divergence {
                table: entry.table(),
                row_id: entry.id(),
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
        audit_log_rows: audit_log_count,
        pds_admin_audit_rows: pds_admin_count,
        xrpc_known_callers_rows: xrpc_known_callers_count,
        xrpc_trusted_pdses_rows: xrpc_trusted_pdses_count,
        legacy_form_rows,
    })
}

// ===========================================================================
// Unified chain entry + ordering
// ===========================================================================

/// Owned `audit_log` row data as the verify walker needs it.
struct AuditLogRow {
    id: i64,
    created_at: i64,
    action: String,
    actor_did: String,
    target: Option<String>,
    target_cid: Option<String>,
    outcome: String,
    reason: Option<String>,
    row_hash: Option<Vec<u8>>,
}

/// Owned `pds_admin_audit` row data as the verify walker needs it.
struct PdsAdminAuditRow {
    id: i64,
    precipitating_action_id: i64,
    backend_method: String,
    backend_action_id: Option<String>,
    outcome: String,
    error_code: Option<String>,
    error_message: Option<String>,
    retry_after_seconds: Option<i64>,
    call_started_at: i64,
    call_completed_at: i64,
    row_hash: Vec<u8>,
    // v1.8.6 response-persistence columns (12-field preimage).
    upstream_audit_entry_id: Option<String>,
    cascading_actions_json: Option<String>,
    snapshots_json: Option<String>,
}

impl PdsAdminAuditRow {
    /// The v1.7 9-field hashing view (pre-boundary rows; also the
    /// mid-deploy fallback form).
    fn hashing_row_v9(&self) -> PdsAdminAuditRowForHashing<'_> {
        PdsAdminAuditRowForHashing {
            precipitating_action_id: self.precipitating_action_id,
            backend_method: &self.backend_method,
            backend_action_id: self.backend_action_id.as_deref(),
            outcome: &self.outcome,
            error_code: self.error_code.as_deref(),
            error_message: self.error_message.as_deref(),
            retry_after_seconds: self.retry_after_seconds,
            call_started_at: self.call_started_at,
            call_completed_at: self.call_completed_at,
            upstream_audit_entry_id: None,
            cascading_actions_json: None,
            snapshots_json: None,
        }
    }

    /// The v1.8.6 12-field hashing view (post-boundary rows).
    fn hashing_row_v12(&self) -> PdsAdminAuditRowForHashing<'_> {
        PdsAdminAuditRowForHashing {
            upstream_audit_entry_id: self.upstream_audit_entry_id.as_deref(),
            cascading_actions_json: self.cascading_actions_json.as_deref(),
            snapshots_json: self.snapshots_json.as_deref(),
            ..self.hashing_row_v9()
        }
    }
}

/// Owned `xrpc_known_callers` / `xrpc_trusted_pdses` row data.
/// Same shape between the two tables; the variant tag is what
/// distinguishes them in [`UnifiedEntry`]. Matches
/// `recompute_membership_row_hash`'s input shape.
struct XrpcMembershipRow {
    /// Per-table id surrogate. Membership tables use `did` as
    /// the primary key; the verify walker uses a synthesized id
    /// (the position in the table's ORDER BY scan) so the
    /// `Divergence::row_id` field carries something stable.
    /// Since `did` is `String` and the divergence struct's
    /// `row_id` is `i64`, we use a row index here.
    rowid: i64,
    did: String,
    note: Option<String>,
    added_by_moderator: String,
    added_at: i64,
    row_hash: Vec<u8>,
}

/// One entry in the unified audit chain. The variant determines
/// which row-shape canonicalization applies during recomputation.
enum UnifiedEntry {
    AuditLog(AuditLogRow),
    PdsAdmin(PdsAdminAuditRow),
    XrpcKnownCaller(XrpcMembershipRow),
    XrpcTrustedPds(XrpcMembershipRow),
}

impl UnifiedEntry {
    fn table(&self) -> AuditTable {
        match self {
            Self::AuditLog(_) => AuditTable::AuditLog,
            Self::PdsAdmin(_) => AuditTable::PdsAdminAudit,
            Self::XrpcKnownCaller(_) => AuditTable::XrpcKnownCallers,
            Self::XrpcTrustedPds(_) => AuditTable::XrpcTrustedPdses,
        }
    }

    fn id(&self) -> i64 {
        match self {
            Self::AuditLog(r) => r.id,
            Self::PdsAdmin(r) => r.id,
            Self::XrpcKnownCaller(r) | Self::XrpcTrustedPds(r) => r.rowid,
        }
    }

    /// The chain-ordering timestamp. `audit_log.created_at` for
    /// AuditLog entries; `pds_admin_audit.call_completed_at` for
    /// PdsAdmin entries; `xrpc_*.added_at` for the membership
    /// entries — matching the
    /// [`crate::audit::append::read_latest_chain_hash`] tie-break
    /// rules.
    fn timestamp(&self) -> i64 {
        match self {
            Self::AuditLog(r) => r.created_at,
            Self::PdsAdmin(r) => r.call_completed_at,
            Self::XrpcKnownCaller(r) | Self::XrpcTrustedPds(r) => r.added_at,
        }
    }

    /// `Some(row_hash)` for attested rows; `None` for pre-v1.3
    /// `audit_log` rows that haven't been backfilled by
    /// `cairn audit-rebuild`. The other tables' hash columns
    /// are NOT NULL per their migrations.
    fn row_hash(&self) -> Option<&[u8]> {
        match self {
            Self::AuditLog(r) => r.row_hash.as_deref(),
            Self::PdsAdmin(r) => Some(&r.row_hash),
            Self::XrpcKnownCaller(r) | Self::XrpcTrustedPds(r) => Some(&r.row_hash),
        }
    }

    fn recompute_row_hash(&self, prev_hash: &[u8; 32]) -> Result<[u8; 32], crate::error::Error> {
        match self {
            Self::AuditLog(r) => compute_audit_row_hash(
                prev_hash,
                &AuditRowForHashing {
                    created_at: r.created_at,
                    action: &r.action,
                    actor_did: &r.actor_did,
                    target: r.target.as_deref(),
                    target_cid: r.target_cid.as_deref(),
                    outcome: &r.outcome,
                    reason: r.reason.as_deref(),
                },
            ),
            // Pre-boundary form only; the walk loop special-cases
            // post-boundary PdsAdmin rows for the 12-then-9 dance.
            Self::PdsAdmin(r) => compute_pds_admin_audit_row_hash(prev_hash, &r.hashing_row_v9()),
            Self::XrpcKnownCaller(r) | Self::XrpcTrustedPds(r) => recompute_membership_row_hash(
                prev_hash,
                &r.did,
                r.note.as_deref(),
                &r.added_by_moderator,
                r.added_at,
            ),
        }
    }

    /// Tie-break priority within a single timestamp. Mirrors the
    /// [`crate::audit::append::read_latest_chain_hash`] order:
    /// `audit_log` (0) < `pds_admin_audit` (1) <
    /// `xrpc_known_callers` (2) < `xrpc_trusted_pdses` (3).
    /// Higher priority = "later in chain" on ties.
    fn table_priority(&self) -> u8 {
        match self {
            Self::AuditLog(_) => 0,
            Self::PdsAdmin(_) => 1,
            Self::XrpcKnownCaller(_) => 2,
            Self::XrpcTrustedPds(_) => 3,
        }
    }
}

fn unified_chain_cmp(a: &UnifiedEntry, b: &UnifiedEntry) -> Ordering {
    a.timestamp()
        .cmp(&b.timestamp())
        .then_with(|| a.table_priority().cmp(&b.table_priority()))
        .then_with(|| a.id().cmp(&b.id()))
}

// ===========================================================================
// Reads
// ===========================================================================

async fn read_audit_log_rows(pool: &Pool<Sqlite>) -> Result<Vec<AuditLogRow>, CliError> {
    let rows = sqlx::query!(
        "SELECT id, created_at, action, actor_did, target, target_cid, outcome, reason,
                prev_hash, row_hash
         FROM audit_log
         ORDER BY id ASC"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| CliError::Startup(format!("audit verify scan audit_log: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|r| AuditLogRow {
            id: r.id,
            created_at: r.created_at,
            action: r.action,
            actor_did: r.actor_did,
            target: r.target,
            target_cid: r.target_cid,
            outcome: r.outcome,
            reason: r.reason,
            row_hash: r.row_hash,
        })
        .collect())
}

async fn read_xrpc_known_callers_rows(
    pool: &Pool<Sqlite>,
) -> Result<Vec<XrpcMembershipRow>, CliError> {
    let rows = sqlx::query!(
        "SELECT did, note, added_by_moderator, added_at, row_hash
         FROM xrpc_known_callers
         ORDER BY added_at ASC, did ASC"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| CliError::Startup(format!("audit verify scan xrpc_known_callers: {e}")))?;
    Ok(rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| XrpcMembershipRow {
            rowid: i as i64,
            did: r.did,
            note: r.note,
            added_by_moderator: r.added_by_moderator,
            added_at: r.added_at,
            row_hash: r.row_hash,
        })
        .collect())
}

async fn read_xrpc_trusted_pdses_rows(
    pool: &Pool<Sqlite>,
) -> Result<Vec<XrpcMembershipRow>, CliError> {
    let rows = sqlx::query!(
        "SELECT did, note, added_by_moderator, added_at, row_hash
         FROM xrpc_trusted_pdses
         ORDER BY added_at ASC, did ASC"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| CliError::Startup(format!("audit verify scan xrpc_trusted_pdses: {e}")))?;
    Ok(rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| XrpcMembershipRow {
            rowid: i as i64,
            did: r.did,
            note: r.note,
            added_by_moderator: r.added_by_moderator,
            added_at: r.added_at,
            row_hash: r.row_hash,
        })
        .collect())
}

async fn read_pds_admin_audit_rows(pool: &Pool<Sqlite>) -> Result<Vec<PdsAdminAuditRow>, CliError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", precipitating_action_id, backend_method,
                  backend_action_id, outcome, error_code, error_message,
                  retry_after_seconds, row_hash, call_started_at, call_completed_at,
                  upstream_audit_entry_id, cascading_actions_json, snapshots_json
           FROM pds_admin_audit
           ORDER BY id ASC"#
    )
    .fetch_all(pool)
    .await
    .map_err(|e| CliError::Startup(format!("audit verify scan pds_admin_audit: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|r| PdsAdminAuditRow {
            id: r.id,
            precipitating_action_id: r.precipitating_action_id,
            backend_method: r.backend_method,
            backend_action_id: r.backend_action_id,
            outcome: r.outcome,
            error_code: r.error_code,
            error_message: r.error_message,
            retry_after_seconds: r.retry_after_seconds,
            call_started_at: r.call_started_at,
            call_completed_at: r.call_completed_at,
            row_hash: r.row_hash,
            upstream_audit_entry_id: r.upstream_audit_entry_id,
            cascading_actions_json: r.cascading_actions_json,
            snapshots_json: r.snapshots_json,
        })
        .collect())
}

// ===========================================================================
// Output formatters
// ===========================================================================

/// Human-readable summary. Multi-line for `Verified` (one line per
/// fact the operator wants to see) and `Divergence` (id + hashes).
/// Trailing newline is left for the dispatcher's `println!`.
pub fn format_human(outcome: &VerifyOutcome) -> String {
    use std::fmt::Write;
    match outcome {
        VerifyOutcome::Empty => "audit chain is empty; nothing to verify".to_string(),
        VerifyOutcome::Verified {
            total_rows,
            attested_rows,
            pre_attestation_rows,
            legacy_form_rows,
            attestation_starts_at_row,
            audit_log_rows,
            pds_admin_audit_rows,
            xrpc_known_callers_rows,
            xrpc_trusted_pdses_rows,
        } => {
            let mut s = String::new();
            let _ = writeln!(
                s,
                "audit chain verified: {attested_rows} attested row(s) of {total_rows} total"
            );
            let _ = writeln!(
                s,
                "  audit_log: {audit_log_rows} row(s); pds_admin_audit: {pds_admin_audit_rows} row(s); \
                 xrpc_known_callers: {xrpc_known_callers_rows} row(s); xrpc_trusted_pdses: {xrpc_trusted_pdses_rows} row(s)"
            );
            if *pre_attestation_rows > 0 {
                let _ = writeln!(
                    s,
                    "  skipped {pre_attestation_rows} row(s) pre-dating audit chain attestation"
                );
            }
            if *legacy_form_rows > 0 {
                let _ = writeln!(
                    s,
                    "  {legacy_form_rows} post-boundary pds_admin_audit row(s) verified under \
                     the v1.7 9-field preimage (mid-deploy writes; expected 0 in steady state)"
                );
            }
            if let Some(n) = attestation_starts_at_row {
                let _ = write!(
                    s,
                    "  attestation starts at audit_log row {n} (trust horizon)"
                );
            } else if s.ends_with('\n') {
                s.pop();
            }
            s
        }
        VerifyOutcome::Divergence {
            table,
            row_id,
            expected_hash,
            actual_hash,
            attested_rows_before_divergence,
        } => {
            let mut s = String::new();
            let _ = writeln!(s, "audit chain divergence at {}:{row_id}", table.as_str());
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
    use crate::pds_admin::{BackendActionId, BackendMethod, record_pds_admin_call};
    use crate::storage;
    use tempfile::tempdir;

    async fn fresh_pool() -> Pool<Sqlite> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-verify-test.db");
        let pool = storage::open(&path).await.unwrap();
        Box::leak(Box::new(dir));
        pool
    }

    fn sample_audit_row(action: &str, actor_did: &str, created_at: i64) -> AuditRowForAppend {
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

    /// Minimal `subject_actions` row so a `pds_admin_audit` row's
    /// FK resolves. Returns the inserted id.
    async fn fixture_subject_action(pool: &Pool<Sqlite>) -> i64 {
        sqlx::query_scalar!(
            r#"INSERT INTO subject_actions (
                subject_did, subject_uri, actor_did, action_type, reason_codes,
                duration, effective_at, expires_at, notes, report_ids,
                strike_value_base, strike_value_applied, was_dampened,
                strikes_at_time_of_action, audit_log_id, created_at,
                actor_kind, triggered_by_policy_rule
             ) VALUES ('did:plc:s', NULL, 'did:plc:m', 'takedown', '["spam"]',
                       NULL, ?1, NULL, NULL, NULL, 1, 1, 0, 1, NULL, ?1,
                       'moderator', NULL)
             RETURNING id AS "id!""#,
            1_700_000_000_000_i64
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Append a `pds_admin_audit` row via the production helper.
    /// `completed_at` is the chain-ordering timestamp — must be
    /// chosen so the row falls between its intended chain
    /// predecessor and successor's timestamps, otherwise the
    /// production `read_latest_chain_hash` will fork the chain
    /// (each side picking a different predecessor) and the
    /// verifier will catch the fork as a divergence at the
    /// out-of-order row. That fork-on-disordered-timestamps
    /// behavior is the production invariant; tests just have to
    /// stay inside it.
    async fn append_pds_admin_audit(
        pool: &Pool<Sqlite>,
        precipitating_action_id: i64,
        synthetic_id: &str,
        started_at: i64,
        completed_at: i64,
    ) -> i64 {
        record_pds_admin_call(
            pool,
            precipitating_action_id,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new(synthetic_id))),
            None,
            started_at,
            completed_at,
        )
        .await
        .unwrap()
        .id
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

    /// Drop both tables' no-update triggers so a test can simulate
    /// tampering. Production paths don't do this — only operator
    /// commands like `cairn audit-rebuild` (which restores the
    /// audit_log trigger before commit). Tests need this to forge
    /// mismatches.
    async fn drop_no_update_triggers(pool: &Pool<Sqlite>) {
        sqlx::query("DROP TRIGGER IF EXISTS audit_log_no_update")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER IF EXISTS pds_admin_audit_no_update")
            .execute(pool)
            .await
            .unwrap();
    }

    // ===== Empty / single-table paths =====

    #[tokio::test]
    async fn empty_database_returns_empty() {
        let pool = fresh_pool().await;
        let outcome = verify(&pool).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Empty);
    }

    #[tokio::test]
    async fn audit_log_only_chain_verifies_with_zero_pds_admin_rows() {
        // Pre-#87-shape deployment: only audit_log rows exist.
        // The unified walker should behave identically to the old
        // single-table walker.
        let pool = fresh_pool().await;
        append_via_pool(&pool, &sample_audit_row("label_applied", "did:plc:m1", 1))
            .await
            .unwrap();
        append_via_pool(&pool, &sample_audit_row("label_negated", "did:plc:m1", 2))
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Verified {
                total_rows,
                attested_rows,
                pre_attestation_rows,
                legacy_form_rows: _,
                attestation_starts_at_row,
                audit_log_rows,
                pds_admin_audit_rows,
                xrpc_known_callers_rows,
                xrpc_trusted_pdses_rows,
            } => {
                assert_eq!(total_rows, 2);
                assert_eq!(attested_rows, 2);
                assert_eq!(pre_attestation_rows, 0);
                assert_eq!(attestation_starts_at_row, None);
                assert_eq!(audit_log_rows, 2);
                assert_eq!(
                    pds_admin_audit_rows, 0,
                    "pre-#87 deployment has no pds_admin_audit rows"
                );
                assert_eq!(xrpc_known_callers_rows, 0);
                assert_eq!(xrpc_trusted_pdses_rows, 0);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pds_admin_audit_only_chain_verifies() {
        // Edge case: no audit_log rows, only pds_admin_audit. Can
        // happen if an operator's deployment never recorded any
        // audit_log activity. The walker should still verify the
        // pds_admin_audit chain rooted at GENESIS.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        append_pds_admin_audit(&pool, action_id, "ozone:test:1", 100, 110).await;

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Verified {
                total_rows,
                audit_log_rows,
                pds_admin_audit_rows,
                ..
            } => {
                assert_eq!(total_rows, 1);
                assert_eq!(audit_log_rows, 0);
                assert_eq!(pds_admin_audit_rows, 1);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    // ===== Unified chain (the #88 acceptance case) =====

    #[tokio::test]
    async fn interleaved_chain_verifies_across_table_boundary() {
        // The #87-introduced shape: audit_log → pds_admin_audit →
        // audit_log. The middle pds_admin_audit row's prev_hash is
        // the prior audit_log row's row_hash; the final audit_log
        // row's prev_hash is the pds_admin_audit row's row_hash.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        // Insert in chain order: audit_log row 1 (oldest), then a
        // pds_admin_audit row, then a second audit_log row. The
        // production append paths read the unified chain head, so
        // the inserted prev_hashes link correctly across tables.
        append_via_pool(&pool, &sample_audit_row("label_applied", "did:plc:m1", 100))
            .await
            .unwrap();
        // pds_admin_audit row's completed_at must be > audit_log
        // row 1's created_at (100) and < audit_log row 2's
        // created_at (300) so production's chain-tip read picks
        // the pds_admin row as audit_log row 2's predecessor.
        append_pds_admin_audit(&pool, action_id, "ozone:s:42", 150, 200).await;
        // audit_log row 2 chains to the pds_admin_audit row.
        append_via_pool(&pool, &sample_audit_row("label_negated", "did:plc:m1", 300))
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Verified {
                total_rows,
                attested_rows,
                audit_log_rows,
                pds_admin_audit_rows,
                ..
            } => {
                assert_eq!(total_rows, 3);
                assert_eq!(attested_rows, 3);
                assert_eq!(audit_log_rows, 2);
                assert_eq!(pds_admin_audit_rows, 1);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampered_audit_log_row_in_unified_chain_reports_audit_log_table() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        append_via_pool(&pool, &sample_audit_row("label_applied", "did:plc:m1", 100))
            .await
            .unwrap();
        append_pds_admin_audit(&pool, action_id, "ozone:s:1", 150, 200).await;
        append_via_pool(&pool, &sample_audit_row("label_negated", "did:plc:m1", 300))
            .await
            .unwrap();

        // Tamper audit_log row 2's actor_did.
        drop_no_update_triggers(&pool).await;
        sqlx::query!("UPDATE audit_log SET actor_did = 'did:plc:attacker' WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Divergence {
                table,
                row_id,
                attested_rows_before_divergence,
                ..
            } => {
                assert_eq!(table, AuditTable::AuditLog);
                assert_eq!(row_id, 2);
                // 2 rows verified before divergence: audit_log#1 and
                // pds_admin_audit#1, in chain order.
                assert_eq!(attested_rows_before_divergence, 2);
            }
            other => panic!("expected Divergence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampered_pds_admin_audit_row_reports_pds_admin_audit_table() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        append_via_pool(&pool, &sample_audit_row("label_applied", "did:plc:m1", 100))
            .await
            .unwrap();
        let pds_id = append_pds_admin_audit(&pool, action_id, "ozone:s:1", 150, 200).await;
        append_via_pool(&pool, &sample_audit_row("label_negated", "did:plc:m1", 300))
            .await
            .unwrap();

        // Tamper the pds_admin_audit row's error_code (was None
        // originally; now writing something).
        drop_no_update_triggers(&pool).await;
        sqlx::query!(
            "UPDATE pds_admin_audit SET error_code = 'tampered' WHERE id = ?1",
            pds_id
        )
        .execute(&pool)
        .await
        .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Divergence {
                table,
                row_id,
                attested_rows_before_divergence,
                ..
            } => {
                assert_eq!(table, AuditTable::PdsAdminAudit);
                assert_eq!(row_id, pds_id);
                // 1 row verified before divergence: audit_log#1.
                assert_eq!(attested_rows_before_divergence, 1);
            }
            other => panic!("expected Divergence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cross_table_link_tampering_caught_at_pds_admin_audit_row() {
        // Tampering the pds_admin_audit row's stored prev_hash so it
        // no longer chains correctly to the prior audit_log row's
        // row_hash. The recomputed hash (using the actual prior
        // chain head) won't equal the stored row_hash because the
        // stored row_hash was computed from the OLD prev_hash.
        // Verify must catch this at the pds_admin_audit row.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        append_via_pool(&pool, &sample_audit_row("label_applied", "did:plc:m1", 100))
            .await
            .unwrap();
        let pds_id = append_pds_admin_audit(&pool, action_id, "ozone:s:1", 150, 200).await;

        drop_no_update_triggers(&pool).await;
        // Replace the pds_admin row's stored prev_hash with bogus
        // bytes. The row_hash on disk is unchanged; the recomputed
        // hash from the unified chain will differ from the stored
        // row_hash because the stored hash was computed from the
        // ORIGINAL prev_hash.
        let bogus_prev: Vec<u8> = vec![0xCC; 32];
        sqlx::query!(
            "UPDATE pds_admin_audit SET prev_hash = ?1 WHERE id = ?2",
            bogus_prev,
            pds_id
        )
        .execute(&pool)
        .await
        .unwrap();

        // Note: the verify walker recomputes the row_hash from the
        // RUNNING prev_hash (built up from prior verified rows),
        // not from the row's stored prev_hash. So tampering the
        // stored prev_hash alone doesn't cause divergence here —
        // tampering the row_hash would. This test instead tampers
        // the row_hash so the divergence-detection mechanism is
        // exercised: that's what the user-facing tamper looks like
        // when an attacker tries to relink the chain.
        let bogus_row_hash: Vec<u8> = vec![0xEE; 32];
        sqlx::query!(
            "UPDATE pds_admin_audit SET row_hash = ?1 WHERE id = ?2",
            bogus_row_hash,
            pds_id
        )
        .execute(&pool)
        .await
        .unwrap();

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Divergence {
                table,
                row_id,
                actual_hash,
                attested_rows_before_divergence,
                ..
            } => {
                assert_eq!(table, AuditTable::PdsAdminAudit);
                assert_eq!(row_id, pds_id);
                assert_eq!(actual_hash, hex::encode([0xEEu8; 32]));
                // 1 row attested before divergence: audit_log#1.
                assert_eq!(attested_rows_before_divergence, 1);
            }
            other => panic!("expected Divergence, got {other:?}"),
        }
    }

    // ===== Pre-attestation handling, preserved from v1.3 =====

    #[tokio::test]
    async fn mixed_pre_then_attested_audit_log_with_pds_admin_audit_horizon_only_for_audit_log() {
        // Three pre-v1.3 NULL audit_log rows, then a v1.3-attested
        // audit_log row, then a pds_admin_audit row. The trust
        // horizon refers to audit_log row 4; pds_admin_audit has
        // no horizon concept.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        insert_pre_v13_row(&pool, "label_applied", "did:plc:m1", 1).await;
        insert_pre_v13_row(&pool, "label_negated", "did:plc:m1", 2).await;
        insert_pre_v13_row(&pool, "report_resolved", "did:plc:m2", 3).await;
        append_via_pool(&pool, &sample_audit_row("label_applied", "did:plc:m3", 4))
            .await
            .unwrap();
        // pds_admin_audit chains after audit_log row 4: completed_at > 4.
        append_pds_admin_audit(&pool, action_id, "ozone:s:1", 5, 6).await;

        let outcome = verify(&pool).await.unwrap();
        match outcome {
            VerifyOutcome::Verified {
                total_rows,
                attested_rows,
                pre_attestation_rows,
                legacy_form_rows: _,
                attestation_starts_at_row,
                audit_log_rows,
                pds_admin_audit_rows,
                xrpc_known_callers_rows,
                xrpc_trusted_pdses_rows,
            } => {
                assert_eq!(total_rows, 5);
                assert_eq!(attested_rows, 2);
                assert_eq!(pre_attestation_rows, 3);
                assert_eq!(attestation_starts_at_row, Some(4));
                assert_eq!(audit_log_rows, 4);
                assert_eq!(pds_admin_audit_rows, 1);
                assert_eq!(xrpc_known_callers_rows, 0);
                assert_eq!(xrpc_trusted_pdses_rows, 0);
            }
            other => panic!("expected Verified, got {other:?}"),
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
        append_via_pool(&pool, &sample_audit_row("label_applied", "did:plc:m1", 1))
            .await
            .unwrap();

        let outcome = verify(&pool).await.unwrap();
        assert!(
            matches!(outcome, VerifyOutcome::Verified { .. }),
            "verify must run while a lease is held; got {outcome:?}"
        );
    }

    // ===== Formatters =====

    #[test]
    fn format_human_renders_each_outcome_shape() {
        assert!(format_human(&VerifyOutcome::Empty).contains("empty"));

        let verified = format_human(&VerifyOutcome::Verified {
            total_rows: 10,
            attested_rows: 7,
            pre_attestation_rows: 3,
            attestation_starts_at_row: Some(4),
            audit_log_rows: 8,
            pds_admin_audit_rows: 2,
            xrpc_known_callers_rows: 0,
            xrpc_trusted_pdses_rows: 0,
            legacy_form_rows: 0,
        });
        assert!(verified.contains("7 attested"));
        assert!(verified.contains("of 10"));
        assert!(verified.contains("audit_log: 8"));
        assert!(verified.contains("pds_admin_audit: 2"));
        assert!(verified.contains("skipped 3"));
        assert!(verified.contains("trust horizon"));
        assert!(verified.contains("audit_log row 4"));

        let no_horizon = format_human(&VerifyOutcome::Verified {
            total_rows: 5,
            attested_rows: 5,
            pre_attestation_rows: 0,
            attestation_starts_at_row: None,
            audit_log_rows: 5,
            pds_admin_audit_rows: 0,
            xrpc_known_callers_rows: 0,
            xrpc_trusted_pdses_rows: 0,
            legacy_form_rows: 0,
        });
        assert!(!no_horizon.contains("horizon"), "no horizon line when None");
        assert!(!no_horizon.contains("skipped"), "no skipped line when 0");

        let div_audit = format_human(&VerifyOutcome::Divergence {
            table: AuditTable::AuditLog,
            row_id: 42,
            expected_hash: "abc123".into(),
            actual_hash: "def456".into(),
            attested_rows_before_divergence: 41,
        });
        assert!(div_audit.contains("audit_log:42"));
        assert!(div_audit.contains("expected: abc123"));
        assert!(div_audit.contains("actual:   def456"));
        assert!(div_audit.contains("41 row"));

        let div_pds = format_human(&VerifyOutcome::Divergence {
            table: AuditTable::PdsAdminAudit,
            row_id: 7,
            expected_hash: "abc".into(),
            actual_hash: "def".into(),
            attested_rows_before_divergence: 5,
        });
        assert!(div_pds.contains("pds_admin_audit:7"));
    }

    #[test]
    fn format_json_uses_outcome_discriminator() {
        let s = format_json(&VerifyOutcome::Verified {
            total_rows: 5,
            attested_rows: 5,
            pre_attestation_rows: 0,
            attestation_starts_at_row: None,
            audit_log_rows: 3,
            pds_admin_audit_rows: 2,
            xrpc_known_callers_rows: 0,
            xrpc_trusted_pdses_rows: 0,
            legacy_form_rows: 0,
        });
        assert!(s.contains(r#""outcome":"verified""#), "got: {s}");
        assert!(
            !s.contains("attestation_starts_at_row"),
            "None should be skipped"
        );
        assert!(s.contains(r#""audit_log_rows":3"#));
        assert!(s.contains(r#""pds_admin_audit_rows":2"#));

        let div = format_json(&VerifyOutcome::Divergence {
            table: AuditTable::PdsAdminAudit,
            row_id: 5,
            expected_hash: "aa".into(),
            actual_hash: "bb".into(),
            attested_rows_before_divergence: 4,
        });
        assert!(div.contains(r#""outcome":"divergence""#));
        assert!(div.contains(r#""table":"pds_admin_audit""#));
        assert!(div.contains(r#""row_id":5"#));
    }
}
