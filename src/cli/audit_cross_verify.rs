//! `cairn audit cross-verify` (v1.8.6, v2 §7.1 / chainlink #139) —
//! cross-chain verification of cairn-mod's dispatch ledger against
//! Aurora's audit chain.
//!
//! Orchestration (CLI-level, not a trait method — it composes
//! multiple trait calls with local-DB queries, matching the
//! `cairn audit verify` direct-DB precedent):
//!
//! 1. **Local pass** — cairn-mod's own 4-table unified-chain verify
//!    ([`crate::cli::audit_verify::verify`]).
//! 2. **Upstream pass** — paginate `get_audit_trail`, record
//!    Aurora's `chainVerified` verdict, then independently
//!    re-verify every collected entry per Path A
//!    ([`crate::pds_admin::rust::upstream_verify`]) and re-walk
//!    linkage/gaps. `upstream_verified` requires BOTH to agree; a
//!    disagreement in either direction is itself a cross-class
//!    divergence note.
//! 3. **Join pass** — every `pds_admin_audit` row with a non-NULL
//!    `upstream_audit_entry_id` must resolve to an upstream entry
//!    (collected trail first, `get_audit_entry(Id(..))` fallback)
//!    whose `event_id` matches the row's `backend_action_id`.
//!    Rows with NULL join keys (v1.7/v1.8.2-era dispatches,
//!    pre-0010) are **unjoinable, not divergent** — counted in the
//!    notes only.
//! 4. Outcome persisted to `cross_verify_outcomes` iff
//!    `[pds_admin.rust].verification_persist` is `true` (the
//!    field's first consumer since its v1.8.1 parse+store landing).
//!
//! Exit taxonomy (v2 §7.2): any divergence exits 15
//! (`AUDIT_DIVERGENCE`) via [`CliError::CrossVerifyDivergence`];
//! the JSON `outcome` discriminator distinguishes
//! `divergence-local` / `divergence-cross` /
//! `divergence-join-mismatch` with precedence local > cross > join.

use serde::Serialize;
use sqlx::{Pool, Sqlite};

use super::audit_verify::{self, VerifyOutcome};
use super::error::CliError;
use crate::pds_admin::PdsAdminBackend;
use crate::pds_admin::rust::audit_types::{AuditEntryLookup, AuditTrailFilter, AuroraAuditEntry};
use crate::pds_admin::rust::upstream_verify::{ChainWalkVerdict, walk_chain};

/// Stable outcome discriminator for JSON consumers + exit mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrossVerifyOutcome {
    /// Both chains verified and every joinable row matched.
    Verified,
    /// Nothing to verify on either side.
    Empty,
    /// cairn-mod's own chain failed local verification.
    DivergenceLocal,
    /// Aurora's chain failed — upstream flag false, or cairn-mod's
    /// independent Path A walk disagreed with a passing flag.
    DivergenceCross,
    /// Join keys resolved but content mismatched (or a referenced
    /// upstream entry is missing).
    DivergenceJoinMismatch,
}

impl CrossVerifyOutcome {
    /// Kebab-case discriminator string (matches the serde form).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Empty => "empty",
            Self::DivergenceLocal => "divergence-local",
            Self::DivergenceCross => "divergence-cross",
            Self::DivergenceJoinMismatch => "divergence-join-mismatch",
        }
    }
}

/// Full report of one cross-verify run.
#[derive(Debug, Serialize)]
pub struct CrossVerifyReport {
    /// Highest-precedence outcome (local > cross > join).
    pub outcome: CrossVerifyOutcome,
    /// Epoch-ms run bounds.
    pub run_started_at: i64,
    pub run_completed_at: i64,
    /// Local 4-table chain pass.
    pub local_verified: bool,
    /// Attested-row count from the local pass (rows before the
    /// divergence when the pass failed).
    pub local_verified_through: Option<i64>,
    /// Aurora's chainVerified AND cairn-mod's independent walk.
    pub upstream_verified: bool,
    /// Aurora-reported chainVerifiedThrough.
    pub upstream_verified_through: Option<i64>,
    /// Aurora-reported legacy-form count.
    pub upstream_legacy_count: Option<i64>,
    /// Join pass verdict.
    pub cross_verified: bool,
    /// Structured notes: unjoinable counts, mismatch details,
    /// independent-walk detail, entry counts.
    pub notes: serde_json::Value,
    /// Whether the outcome row was persisted
    /// (`verification_persist` gate).
    pub persisted: bool,
}

/// One `--history` row.
#[derive(Debug, Serialize)]
pub struct CrossVerifyHistoryRow {
    pub id: i64,
    pub run_started_at: i64,
    pub run_completed_at: i64,
    pub local_verified: bool,
    pub upstream_verified: bool,
    pub cross_verified: bool,
    pub notes: Option<String>,
}

/// Joinable local dispatch row (non-NULL upstream join key).
struct JoinRow {
    id: i64,
    backend_action_id: Option<String>,
    upstream_audit_entry_id: String,
    outcome: String,
}

/// Run the full cross-verify orchestration.
///
/// `sequence_bounds` optionally restricts the independent walk +
/// join window to `[start, end]` (inclusive; either side open).
/// Aurora's own `chainVerified` is whole-chain regardless.
pub async fn run(
    pool: &Pool<Sqlite>,
    backend: &dyn PdsAdminBackend,
    verification_persist: bool,
    sequence_bounds: (Option<i64>, Option<i64>),
) -> Result<CrossVerifyReport, CliError> {
    let run_started_at = crate::writer::epoch_ms_now();

    // ---- 1. Local pass. ----
    let local = audit_verify::verify(pool).await?;
    let (local_verified, local_verified_through, local_empty) = match &local {
        VerifyOutcome::Empty => (true, None, true),
        VerifyOutcome::Verified { attested_rows, .. } => (true, Some(*attested_rows), false),
        VerifyOutcome::Divergence {
            attested_rows_before_divergence,
            ..
        } => (false, Some(*attested_rows_before_divergence), false),
    };

    // ---- 2. Upstream pass. ----
    let mut entries: Vec<AuroraAuditEntry> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut upstream_chain_verified: Option<bool> = None;
    let mut upstream_verified_through: Option<i64> = None;
    let mut upstream_legacy_count: Option<i64> = None;
    loop {
        let page = backend
            .get_audit_trail(AuditTrailFilter::default(), cursor.as_deref(), Some(100))
            .await?;
        if upstream_chain_verified.is_none() {
            // Chain-level verdict is whole-chain and identical on
            // every page; capture once from the first.
            upstream_chain_verified = Some(page.chain_verified);
            upstream_verified_through = Some(page.chain_verified_through);
            upstream_legacy_count = Some(page.chain_legacy_count);
        }
        entries.extend(page.items);
        match page.cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    let (start_bound, end_bound) = sequence_bounds;
    let window: Vec<AuroraAuditEntry> = entries
        .iter()
        .filter(|e| {
            start_bound.is_none_or(|s| e.sequence >= s)
                && end_bound.is_none_or(|en| e.sequence <= en)
        })
        .cloned()
        .collect();

    let walk = walk_chain(&window, None);
    let (walk_ok, walk_detail) = match &walk {
        ChainWalkVerdict::Verified {
            v09_count,
            legacy_count,
            sentinel_count,
        } => (
            true,
            serde_json::json!({
                "v09Count": v09_count,
                "legacyCount": legacy_count,
                "sentinelCount": sentinel_count,
            }),
        ),
        ChainWalkVerdict::Failed {
            failing_sequence,
            kind,
        } => (
            false,
            serde_json::json!({
                "failingSequence": failing_sequence,
                "kind": format!("{kind:?}"),
            }),
        ),
    };
    let aurora_flag = upstream_chain_verified.unwrap_or(false);
    let upstream_verified = aurora_flag && walk_ok;
    let flag_disagreement = aurora_flag != walk_ok;

    // ---- 3. Join pass. ----
    let join_rows = sqlx::query!(
        r#"SELECT id AS "id!", backend_action_id, upstream_audit_entry_id AS "upstream_audit_entry_id!", outcome
           FROM pds_admin_audit
           WHERE upstream_audit_entry_id IS NOT NULL
           ORDER BY id ASC"#
    )
    .fetch_all(pool)
    .await
    .map_err(|e| CliError::Startup(format!("cross-verify join scan: {e}")))?
    .into_iter()
    .map(|r| JoinRow {
        id: r.id,
        backend_action_id: r.backend_action_id,
        upstream_audit_entry_id: r.upstream_audit_entry_id,
        outcome: r.outcome,
    })
    .collect::<Vec<_>>();

    let unjoinable: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM pds_admin_audit WHERE upstream_audit_entry_id IS NULL"#
    )
    .fetch_one(pool)
    .await
    .map_err(|e| CliError::Startup(format!("cross-verify unjoinable count: {e}")))?;

    let mut join_mismatches: Vec<serde_json::Value> = Vec::new();
    let mut joined_ok: i64 = 0;
    for row in &join_rows {
        // Only successful dispatches carry a real upstream entry;
        // a non-success row with a join key would itself be odd.
        if row.outcome != "success" {
            join_mismatches.push(serde_json::json!({
                "auditId": row.id,
                "kind": "non-success-row-with-join-key",
                "outcome": row.outcome,
            }));
            continue;
        }
        let upstream_entry = match entries
            .iter()
            .find(|e| e.id == row.upstream_audit_entry_id)
        {
            Some(e) => Some(e.clone()),
            None => match row.upstream_audit_entry_id.parse::<i64>() {
                Ok(id) => match backend.get_audit_entry(&AuditEntryLookup::Id(id)).await {
                    Ok(e) => Some(e),
                    Err(crate::pds_admin::backend::BackendError::Terminal(_)) => None,
                    Err(e) => return Err(e.into()),
                },
                Err(_) => None,
            },
        };
        match upstream_entry {
            None => join_mismatches.push(serde_json::json!({
                "auditId": row.id,
                "kind": "upstream-entry-missing",
                "upstreamAuditEntryId": row.upstream_audit_entry_id,
            })),
            Some(entry) => {
                if entry.event_id.as_deref() != row.backend_action_id.as_deref() {
                    join_mismatches.push(serde_json::json!({
                        "auditId": row.id,
                        "kind": "event-id-mismatch",
                        "local": row.backend_action_id,
                        "upstream": entry.event_id,
                    }));
                } else {
                    joined_ok += 1;
                }
            }
        }
    }
    let cross_verified = join_mismatches.is_empty();

    // ---- Outcome precedence: local > cross > join. ----
    let upstream_empty = entries.is_empty();
    let outcome = if !local_verified {
        CrossVerifyOutcome::DivergenceLocal
    } else if !upstream_verified && !upstream_empty {
        CrossVerifyOutcome::DivergenceCross
    } else if !cross_verified {
        CrossVerifyOutcome::DivergenceJoinMismatch
    } else if local_empty && upstream_empty {
        CrossVerifyOutcome::Empty
    } else {
        CrossVerifyOutcome::Verified
    };

    let notes = serde_json::json!({
        "collectedEntries": entries.len(),
        "windowEntries": window.len(),
        "independentWalk": walk_detail,
        "auroraChainVerified": aurora_flag,
        "auroraDisagreesWithIndependentWalk": flag_disagreement,
        "joinableRows": join_rows.len(),
        "joinedOk": joined_ok,
        "unjoinableRows": unjoinable,
        "joinMismatches": join_mismatches,
    });

    let run_completed_at = crate::writer::epoch_ms_now();

    // ---- 4. Persist (the verification_persist consumer). ----
    let mut persisted = false;
    if verification_persist {
        let notes_str = notes.to_string();
        let local_v = local_verified as i64;
        let upstream_v = upstream_verified as i64;
        let cross_v = cross_verified as i64;
        sqlx::query!(
            r#"INSERT INTO cross_verify_outcomes
                 (run_started_at, run_completed_at, local_verified,
                  local_verified_through, upstream_verified,
                  upstream_verified_through, upstream_legacy_count,
                  cross_verified, cross_verify_notes)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            run_started_at,
            run_completed_at,
            local_v,
            local_verified_through,
            upstream_v,
            upstream_verified_through,
            upstream_legacy_count,
            cross_v,
            notes_str,
        )
        .execute(pool)
        .await
        .map_err(|e| CliError::Startup(format!("cross-verify outcome persist: {e}")))?;
        persisted = true;
    }

    Ok(CrossVerifyReport {
        outcome,
        run_started_at,
        run_completed_at,
        local_verified,
        local_verified_through,
        upstream_verified,
        upstream_verified_through,
        upstream_legacy_count,
        cross_verified,
        notes,
        persisted,
    })
}

/// Read past outcomes for `--history` (newest first).
pub async fn history(
    pool: &Pool<Sqlite>,
    limit: i64,
) -> Result<Vec<CrossVerifyHistoryRow>, CliError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", run_started_at, run_completed_at,
                  local_verified, upstream_verified, cross_verified,
                  cross_verify_notes
           FROM cross_verify_outcomes
           ORDER BY run_started_at DESC, id DESC
           LIMIT ?1"#,
        limit,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| CliError::Startup(format!("cross-verify history read: {e}")))?;
    Ok(rows
        .into_iter()
        .map(|r| CrossVerifyHistoryRow {
            id: r.id,
            run_started_at: r.run_started_at,
            run_completed_at: r.run_completed_at,
            local_verified: r.local_verified != 0,
            upstream_verified: r.upstream_verified != 0,
            cross_verified: r.cross_verified != 0,
            notes: r.cross_verify_notes,
        })
        .collect())
}

/// Human one-per-line summary for `--history`.
pub fn format_history_human(rows: &[CrossVerifyHistoryRow]) -> String {
    if rows.is_empty() {
        return "no cross-verify runs recorded".to_string();
    }
    rows.iter()
        .map(|r| {
            format!(
                "run {} @ {}: local={} upstream={} cross={}",
                r.id,
                r.run_started_at,
                if r.local_verified { "ok" } else { "FAIL" },
                if r.upstream_verified { "ok" } else { "FAIL" },
                if r.cross_verified { "ok" } else { "FAIL" },
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Human summary of one run.
pub fn format_report_human(r: &CrossVerifyReport) -> String {
    let mut s = format!(
        "cross-verify: {}\n  local chain: {}{}\n  upstream chain: {} (Aurora chainVerified={}, independent walk agrees={})\n  join pass: {} ({} joined, {} unjoinable pre-v1.8.5 rows)",
        r.outcome.as_str(),
        if r.local_verified { "verified" } else { "DIVERGENT" },
        r.local_verified_through
            .map(|n| format!(" ({n} attested rows)"))
            .unwrap_or_default(),
        if r.upstream_verified { "verified" } else { "DIVERGENT" },
        r.notes["auroraChainVerified"],
        !r.notes["auroraDisagreesWithIndependentWalk"]
            .as_bool()
            .unwrap_or(false),
        if r.cross_verified { "clean" } else { "MISMATCHES" },
        r.notes["joinedOk"],
        r.notes["unjoinableRows"],
    );
    if !r.persisted {
        s.push_str("\n  (not persisted: verification_persist = false)");
    }
    s
}
