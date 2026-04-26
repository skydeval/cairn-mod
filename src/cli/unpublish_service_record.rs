//! `cairn unpublish-service-record` (#34) — inverse of
//! [`crate::cli::publish_service_record`]. Removes the published
//! `app.bsky.labeler.service` record from the operator's PDS and
//! clears the local `labeler_config` state that tracks it.
//!
//! Flow:
//! 1. Load operator session (requires prior `cairn operator-login`).
//! 2. Read prior state from `labeler_config` (cid + content_hash +
//!    created_at).
//! 3. If no prior state → idempotent no-op. Write a `content_changed`-
//!    style audit row anyway (the §F10 / #20 invariant: every
//!    invocation produces exactly one audit_log row so operators
//!    reconstructing history see every attempt).
//! 4. Otherwise, call `com.atproto.repo.deleteRecord` with
//!    `swap_record = prior.cid`. Swap-race detection mirrors the
//!    publish path — a stale prior CID returns
//!    `PdsError::SwapRace`, surfaced as a clear non-zero exit.
//! 5. On 200: in a single transaction, DELETE the three
//!    `labeler_config` rows AND INSERT the audit row. Atomic so a
//!    partial crash can't leave the audit trail out of sync with
//!    state — same atomicity rationale as `publish::commit_publish`.
//!
//! **F19 startup verify after unpublish.** `serve::verify::
//! verify_service_record` does NOT consult `labeler_config`; it
//! fetches directly from the PDS. After unpublish, the PDS returns
//! `RecordNotFound` and the existing
//! [`crate::cli::error::code::SERVICE_RECORD_ABSENT`] (exit 13)
//! covers it. No new exit code is needed (§F19 question raised at
//! v1.2 kickoff, resolved here).
//!
//! The signing key is unaffected — only the service record is
//! removed. A subsequent `cairn publish-service-record` re-creates
//! the record with the operator's same identity.

use std::path::Path;

use serde_json::json;
use sqlx::{Pool, Sqlite};

use super::error::CliError;
use super::operator_session::OperatorSession;
use super::pds::PdsClient;
use crate::config::Config;
use crate::service_record::{RECORD_COLLECTION, RECORD_RKEY};

/// `audit_log.action` for an unpublish call. Same naming convention
/// as [`crate::cli::publish_service_record::AUDIT_ACTION_SERVICE_RECORD_PUBLISHED`];
/// kept out of [`crate::writer::AUDIT_ACTION_VALUES`] for the same
/// reason — that allowlist gates listAuditLog's action filter and
/// only covers the moderation-decision set.
pub const AUDIT_ACTION_SERVICE_RECORD_UNPUBLISHED: &str = "service_record_unpublished";

/// Audit-log `reason` JSON schema for `service_record_unpublished`.
///
/// ```json
/// {
///   "cid": "<previously-published CID, or null if no-op>",
///   "content_hash_hex": "<previously-stored hash, or null if no-op>",
///   "content_changed": true | false
/// }
/// ```
///
/// `content_changed: true` on the real-delete branch (state went
/// from "published" → "absent"); `content_changed: false` on the
/// no-op branch (state was already "absent"). Mirrors the publish
/// audit's content_changed semantics.
pub const AUDIT_REASON_SERVICE_RECORD_UNPUBLISH: &str =
    "service_record_unpublished: { cid, content_hash_hex, content_changed }";

/// Outcome of an unpublish call. Tests assert on this to distinguish
/// "no-op" from "real PDS delete" without parsing stdout.
#[derive(Debug)]
pub enum UnpublishOutcome {
    /// `labeler_config` had no prior service-record state — nothing
    /// to delete. No PDS round-trip; an audit row is still written.
    NoChange,
    /// PDS record was deleted and `labeler_config` cleared. `cid`
    /// is the just-deleted record's CID for the operator's logs.
    Unpublished {
        /// Content-addressed ID of the record that was just removed.
        cid: String,
    },
}

/// Run the unpublish flow end-to-end. `pool` is the labeler's own
/// SQLite pool (same as `cairn serve`); we borrow it to read/clear
/// `labeler_config` + write the audit row.
pub async fn unpublish(
    pool: &Pool<Sqlite>,
    config: &Config,
    session_path: &Path,
) -> Result<UnpublishOutcome, CliError> {
    // Match publish's posture: require both [labeler] and [operator]
    // even though we don't render a record. The operator session is
    // load-bearing (we authenticate the deleteRecord call); rejecting
    // without [labeler] keeps the failure mode symmetric so operators
    // running the inverse don't hit a different error shape.
    let _labeler_cfg = config
        .labeler
        .as_ref()
        .ok_or_else(|| CliError::Config("missing [labeler] section in config".into()))?;
    let operator_cfg = config
        .operator
        .as_ref()
        .ok_or_else(|| CliError::Config("missing [operator] section in config".into()))?;

    let session = OperatorSession::load(session_path)
        .map_err(|e| CliError::Config(format!("operator session: {e}")))?
        .ok_or_else(|| {
            CliError::Config(format!(
                "no operator session at {}; run `cairn operator-login`",
                session_path.display()
            ))
        })?;

    let prior = load_prior_state(pool).await?;

    let Some(prior) = prior else {
        // No-op branch: nothing was published locally. Audit the
        // attempt with content_changed=false and null cid/hash.
        record_noop_audit(pool, &session.operator_did).await?;
        return Ok(UnpublishOutcome::NoChange);
    };

    // Swap-race detection: pin the delete to the CID we believe the
    // PDS has. A concurrent operator update returns SwapRace; the
    // local clear + audit don't run, so labeler_config stays
    // consistent with the PDS until the operator reconciles.
    let pds = PdsClient::new(&operator_cfg.pds_url)?;
    pds.delete_record(
        &session.access_jwt,
        &session.operator_did,
        RECORD_COLLECTION,
        RECORD_RKEY,
        Some(&prior.cid),
    )
    .await?;

    commit_unpublish(pool, &session.operator_did, &prior).await?;

    Ok(UnpublishOutcome::Unpublished { cid: prior.cid })
}

/// Cached state for the last-published record. Mirrors
/// [`publish_service_record::PriorState`] — same three keys, same
/// "partial row → treat as none" tolerance.
#[derive(Debug, Clone)]
struct PriorState {
    cid: String,
    content_hash_hex: String,
    #[allow(dead_code)]
    created_at: String,
}

async fn load_prior_state(pool: &Pool<Sqlite>) -> Result<Option<PriorState>, CliError> {
    let cid = get_labeler_config(pool, "service_record_cid").await?;
    let hash = get_labeler_config(pool, "service_record_content_hash").await?;
    let created = get_labeler_config(pool, "service_record_created_at").await?;
    match (cid, hash, created) {
        (Some(cid), Some(content_hash_hex), Some(created_at)) => Ok(Some(PriorState {
            cid,
            content_hash_hex,
            created_at,
        })),
        (None, None, None) => Ok(None),
        // Partial rows mean a prior run crashed between writes. Treat
        // as "no prior" — same posture as the publish path.
        _ => Ok(None),
    }
}

async fn get_labeler_config(pool: &Pool<Sqlite>, key: &str) -> Result<Option<String>, CliError> {
    sqlx::query_scalar!("SELECT value FROM labeler_config WHERE key = ?1", key)
        .fetch_optional(pool)
        .await
        .map_err(|e| CliError::Startup(format!("read labeler_config: {e}")))
}

/// Real-delete path: clear the three `labeler_config` keys AND
/// insert the audit row inside a single transaction. Same atomicity
/// rationale as `publish::commit_publish`.
async fn commit_unpublish(
    pool: &Pool<Sqlite>,
    actor_did: &str,
    prior: &PriorState,
) -> Result<(), CliError> {
    let now_ms = crate::writer::epoch_ms_now();
    let reason = audit_reason_json(Some(&prior.cid), Some(&prior.content_hash_hex), true);
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| CliError::Startup(format!("begin tx: {e}")))?;
    for key in [
        "service_record_cid",
        "service_record_content_hash",
        "service_record_created_at",
    ] {
        sqlx::query!("DELETE FROM labeler_config WHERE key = ?1", key)
            .execute(&mut *tx)
            .await
            .map_err(|e| CliError::Startup(format!("delete labeler_config {key}: {e}")))?;
    }
    crate::audit::append::append_in_tx(
        &mut tx,
        &crate::audit::append::AuditRowForAppend {
            created_at: now_ms,
            action: AUDIT_ACTION_SERVICE_RECORD_UNPUBLISHED.into(),
            actor_did: actor_did.into(),
            target: None,
            target_cid: Some(prior.cid.clone()),
            outcome: "success".into(),
            reason: Some(reason),
        },
    )
    .await
    .map_err(|e| CliError::Startup(format!("audit insert: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| CliError::Startup(format!("commit unpublish: {e}")))?;
    Ok(())
}

/// No-op branch: audit-only. No `labeler_config` change to make,
/// no PDS call, no swap CID — `target_cid` is NULL and the reason
/// payload's `cid` / `content_hash_hex` are JSON null.
async fn record_noop_audit(pool: &Pool<Sqlite>, actor_did: &str) -> Result<(), CliError> {
    let now_ms = crate::writer::epoch_ms_now();
    let reason = audit_reason_json(None, None, false);
    crate::audit::append::append_via_pool(
        pool,
        &crate::audit::append::AuditRowForAppend {
            created_at: now_ms,
            action: AUDIT_ACTION_SERVICE_RECORD_UNPUBLISHED.into(),
            actor_did: actor_did.into(),
            target: None,
            target_cid: None,
            outcome: "success".into(),
            reason: Some(reason),
        },
    )
    .await
    .map_err(|e| CliError::Startup(format!("audit insert: {e}")))?;
    Ok(())
}

/// Serialize the `reason` payload per
/// [`AUDIT_REASON_SERVICE_RECORD_UNPUBLISH`].
fn audit_reason_json(cid: Option<&str>, hash_hex: Option<&str>, content_changed: bool) -> String {
    json!({
        "cid": cid,
        "content_hash_hex": hash_hex,
        "content_changed": content_changed,
    })
    .to_string()
}
