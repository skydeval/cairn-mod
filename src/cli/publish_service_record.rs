//! `cairn publish-service-record` — emit the
//! `app.bsky.labeler.service` record to the operator's PDS (§F1).
//!
//! Flow:
//! 1. Load operator session (requires prior `cairn operator-login`).
//! 2. Render the record from `config.labeler`.
//! 3. Compute content hash (§F1 idempotency, excludes `createdAt`).
//! 4. Compare against `labeler_config.service_record_content_hash`:
//!    - match → no-op, exit 0 with "no change" message.
//!    - differ (or first publish) → continue.
//! 5. `PdsClient::put_record` with `swap_record = prior_cid`.
//!    §F1 swap-race detection: a stale prior_cid returns
//!    `PdsError::SwapRace`, which maps to a clear exit-non-zero
//!    message directing the operator to reconcile.
//! 6. On 200: persist new cid + content_hash + created_at;
//!    INSERT `audit_log` row (`service_record_published` action).

use std::path::Path;

use serde_json::json;
use sqlx::{Pool, Sqlite};
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;

use super::error::CliError;
use super::operator_session::OperatorSession;
use super::pds::PdsClient;
use crate::config::{Config, LabelerConfigToml};
use crate::service_record::{self, RECORD_COLLECTION, RECORD_RKEY};

const CTS_FORMAT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

/// `audit_log.action` for a successful publish (matches existing
/// [`crate::writer::AUDIT_ACTION_VALUES`] naming convention). The
/// `AUDIT_ACTION_VALUES` slice in writer.rs does NOT include this
/// value because listAuditLog's action-filter allowlist covers the
/// moderation-decision set; a future widening to include ops
/// actions would add this there.
pub const AUDIT_ACTION_SERVICE_RECORD_PUBLISHED: &str = "service_record_published";

/// Audit-log `reason` JSON schema for `service_record_published`.
/// Documents the payload shape the audit row carries.
///
/// ```json
/// {
///   "cid": "<new record CID>",
///   "content_hash_hex": "<hex-encoded sha256 of rendered body>",
///   "content_changed": true | false
/// }
/// ```
pub const AUDIT_REASON_SERVICE_RECORD: &str =
    "service_record_published: { cid, content_hash_hex, content_changed }";

/// Outcome of a publish call. Tests assert on this to distinguish
/// "no-op skip" from "real publish" without parsing stdout.
#[derive(Debug)]
pub enum PublishOutcome {
    /// Content hash matched the stored value — no PDS round-trip.
    NoChange,
    /// Record was written to the PDS. `cid` is the new record CID
    /// (used by the next publish's swap-race check).
    Published { cid: String, created_at: String },
}

/// Run the publish flow end-to-end. `pool` is the labeler's own
/// SQLite pool (same as `cairn serve`); we borrow it to read/write
/// `labeler_config` + write the audit row. No Writer task is
/// involved — this isn't a label emission.
pub async fn publish(
    pool: &Pool<Sqlite>,
    config: &Config,
    session_path: &Path,
) -> Result<PublishOutcome, CliError> {
    let labeler_cfg = config
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

    let created_at = prior
        .as_ref()
        .map(|p| p.created_at.clone())
        .unwrap_or_else(now_rfc3339);

    let record = service_record::render(labeler_cfg, &created_at)
        .map_err(|e| CliError::Config(format!("render service record: {e}")))?;
    let new_hash = service_record::content_hash(&record);
    let new_hash_hex = hex::encode(new_hash);

    if let Some(p) = &prior {
        if p.content_hash_hex == new_hash_hex {
            // §F1 idempotency: content unchanged, preserve created_at,
            // skip the PDS call entirely.
            return Ok(PublishOutcome::NoChange);
        }
    }

    // Content has changed (or this is the first publish). If we have
    // a prior CID, use it as the swap guard so a concurrent update
    // fails noisily rather than silently overwriting.
    let swap = prior.as_ref().map(|p| p.cid.as_str());
    let pds = PdsClient::new(&operator_cfg.pds_url)?;
    let record_json = serde_json::to_value(&record).expect("record serializes");
    let put = pds
        .put_record(
            &session.access_jwt,
            &session.operator_did,
            RECORD_COLLECTION,
            RECORD_RKEY,
            &record_json,
            swap,
        )
        .await?;

    persist_state(pool, &put.cid, &new_hash_hex, &created_at, labeler_cfg).await?;
    insert_audit_row(
        pool,
        &session.operator_did,
        &put.cid,
        &new_hash_hex,
        prior.is_some(),
    )
    .await?;

    Ok(PublishOutcome::Published {
        cid: put.cid,
        created_at,
    })
}

/// Cached state for the last-published record. `None` iff no row
/// exists (first-time publish).
#[derive(Debug, Clone)]
struct PriorState {
    cid: String,
    content_hash_hex: String,
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
        // as "no prior" — the next publish will retry cleanly.
        _ => Ok(None),
    }
}

async fn get_labeler_config(pool: &Pool<Sqlite>, key: &str) -> Result<Option<String>, CliError> {
    sqlx::query_scalar!("SELECT value FROM labeler_config WHERE key = ?1", key)
        .fetch_optional(pool)
        .await
        .map_err(|e| CliError::Startup(format!("read labeler_config: {e}")))
}

async fn persist_state(
    pool: &Pool<Sqlite>,
    cid: &str,
    hash_hex: &str,
    created_at: &str,
    _labeler: &LabelerConfigToml,
) -> Result<(), CliError> {
    let now_ms = crate::writer::epoch_ms_now();
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| CliError::Startup(format!("begin tx: {e}")))?;
    for (key, val) in [
        ("service_record_cid", cid),
        ("service_record_content_hash", hash_hex),
        ("service_record_created_at", created_at),
    ] {
        sqlx::query!(
            "INSERT INTO labeler_config (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            key,
            val,
            now_ms,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| CliError::Startup(format!("upsert labeler_config {key}: {e}")))?;
    }
    tx.commit()
        .await
        .map_err(|e| CliError::Startup(format!("commit labeler_config: {e}")))?;
    Ok(())
}

async fn insert_audit_row(
    pool: &Pool<Sqlite>,
    actor_did: &str,
    cid: &str,
    hash_hex: &str,
    content_changed: bool,
) -> Result<(), CliError> {
    let now_ms = crate::writer::epoch_ms_now();
    let reason = json!({
        "cid": cid,
        "content_hash_hex": hash_hex,
        "content_changed": content_changed,
    })
    .to_string();
    sqlx::query!(
        "INSERT INTO audit_log
             (created_at, action, actor_did, target, target_cid, outcome, reason)
         VALUES (?1, ?2, ?3, NULL, ?4, 'success', ?5)",
        now_ms,
        AUDIT_ACTION_SERVICE_RECORD_PUBLISHED,
        actor_did,
        cid,
        reason,
    )
    .execute(pool)
    .await
    .map_err(|e| CliError::Startup(format!("audit insert: {e}")))?;
    Ok(())
}

fn now_rfc3339() -> String {
    let dt = OffsetDateTime::now_utc();
    let formatted = dt.format(&CTS_FORMAT).expect("format rfc3339");
    format!("{formatted}Z")
}
