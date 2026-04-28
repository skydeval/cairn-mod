//! Projection of a `pending_policy_actions` row into the wire shape
//! referenced by `tools.cairn.admin.defs#pendingAction` (§F22 / #70,
//! read surface in #77).
//!
//! Same posture as [`super::subject_action_view`]: stored row uses
//! epoch-ms timestamps + JSON-encoded TEXT for `reason_codes`; the
//! wire shape uses RFC-3339 Z + actual JSON arrays.
//!
//! Wire-side `resolution` is always one of three string literals
//! (`pending`, `confirmed`, `dismissed`). Storage NULL maps to
//! wire `pending` — i.e., the wire shape has no nullable
//! resolution state, only an explicit "still queued for review"
//! discriminator.

use serde::Serialize;
use sqlx::FromRow;

use crate::error::{Error, Result};
use crate::writer::rfc3339_from_epoch_ms;

/// Whether any `pending_policy_actions` row exists for this DID.
/// Used by `listPendingActions` (#77) to surface SubjectNotFound
/// (404) when the `subject` filter is set and the subject has
/// never had a pending — distinct from "has rows but the
/// resolution filter excluded them all" (which returns 200 with
/// an empty `actions` array).
///
/// Mirrors [`crate::server::strike_state::subject_has_history`]'s
/// posture for the subject_actions table.
pub(super) async fn subject_has_pending_actions(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    subject_did: &str,
) -> Result<bool> {
    let row = sqlx::query!(
        r#"SELECT EXISTS(SELECT 1 FROM pending_policy_actions WHERE subject_did = ?1) AS "exists!: i64""#,
        subject_did,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.exists != 0)
}

/// Raw `pending_policy_actions` row as read from SQLite. JSON-
/// encoded TEXT column (`reason_codes`) is kept as a string here;
/// [`project`] decodes it.
#[derive(Debug, FromRow)]
pub(super) struct PendingActionRow {
    pub id: i64,
    pub subject_did: String,
    pub subject_uri: Option<String>,
    pub action_type: String,
    pub duration_ms: Option<i64>,
    pub reason_codes: String,
    pub triggered_by_policy_rule: String,
    pub triggered_at: i64,
    pub triggering_action_id: i64,
    pub resolution: Option<String>,
    pub resolved_at: Option<i64>,
    pub resolved_by_did: Option<String>,
    pub confirmed_action_id: Option<i64>,
}

/// Wire shape per `tools.cairn.admin.defs#pendingAction`. Optional
/// fields use `skip_serializing_if` so absent maps to JSON-key-omit
/// rather than `null`, matching the §F11 anti-leak posture.
#[derive(Debug, Serialize)]
pub(super) struct PendingActionEntry {
    pub id: i64,
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    #[serde(rename = "subjectUri", skip_serializing_if = "Option::is_none")]
    pub subject_uri: Option<String>,
    #[serde(rename = "actionType")]
    pub action_type: String,
    #[serde(rename = "durationIso", skip_serializing_if = "Option::is_none")]
    pub duration_iso: Option<String>,
    #[serde(rename = "reasonCodes")]
    pub reason_codes: Vec<String>,
    #[serde(rename = "triggeredByPolicyRule")]
    pub triggered_by_policy_rule: String,
    #[serde(rename = "triggeredAt")]
    pub triggered_at: String,
    #[serde(rename = "triggeringActionId")]
    pub triggering_action_id: i64,
    /// Always one of `"pending"`, `"confirmed"`, `"dismissed"`;
    /// NULL in storage maps to `"pending"` here.
    pub resolution: String,
    #[serde(rename = "resolvedAt", skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(rename = "resolvedByDid", skip_serializing_if = "Option::is_none")]
    pub resolved_by_did: Option<String>,
    #[serde(rename = "confirmedActionId", skip_serializing_if = "Option::is_none")]
    pub confirmed_action_id: Option<i64>,
}

/// Convert a [`PendingActionRow`] to the wire shape. Fails on
/// invalid stored timestamps or malformed `reason_codes` JSON —
/// both indicate schema corruption (the writer validates on
/// insert).
pub(super) fn project(row: PendingActionRow) -> Result<PendingActionEntry> {
    let reason_codes: Vec<String> = serde_json::from_str(&row.reason_codes).map_err(|e| {
        Error::Signing(format!(
            "pending_policy_actions row {} has malformed reason_codes JSON: {e}",
            row.id
        ))
    })?;
    let duration_iso = row.duration_ms.map(|ms| format!("PT{}S", ms / 1000));
    // Storage NULL → wire "pending"; the wire shape has no
    // nullable resolution. Unrecognized non-NULL values are
    // surfaced as schema corruption (the writer + schema CHECK
    // constraint together pin the set).
    let resolution = match row.resolution.as_deref() {
        None => "pending".to_string(),
        Some("confirmed") => "confirmed".to_string(),
        Some("dismissed") => "dismissed".to_string(),
        Some(other) => {
            return Err(Error::Signing(format!(
                "pending_policy_actions row {} has invalid resolution {:?}",
                row.id, other
            )));
        }
    };
    Ok(PendingActionEntry {
        id: row.id,
        subject_did: row.subject_did,
        subject_uri: row.subject_uri,
        action_type: row.action_type,
        duration_iso,
        reason_codes,
        triggered_by_policy_rule: row.triggered_by_policy_rule,
        triggered_at: rfc3339_from_epoch_ms(row.triggered_at)?,
        triggering_action_id: row.triggering_action_id,
        resolution,
        resolved_at: row.resolved_at.map(rfc3339_from_epoch_ms).transpose()?,
        resolved_by_did: row.resolved_by_did,
        confirmed_action_id: row.confirmed_action_id,
    })
}
