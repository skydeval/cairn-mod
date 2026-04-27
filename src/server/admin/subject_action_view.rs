//! Projection of a `subject_actions` row into the wire shape
//! referenced by `tools.cairn.admin.defs#subjectAction` (§F20 / #51,
//! read surface in #52 / read-half of #53).
//!
//! Same posture as [`super::audit_view`]: stored row uses epoch-ms
//! timestamps + JSON-encoded TEXT for `reason_codes` / `report_ids`;
//! the wire shape uses RFC-3339 Z + actual JSON arrays. A single
//! formatter ([`crate::writer::rfc3339_from_epoch_ms`]) handles all
//! timestamp conversions so the read side and the audit side agree
//! on representation.
//!
//! `reasonCodes` / `reportIds` are decoded from their TEXT-stored
//! JSON. Failures here are treated as internal errors — the writer
//! is the only path that produces these rows and writes valid JSON,
//! so a parse failure indicates schema corruption rather than user
//! input.

use serde::Serialize;
use sqlx::FromRow;

use crate::error::{Error, Result};
use crate::writer::rfc3339_from_epoch_ms;

/// Raw `subject_actions` row as read from SQLite. JSON-encoded
/// TEXT columns (`reason_codes`, `report_ids`) are kept as strings
/// here; [`project`] decodes them.
#[derive(Debug, FromRow)]
pub(super) struct SubjectActionRow {
    pub id: i64,
    pub subject_did: String,
    pub subject_uri: Option<String>,
    pub actor_did: String,
    pub action_type: String,
    pub reason_codes: String,
    pub duration: Option<String>,
    pub effective_at: i64,
    pub expires_at: Option<i64>,
    pub notes: Option<String>,
    pub report_ids: Option<String>,
    pub strike_value_base: i64,
    pub strike_value_applied: i64,
    pub was_dampened: i64,
    pub strikes_at_time_of_action: i64,
    pub revoked_at: Option<i64>,
    pub revoked_by_did: Option<String>,
    pub revoked_reason: Option<String>,
    pub audit_log_id: Option<i64>,
    pub created_at: i64,
}

/// Wire shape per `tools.cairn.admin.defs#subjectAction`. Optional
/// fields use `skip_serializing_if` so absent maps to JSON-key-omit
/// rather than `null`, matching the §F11 anti-leak posture.
#[derive(Debug, Serialize)]
pub(super) struct SubjectActionEntry {
    pub id: i64,
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    #[serde(rename = "subjectUri", skip_serializing_if = "Option::is_none")]
    pub subject_uri: Option<String>,
    #[serde(rename = "actorDid")]
    pub actor_did: String,
    #[serde(rename = "actionType")]
    pub action_type: String,
    #[serde(rename = "reasonCodes")]
    pub reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    #[serde(rename = "effectiveAt")]
    pub effective_at: String,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(rename = "reportIds", skip_serializing_if = "Option::is_none")]
    pub report_ids: Option<Vec<i64>>,
    #[serde(rename = "strikeValueBase")]
    pub strike_value_base: i64,
    #[serde(rename = "strikeValueApplied")]
    pub strike_value_applied: i64,
    #[serde(rename = "wasDampened")]
    pub was_dampened: bool,
    #[serde(rename = "strikesAtTimeOfAction")]
    pub strikes_at_time_of_action: i64,
    #[serde(rename = "revokedAt", skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(rename = "revokedByDid", skip_serializing_if = "Option::is_none")]
    pub revoked_by_did: Option<String>,
    #[serde(rename = "revokedReason", skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
    #[serde(rename = "auditLogId", skip_serializing_if = "Option::is_none")]
    pub audit_log_id: Option<i64>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Convert a [`SubjectActionRow`] to the wire shape. Fails on
/// invalid stored timestamps or malformed JSON — both indicate
/// schema corruption (the writer validates on insert).
pub(super) fn project(row: SubjectActionRow) -> Result<SubjectActionEntry> {
    let reason_codes: Vec<String> = serde_json::from_str(&row.reason_codes).map_err(|e| {
        Error::Signing(format!(
            "subject_actions row {} has malformed reason_codes JSON: {e}",
            row.id
        ))
    })?;
    let report_ids: Option<Vec<i64>> = match row.report_ids {
        None => None,
        Some(s) => Some(serde_json::from_str(&s).map_err(|e| {
            Error::Signing(format!(
                "subject_actions row {} has malformed report_ids JSON: {e}",
                row.id
            ))
        })?),
    };
    Ok(SubjectActionEntry {
        id: row.id,
        subject_did: row.subject_did,
        subject_uri: row.subject_uri,
        actor_did: row.actor_did,
        action_type: row.action_type,
        reason_codes,
        duration: row.duration,
        effective_at: rfc3339_from_epoch_ms(row.effective_at)?,
        expires_at: row.expires_at.map(rfc3339_from_epoch_ms).transpose()?,
        notes: row.notes,
        report_ids,
        strike_value_base: row.strike_value_base,
        strike_value_applied: row.strike_value_applied,
        was_dampened: row.was_dampened != 0,
        strikes_at_time_of_action: row.strikes_at_time_of_action,
        revoked_at: row.revoked_at.map(rfc3339_from_epoch_ms).transpose()?,
        revoked_by_did: row.revoked_by_did,
        revoked_reason: row.revoked_reason,
        audit_log_id: row.audit_log_id,
        created_at: rfc3339_from_epoch_ms(row.created_at)?,
    })
}
