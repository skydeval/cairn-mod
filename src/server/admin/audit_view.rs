//! Projection of an `audit_log` row into the wire shape referenced by
//! the `tools.cairn.admin.defs#auditEntry` lexicon.
//!
//! The stored row uses epoch-ms for `created_at` (matching the writer's
//! `cts` convention); the wire shape uses RFC-3339 Z. The single formatter
//! [`crate::writer::rfc3339_from_epoch_ms`] is reused so list and audit
//! responses agree on representation.
//!
//! `reason` is a passthrough: stored as opaque TEXT, serialized as the
//! same opaque string. The per-action JSON schemas are documented as
//! const strings in [`crate::writer`] (`AUDIT_REASON_*`); clients parse
//! by action.
//!
//! `prevHash` / `rowHash` (#42, v1.3) are hex-encoded SHA-256 hashes from
//! the audit chain (#39). Both are `Option<String>`: absent when the
//! stored BLOB column is NULL, which is the pre-v1.3 / pre-rebuild
//! "trust horizon" convention (#40 documents this). Present rows always
//! carry both, since the v1.3 append paths populate them together.

use serde::Serialize;
use sqlx::FromRow;

use crate::error::{Error, Result};
use crate::writer::rfc3339_from_epoch_ms;

/// Raw `audit_log` row as read from SQLite. Timestamps are stored as
/// epoch-ms INTEGER; the projection converts to RFC-3339 for the wire.
/// `prev_hash` / `row_hash` are 32-byte BLOBs (hex-encoded for the
/// wire); `None` means the row hasn't been hash-attested yet.
#[derive(Debug, FromRow)]
pub(super) struct AuditRow {
    pub id: i64,
    pub created_at: i64,
    pub action: String,
    pub actor_did: String,
    pub target: Option<String>,
    pub target_cid: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub prev_hash: Option<Vec<u8>>,
    pub row_hash: Option<Vec<u8>>,
}

/// Wire shape per `tools.cairn.admin.defs#auditEntry`. Optional fields
/// use `#[skip_serializing_if_none]` — the lexicon marks them optional,
/// and the §F11 anti-leak principle prefers field-absent over null for
/// empty.
#[derive(Debug, Serialize)]
pub(super) struct AuditEntry {
    pub id: i64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub action: String,
    #[serde(rename = "actorDid")]
    pub actor_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "targetCid")]
    pub target_cid: Option<String>,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Hex-encoded SHA-256 (64 lowercase chars) of the prior row's
    /// row_hash. Absent for pre-v1.3 / pre-rebuild rows.
    #[serde(skip_serializing_if = "Option::is_none", rename = "prevHash")]
    pub prev_hash: Option<String>,
    /// Hex-encoded SHA-256 (64 lowercase chars) of
    /// `prevHash || dag_cbor_canonical(row_content)`. Absent for
    /// pre-v1.3 / pre-rebuild rows.
    #[serde(skip_serializing_if = "Option::is_none", rename = "rowHash")]
    pub row_hash: Option<String>,
}

/// Project a stored audit row to the wire entry. Propagates the
/// formatter's error if the stored timestamp is out of range (shouldn't
/// happen for values the writer has produced, but the conversion is
/// fallible at the time-crate boundary).
///
/// Hash columns are hex-encoded with `hex::encode` — same lowercase
/// 64-char convention `cairn audit verify` uses (#41) so operators
/// see consistent string formatting across `show`, `verify`, and any
/// future hash surfaces.
pub(super) fn project(row: AuditRow) -> Result<AuditEntry> {
    let created_at = rfc3339_from_epoch_ms(row.created_at).map_err(|e| {
        Error::Signing(format!(
            "audit_log row {id} created_at out of range: {e}",
            id = row.id
        ))
    })?;
    Ok(AuditEntry {
        id: row.id,
        created_at,
        action: row.action,
        actor_did: row.actor_did,
        target: row.target,
        target_cid: row.target_cid,
        outcome: row.outcome,
        reason: row.reason,
        prev_hash: row.prev_hash.as_deref().map(hex::encode),
        row_hash: row.row_hash.as_deref().map(hex::encode),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(reason: Option<&str>) -> AuditRow {
        AuditRow {
            id: 42,
            // 2026-04-23T00:00:00.000Z
            created_at: 1_776_902_400_000,
            action: "label_applied".into(),
            actor_did: "did:plc:mod".into(),
            target: Some("at://did:plc:target/col/r".into()),
            target_cid: Some("bafy".into()),
            outcome: "success".into(),
            reason: reason.map(str::to_string),
            prev_hash: Some(vec![0u8; 32]),
            row_hash: Some(vec![0xAB; 32]),
        }
    }

    fn row_pre_attestation() -> AuditRow {
        AuditRow {
            id: 7,
            created_at: 1_776_902_400_000,
            action: "label_applied".into(),
            actor_did: "did:plc:mod".into(),
            target: None,
            target_cid: None,
            outcome: "success".into(),
            reason: None,
            prev_hash: None,
            row_hash: None,
        }
    }

    #[test]
    fn projection_converts_epoch_ms_to_rfc3339_z() {
        let entry = project(row(None)).expect("project");
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["createdAt"], "2026-04-23T00:00:00.000Z");
    }

    #[test]
    fn reason_passthrough_preserves_json_bytes() {
        // Per §F10 reason is opaque TEXT; projection must NOT re-parse
        // or re-serialize — clients get the exact stored bytes.
        let stored = r#"{"val":"spam","neg":false,"moderator_reason":null}"#;
        let entry = project(row(Some(stored))).expect("project");
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["reason"], stored);
    }

    #[test]
    fn absent_reason_serializes_without_field() {
        let entry = project(row(None)).expect("project");
        let json = serde_json::to_value(&entry).unwrap();
        assert!(
            json.get("reason").is_none(),
            "absent reason must be field-omitted, not null: {json}"
        );
    }

    #[test]
    fn required_fields_always_present() {
        let entry = project(row(None)).expect("project");
        let json = serde_json::to_value(&entry).unwrap();
        for k in &["id", "createdAt", "action", "actorDid", "outcome"] {
            assert!(json.get(k).is_some(), "required field {k} missing: {json}");
        }
    }

    #[test]
    fn hash_columns_hex_encoded_on_attested_row() {
        let entry = project(row(None)).expect("project");
        let json = serde_json::to_value(&entry).unwrap();
        // prev_hash is the 32-byte zero sentinel — the genesis-row
        // value any deployment using #39's chain will see as the
        // first row's prevHash.
        assert_eq!(json["prevHash"].as_str().unwrap(), "0".repeat(64));
        // row_hash was 32 × 0xAB → 64 chars of "ab".
        assert_eq!(json["rowHash"].as_str().unwrap(), "ab".repeat(32));
    }

    #[test]
    fn hash_columns_field_absent_on_pre_attestation_row() {
        let entry = project(row_pre_attestation()).expect("project");
        let json = serde_json::to_value(&entry).unwrap();
        assert!(
            json.get("prevHash").is_none(),
            "prevHash must be field-absent for pre-attestation rows: {json}"
        );
        assert!(
            json.get("rowHash").is_none(),
            "rowHash must be field-absent for pre-attestation rows: {json}"
        );
    }
}
