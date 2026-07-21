//! Audit-trail read mirror types for `tools.aurora.admin.getAuditTrail`
//! / `getAuditEntry` (v1.8.6, §3).
//!
//! Byte-faithful mirrors of Aurora-Locus wire shapes at recon HEAD
//! `2ffeb1a`, per the v1.8.6 R1 pins (chainlink #138):
//!
//! - [`AuditTrailPage`] ← Aurora `GetAuditTrailOutput`
//!   (`aurora_admin.rs:3615-3630`): five fields; `chainVerified` is
//!   a whole-chain verdict computed per request; `chainVerifiedThrough`
//!   is a sequence number (`head_seq` on success, `failing_sequence - 1`
//!   on failure); `chainLegacyCount` is **0 on failure** (Aurora
//!   discards the partial count — do not reinterpret).
//! - [`AuroraAuditEntry`] ← Aurora `AuditEntry`
//!   (`audit_chain.rs:176-230`), with three deliberate mirror deltas
//!   that are load-bearing for Path A re-verification (v2 §3.1):
//!   `timestamp` stays a **`String`** (the T1 reparse transform owns
//!   its interpretation — serde must not re-serialize precision);
//!   `payload` is a **`Box<RawValue>`** (byte/order-preserving — the
//!   canonical form embeds Aurora's stored serialization verbatim);
//!   subjects use the v1.8.3 [`ReadSubject`] union (same `$type`
//!   tagging as Aurora's `Subject`).
//! - [`AuditTrailFilter`] ← the seven committed `GetAuditTrailParams`
//!   filters + `source` (`aurora_admin.rs:3515-3562`). The three
//!   UI-toggle booleans (`ruleManagement`, `hookManagement`,
//!   `federationManagement`) are deliberately not mirrored (v2 §3.1).
//!
//! Wire-form pinning (v2 §3.1 table): Aurora's `AuditEntry` is
//! Serialize-only with exactly one `skip_serializing_if` (on
//! `payload`) — absent `subjectRef`/`snapshotId`/`eventId`/
//! `previousHash` arrive as literal `null`, empty cascade arrays as
//! `[]`, and only `payload` is key-omitted. `id`/`snapshotId`/
//! `eventId`/`cascadeSnapshotIds` elements are stringified i64 for
//! JS-precision parity.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::read_types::ReadSubject;

/// Filter set for `get_audit_trail` — the seven committed
/// `GetAuditTrailParams` filters plus the `source` provenance
/// discriminator, AND-combined upstream. camelCase on the wire;
/// `None` fields omitted.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditTrailFilter {
    /// Filter by the deciding actor's DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_did: Option<String>,
    /// Filter by action verb (e.g. `TakedownAccount`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Filter by subject DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    /// Filter by subject record URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_uri: Option<String>,
    /// Filter by subject CID (blob or record).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_cid: Option<String>,
    /// Lower bound on created_at (inclusive), RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_created: Option<String>,
    /// Upper bound on created_at (inclusive), RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_created: Option<String>,
    /// Provenance discriminator (`manual`, `auto_label_rule`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Mirror of Aurora's `GetAuditTrailOutput` (v1.8.6 §3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditTrailPage {
    /// One page of audit-chain entries, newest first.
    pub items: Vec<AuroraAuditEntry>,
    /// Opaque forward cursor; absent on the last page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Aurora's whole-chain verdict for `[1..chain head]`,
    /// recomputed on every request (not page-scoped).
    pub chain_verified: bool,
    /// Highest sequence covered by the verification window:
    /// `head_seq` on success, `failing_sequence - 1` (saturating)
    /// on failure.
    pub chain_verified_through: i64,
    /// Entries in the verified window matching only the pre-v0.9
    /// legacy hash form. Zero on verification failure (upstream
    /// discards the partial count).
    pub chain_legacy_count: i64,
}

/// Mirror of Aurora's `AuditEntry` (v1.8.6 §3.1) — the per-entry
/// wire shape shared by `getAuditTrail` items and `getAuditEntry`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuroraAuditEntry {
    /// Row primary key, stringified i64.
    pub id: String,
    /// Monotonic chain sequence.
    pub sequence: i64,
    /// RFC3339 timestamp — kept as the wire **string** so the T1
    /// reparse transform (v2 §4.3) owns reconstruction of the
    /// stored `+00:00`-form bytes from the wire's `Z` form.
    pub timestamp: String,
    /// DID that authored the decision.
    pub actor_did: String,
    /// Action verb.
    pub action: String,
    /// Discriminated subject; wire `null` for subject-less entries.
    pub subject_ref: Option<ReadSubject>,
    /// Operator-supplied rationale.
    pub rationale: String,
    /// Audit snapshot id, stringified i64; wire `null` when absent.
    pub snapshot_id: Option<String>,
    /// Moderation event id, stringified i64; wire `null` when
    /// absent. Join key against cairn-mod's
    /// `pds_admin_audit.backend_action_id`.
    pub event_id: Option<String>,
    /// SHA-256 over the canonical input, hex-lowercase — or the
    /// literal `"pre-chain"` sentinel on pre-Phase-3.8 rows.
    pub current_hash: String,
    /// Prior row's `current_hash`; `null` for the genesis row.
    pub previous_hash: Option<String>,
    /// Aurora's own per-row verify verdict (v0.9-or-legacy match).
    /// Path A recomputes independently; this field is informational.
    pub verified: bool,
    /// Per-subject cascade list; `[]` when empty on the wire.
    #[serde(default)]
    pub cascade_subjects: Vec<ReadSubject>,
    /// Snapshot ids paired by index with `cascade_subjects`,
    /// stringified i64 elements; `[]` when empty.
    #[serde(default)]
    pub cascade_snapshot_ids: Vec<Option<String>>,
    /// Provenance discriminator (v0.9 canonical field). Never null.
    pub source: String,
    /// Action-specific scalars — **key-omitted** on the wire when
    /// the action carries no payload (the only omitted-when-absent
    /// field). Captured as a raw value so the canonical form can
    /// re-embed Aurora's byte-exact serialization (T2, v2 §4.3);
    /// an alphabetizing `serde_json::Value` would corrupt key
    /// order under multi-key payloads.
    #[serde(default)]
    pub payload: Option<Box<RawValue>>,
}

impl Clone for AuroraAuditEntry {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            sequence: self.sequence,
            timestamp: self.timestamp.clone(),
            actor_did: self.actor_did.clone(),
            action: self.action.clone(),
            subject_ref: self.subject_ref.clone(),
            rationale: self.rationale.clone(),
            snapshot_id: self.snapshot_id.clone(),
            event_id: self.event_id.clone(),
            current_hash: self.current_hash.clone(),
            previous_hash: self.previous_hash.clone(),
            verified: self.verified,
            cascade_subjects: self.cascade_subjects.clone(),
            cascade_snapshot_ids: self.cascade_snapshot_ids.clone(),
            source: self.source.clone(),
            payload: self.payload.as_ref().map(|p| p.to_owned()),
        }
    }
}

/// Single-entry lookup for `get_audit_entry` — Aurora requires
/// exactly one of `id` / `hash` (400 otherwise); the enum makes the
/// invalid both/neither shapes unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEntryLookup {
    /// Fetch by audit-chain entry id (`audit_chain_entry.id` — the
    /// value cairn-mod stores as
    /// `pds_admin_audit.upstream_audit_entry_id`).
    Id(i64),
    /// Fetch by the entry's `current_hash` (chain-walk affordance).
    Hash(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_trail_page_deserializes_canonical_wire_shape() {
        // Wire-form table (v2 §3.1): absent options are literal
        // null, empty cascades are [], payload key-omitted.
        let wire = json!({
            "items": [{
                "id": "42",
                "sequence": 7,
                "timestamp": "2026-05-09T00:00:00Z",
                "actorDid": "did:plc:moderator",
                "action": "TakedownAccount",
                "subjectRef": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"},
                "rationale": "spam",
                "snapshotId": null,
                "eventId": "9007199254740993",
                "currentHash": "abc123",
                "previousHash": null,
                "verified": true,
                "cascadeSubjects": [],
                "cascadeSnapshotIds": [],
                "source": "manual"
            }],
            "chainVerified": true,
            "chainVerifiedThrough": 7,
            "chainLegacyCount": 0
        });
        let page: AuditTrailPage = serde_json::from_value(wire).unwrap();
        assert!(page.chain_verified);
        assert_eq!(page.chain_verified_through, 7);
        assert!(page.cursor.is_none());
        let e = &page.items[0];
        assert_eq!(e.id, "42");
        assert_eq!(e.event_id.as_deref(), Some("9007199254740993"));
        assert!(e.snapshot_id.is_none());
        assert!(e.payload.is_none(), "key-omitted payload is None");
        assert!(e.cascade_subjects.is_empty());
    }

    #[test]
    fn payload_raw_value_preserves_bytes_and_key_order() {
        // preserve_order is enabled crate-wide, but RawValue must
        // keep the exact wire bytes regardless — including a key
        // order an alphabetizing Value would rewrite.
        let wire = r#"{"id":"1","sequence":1,"timestamp":"2026-05-09T00:00:00Z","actorDid":"did:system","action":"x","subjectRef":null,"rationale":"r","snapshotId":null,"eventId":null,"currentHash":"h","previousHash":null,"verified":true,"cascadeSubjects":[],"cascadeSnapshotIds":[],"source":"auto_label_rule","payload":{"zeta":1,"alpha":true}}"#;
        let e: AuroraAuditEntry = serde_json::from_str(wire).unwrap();
        assert_eq!(
            e.payload.as_ref().unwrap().get(),
            r#"{"zeta":1,"alpha":true}"#,
            "RawValue must preserve wire bytes verbatim"
        );
    }

    #[test]
    fn filter_serializes_camel_case_and_omits_none() {
        let filter = AuditTrailFilter {
            actor_did: Some("did:plc:mod".to_string()),
            after_created: Some("2026-01-01T00:00:00Z".to_string()),
            source: Some("manual".to_string()),
            ..Default::default()
        };
        let v = serde_json::to_value(&filter).unwrap();
        assert_eq!(v["actorDid"], "did:plc:mod");
        assert_eq!(v["afterCreated"], "2026-01-01T00:00:00Z");
        assert_eq!(v["source"], "manual");
        assert!(v.get("subjectUri").is_none(), "None fields omitted");
        assert!(v.get("ruleManagement").is_none(), "UI toggles not mirrored");
    }
}
