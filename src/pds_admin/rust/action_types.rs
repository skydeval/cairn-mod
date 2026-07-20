//! Action-response mirror types for `tools.aurora.admin.emitEvent`
//! (v1.8.5, §4.2).
//!
//! Byte-identical mirrors of Aurora-Locus response/enum shapes at
//! recon HEAD `2ffeb1a`, per the R1/R2/R3 review-cycle pins
//! (chainlinks #131/#132/#133):
//!
//! - [`ActionResponse`] ← Aurora `EmitEventOutput`
//!   (`aurora_admin.rs:213-230`): **String** ids, and
//!   `cascadingActions` is a bare list of event-id strings — no
//!   struct (R1 LB-E: Aurora has no `CascadedAction` type).
//! - [`SnapshotRef`] ← Aurora `SnapshotRef`
//!   (`aurora_admin.rs:1390-1401`).
//! - [`ReportResolution`] ← Aurora `ReportResolution`
//!   (`aurora_admin.rs:284-291`, snake_case wire values).
//! - [`AppealDecision`] ← Aurora `AppealResolutionDecision`
//!   (`aurora_admin.rs:315-321`, snake_case). The wire field that
//!   carries it inside `ResolveAppeal` is named `resolution`.
//! - [`SubjectStatus`] ← Aurora `SubjectStatusValue`
//!   (`aurora_admin.rs:322-330`, snake_case): account-dimension
//!   tri-state, not a generic status object.
//!
//! [`BlobSubject`] is trait-boundary vocabulary (the blob methods'
//! subject coordinates); its wire form is
//! the crate-internal `EmitEventSubject::Blob` arm
//! (`com.atproto.admin.defs#repoBlobRef`).

use serde::{Deserialize, Serialize};

use super::read_types::ReadSubject;

/// Mirror of Aurora's `EmitEventOutput` — the response every
/// `emitEvent` dispatch returns (v1.8.5 §4.2). Returned by the
/// v1.8.5 action methods so `cascading_actions` reaches the CLI
/// (R2 NEW-1); the writer extracts [`Self::event_id`] for its
/// `BackendActionId::PerEvent` stamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResponse {
    /// Aurora's moderation-event id for the dispatched action.
    /// String on the wire (not numeric) per R1 LB-E.
    pub event_id: String,
    /// Aurora's audit-chain entry id. Always populated on success
    /// (Aurora writes the chain entry in the same transaction as
    /// the event row).
    pub audit_entry_id: String,
    /// Per-subject snapshot list, 1:1 with the request's
    /// `subjects`; empty when snapshot capture was disabled
    /// upstream.
    #[serde(default)]
    pub snapshots: Vec<SnapshotRef>,
    /// Event ids of actions Aurora cascaded server-side. Bare
    /// id strings — resolve details via `queryEvents`/`getEvent`
    /// (v1.8.3). Sole v0.10 cascade source relevant to v1.8.5:
    /// `ResolveAppeal{Approve}` reversing the original action.
    #[serde(default)]
    pub cascading_actions: Vec<String>,
}

/// Mirror of Aurora's `SnapshotRef` (`aurora_admin.rs:1390-1401`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRef {
    /// Subject the snapshot was captured for (`$type`-tagged
    /// union — same wire shape as the v1.8.3 read-side
    /// [`ReadSubject`]).
    pub subject: ReadSubject,
    /// Snapshot id when captured; `None` for single-subject
    /// paths that use the scalar chain-entry snapshot instead.
    pub snapshot_id: Option<String>,
}

/// Trait-boundary blob coordinates for the three blob action
/// methods (v1.8.5 §4.1). Wire form:
/// `com.atproto.admin.defs#repoBlobRef` via
/// `EmitEventSubject::Blob`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobSubject {
    /// Owning account DID.
    pub did: String,
    /// Blob CID.
    pub cid: String,
    /// Referencing record URI, when known.
    pub record_uri: Option<String>,
}

/// Mirror of Aurora's `ReportResolution` — outcome of a report
/// review, carried inside the `ResolveReport` action variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportResolution {
    /// Report resolved with action taken.
    Resolved,
    /// Report acknowledged without action.
    Acknowledged,
    /// Report escalated for further review.
    Escalated,
}

impl ReportResolution {
    /// Wire/CLI string form (snake_case, matching serde).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Acknowledged => "acknowledged",
            Self::Escalated => "escalated",
        }
    }

    /// Parse the wire/CLI string form.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "resolved" => Some(Self::Resolved),
            "acknowledged" => Some(Self::Acknowledged),
            "escalated" => Some(Self::Escalated),
            _ => None,
        }
    }
}

/// Mirror of Aurora's `AppealResolutionDecision` — carried inside
/// the `ResolveAppeal` action variant under the wire field name
/// `resolution`. `Approve` triggers Aurora's cascade: the original
/// moderation action reverses atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealDecision {
    /// Uphold the appeal; Aurora reverses the original action
    /// (cascading action in the response).
    Approve,
    /// Deny the appeal; the original action stands.
    Deny,
}

impl AppealDecision {
    /// Wire/CLI string form (snake_case, matching serde).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }

    /// Parse the wire/CLI string form.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "approve" => Some(Self::Approve),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// Mirror of Aurora's `SubjectStatusValue` — the account-dimension
/// tri-state `UpdateSubjectStatus` sets (R1 substantial: NOT a
/// generic status update; Aurora's dispatch arm rejects non-repo
/// subjects).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectStatus {
    /// Take the account down (maps upstream to a takedown
    /// moderation action).
    Takedown,
    /// Deactivate (maps upstream to a suspension action).
    Deactivated,
    /// Restore to active (maps upstream to a restore action).
    Active,
}

impl SubjectStatus {
    /// Wire/CLI string form (snake_case, matching serde).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Takedown => "takedown",
            Self::Deactivated => "deactivated",
            Self::Active => "active",
        }
    }

    /// Parse the wire/CLI string form.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "takedown" => Some(Self::Takedown),
            "deactivated" => Some(Self::Deactivated),
            "active" => Some(Self::Active),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn action_response_deserializes_canonical_wire_shape() {
        // String ids + bare cascade id strings per R1 LB-E.
        let wire = json!({
            "eventId": "42",
            "auditEntryId": "1042",
            "snapshots": [{
                "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"},
                "snapshotId": null
            }],
            "cascadingActions": ["43"]
        });
        let parsed: ActionResponse = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.event_id, "42");
        assert_eq!(parsed.audit_entry_id, "1042");
        assert_eq!(parsed.snapshots.len(), 1);
        assert!(matches!(
            parsed.snapshots[0].subject,
            ReadSubject::Account { ref did } if did == "did:plc:x"
        ));
        assert_eq!(parsed.cascading_actions, vec!["43".to_string()]);
    }

    #[test]
    fn action_response_tolerates_missing_optional_lists() {
        // Defensive defaults — a minimal success body still parses.
        let wire = json!({"eventId": "7", "auditEntryId": "8"});
        let parsed: ActionResponse = serde_json::from_value(wire).unwrap();
        assert!(parsed.snapshots.is_empty());
        assert!(parsed.cascading_actions.is_empty());
    }

    #[test]
    fn enum_wire_values_are_snake_case() {
        assert_eq!(
            serde_json::to_value(ReportResolution::Acknowledged).unwrap(),
            json!("acknowledged")
        );
        assert_eq!(
            serde_json::to_value(AppealDecision::Approve).unwrap(),
            json!("approve")
        );
        assert_eq!(
            serde_json::to_value(SubjectStatus::Deactivated).unwrap(),
            json!("deactivated")
        );
        assert_eq!(
            SubjectStatus::from_wire_str("active"),
            Some(SubjectStatus::Active)
        );
        assert_eq!(ReportResolution::from_wire_str("bogus"), None);
        assert_eq!(
            AppealDecision::from_wire_str("deny"),
            Some(AppealDecision::Deny)
        );
    }
}
