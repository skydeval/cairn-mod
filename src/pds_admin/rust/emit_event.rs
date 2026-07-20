//! Outbound wire types for `tools.aurora.admin.emitEvent`
//! (v1.8.2, §4.3).
//!
//! Mirrors Aurora-Locus's `EmitEventInputRaw` / `ModEventAction` /
//! `EmitEventOutput` (Aurora `src/api/aurora_admin.rs:107-124`,
//! `:236-282`, `:213-230` at recon HEAD `2ffeb1a`). Named
//! `EmitEventDispatch` — not `EmitEventRequest` — to avoid
//! colliding with the *inbound* Ozone-dialect gateway type of that
//! name at `crate::xrpc_gateway::handlers::emit_event`.
//!
//! Wire-contract notes (each verified against Aurora source
//! during the v1.8.2 CC-adversarial rounds):
//!
//! - Actions are `#[serde(tag = "kind")]` with **variant-name**
//!   discriminators (`{"kind": "TakedownAccount"}`), not
//!   `$type`-tagged NSID strings — those belong to the inbound
//!   Ozone dialect.
//! - The subject field is the canonical plural `subjects: [s]`;
//!   Aurora still accepts the legacy single-`subject` shape but
//!   flags it as migration debt on operator dashboards, so
//!   cairn-mod never sends it.
//! - `SuspendAccount` is a unit variant; duration rides the
//!   top-level `metadata: {"durationDays": n}` channel.
//! - There is no `notes` wire field (documented non-transmission,
//!   §4.5-notes); `rationale` is the only text channel.
//! - `snapshotCapture` is deliberately not set — Aurora defaults
//!   it to `true`, giving operator-visibility snapshots.
//! - Record subjects require a CID (`com.atproto.repo.strongRef`
//!   with `uri` + `cid`, both mandatory on Aurora's side).

use serde::{Deserialize, Serialize};

/// One `emitEvent` request body. Borrowed fields — the dispatch
/// path builds this per call from trait-method arguments and
/// serializes immediately.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmitEventDispatch<'a> {
    /// Canonical multi-subject shape; single-subject dispatches
    /// send a one-element vec.
    pub subjects: Vec<EmitEventSubject<'a>>,
    pub action: EmitEventAction,
    pub rationale: &'a str,
    /// Action-specific options (`{"durationDays": n}` for
    /// `SuspendAccount`). Omitted from the wire when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Subject union — `$type`-tagged per ATProto convention (this
/// tagging applies to *subjects* only; actions use `kind`).
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum EmitEventSubject<'a> {
    /// `com.atproto.admin.defs#repoRef` — account-level.
    Account {
        #[serde(rename = "$type")]
        type_field: &'static str,
        did: &'a str,
    },
    /// `com.atproto.repo.strongRef` — record-level. `cid` is
    /// mandatory on Aurora's wire (`Subject::Record { uri, cid }`,
    /// no Option); callers reject CID-less subjects before
    /// constructing this variant.
    Record {
        #[serde(rename = "$type")]
        type_field: &'static str,
        uri: &'a str,
        cid: &'a str,
    },
}

/// `$type` string for account subjects.
pub(crate) const SUBJECT_TYPE_REPO_REF: &str = "com.atproto.admin.defs#repoRef";
/// `$type` string for record subjects.
pub(crate) const SUBJECT_TYPE_STRONG_REF: &str = "com.atproto.repo.strongRef";

impl<'a> EmitEventSubject<'a> {
    /// Account-level subject.
    pub fn account(did: &'a str) -> Self {
        Self::Account {
            type_field: SUBJECT_TYPE_REPO_REF,
            did,
        }
    }

    /// Record-level subject. The caller guarantees `cid` presence
    /// (trait-boundary Validation rejection covers the `None`
    /// case).
    pub fn record(uri: &'a str, cid: &'a str) -> Self {
        Self::Record {
            type_field: SUBJECT_TYPE_STRONG_REF,
            uri,
            cid,
        }
    }
}

/// Action discriminator — mirrors Aurora's `ModEventAction` for
/// the four v1.8.2 variants. Internally-tagged with `kind`;
/// unit variants serialize as `{"kind": "<VariantName>"}`,
/// byte-matching Aurora's deserializer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum EmitEventAction {
    TakedownAccount,
    /// Unit variant — duration rides top-level `metadata`.
    SuspendAccount,
    RestoreAccount,
    /// Distinct kind; Aurora's dispatch arm validates that the
    /// subject is record-shaped for this action.
    TakedownRecord,
}

/// `emitEvent` response — cairn-mod consumes `eventId` (the
/// [`BackendActionId`](crate::pds_admin::BackendActionId) source)
/// and deserializes `auditEntryId` for forward-compat with
/// v1.8.6's cross-chain verify. `snapshots` / `cascadingActions`
/// are ignored (serde skips unknown fields by default; Aurora
/// adding response fields later cannot break this parse).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmitEventResponse {
    pub event_id: String,
    /// Aurora's audit-chain entry id. Unused at v1.8.2; becomes
    /// cross-chain-verify-relevant at v1.8.6. Deserialized now so
    /// the field's presence is contract-tested.
    #[allow(dead_code)]
    pub audit_entry_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn to_value(d: &EmitEventDispatch<'_>) -> serde_json::Value {
        serde_json::to_value(d).unwrap()
    }

    #[test]
    fn takedown_account_body_shape() {
        let d = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account("did:plc:xxx")],
            action: EmitEventAction::TakedownAccount,
            rationale: "reason text",
            metadata: None,
        };
        assert_eq!(
            to_value(&d),
            json!({
                "subjects": [
                    {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:xxx"}
                ],
                "action": {"kind": "TakedownAccount"},
                "rationale": "reason text"
            })
        );
    }

    #[test]
    fn suspend_account_with_duration_puts_duration_in_top_level_metadata() {
        let d = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account("did:plc:xxx")],
            action: EmitEventAction::SuspendAccount,
            rationale: "reason",
            metadata: Some(json!({"durationDays": 7})),
        };
        let v = to_value(&d);
        assert_eq!(v["action"], json!({"kind": "SuspendAccount"}));
        // Top-level metadata, not inline with the action.
        assert_eq!(v["metadata"], json!({"durationDays": 7}));
        assert!(v["action"].get("durationDays").is_none());
    }

    #[test]
    fn suspend_account_without_duration_omits_metadata_entirely() {
        let d = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account("did:plc:xxx")],
            action: EmitEventAction::SuspendAccount,
            rationale: "reason",
            metadata: None,
        };
        let v = to_value(&d);
        assert!(v.get("metadata").is_none());
    }

    #[test]
    fn restore_account_body_shape() {
        let d = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account("did:plc:xxx")],
            action: EmitEventAction::RestoreAccount,
            rationale: "reason",
            metadata: None,
        };
        let v = to_value(&d);
        assert_eq!(v["action"], json!({"kind": "RestoreAccount"}));
        // prior_action_id never appears anywhere in the wire body
        // (§4.5 non-transmission).
        assert!(!v.to_string().contains("prior"));
    }

    #[test]
    fn takedown_record_uses_strong_ref_with_cid() {
        let d = EmitEventDispatch {
            subjects: vec![EmitEventSubject::record(
                "at://did:plc:xxx/app.bsky.feed.post/rkey",
                "bafyabcxyz",
            )],
            action: EmitEventAction::TakedownRecord,
            rationale: "reason",
            metadata: None,
        };
        assert_eq!(
            to_value(&d),
            json!({
                "subjects": [{
                    "$type": "com.atproto.repo.strongRef",
                    "uri": "at://did:plc:xxx/app.bsky.feed.post/rkey",
                    "cid": "bafyabcxyz"
                }],
                "action": {"kind": "TakedownRecord"},
                "rationale": "reason"
            })
        );
    }

    #[test]
    fn all_action_variants_use_kind_discriminator_with_variant_names() {
        // Pinned byte-for-byte against Aurora's #[serde(tag = "kind")]
        // deserializer (aurora_admin.rs:236-282).
        for (action, kind) in [
            (EmitEventAction::TakedownAccount, "TakedownAccount"),
            (EmitEventAction::SuspendAccount, "SuspendAccount"),
            (EmitEventAction::RestoreAccount, "RestoreAccount"),
            (EmitEventAction::TakedownRecord, "TakedownRecord"),
        ] {
            let v = serde_json::to_value(action).unwrap();
            assert_eq!(v, json!({"kind": kind}), "{action:?}");
        }
    }

    #[test]
    fn no_notes_field_exists_on_the_wire() {
        // §4.5-notes: documented non-transmission. The dispatch
        // type has no notes field; serialization can never leak
        // one.
        let d = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account("did:plc:xxx")],
            action: EmitEventAction::TakedownAccount,
            rationale: "r",
            metadata: None,
        };
        assert!(to_value(&d).get("notes").is_none());
    }

    #[test]
    fn response_parses_aurora_output_and_tolerates_extra_fields() {
        let wire = json!({
            "eventId": "evt-42",
            "auditEntryId": "chain-99",
            "snapshots": [{"snapshotId": 1}],
            "cascadingActions": ["evt-43"],
            "someFutureField": true
        });
        let parsed: EmitEventResponse = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.event_id, "evt-42");
        assert_eq!(parsed.audit_entry_id, "chain-99");
    }
}
