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

use serde::Serialize;

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
    /// `com.atproto.admin.defs#repoBlobRef` — blob-level
    /// (v1.8.5). Field order mirrors Aurora's `Subject::Blob`
    /// (`did`, `cid`, optional `record_uri`); `record_uri` is
    /// omitted from the wire when absent, matching Aurora's
    /// `skip_serializing_if` on the same field.
    Blob {
        #[serde(rename = "$type")]
        type_field: &'static str,
        did: &'a str,
        cid: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        record_uri: Option<&'a str>,
    },
}

/// `$type` string for account subjects.
pub(crate) const SUBJECT_TYPE_REPO_REF: &str = "com.atproto.admin.defs#repoRef";
/// `$type` string for record subjects.
pub(crate) const SUBJECT_TYPE_STRONG_REF: &str = "com.atproto.repo.strongRef";
/// `$type` string for blob subjects (v1.8.5).
pub(crate) const SUBJECT_TYPE_REPO_BLOB_REF: &str = "com.atproto.admin.defs#repoBlobRef";

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

    /// Blob-level subject (v1.8.5).
    pub fn blob(did: &'a str, cid: &'a str, record_uri: Option<&'a str>) -> Self {
        Self::Blob {
            type_field: SUBJECT_TYPE_REPO_BLOB_REF,
            did,
            cid,
            record_uri,
        }
    }
}

/// Action discriminator — mirrors Aurora's `ModEventAction`
/// (v1.8.2 shipped 4 variants; v1.8.5 adds the 10 remaining
/// dispatchable ones). Internally-tagged with `kind`; unit
/// variants serialize as `{"kind": "<VariantName>"}`,
/// byte-matching Aurora's deserializer. **No `rename_all`** —
/// the discriminator is the PascalCase variant name (R3
/// NEW-R3-1; `{"kind": "DeleteAccount"}`, never
/// `"delete_account"`). Inner-field names carry explicit
/// camelCase renames mirroring Aurora's per-field attributes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum EmitEventAction {
    TakedownAccount,
    /// Unit variant — duration rides top-level `metadata`.
    SuspendAccount,
    RestoreAccount,
    /// Distinct kind; Aurora's dispatch arm validates that the
    /// subject is record-shaped for this action.
    TakedownRecord,
    // ---- v1.8.5 additions (Aurora `ModEventAction`,
    // aurora_admin.rs:238-282 at 2ffeb1a) ----
    /// Admin+ role floor upstream (`check_role`).
    DeleteAccount,
    QuarantineBlob,
    /// Unit variant — the prior action id is trait-boundary
    /// vocabulary only; nothing rides the wire (same
    /// non-transmission as `RestoreAccount`).
    RestoreBlob,
    DeleteBlob,
    ResolveReport {
        #[serde(rename = "reportId")]
        report_id: i64,
        resolution: super::action_types::ReportResolution,
    },
    DismissReport {
        #[serde(rename = "reportId")]
        report_id: i64,
    },
    /// Aurora's inner field is named `resolution` (its
    /// `AppealResolutionDecision`); cairn-mod's trait-side name
    /// for the value is `decision`, mapped here.
    ResolveAppeal {
        #[serde(rename = "appealId")]
        appeal_id: i64,
        resolution: super::action_types::AppealDecision,
    },
    EscalateAppeal {
        #[serde(rename = "appealId")]
        appeal_id: i64,
    },
    /// Admin+ role floor upstream. `subject` here is the email
    /// subject line (Aurora's field name — not `subject_line`,
    /// R3 NEW-R3-1/NEW-7); the recipient rides `subjects[0]`.
    SendEmail {
        #[serde(skip_serializing_if = "Option::is_none")]
        template: Option<String>,
        subject: String,
        body: String,
    },
    UpdateSubjectStatus {
        status: super::action_types::SubjectStatus,
    },
}

// The v1.8.2-era 2-field `EmitEventResponse` mirror is retired in
// v1.8.5: `dispatch_emit_event` now parses the full 4-field
// [`crate::pds_admin::rust::action_types::ActionResponse`]
// (String ids + snapshots + cascadingActions) so the v1.8.5
// action methods can surface cascades. v1.8.2 call sites extract
// `.event_id` from the widened response (R3 NEW-R3-3, option a).

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
            let v = serde_json::to_value(&action).unwrap();
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
        // v1.8.5: the dispatch path parses the full ActionResponse
        // (the 2-field EmitEventResponse mirror is retired).
        let wire = json!({
            "eventId": "evt-42",
            "auditEntryId": "chain-99",
            "snapshots": [],
            "cascadingActions": ["evt-43"],
            "someFutureField": true
        });
        let parsed: crate::pds_admin::rust::action_types::ActionResponse =
            serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.event_id, "evt-42");
        assert_eq!(parsed.audit_entry_id, "chain-99");
        assert_eq!(parsed.cascading_actions, vec!["evt-43".to_string()]);
    }

    #[test]
    fn v1_8_5_action_variants_use_pascal_case_kind_and_camel_case_fields() {
        use crate::pds_admin::rust::action_types::{
            AppealDecision, ReportResolution, SubjectStatus,
        };
        // Unit variants: bare PascalCase kind (R3 NEW-R3-1).
        for (action, kind) in [
            (EmitEventAction::DeleteAccount, "DeleteAccount"),
            (EmitEventAction::QuarantineBlob, "QuarantineBlob"),
            (EmitEventAction::RestoreBlob, "RestoreBlob"),
            (EmitEventAction::DeleteBlob, "DeleteBlob"),
        ] {
            let v = serde_json::to_value(&action).unwrap();
            assert_eq!(v, json!({"kind": kind}), "{action:?}");
        }
        // Data variants: camelCase inner fields, snake_case enum
        // VALUES, PascalCase kind.
        assert_eq!(
            serde_json::to_value(EmitEventAction::ResolveReport {
                report_id: 5,
                resolution: ReportResolution::Resolved,
            })
            .unwrap(),
            json!({"kind": "ResolveReport", "reportId": 5, "resolution": "resolved"})
        );
        assert_eq!(
            serde_json::to_value(EmitEventAction::DismissReport { report_id: 6 }).unwrap(),
            json!({"kind": "DismissReport", "reportId": 6})
        );
        assert_eq!(
            serde_json::to_value(EmitEventAction::ResolveAppeal {
                appeal_id: 9,
                resolution: AppealDecision::Approve,
            })
            .unwrap(),
            json!({"kind": "ResolveAppeal", "appealId": 9, "resolution": "approve"})
        );
        assert_eq!(
            serde_json::to_value(EmitEventAction::EscalateAppeal { appeal_id: 9 }).unwrap(),
            json!({"kind": "EscalateAppeal", "appealId": 9})
        );
        // SendEmail: wire field is `subject` (the email subject
        // line), template omitted when None.
        assert_eq!(
            serde_json::to_value(EmitEventAction::SendEmail {
                template: None,
                subject: "Notice".to_string(),
                body: "Body text".to_string(),
            })
            .unwrap(),
            json!({"kind": "SendEmail", "subject": "Notice", "body": "Body text"})
        );
        assert_eq!(
            serde_json::to_value(EmitEventAction::UpdateSubjectStatus {
                status: SubjectStatus::Active,
            })
            .unwrap(),
            json!({"kind": "UpdateSubjectStatus", "status": "active"})
        );
    }

    #[test]
    fn blob_subject_serializes_repo_blob_ref() {
        let full = serde_json::to_value(EmitEventSubject::blob(
            "did:plc:x",
            "bafyblob",
            Some("at://did:plc:x/app.bsky.feed.post/r"),
        ))
        .unwrap();
        assert_eq!(
            full,
            json!({
                "$type": "com.atproto.admin.defs#repoBlobRef",
                "did": "did:plc:x",
                "cid": "bafyblob",
                "record_uri": "at://did:plc:x/app.bsky.feed.post/r"
            })
        );
        let bare =
            serde_json::to_value(EmitEventSubject::blob("did:plc:x", "bafyblob", None)).unwrap();
        assert!(bare.get("record_uri").is_none());
    }
}
