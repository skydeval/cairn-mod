//! Read-side wire types for `tools.aurora.moderator.queryEvents` /
//! `queryStatuses` (v1.8.3, §4.2-§4.3).
//!
//! Every type here mirrors Aurora source byte-identically in wire
//! naming; each carries its `file:line` provenance (Aurora HEAD
//! `2ffeb1a`):
//!
//! - [`PaginatedResponse`] ← `aurora-locus/src/admin/defs.rs:161-166`
//! - [`EventWithContext`] ← `aurora-locus/src/api/aurora_moderator.rs:48-59`
//! - [`StatusWithContext`] ← `aurora-locus/src/api/aurora_moderator.rs:62-77`
//! - [`ReadSubject`] ← `aurora-locus/src/admin/defs.rs:46-88` (three
//!   variants, `$type`-tagged)
//! - [`QueryEventsFilter`] ← `QueryEventsParams`,
//!   `aurora_moderator.rs:188-206`
//! - [`QueryStatusesFilter`] ← `QueryStatusesParams`,
//!   `aurora_moderator.rs:480-499`
//!
//! Wire casing: **field names are camelCase** (Aurora's structs are
//! `#[serde(rename_all = "camelCase")]`, `aurora_moderator.rs:48-49`,
//! `:62-63`); `event_type` **values** are snake_case scalars (e.g.
//! `"account_takedown"`, per the param doc-comment at
//! `aurora_moderator.rs:189-190`) — value-casing and field-casing
//! are independent facts.
//!
//! Timestamps: Aurora serializes `chrono::DateTime<Utc>` as RFC3339
//! strings. cairn-mod mirrors them as `String` — lossless on the
//! wire and avoids a chrono dependency; callers parse with the
//! `time` crate if they need instants.

use serde::{Deserialize, Serialize};

/// Standard paginated wrapper for Aurora's Phase-3 list endpoints.
/// Mirror of `aurora-locus/src/admin/defs.rs:161-166`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    /// Page items, in upstream order.
    pub items: Vec<T>,
    /// Present only when more pages remain.
    pub cursor: Option<String>,
}

/// One moderation event with rich resolved context. Mirror of
/// `EventWithContext` at `aurora_moderator.rs:48-59`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventWithContext {
    /// Aurora-side event row id.
    pub id: i64,
    /// Snake_case event-type scalar (e.g. `"account_takedown"`) —
    /// a plain string, NOT a `kind`-tagged action enum; read
    /// responses carry no `ModEventAction`.
    pub event_type: String,
    /// DID of the actor that emitted the event.
    pub actor_did: String,
    /// Resolved handle for the actor, when Aurora could resolve it.
    pub actor_handle: Option<String>,
    /// `None` for server-level events with no subject.
    pub subject: Option<ReadSubject>,
    /// Resolved handle for the subject's DID, when resolvable.
    pub subject_handle: Option<String>,
    /// Opaque action payload; cairn-mod passes it through.
    pub details: serde_json::Value,
    /// RFC3339 timestamp.
    pub created_at: String,
}

/// One per-DID moderation-status row. Mirror of `StatusWithContext`
/// at `aurora_moderator.rs:62-77`. **Account-scoped only** — this
/// surface carries no record URIs or CIDs (Record/Blob filters on
/// the endpoint are accepted but yield empty results until Aurora
/// ships per-record/per-blob status surfaces).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusWithContext {
    /// Aurora-side status row id.
    pub id: i64,
    /// Subject account DID.
    pub did: String,
    /// Resolved handle, when resolvable.
    pub handle: Option<String>,
    /// Action string (e.g. `"takedown"`, `"suspend"`).
    pub action: String,
    /// Moderator-supplied rationale.
    pub reason: String,
    /// DID of the moderator that applied the action.
    pub moderated_by: String,
    /// Resolved moderator handle, when resolvable.
    pub moderated_by_handle: Option<String>,
    /// RFC3339 timestamp.
    pub moderated_at: String,
    /// RFC3339 timestamp; `None` for indefinite actions.
    pub expires_at: Option<String>,
    /// Whether the action has been reversed.
    pub reversed: bool,
    /// RFC3339 timestamp; `None` when not reversed.
    pub reversed_at: Option<String>,
    /// Originating report row id, when the action came from one.
    pub report_id: Option<i64>,
}

/// Aurora's subject union as it appears in read responses —
/// `$type`-tagged, three variants. Mirror of
/// `aurora-locus/src/admin/defs.rs:46-88`. (Named `ReadSubject` to
/// avoid colliding with cairn-mod's own
/// [`crate::pds_admin::types::Subject`] label-target type.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum ReadSubject {
    /// Account-level subject.
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    Account {
        /// Account DID.
        did: String,
    },
    /// Record-level subject. `cid` is required on Aurora's wire
    /// (empty string = URI-level semantics, a batch-cascade
    /// convention).
    #[serde(rename = "com.atproto.repo.strongRef")]
    Record {
        /// Record AT-URI.
        uri: String,
        /// Record CID (strong reference).
        cid: String,
    },
    /// Blob-level subject. `record_uri` optional per
    /// `defs.rs:81-88`.
    #[serde(rename = "com.atproto.admin.defs#repoBlobRef")]
    Blob {
        /// Owning account DID.
        did: String,
        /// Blob CID.
        cid: String,
        /// Originating record AT-URI, when known.
        record_uri: Option<String>,
    },
}

/// Query-string filter for `queryEvents`. Field-for-field mirror of
/// `QueryEventsParams` at `aurora_moderator.rs:188-206` (pagination
/// travels separately as trait-method `cursor`/`limit` arguments).
///
/// Serializes camelCase for the wire query string; `None` fields
/// are omitted entirely.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryEventsFilter {
    /// Snake_case event-type value (e.g. `"account_takedown"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Actor DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Subject DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    /// Lower bound on `created_at` (inclusive), RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// Upper bound on `created_at` (inclusive), RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
}

/// Query-string filter for `queryStatuses`. Field-for-field mirror
/// of `QueryStatusesParams` at `aurora_moderator.rs:480-499`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryStatusesFilter {
    /// Subject DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Subject category — wire values are lowercase
    /// (`"account"` | `"record"` | `"blob"` per Aurora's
    /// `SubjectType`, `defs.rs:150-156`). Record/Blob currently
    /// yield empty results on Aurora's side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    /// Action-type filter (e.g. `"takedown"`, `"suspend"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Include reversed actions (Aurora default: true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_reversed: Option<bool>,
}

// ===========================================================================
// v1.8.4 — moderator read-surface completion (§4.2)
// ===========================================================================
//
// Provenance (Aurora HEAD `2ffeb1a`, per the v1.8.4 R1 report):
// - `SubjectContextResponse` ← `aurora_moderator.rs:84-96`
// - `CurrentStatus` ← `:98-104`; `RelatedReport` ← `:106-113`;
//   `RelatedAppeal` ← `:112-120`
// - `AppealView` ← `:1054-1068` (`OriginalActionSummary` `:1032-1040`,
//   `AppealResolution` `:1045-1052`)
// - `AppealDetail` + `AppealTimelineEntry` ← `:1082-1090` / `:1070-1079`
// - `SubjectHistoryFilter` ← `GetSubjectHistoryParams`, `:839-850`
// - `ListAppealsFilter` ← `ListAppealsParams`, `:1226-1244`
//
// Enum-typed Aurora fields (`ApiAppealStatus`, snake_case values
// `pending`/`under_review`/`approved`/`denied`/`escalated` per
// `aurora_moderator.rs:994-1001`) mirror as `String`, following the
// v1.8.3 `subject_type` precedent — wire-identical, and Aurora
// remains the validator.

/// Subject-context fetch response. Mirror of
/// `SubjectContextResponse` at `aurora_moderator.rs:84-96`.
/// Queried by DID (account-scoped parameter); the `subject` field
/// in the response is the full union.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectContextResponse {
    /// Subject union for the queried DID.
    pub subject: ReadSubject,
    /// The DID the context rolls up to, when derivable.
    pub primary_did: Option<String>,
    /// Resolved handle, when resolvable.
    pub handle: Option<String>,
    /// Current moderation status, when any.
    pub current_status: Option<CurrentStatus>,
    /// Recent moderation actions (same row shape as
    /// `queryStatuses` / `getSubjectHistory` items).
    pub recent_actions: Vec<StatusWithContext>,
    /// Open/related reports for the subject.
    pub related_reports: Vec<RelatedReport>,
    /// Related appeals for the subject.
    pub related_appeals: Vec<RelatedAppeal>,
}

/// Current-status fragment. Mirror of `aurora_moderator.rs:98-104`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentStatus {
    /// Takedown reference, when taken down.
    pub takedown_ref: Option<String>,
    /// RFC3339 deactivation timestamp, when deactivated.
    pub deactivated_at: Option<String>,
    /// Active moderation action string, when any.
    pub active_action: Option<String>,
}

/// Related-report fragment. Mirror of `aurora_moderator.rs:106-113`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedReport {
    /// Report row id.
    pub id: i64,
    /// Report reason type (NSID-shaped).
    pub reason_type: String,
    /// Free-text reason, when supplied.
    pub reason: Option<String>,
    /// Reporter DID.
    pub reported_by: String,
    /// RFC3339 submission timestamp.
    pub reported_at: String,
    /// Report status string.
    pub status: String,
}

/// Related-appeal fragment. Mirror of `aurora_moderator.rs:112-120`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedAppeal {
    /// Appeal row id.
    pub id: i64,
    /// Appellant DID.
    pub appellant_did: String,
    /// Resolved appellant handle, when resolvable.
    pub appellant_handle: Option<String>,
    /// Appeal status (snake_case value).
    pub status: String,
    /// RFC3339 submission timestamp.
    pub submitted_at: String,
}

/// Paginated appeal list item. Mirror of `AppealView` at
/// `aurora_moderator.rs:1054-1068`. Note the view field is
/// `submitterDid` — the *filter* parameter on `listAppeals` is
/// named `appellant`, but the response field is submitter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppealView {
    /// Appeal row id.
    pub id: i64,
    /// Appeal status — snake_case value (`pending`,
    /// `under_review`, `approved`, `denied`, `escalated`).
    pub status: String,
    /// Appellant DID.
    pub submitter_did: String,
    /// Resolved appellant handle, when resolvable.
    pub submitter_handle: Option<String>,
    /// Appealed subject, when the appeal targets one.
    pub subject: Option<ReadSubject>,
    /// Appellant-supplied reason.
    pub reason: String,
    /// Appellant-supplied detail text, when any.
    pub details: Option<String>,
    /// RFC3339 submission timestamp.
    pub submitted_at: String,
    /// Summary of the appealed action, when linked.
    pub original_action_summary: Option<OriginalActionSummary>,
    /// Resolution, present only once reviewed.
    pub resolution: Option<AppealResolution>,
}

/// Appealed-action summary. Mirror of `aurora_moderator.rs:1032-1040`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginalActionSummary {
    /// One of `"moderation"`, `"report"`, `"quarantine"`.
    pub kind: String,
    /// Row id in the kind's table.
    pub id: i64,
    /// Short human-readable summary.
    pub summary: String,
}

/// Appeal resolution fragment. Mirror of `aurora_moderator.rs:1045-1052`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppealResolution {
    /// Reviewer DID.
    pub reviewed_by: String,
    /// Resolved reviewer handle, when resolvable.
    pub reviewed_by_handle: Option<String>,
    /// RFC3339 review timestamp.
    pub reviewed_at: String,
    /// Decision string, when recorded.
    pub decision: Option<String>,
    /// Reviewer notes, when any.
    pub notes: Option<String>,
}

/// Detailed appeal view returned by `getAppeal`. Mirror of
/// `AppealDetail` at `aurora_moderator.rs:1082-1090`: `AppealView`
/// flattened + a chronological lifecycle timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppealDetail {
    /// The appeal's list-view fields, flattened on the wire.
    #[serde(flatten)]
    pub view: AppealView,
    /// Chronological lifecycle entries.
    pub timeline: Vec<AppealTimelineEntry>,
}

/// One appeal lifecycle entry. Mirror of `aurora_moderator.rs:1070-1079`
/// (Aurora's `kind` is `&'static str` server-side; `String` here).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppealTimelineEntry {
    /// `"submitted"` or `"reviewed"`.
    pub kind: String,
    /// RFC3339 timestamp.
    pub at: String,
    /// Acting DID.
    pub by_did: String,
    /// Resolved handle, when resolvable.
    pub by_handle: Option<String>,
    /// Free-text note, when any.
    pub note: Option<String>,
}

/// Query-string filter for `getSubjectHistory` beyond the DID —
/// mirror of `GetSubjectHistoryParams`' filter fields at
/// `aurora_moderator.rs:839-850` (the `did` travels as a separate
/// trait-method argument; pagination as cursor/limit arguments).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectHistoryFilter {
    /// Filter by action type (e.g. `"takedown"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// `"asc"` (oldest-first) or `"desc"` (newest-first, Aurora
    /// default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
}

/// Query-string filter for `listAppeals`. Mirror of
/// `ListAppealsParams` at `aurora_moderator.rs:1226-1244`. There is
/// no `subject` filter on this endpoint.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAppealsFilter {
    /// Appeal status — snake_case value per `ApiAppealStatus`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Filter by appellant DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appellant: Option<String>,
    /// Filter by reviewer DID (matches `reviewed_by`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    /// Lower bound on `submitted_at` (inclusive), RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitted_after: Option<String>,
    /// Upper bound on `submitted_at` (inclusive), RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitted_before: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn paginated_events_response_deserializes_canonical_wire_shape() {
        // camelCase field names per aurora_moderator.rs:48-49;
        // snake_case event_type VALUE per :189-190.
        let wire = json!({
            "items": [{
                "id": 42,
                "eventType": "account_takedown",
                "actorDid": "did:web:cairn-mod.example.test",
                "actorHandle": null,
                "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"},
                "subjectHandle": "user.example.com",
                "details": {"rationale": "spam"},
                "createdAt": "2026-07-20T12:00:00Z"
            }],
            "cursor": "opaque-cursor"
        });
        let parsed: PaginatedResponse<EventWithContext> = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.items.len(), 1);
        let ev = &parsed.items[0];
        assert_eq!(ev.id, 42);
        assert_eq!(ev.event_type, "account_takedown");
        assert_eq!(
            ev.subject,
            Some(ReadSubject::Account {
                did: "did:plc:x".to_string()
            })
        );
        assert_eq!(parsed.cursor.as_deref(), Some("opaque-cursor"));
    }

    #[test]
    fn event_without_subject_deserializes() {
        // Server-level events carry no subject (Option per
        // aurora_moderator.rs:55).
        let wire = json!({
            "id": 1,
            "eventType": "report_review",
            "actorDid": "did:plc:mod",
            "actorHandle": null,
            "subject": null,
            "subjectHandle": null,
            "details": {},
            "createdAt": "2026-07-20T12:00:00Z"
        });
        let ev: EventWithContext = serde_json::from_value(wire).unwrap();
        assert!(ev.subject.is_none());
    }

    #[test]
    fn read_subject_three_variants_deserialize() {
        let record: ReadSubject = serde_json::from_value(json!({
            "$type": "com.atproto.repo.strongRef",
            "uri": "at://did:plc:x/app.bsky.feed.post/r",
            "cid": "bafyr"
        }))
        .unwrap();
        assert_eq!(
            record,
            ReadSubject::Record {
                uri: "at://did:plc:x/app.bsky.feed.post/r".to_string(),
                cid: "bafyr".to_string()
            }
        );

        // Blob with and without record_uri (Option per defs.rs:81-88).
        let blob_full: ReadSubject = serde_json::from_value(json!({
            "$type": "com.atproto.admin.defs#repoBlobRef",
            "did": "did:plc:x",
            "cid": "bafyblob",
            "record_uri": "at://did:plc:x/app.bsky.feed.post/r"
        }))
        .unwrap();
        assert!(matches!(
            blob_full,
            ReadSubject::Blob { ref record_uri, .. } if record_uri.is_some()
        ));

        let blob_bare: ReadSubject = serde_json::from_value(json!({
            "$type": "com.atproto.admin.defs#repoBlobRef",
            "did": "did:plc:x",
            "cid": "bafyblob"
        }))
        .unwrap();
        assert!(matches!(
            blob_bare,
            ReadSubject::Blob { ref record_uri, .. } if record_uri.is_none()
        ));
    }

    #[test]
    fn status_with_context_deserializes_per_did_shape() {
        let wire = json!({
            "items": [{
                "id": 7,
                "did": "did:plc:x",
                "handle": "user.example.com",
                "action": "takedown",
                "reason": "spam",
                "moderatedBy": "did:plc:mod",
                "moderatedByHandle": null,
                "moderatedAt": "2026-07-20T12:00:00Z",
                "expiresAt": null,
                "reversed": false,
                "reversedAt": null,
                "reportId": 3
            }],
            "cursor": null
        });
        let parsed: PaginatedResponse<StatusWithContext> = serde_json::from_value(wire).unwrap();
        let st = &parsed.items[0];
        assert_eq!(st.did, "did:plc:x");
        assert_eq!(st.action, "takedown");
        assert!(!st.reversed);
        assert_eq!(st.report_id, Some(3));
        assert!(parsed.cursor.is_none());
    }

    #[test]
    fn response_tolerates_future_fields() {
        // No deny_unknown_fields anywhere: Aurora adding response
        // fields later must not break the parse.
        let wire = json!({
            "items": [],
            "cursor": null,
            "someFutureField": true
        });
        let parsed: PaginatedResponse<EventWithContext> = serde_json::from_value(wire).unwrap();
        assert!(parsed.items.is_empty());
    }

    /// Build a request the way the dispatch helpers do and return
    /// its query string — exercises the exact serialization path
    /// (`reqwest::RequestBuilder::query` → serde_urlencoded) with
    /// no new dependency.
    fn query_string_of<T: Serialize>(filter: &T) -> String {
        let req = reqwest::Client::new()
            .get("http://localhost/xrpc/test")
            .query(filter)
            .build()
            .unwrap();
        req.url().query().unwrap_or("").to_string()
    }

    #[test]
    fn events_filter_serializes_camel_case_and_omits_none() {
        let filter = QueryEventsFilter {
            event_type: Some("account_takedown".to_string()),
            subject_did: Some("did:plc:x".to_string()),
            ..Default::default()
        };
        let qs = query_string_of(&filter);
        assert!(qs.contains("eventType=account_takedown"), "{qs}");
        assert!(qs.contains("subjectDid=did%3Aplc%3Ax"), "{qs}");
        assert!(!qs.contains("actor"), "None fields omitted: {qs}");
        assert!(!qs.contains("sortOrder"), "no fabricated params: {qs}");
    }

    #[test]
    fn statuses_filter_serializes_camel_case_lowercase_subject_type() {
        let filter = QueryStatusesFilter {
            did: Some("did:plc:x".to_string()),
            subject_type: Some("account".to_string()),
            include_reversed: Some(false),
            ..Default::default()
        };
        let qs = query_string_of(&filter);
        assert!(qs.contains("did=did%3Aplc%3Ax"), "{qs}");
        assert!(qs.contains("subjectType=account"), "{qs}");
        assert!(qs.contains("includeReversed=false"), "{qs}");
    }

    #[test]
    fn subject_context_response_deserializes_nested_shape() {
        // Full nested shape per aurora_moderator.rs:84-120
        // (camelCase throughout).
        let wire = json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"},
            "primaryDid": "did:plc:x",
            "handle": "user.example.com",
            "currentStatus": {
                "takedownRef": "TAKEDOWN-9",
                "deactivatedAt": null,
                "activeAction": "takedown"
            },
            "recentActions": [{
                "id": 7,
                "did": "did:plc:x",
                "handle": "user.example.com",
                "action": "takedown",
                "reason": "spam",
                "moderatedBy": "did:plc:mod",
                "moderatedByHandle": null,
                "moderatedAt": "2026-07-20T12:00:00Z",
                "expiresAt": null,
                "reversed": false,
                "reversedAt": null,
                "reportId": 3
            }],
            "relatedReports": [{
                "id": 11,
                "reasonType": "com.atproto.moderation.defs#reasonSpam",
                "reason": "spam wave",
                "reportedBy": "did:plc:reporter",
                "reportedAt": "2026-07-19T09:00:00Z",
                "status": "resolved"
            }],
            "relatedAppeals": [{
                "id": 5,
                "appellantDid": "did:plc:x",
                "appellantHandle": "user.example.com",
                "status": "pending",
                "submittedAt": "2026-07-20T13:00:00Z"
            }]
        });
        let ctx: SubjectContextResponse = serde_json::from_value(wire).unwrap();
        assert_eq!(ctx.primary_did.as_deref(), Some("did:plc:x"));
        let status = ctx.current_status.expect("currentStatus present");
        assert_eq!(status.takedown_ref.as_deref(), Some("TAKEDOWN-9"));
        assert_eq!(status.active_action.as_deref(), Some("takedown"));
        assert_eq!(ctx.recent_actions.len(), 1);
        assert_eq!(ctx.recent_actions[0].action, "takedown");
        assert_eq!(
            ctx.related_reports[0].reason_type,
            "com.atproto.moderation.defs#reasonSpam"
        );
        assert_eq!(ctx.related_appeals[0].status, "pending");
    }

    #[test]
    fn subject_context_minimal_shape_deserializes() {
        // All-optional context: unknown DID with no history.
        let wire = json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:ghost"},
            "primaryDid": null,
            "handle": null,
            "currentStatus": null,
            "recentActions": [],
            "relatedReports": [],
            "relatedAppeals": []
        });
        let ctx: SubjectContextResponse = serde_json::from_value(wire).unwrap();
        assert!(ctx.current_status.is_none());
        assert!(ctx.recent_actions.is_empty());
    }

    #[test]
    fn appeal_view_page_deserializes() {
        // AppealView per aurora_moderator.rs:1054-1068; status
        // VALUES are snake_case (ApiAppealStatus, :994-1001).
        let wire = json!({
            "items": [{
                "id": 5,
                "status": "under_review",
                "submitterDid": "did:plc:x",
                "submitterHandle": "user.example.com",
                "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"},
                "reason": "wrongful takedown",
                "details": "context here",
                "submittedAt": "2026-07-20T13:00:00Z",
                "originalActionSummary": {
                    "kind": "moderation",
                    "id": 7,
                    "summary": "takedown: spam"
                },
                "resolution": null
            }],
            "cursor": null
        });
        let page: PaginatedResponse<AppealView> = serde_json::from_value(wire).unwrap();
        let appeal = &page.items[0];
        assert_eq!(appeal.status, "under_review");
        assert_eq!(appeal.submitter_did, "did:plc:x");
        let summary = appeal.original_action_summary.as_ref().unwrap();
        assert_eq!(summary.kind, "moderation");
        assert!(appeal.resolution.is_none());
    }

    #[test]
    fn appeal_detail_deserializes_flattened_view_plus_timeline() {
        // AppealDetail flattens AppealView inline + adds timeline
        // (aurora_moderator.rs:1082-1090, :1070-1079) — the wire
        // has NO "view" wrapper key.
        let wire = json!({
            "id": 5,
            "status": "approved",
            "submitterDid": "did:plc:x",
            "submitterHandle": null,
            "subject": null,
            "reason": "wrongful takedown",
            "details": null,
            "submittedAt": "2026-07-20T13:00:00Z",
            "originalActionSummary": null,
            "resolution": {
                "reviewedBy": "did:plc:mod",
                "reviewedByHandle": "mod.example.com",
                "reviewedAt": "2026-07-21T09:00:00Z",
                "decision": "overturned",
                "notes": "insufficient evidence"
            },
            "timeline": [
                {
                    "kind": "submitted",
                    "at": "2026-07-20T13:00:00Z",
                    "byDid": "did:plc:x",
                    "byHandle": null,
                    "note": null
                },
                {
                    "kind": "reviewed",
                    "at": "2026-07-21T09:00:00Z",
                    "byDid": "did:plc:mod",
                    "byHandle": "mod.example.com",
                    "note": "insufficient evidence"
                }
            ]
        });
        let detail: AppealDetail = serde_json::from_value(wire).unwrap();
        assert_eq!(detail.view.id, 5);
        assert_eq!(detail.view.status, "approved");
        let resolution = detail.view.resolution.as_ref().unwrap();
        assert_eq!(resolution.reviewed_by, "did:plc:mod");
        assert_eq!(resolution.decision.as_deref(), Some("overturned"));
        assert_eq!(detail.timeline.len(), 2);
        assert_eq!(detail.timeline[0].kind, "submitted");
        assert_eq!(detail.timeline[1].by_did, "did:plc:mod");
    }

    #[test]
    fn subject_history_filter_serializes_and_omits_none() {
        let filter = SubjectHistoryFilter {
            action: Some("takedown".to_string()),
            ..Default::default()
        };
        let qs = query_string_of(&filter);
        assert!(qs.contains("action=takedown"), "{qs}");
        assert!(!qs.contains("direction"), "None fields omitted: {qs}");
    }

    #[test]
    fn list_appeals_filter_serializes_camel_case_and_omits_none() {
        let filter = ListAppealsFilter {
            status: Some("pending".to_string()),
            reviewer: Some("did:plc:mod".to_string()),
            submitted_after: Some("2026-07-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        let qs = query_string_of(&filter);
        assert!(qs.contains("status=pending"), "{qs}");
        assert!(qs.contains("reviewer=did%3Aplc%3Amod"), "{qs}");
        assert!(qs.contains("submittedAfter="), "camelCase bound: {qs}");
        assert!(!qs.contains("appellant"), "None fields omitted: {qs}");
        assert!(!qs.contains("submittedBefore"), "None fields omitted: {qs}");
    }
}
