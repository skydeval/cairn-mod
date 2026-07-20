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
}
