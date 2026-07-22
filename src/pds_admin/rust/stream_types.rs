//! Wire mirrors for `tools.aurora.admin.subscribeModEvents`
//! (v1.8.8, v2 §4, chainlink #147).
//!
//! Aurora streams **JSON text frames** (not CBOR) with `$type`
//! envelope discriminators — six bare lowerCamel values per
//! Aurora's `SubscribeMessage` serde renames (`aurora_subscribe.rs`
//! at `2ffeb1a`; R1 A1 verification). The `event` payload is the
//! flat v0.2 shape built in `fetch_new_events` — NOT v1.8.3's
//! `EventWithContext` (no handle enrichment, no `$type` subject
//! union). `auditEntry` frames carry the byte-identical
//! `getAuditTrail` entry shape, so the v1.8.6
//! [`AuroraAuditEntry`] mirror is reused, not redefined.

use serde::{Deserialize, Serialize};

use super::audit_types::AuroraAuditEntry;

/// Mirror of the `event` frame payload — Aurora's v0.2-stable flat
/// shape (v2 §4.1). `id` is `moderation_event.id`: the same id
/// space `queryEvents` items use, and the payload cairn-mod's own
/// dispatches store as `BackendActionId::PerEvent`/`PerBatch`
/// (stringified) — the echo-suppression and reconciliation-dedup
/// join key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamEvent {
    /// Aurora `moderation_event.id`.
    pub id: i64,
    /// Snake_case `ModerationEventType::as_str` value. LOSSY for
    /// emitEvent-originated events (`event_type_for` collapses
    /// verbs); `details.action` is the disambiguator (v2 §4.3).
    pub event_type: String,
    /// DID of the actor that performed the action.
    pub actor_did: String,
    /// Flat subject columns — nullable; multi-subject and batch
    /// events carry NULL columns with the list in `details`.
    pub subject_did: Option<String>,
    /// Record AT-URI when the event targets a record.
    pub subject_uri: Option<String>,
    /// Record/blob CID when known.
    pub subject_cid: Option<String>,
    /// Parsed detail JSON or `null` (Aurora substitutes null on
    /// parse failure).
    #[serde(default)]
    pub details: serde_json::Value,
    /// RFC3339 — also the reconciliation window bound (A4).
    pub created_at: String,
}

/// One server frame (v2 §4.2). Discriminators are Aurora's bare
/// lowerCamel rename values — NOT NSID-qualified (R1 A1).
#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub enum StreamFrame {
    /// Connection greeting: server version + the join-point event
    /// cursor (seeds `stream_cursors` on cursor-less connects).
    #[serde(rename = "hello")]
    Hello {
        /// Aurora's `CARGO_PKG_VERSION`.
        #[serde(rename = "instanceVersion")]
        instance_version: String,
        /// Starting event cursor (the tail at join, or the
        /// caller-presented resume position).
        sequence: i64,
    },
    /// One moderation event; `sequence` is the `mod_event_seq.seq`
    /// cursor value (NOT the payload's `id`).
    #[serde(rename = "event")]
    Event {
        /// The flat v0.2 payload.
        event: UpstreamEvent,
        /// Event-cursor position of this delivery.
        sequence: i64,
    },
    /// One audit-chain entry (only when `includeAuditChain` is on).
    #[serde(rename = "auditEntry", rename_all = "camelCase")]
    AuditEntry {
        /// v1.8.6-shipped mirror, byte-identical on this wire
        /// (Aurora pins stream `entry` == `getAuditTrail` item).
        entry: Box<AuroraAuditEntry>,
        /// Chain-cursor position (duplicates `entry.sequence` by
        /// spec so consumers cursor without inspecting payloads).
        sequence: i64,
    },
    /// Keepalive echo — its `sequence` repeats the server-side
    /// event cursor and MUST NOT advance persisted cursors.
    #[serde(rename = "heartbeat")]
    Heartbeat {
        /// Echoed event cursor.
        sequence: i64,
    },
    /// Presented cursor predates the retention window; the server
    /// closes cleanly (1000) after this frame. Client re-bootstraps
    /// via queryEvents reconciliation and resubscribes.
    #[serde(rename = "outdatedCursor", rename_all = "camelCase")]
    OutdatedCursor {
        /// Lowest seq currently retained upstream; resuming from
        /// ≥ this avoids the outdated failure on next connect.
        oldest_available_seq: i64,
        /// Operator-facing explanation.
        message: String,
    },
    /// Server-side failure notice; the socket drops after this
    /// frame with no close handshake.
    #[serde(rename = "error")]
    Error {
        /// Error code (only `"Internal"` is constructed at HEAD).
        code: String,
        /// Operator-facing message.
        message: String,
    },
}

/// Best-effort verb classification for an incoming event (v2
/// §4.3): `details.action` carries the PascalCase emitEvent kind
/// for emitEvent-originated events; dedicated-batch events carry
/// the lossy snake_case string plus `batch: true` + `subjects`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventVerb {
    /// `details.action` carried a PascalCase emitEvent kind
    /// (e.g. `"DeleteAccount"` on an `account_takedown` event).
    EmitEvent(String),
    /// `details.batch == true` — dedicated-batch origin.
    DedicatedBatch,
    /// Everything else — classify by `event_type` alone.
    Other,
}

/// Classify an event's originating verb from its details payload.
pub fn disambiguate_event_verb(event: &UpstreamEvent) -> EventVerb {
    if event
        .details
        .get("batch")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return EventVerb::DedicatedBatch;
    }
    match event
        .details
        .get("action")
        .and_then(serde_json::Value::as_str)
    {
        // PascalCase = emitEvent kind vocabulary; snake_case or
        // absent = not an emitEvent detail payload.
        Some(a) if a.chars().next().is_some_and(char::is_uppercase) => {
            EventVerb::EmitEvent(a.to_string())
        }
        _ => EventVerb::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(v: serde_json::Value) -> StreamFrame {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn all_six_frame_types_parse_with_bare_discriminators() {
        // Recon §2a verbatim shapes (A1: bare lowerCamel, never
        // NSID-qualified).
        match parse(json!({"$type": "hello", "instanceVersion": "0.10.0", "sequence": 7})) {
            StreamFrame::Hello {
                instance_version,
                sequence,
            } => {
                assert_eq!(instance_version, "0.10.0");
                assert_eq!(sequence, 7);
            }
            other => panic!("{other:?}"),
        }
        match parse(json!({
            "$type": "event",
            "event": {
                "id": 42,
                "eventType": "account_takedown",
                "actorDid": "did:plc:mod",
                "subjectDid": "did:plc:s",
                "subjectUri": null,
                "subjectCid": null,
                "details": {"rationale": "spam", "action": "DeleteAccount"},
                "createdAt": "2026-07-21T00:00:00Z"
            },
            "sequence": 9
        })) {
            StreamFrame::Event { event, sequence } => {
                assert_eq!(sequence, 9);
                assert_eq!(event.id, 42);
                assert_eq!(event.event_type, "account_takedown");
                assert_eq!(event.details["action"], "DeleteAccount");
            }
            other => panic!("{other:?}"),
        }
        match parse(json!({"$type": "heartbeat", "sequence": 12})) {
            StreamFrame::Heartbeat { sequence } => assert_eq!(sequence, 12),
            other => panic!("{other:?}"),
        }
        match parse(json!({
            "$type": "outdatedCursor",
            "oldestAvailableSeq": 30,
            "message": "cursor is older than the retention window"
        })) {
            StreamFrame::OutdatedCursor {
                oldest_available_seq,
                ..
            } => assert_eq!(oldest_available_seq, 30),
            other => panic!("{other:?}"),
        }
        match parse(json!({"$type": "error", "code": "Internal", "message": "event poll failed"})) {
            StreamFrame::Error { code, .. } => assert_eq!(code, "Internal"),
            other => panic!("{other:?}"),
        }
        // auditEntry: entry payload is the v1.8.6 mirror shape.
        match parse(json!({
            "$type": "auditEntry",
            "entry": {
                "id": "100",
                "sequence": 42,
                "timestamp": "2026-07-21T00:00:00Z",
                "actorDid": "did:plc:m1",
                "action": "TakedownAccount",
                "subjectRef": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:s"},
                "rationale": "spam",
                "currentHash": "h",
                "previousHash": null,
                "verified": true,
                "cascadeSubjects": [],
                "cascadeSnapshotIds": [],
                "source": "manual"
            },
            "sequence": 42
        })) {
            StreamFrame::AuditEntry { entry, sequence } => {
                assert_eq!(sequence, 42);
                assert_eq!(entry.sequence, 42);
                assert_eq!(entry.action, "TakedownAccount");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nsid_qualified_discriminators_are_rejected() {
        // A1 pin: the pre-amendment NSID-qualified form must NOT
        // parse — Aurora never sends it.
        let r: Result<StreamFrame, _> = serde_json::from_value(json!({
            "$type": "tools.aurora.admin.subscribeModEvents#heartbeat",
            "sequence": 1
        }));
        assert!(r.is_err());
    }

    #[test]
    fn verb_disambiguation_covers_the_lossy_cases() {
        let mk = |details: serde_json::Value| UpstreamEvent {
            id: 1,
            event_type: "account_takedown".to_string(),
            actor_did: "did:plc:m".to_string(),
            subject_did: None,
            subject_uri: None,
            subject_cid: None,
            details,
            created_at: "2026-07-21T00:00:00Z".to_string(),
        };
        assert_eq!(
            disambiguate_event_verb(&mk(json!({"rationale": "r", "action": "DeleteAccount"}))),
            EventVerb::EmitEvent("DeleteAccount".to_string())
        );
        // Dedicated batch: lossy snake_case action + batch marker.
        assert_eq!(
            disambiguate_event_verb(&mk(json!({
                "rationale": "r", "action": "account_takedown",
                "batch": true, "subjects": ["did:plc:a"]
            }))),
            EventVerb::DedicatedBatch
        );
        // Non-emitEvent details (report_submit shapes etc.).
        assert_eq!(disambiguate_event_verb(&mk(json!(null))), EventVerb::Other);
        assert_eq!(
            disambiguate_event_verb(&mk(json!({"action": "account_takedown"}))),
            EventVerb::Other
        );
    }
}
