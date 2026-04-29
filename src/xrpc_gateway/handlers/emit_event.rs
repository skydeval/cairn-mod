//! `tools.ozone.moderation.emitEvent` handler body (#95, v1.7).
//!
//! First inbound XRPC handler with a real body. Translates Ozone's
//! discriminated `ModEvent*` wire shapes into cairn-mod's canonical
//! [`crate::writer::WriterHandle::record_action`] pipeline (§A14:
//! "one canonical action-recording path"). The four event variants
//! map to:
//!
//! | Ozone `$type`                  | cairn-mod call           | action_type   |
//! |--------------------------------|--------------------------|---------------|
//! | `modEventLabel`                | `record_action`          | `warning`     |
//! | `modEventTakedown`             | `record_action`          | `takedown` (or `temp_suspension` if `durationInHours`) |
//! | `modEventReverseTakedown`      | `revoke_action` (after a history lookup for the most recent unrevoked Takedown) | — |
//! | `modEventComment`              | `record_action`          | `note`        |
//!
//! Anything else (Ozone has many more variants — `modEventMute`,
//! `modEventEmail`, `modEventResolveAppeal`, etc.) returns a
//! 400 `InvalidRequest` with the operator-facing message naming
//! the unsupported `$type`. Subsetting the surface this tightly is
//! deliberate per §A6 (cairn-mod is not a full Ozone replacement).
//!
//! # `createdBy` ↔ `claims.iss` coupling
//!
//! The wire shape requires a `createdBy` DID. Per §A8.1
//! defense-in-depth, the handler enforces `createdBy ==
//! claims.iss`: a moderator who authenticates as DID A cannot
//! attribute the action to DID B. This redundancy is intentional —
//! the auth middleware already proved `claims.iss` is who the
//! caller is; the createdBy field is preserved on the wire for
//! Ozone-client compatibility, but cairn-mod treats `claims.iss`
//! as the authoritative actor.
//!
//! # Reason-code vocabulary
//!
//! cairn-mod requires non-empty `reason_codes` on every action.
//! Ozone's modEventLabel naturally carries them (1:1 from
//! `createLabelVals`); the other three variants don't, so this
//! handler falls back to [`XRPC_GATEWAY_DEFAULT_REASON_CODE`]
//! (`"xrpc-gateway-default"`). Operators who want to receive
//! Takedown / Comment events must declare this code in
//! `[moderation_reasons]`; otherwise the writer surfaces
//! `ReasonNotFound` and the gateway returns 400.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Pool, Sqlite};

use crate::error::Error;
use crate::moderation::types::ActionType;
use crate::writer::{
    RecordActionRequest, RecordedAction, RevokeActionRequest, RevokedAction, WriterHandle,
};
use crate::xrpc_gateway::XrpcAuthClaims;

use super::XrpcGatewayState;

/// Reserved reason code used when an inbound Ozone event has no
/// natural `reason_codes` mapping (e.g., `modEventTakedown` only
/// carries a comment). Operators who want to accept these events
/// must declare this code in `[moderation_reasons]`; otherwise the
/// writer surfaces `ReasonNotFound` and the gateway returns
/// 400 `InvalidRequest`.
///
/// Mirrors [`crate::policy::automation::DEFAULT_POLICY_REASON_CODE`]
/// in spirit — a single reserved name the operator must opt into.
/// Hyphenated per the §F22.1 reason-code naming convention.
pub const XRPC_GATEWAY_DEFAULT_REASON_CODE: &str = "xrpc-gateway-default";

// ==========================================================================
// Wire types — input
// ==========================================================================

/// Wire shape of `tools.ozone.moderation.emitEvent`'s request body.
///
/// `subject` and `event` are kept as opaque [`serde_json::Value`]
/// after parsing-and-extracting the discriminator: this lets the
/// response envelope echo them verbatim (per Ozone's `ModEventView`
/// response shape) without round-tripping through cairn-mod's
/// internal types and risking byte-shape drift.
#[derive(Debug, Deserialize)]
pub struct EmitEventRequest {
    /// Discriminated subject. v1.7 supports only
    /// `com.atproto.admin.defs#repoRef` (account-level subjects);
    /// per-record `strongRef` subjects return `InvalidRequest`.
    pub subject: Value,
    /// Discriminated event body. Parsed into [`ModEvent`] for
    /// dispatch; the original [`Value`] is preserved alongside for
    /// the response envelope.
    pub event: Value,
    /// DID the caller claims authored this event. Per §A8.1
    /// defense-in-depth: must equal the authenticated `claims.iss`.
    #[serde(rename = "createdBy")]
    pub created_by: String,
    /// Optional blob CIDs the event references. cairn-mod doesn't
    /// store blob references in v1.7 — preserved on the response
    /// for wire fidelity but otherwise ignored.
    #[serde(rename = "subjectBlobCids", default)]
    pub subject_blob_cids: Vec<String>,
}

/// Discriminated subject wire shape. v1.7 supports
/// `com.atproto.admin.defs#repoRef` only.
///
/// The `strongRef` variant (per-record subjects) is rejected at the
/// handler-dispatch layer rather than parse layer so the operator-
/// facing error message can name the unsupported `$type` precisely.
#[derive(Debug, Deserialize, Serialize)]
pub struct RepoRef {
    /// Discriminator — must be `com.atproto.admin.defs#repoRef`.
    #[serde(rename = "$type")]
    pub r#type: String,
    /// The account DID this event targets.
    pub did: String,
}

/// Discriminated event body. Tagged on the `$type` field per the
/// ATProto lexicon convention.
///
/// The `Unsupported` variant catches any `$type` not matched by the
/// four supported variants; the handler returns
/// `InvalidRequest` naming the unsupported `$type` so an Ozone
/// client trying to send `modEventMute` (etc.) gets a precise
/// error rather than a generic parse failure.
#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub enum ModEvent {
    /// `tools.ozone.moderation.defs#modEventLabel` — apply (or
    /// negate) labels on a subject. cairn-mod maps `createLabelVals`
    /// 1:1 to `reason_codes`; the operator's `[moderation_reasons]`
    /// MUST declare each value as a reason that drives label
    /// emission per §F21. `negateLabelVals` is rejected with
    /// `InvalidRequest` in v1.7 (deferred — the negate path through
    /// the writer needs design work).
    #[serde(rename = "tools.ozone.moderation.defs#modEventLabel")]
    Label {
        /// Labels to apply to the subject. Mapped 1:1 to cairn-mod
        /// reason_codes.
        #[serde(rename = "createLabelVals")]
        create_label_vals: Vec<String>,
        /// Labels to remove. Rejected with `InvalidRequest` in v1.7.
        #[serde(rename = "negateLabelVals", default)]
        negate_label_vals: Vec<String>,
        /// Optional moderator-facing rationale.
        #[serde(default)]
        comment: Option<String>,
    },

    /// `tools.ozone.moderation.defs#modEventTakedown` — terminal
    /// or duration-bounded suspension. Maps to
    /// [`ActionType::Takedown`]; if `durationInHours` is set, maps
    /// to [`ActionType::TempSuspension`] with `duration_iso =
    /// PT{h}H` instead.
    #[serde(rename = "tools.ozone.moderation.defs#modEventTakedown")]
    Takedown {
        /// Optional moderator-facing rationale. Stored on the
        /// recorded action's `notes` field.
        #[serde(default)]
        comment: Option<String>,
        /// When set, the takedown is duration-bounded
        /// (`temp_suspension`); otherwise it's terminal
        /// (`takedown`).
        #[serde(rename = "durationInHours", default)]
        duration_in_hours: Option<u32>,
        /// Ozone's flag for cascading takedown across an account's
        /// records. cairn-mod's takedown is account-scoped already
        /// (§F20); the flag is accepted but has no effect.
        #[serde(rename = "acknowledgeAccountSubjects", default)]
        acknowledge_account_subjects: Option<bool>,
    },

    /// `tools.ozone.moderation.defs#modEventReverseTakedown` —
    /// revoke a prior Takedown for the subject. cairn-mod looks up
    /// the most-recent unrevoked Takedown by `subject_did`; if
    /// none exists, returns `InvalidRequest`. The Ozone wire shape
    /// has no `actionId`, so this lookup is the only way to bind
    /// the reversal to a specific cairn-mod row.
    #[serde(rename = "tools.ozone.moderation.defs#modEventReverseTakedown")]
    ReverseTakedown {
        /// Optional rationale. Stored on the revoked action's
        /// `revoked_reason` field.
        #[serde(default)]
        comment: Option<String>,
    },

    /// `tools.ozone.moderation.defs#modEventComment` — plain
    /// moderator note. Maps to [`ActionType::Note`] (no strikes,
    /// no labels by default).
    #[serde(rename = "tools.ozone.moderation.defs#modEventComment")]
    Comment {
        /// Moderator-facing comment. Required by Ozone's lexicon;
        /// stored on the recorded action's `notes` field.
        comment: String,
        /// Ozone's flag for "pin this comment to the subject". cairn-
        /// mod doesn't have stickiness as a first-class concept;
        /// the flag is accepted but has no effect.
        #[serde(default)]
        sticky: Option<bool>,
    },

    /// Catch-all for `$type` values cairn-mod doesn't support
    /// (e.g., `modEventMute`, `modEventEmail`,
    /// `modEventResolveAppeal`). The handler returns
    /// `InvalidRequest` naming the unsupported `$type`.
    #[serde(other)]
    Unsupported,
}

// ==========================================================================
// Wire types — output
// ==========================================================================

/// Wire shape of `tools.ozone.moderation.emitEvent`'s response body.
///
/// `event` and `subject` are echoed back as opaque
/// [`serde_json::Value`]: this preserves any extension fields the
/// caller sent (Ozone clients may carry forward-compat fields
/// cairn-mod doesn't recognize), and matches Ozone's own
/// `ModEventView` shape for client compatibility.
#[derive(Debug, Serialize)]
pub struct ModEventView {
    /// Stable event identifier. Maps to cairn-mod's
    /// `subject_actions.id` (or, for `ReverseTakedown`, the action
    /// being revoked). Same i64 surface cairn-mod's
    /// `tools.cairn.admin.recordAction` returns.
    pub id: i64,
    /// Echoed event body. Same bytes the caller sent.
    pub event: Value,
    /// Echoed subject. Same bytes the caller sent.
    pub subject: Value,
    /// Echoed blob CIDs. Same vec the caller sent (or empty if
    /// absent).
    #[serde(rename = "subjectBlobCids")]
    pub subject_blob_cids: Vec<String>,
    /// DID that authored the event. Always equal to `claims.iss`
    /// (the `createdBy == iss` check fires before this point).
    #[serde(rename = "createdBy")]
    pub created_by: String,
    /// RFC-3339-Z timestamp of the action. For `record_action`
    /// callers, this is the writer's wall-clock at INSERT time;
    /// for `revoke_action`, it's the revocation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Ozone's optional handle resolution. cairn-mod doesn't
    /// resolve handles in v1.7; always `null`.
    #[serde(rename = "creatorHandle", skip_serializing_if = "Option::is_none")]
    pub creator_handle: Option<String>,
}

// ==========================================================================
// Handler
// ==========================================================================

/// Handler entry point. Wired into the gateway router by
/// [`crate::xrpc_gateway::router::build_router`] for
/// `POST /xrpc/tools.ozone.moderation.emitEvent`.
///
/// Pipeline:
/// 1. Parse the request body. Malformed JSON → 400 `InvalidRequest`.
/// 2. Extract the subject DID. Non-`repoRef` subjects → 400.
/// 3. Enforce `createdBy == claims.iss`. Mismatch → 400.
/// 4. Dispatch on the [`ModEvent`] variant.
/// 5. Build the [`ModEventView`] response, echoing the original
///    `event` / `subject` bytes.
pub(crate) async fn handler(
    Extension(state): Extension<XrpcGatewayState>,
    Extension(claims): Extension<XrpcAuthClaims>,
    body: Bytes,
) -> Response {
    let req: EmitEventRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return invalid_request(format!("malformed request body: {e}")),
    };

    let subject_did = match parse_subject_did(&req.subject) {
        Ok(d) => d,
        Err(msg) => return invalid_request(msg),
    };

    if req.created_by != claims.iss {
        return invalid_request(format!(
            "createdBy {} does not match authenticated issuer {}",
            req.created_by, claims.iss
        ));
    }

    let event: ModEvent = match serde_json::from_value(req.event.clone()) {
        Ok(e) => e,
        Err(e) => return invalid_request(format!("malformed event body: {e}")),
    };

    match event {
        ModEvent::Label {
            create_label_vals,
            negate_label_vals,
            comment,
        } => {
            handle_label(
                &state.writer,
                &claims.iss,
                &subject_did,
                create_label_vals,
                negate_label_vals,
                comment,
                req.subject,
                req.event,
                req.subject_blob_cids,
            )
            .await
        }
        ModEvent::Takedown {
            comment,
            duration_in_hours,
            acknowledge_account_subjects: _,
        } => {
            handle_takedown(
                &state.writer,
                &claims.iss,
                &subject_did,
                comment,
                duration_in_hours,
                req.subject,
                req.event,
                req.subject_blob_cids,
            )
            .await
        }
        ModEvent::ReverseTakedown { comment } => {
            handle_reverse_takedown(
                &state.writer,
                &state.pool,
                &claims.iss,
                &subject_did,
                comment,
                req.subject,
                req.event,
                req.subject_blob_cids,
            )
            .await
        }
        ModEvent::Comment { comment, sticky: _ } => {
            handle_comment(
                &state.writer,
                &claims.iss,
                &subject_did,
                comment,
                req.subject,
                req.event,
                req.subject_blob_cids,
            )
            .await
        }
        ModEvent::Unsupported => {
            // Surface the original `$type` for the operator-facing
            // message. Falls back to "<unknown>" if the field is
            // missing or non-string (already-malformed input that
            // somehow survived the parse).
            let ty = req
                .event
                .get("$type")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            invalid_request(format!("event $type {ty} is not supported by cairn-mod"))
        }
    }
}

// ==========================================================================
// Per-event-type dispatch
// ==========================================================================

#[allow(clippy::too_many_arguments)]
async fn handle_label(
    writer: &WriterHandle,
    actor_did: &str,
    subject_did: &str,
    create_label_vals: Vec<String>,
    negate_label_vals: Vec<String>,
    comment: Option<String>,
    subject_echo: Value,
    event_echo: Value,
    blobs_echo: Vec<String>,
) -> Response {
    if !negate_label_vals.is_empty() {
        return invalid_request(
            "modEventLabel.negateLabelVals is not supported in v1.7; \
             call tools.cairn.admin.negateLabel instead"
                .to_string(),
        );
    }
    if create_label_vals.is_empty() {
        return invalid_request("modEventLabel.createLabelVals must be non-empty".to_string());
    }

    let req = RecordActionRequest {
        subject: subject_did.to_string(),
        actor_did: actor_did.to_string(),
        action_type: ActionType::Warning,
        reason_codes: create_label_vals,
        duration_iso: None,
        notes: comment,
        report_ids: Vec::new(),
    };

    match writer.record_action(req).await {
        Ok(recorded) => {
            recorded_action_view(recorded, actor_did, subject_echo, event_echo, blobs_echo)
        }
        Err(e) => map_record_action_error(e),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_takedown(
    writer: &WriterHandle,
    actor_did: &str,
    subject_did: &str,
    comment: Option<String>,
    duration_in_hours: Option<u32>,
    subject_echo: Value,
    event_echo: Value,
    blobs_echo: Vec<String>,
) -> Response {
    let (action_type, duration_iso) = match duration_in_hours {
        Some(0) => {
            return invalid_request(
                "modEventTakedown.durationInHours must be > 0 when set".to_string(),
            );
        }
        Some(h) => (ActionType::TempSuspension, Some(format!("PT{h}H"))),
        None => (ActionType::Takedown, None),
    };

    let req = RecordActionRequest {
        subject: subject_did.to_string(),
        actor_did: actor_did.to_string(),
        action_type,
        reason_codes: vec![XRPC_GATEWAY_DEFAULT_REASON_CODE.to_string()],
        duration_iso,
        notes: comment,
        report_ids: Vec::new(),
    };

    match writer.record_action(req).await {
        Ok(recorded) => {
            recorded_action_view(recorded, actor_did, subject_echo, event_echo, blobs_echo)
        }
        Err(e) => map_record_action_error(e),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_reverse_takedown(
    writer: &WriterHandle,
    pool: &Pool<Sqlite>,
    actor_did: &str,
    subject_did: &str,
    comment: Option<String>,
    subject_echo: Value,
    event_echo: Value,
    blobs_echo: Vec<String>,
) -> Response {
    let action_id = match find_active_takedown_action_id(pool, subject_did).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return invalid_request(format!(
                "no active takedown to reverse for subject {subject_did}"
            ));
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                subject = subject_did,
                "xrpc_gateway emitEvent: takedown lookup failed"
            );
            return internal_server_error();
        }
    };

    let req = RevokeActionRequest {
        action_id,
        revoked_by_did: actor_did.to_string(),
        revoked_reason: comment,
    };

    match writer.revoke_action(req).await {
        Ok(revoked) => {
            revoked_action_view(revoked, actor_did, subject_echo, event_echo, blobs_echo)
        }
        Err(e) => map_revoke_action_error(e),
    }
}

async fn handle_comment(
    writer: &WriterHandle,
    actor_did: &str,
    subject_did: &str,
    comment: String,
    subject_echo: Value,
    event_echo: Value,
    blobs_echo: Vec<String>,
) -> Response {
    let req = RecordActionRequest {
        subject: subject_did.to_string(),
        actor_did: actor_did.to_string(),
        action_type: ActionType::Note,
        reason_codes: vec![XRPC_GATEWAY_DEFAULT_REASON_CODE.to_string()],
        duration_iso: None,
        notes: Some(comment),
        report_ids: Vec::new(),
    };

    match writer.record_action(req).await {
        Ok(recorded) => {
            recorded_action_view(recorded, actor_did, subject_echo, event_echo, blobs_echo)
        }
        Err(e) => map_record_action_error(e),
    }
}

// ==========================================================================
// Helpers
// ==========================================================================

/// Extract the subject DID from a `repoRef` value. Rejects any
/// other discriminator (`strongRef` is the canonical other shape;
/// arbitrary objects also fail).
pub(crate) fn parse_subject_did(subject: &Value) -> Result<String, String> {
    let ty = subject
        .get("$type")
        .and_then(Value::as_str)
        .ok_or_else(|| "subject is missing $type discriminator".to_string())?;
    if ty != "com.atproto.admin.defs#repoRef" {
        return Err(format!(
            "subject $type {ty} is not supported; only com.atproto.admin.defs#repoRef is accepted in v1.7"
        ));
    }
    let did = subject
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| "subject.did is missing or not a string".to_string())?;
    if !did.starts_with("did:") {
        return Err(format!("subject.did {did:?} is not a DID"));
    }
    Ok(did.to_string())
}

/// Most-recent unrevoked Takedown action_id for a subject DID, or
/// `None` if no active Takedown exists. Used by
/// `modEventReverseTakedown`'s lookup path.
///
/// Direct SQL rather than reusing
/// [`crate::server::strike_state::load_action_history`] because
/// that helper drops the `id` column in its projection — the row
/// id is exactly what the reversal needs.
async fn find_active_takedown_action_id(
    pool: &Pool<Sqlite>,
    subject_did: &str,
) -> sqlx::Result<Option<i64>> {
    let row = sqlx::query!(
        r#"SELECT id as "id!: i64"
           FROM subject_actions
           WHERE subject_did = ?1
             AND action_type = 'takedown'
             AND revoked_at IS NULL
           ORDER BY id DESC
           LIMIT 1"#,
        subject_did,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.id))
}

fn recorded_action_view(
    recorded: RecordedAction,
    actor_did: &str,
    subject: Value,
    event: Value,
    blobs: Vec<String>,
) -> Response {
    let view = ModEventView {
        id: recorded.action_id,
        event,
        subject,
        subject_blob_cids: blobs,
        created_by: actor_did.to_string(),
        created_at: crate::writer::rfc3339_from_epoch_ms(crate::writer::epoch_ms_now())
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00.000Z")),
        creator_handle: None,
    };
    (StatusCode::OK, Json(view)).into_response()
}

fn revoked_action_view(
    revoked: RevokedAction,
    actor_did: &str,
    subject: Value,
    event: Value,
    blobs: Vec<String>,
) -> Response {
    let view = ModEventView {
        id: revoked.action_id,
        event,
        subject,
        subject_blob_cids: blobs,
        created_by: actor_did.to_string(),
        created_at: revoked.revoked_at,
        creator_handle: None,
    };
    (StatusCode::OK, Json(view)).into_response()
}

fn map_record_action_error(e: Error) -> Response {
    match e {
        Error::ReasonNotFound(name) => invalid_request(format!(
            "reason code {name:?} not declared in [moderation_reasons]; \
             see XRPC_GATEWAY_DEFAULT_REASON_CODE in §F23 docs"
        )),
        Error::DurationRequiredForTempSuspension => {
            invalid_request("durationInHours must be set for temp-suspension Takedown".to_string())
        }
        Error::DurationOnlyForTempSuspension => invalid_request(
            "durationInHours is only valid for temp-suspension Takedown".to_string(),
        ),
        Error::SubjectUriMismatch => {
            invalid_request("subject URI repo does not match subject DID".to_string())
        }
        Error::Signing(msg) => invalid_request(msg),
        other => {
            tracing::error!(
                error = %other,
                "xrpc_gateway emitEvent: writer.record_action failed"
            );
            internal_server_error()
        }
    }
}

fn map_revoke_action_error(e: Error) -> Response {
    match e {
        Error::ActionNotFound(_) => {
            // Race window: lookup found the action but the writer's
            // load-and-update transaction couldn't find it. Surface
            // as InvalidRequest with the same message the Ok(None)
            // path uses so a flapping integration test sees a
            // single shape.
            invalid_request("no active takedown to reverse".to_string())
        }
        Error::ActionAlreadyRevoked(_) => {
            // Same race-window posture as ActionNotFound.
            invalid_request("takedown is already revoked".to_string())
        }
        Error::Signing(msg) => invalid_request(msg),
        other => {
            tracing::error!(
                error = %other,
                "xrpc_gateway emitEvent: writer.revoke_action failed"
            );
            internal_server_error()
        }
    }
}

fn invalid_request(message: String) -> Response {
    let body = ErrorEnvelope {
        error: "InvalidRequest",
        message,
    };
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

fn internal_server_error() -> Response {
    let body = ErrorEnvelope {
        error: "InternalServerError",
        message: "service temporarily unavailable".to_string(),
    };
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: &'static str,
    message: String,
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ===== parse_subject_did =====

    #[test]
    fn parse_subject_accepts_repo_ref() {
        let v = json!({
            "$type": "com.atproto.admin.defs#repoRef",
            "did": "did:plc:abc"
        });
        assert_eq!(parse_subject_did(&v).unwrap(), "did:plc:abc");
    }

    #[test]
    fn parse_subject_rejects_strong_ref() {
        let v = json!({
            "$type": "com.atproto.repo.strongRef",
            "uri": "at://did:plc:abc/app.bsky.feed.post/x",
            "cid": "bafy...",
        });
        let err = parse_subject_did(&v).unwrap_err();
        assert!(err.contains("strongRef") || err.contains("not supported"));
    }

    #[test]
    fn parse_subject_rejects_missing_type() {
        let v = json!({ "did": "did:plc:abc" });
        let err = parse_subject_did(&v).unwrap_err();
        assert!(err.contains("$type"));
    }

    #[test]
    fn parse_subject_rejects_non_did_value() {
        let v = json!({
            "$type": "com.atproto.admin.defs#repoRef",
            "did": "not-a-did"
        });
        let err = parse_subject_did(&v).unwrap_err();
        assert!(err.contains("not a DID"));
    }

    // ===== ModEvent parsing =====

    #[test]
    fn parse_mod_event_label() {
        let v = json!({
            "$type": "tools.ozone.moderation.defs#modEventLabel",
            "createLabelVals": ["spam", "harassment"],
        });
        let e: ModEvent = serde_json::from_value(v).unwrap();
        match e {
            ModEvent::Label {
                create_label_vals, ..
            } => {
                assert_eq!(create_label_vals, vec!["spam", "harassment"]);
            }
            other => panic!("expected Label, got {other:?}"),
        }
    }

    #[test]
    fn parse_mod_event_takedown_with_duration() {
        let v = json!({
            "$type": "tools.ozone.moderation.defs#modEventTakedown",
            "comment": "spam farm",
            "durationInHours": 168,
        });
        let e: ModEvent = serde_json::from_value(v).unwrap();
        match e {
            ModEvent::Takedown {
                duration_in_hours,
                comment,
                ..
            } => {
                assert_eq!(duration_in_hours, Some(168));
                assert_eq!(comment.as_deref(), Some("spam farm"));
            }
            other => panic!("expected Takedown, got {other:?}"),
        }
    }

    #[test]
    fn parse_mod_event_reverse_takedown() {
        let v = json!({
            "$type": "tools.ozone.moderation.defs#modEventReverseTakedown",
            "comment": "appeal granted",
        });
        let e: ModEvent = serde_json::from_value(v).unwrap();
        assert!(matches!(e, ModEvent::ReverseTakedown { .. }));
    }

    #[test]
    fn parse_mod_event_comment() {
        let v = json!({
            "$type": "tools.ozone.moderation.defs#modEventComment",
            "comment": "needs second review",
        });
        let e: ModEvent = serde_json::from_value(v).unwrap();
        match e {
            ModEvent::Comment { comment, .. } => {
                assert_eq!(comment, "needs second review");
            }
            other => panic!("expected Comment, got {other:?}"),
        }
    }

    #[test]
    fn parse_mod_event_unsupported_falls_through_to_unsupported_variant() {
        // Ozone has many other event types — modEventMute,
        // modEventEmail, modEventResolveAppeal, etc. The
        // `serde(other)` catch-all swallows them all so the
        // handler can produce a precise error message.
        let v = json!({
            "$type": "tools.ozone.moderation.defs#modEventMute",
            "durationInHours": 24,
        });
        let e: ModEvent = serde_json::from_value(v).unwrap();
        assert!(matches!(e, ModEvent::Unsupported));
    }

    #[test]
    fn parse_emit_event_request_round_trip() {
        // Pin the full request shape so a future field-rename
        // breaks loudly. The `event` and `subject` fields are
        // opaque Values — verify they're carried verbatim.
        let body = json!({
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": "did:plc:target"
            },
            "event": {
                "$type": "tools.ozone.moderation.defs#modEventComment",
                "comment": "x",
            },
            "createdBy": "did:plc:moderator",
            "subjectBlobCids": [],
        });
        let req: EmitEventRequest = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(req.created_by, "did:plc:moderator");
        // event and subject preserve the exact wire bytes
        assert_eq!(req.event, body["event"]);
        assert_eq!(req.subject, body["subject"]);
    }

    // ===== Wire constants =====

    #[test]
    fn default_reason_code_is_hyphenated() {
        // §F22.1 reason-code naming convention. Pinned because the
        // operator's [moderation_reasons] config uses the same
        // string and a drift would silently break inbound
        // Takedown / Comment events.
        assert_eq!(XRPC_GATEWAY_DEFAULT_REASON_CODE, "xrpc-gateway-default");
    }
}
