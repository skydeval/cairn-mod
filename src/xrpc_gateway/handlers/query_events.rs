//! `tools.ozone.moderation.queryEvents` handler body (#98, v1.7).
//!
//! Phase D's final handler. Closes the inbound NSID surface for
//! v1.7. Returns a paginated list of `modEventView`s projected
//! from cairn-mod's audit_log (joined with subject_actions where
//! relevant).
//!
//! The translation logic — including the **filter-out policy for
//! cairn-mod-internal audit entries** — lives in
//! [`crate::xrpc_gateway::handlers::projections::audit_event`].
//! Operators reading the response see the Ozone-shaped subset of
//! the audit log; the CLI (§F18) and `cairn audit verify` remain
//! the operator-tier views over the complete chain.
//!
//! # v1.7 supported filters
//!
//! - `subject` (DID for account-level; AT-URI for record-level)
//! - `types` (comma-separated Ozone $type strings)
//! - `createdBy` (moderator DID)
//! - `sortDirection` (`asc` / `desc`, default `desc`)
//! - `createdAfter` / `createdBefore` (RFC-3339)
//! - `limit` (capped at 100)
//! - `cursor` (opaque, base64url JSON of `{cursor_id: i64}`)
//! - `includeAllUserRecords` (when `true` and `subject` is a DID,
//!   includes record-level events for that DID's records)
//!
//! Other filters (`addedLabels`, `removedLabels`, `addedTags`,
//! `removedTags`, `comment`, `hasComment`, `reportTypes`) return
//! 400 `InvalidRequest` naming the field — same posture as #97.
//!
//! # Pagination
//!
//! Cursor: base64url(JSON `{cursor_id: i64}`) where cursor_id is
//! the `audit_log.id` of the last surfaced row. Simpler than #97's
//! tuple cursor since `audit_log.id` is monotonic AUTOINCREMENT —
//! a single i64 is sufficient.
//!
//! # SQL shape
//!
//! Single page query: `audit_log` filtered to Ozone-eligible
//! actions, LEFT JOINed to `subject_actions` via two paths
//! (`audit_log_id` for `subject_action_recorded`; the audit
//! row's `target` for `subject_action_revoked`, since the
//! revocation audit row stores the action_id in its `target`
//! column). Per #97's precedent, post-fetch projection in Rust;
//! filter-out happens in two places (SQL `WHERE` for action
//! eligibility, projection's `Option<ProjectedModEvent>` for
//! per-row eligibility — e.g., revoked-warning).

use axum::Extension;
use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::QueryBuilder;
use sqlx::{Pool, Sqlite};

use crate::xrpc_gateway::XrpcAuthClaims;

use super::XrpcGatewayState;
use super::projections::audit_event::{
    AuditEventRow, OZONE_ELIGIBLE_ACTIONS, ProjectedModEvent, project_audit_event,
};

const MAX_LIMIT: u32 = 100;
const DEFAULT_LIMIT: u32 = 50;

// ==========================================================================
// Wire types — input
// ==========================================================================

/// Query-param shape for `tools.ozone.moderation.queryEvents`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct QueryEventsParams {
    /// Filter to events about a specific subject (DID for
    /// account-level, AT-URI for record-level).
    #[serde(default)]
    pub subject: Option<String>,
    /// Filter to events of these Ozone $type strings.
    /// Comma-separated.
    #[serde(default)]
    pub types: Option<String>,
    /// Filter to events by this moderator DID.
    #[serde(default)]
    pub created_by: Option<String>,
    /// `asc` / `desc`. Default `desc`.
    #[serde(default)]
    pub sort_direction: Option<String>,
    /// RFC-3339 lower bound.
    #[serde(default)]
    pub created_after: Option<String>,
    /// RFC-3339 upper bound.
    #[serde(default)]
    pub created_before: Option<String>,
    /// **Not supported in v1.7** → 400.
    #[serde(default)]
    pub added_labels: Option<String>,
    /// **Not supported in v1.7** → 400.
    #[serde(default)]
    pub removed_labels: Option<String>,
    /// **Not supported in v1.7** → 400.
    #[serde(default)]
    pub added_tags: Option<String>,
    /// **Not supported in v1.7** → 400.
    #[serde(default)]
    pub removed_tags: Option<String>,
    /// **Not supported in v1.7** → 400.
    #[serde(default)]
    pub comment: Option<String>,
    /// **Not supported in v1.7** → 400.
    #[serde(default)]
    pub has_comment: Option<bool>,
    /// **Not supported in v1.7** → 400.
    #[serde(default)]
    pub report_types: Option<String>,
    /// Page size. v1.7 caps at 100.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Opaque pagination cursor.
    #[serde(default)]
    pub cursor: Option<String>,
    /// When `true` and `subject` is a DID, includes events about
    /// records owned by that DID (record-level subjects whose
    /// `subject_did` matches). When `false` (default) and
    /// `subject` is a DID, only account-level events match.
    #[serde(default)]
    pub include_all_user_records: Option<bool>,
}

// ==========================================================================
// Wire types — output
// ==========================================================================

/// Response body. Matches Ozone's `queryEvents` output: `events`
/// is an array of `modEventView`; `cursor` is opaque and present
/// iff there are more pages.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryEventsResponse {
    /// Opaque cursor for the next page. Absent on the final page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Projected `modEventView`s.
    pub events: Vec<ModEventView>,
}

/// Wire shape of one row in `events` per Ozone's
/// `tools.ozone.moderation.defs#modEventView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModEventView {
    /// `audit_log.id`.
    pub id: i64,
    /// Discriminated event body.
    pub event: Value,
    /// Discriminated subject ref.
    pub subject: Value,
    /// Empty in v1.7 (cairn-mod doesn't track blob CIDs).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject_blob_cids: Vec<String>,
    /// `audit_log.actor_did`.
    pub created_by: String,
    /// RFC-3339 Z. Converted from `audit_log.created_at` epoch-ms.
    pub created_at: String,
}

// ==========================================================================
// Cursor
// ==========================================================================

/// Opaque pagination cursor. Encoded as base64url(JSON
/// `{cursor_id: i64}`) on the wire. Simpler than #97's tuple
/// cursor since `audit_log.id` is monotonic AUTOINCREMENT — a
/// single i64 is sufficient for stable next-page filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cursor {
    cursor_id: i64,
}

impl Cursor {
    fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("cursor serializes");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    fn decode(s: &str) -> Result<Self, String> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| format!("malformed cursor (base64): {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("malformed cursor (json): {e}"))
    }
}

// ==========================================================================
// Handler
// ==========================================================================

/// Handler entry point. Wired into the gateway router for
/// `GET /xrpc/tools.ozone.moderation.queryEvents`.
pub(crate) async fn handler(
    Extension(state): Extension<XrpcGatewayState>,
    Extension(_claims): Extension<XrpcAuthClaims>,
    Query(params): Query<QueryEventsParams>,
) -> Response {
    let parsed = match parse_params(params) {
        Ok(p) => p,
        Err(msg) => return invalid_request(msg),
    };

    let rows = match fetch_page(&state.pool, &parsed).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "xrpc_gateway queryEvents: page query failed");
            return internal_server_error();
        }
    };

    let has_more = rows.len() > parsed.limit as usize;
    let surfaced_rows: Vec<&AuditEventRow> = rows.iter().take(parsed.limit as usize).collect();

    let mut events = Vec::with_capacity(surfaced_rows.len());
    let mut last_audit_id_in_page: Option<i64> = None;
    for row in &surfaced_rows {
        last_audit_id_in_page = Some(row.audit_id);
        let Some(projected) = project_audit_event(row) else {
            continue;
        };
        // Apply types filter post-projection (the filter operates
        // on Ozone $type strings, which the projection produces).
        if let Some(types_filter) = &parsed.types
            && !types_filter
                .iter()
                .any(|t| projected.event["$type"].as_str() == Some(t.as_str()))
        {
            continue;
        }
        events.push(serialize_view(projected));
    }

    let cursor = if has_more {
        last_audit_id_in_page.map(|id| Cursor { cursor_id: id }.encode())
    } else {
        None
    };

    Json(QueryEventsResponse { cursor, events }).into_response()
}

// ==========================================================================
// Param parsing
// ==========================================================================

#[derive(Debug)]
struct ParsedParams {
    subject_did: Option<String>,
    subject_uri: Option<String>,
    include_all_user_records: bool,
    types: Option<Vec<String>>,
    created_by: Option<String>,
    descending: bool,
    created_after_ms: Option<i64>,
    created_before_ms: Option<i64>,
    limit: u32,
    cursor: Option<Cursor>,
}

fn parse_params(p: QueryEventsParams) -> Result<ParsedParams, String> {
    if p.added_labels.is_some() {
        return Err("filter 'addedLabels' is not supported in v1.7".to_string());
    }
    if p.removed_labels.is_some() {
        return Err("filter 'removedLabels' is not supported in v1.7".to_string());
    }
    if p.added_tags.is_some() {
        return Err("filter 'addedTags' is not supported in v1.7".to_string());
    }
    if p.removed_tags.is_some() {
        return Err("filter 'removedTags' is not supported in v1.7".to_string());
    }
    if p.comment.is_some() {
        return Err("filter 'comment' is not supported in v1.7".to_string());
    }
    if p.has_comment.is_some() {
        return Err("filter 'hasComment' is not supported in v1.7".to_string());
    }
    if p.report_types.is_some() {
        return Err("filter 'reportTypes' is not supported in v1.7".to_string());
    }

    let descending = match p.sort_direction.as_deref() {
        None | Some("desc") => true,
        Some("asc") => false,
        Some(other) => {
            return Err(format!(
                "sortDirection '{other}' is invalid; expected 'asc' or 'desc'"
            ));
        }
    };

    let limit = match p.limit {
        None => DEFAULT_LIMIT,
        Some(0) => return Err("limit must be at least 1".to_string()),
        Some(n) if n > MAX_LIMIT => {
            return Err(format!("limit {n} exceeds maximum {MAX_LIMIT}"));
        }
        Some(n) => n,
    };

    let cursor = match p.cursor.as_deref() {
        Some(s) => Some(Cursor::decode(s)?),
        None => None,
    };

    let (subject_did, subject_uri) = match p.subject.as_deref() {
        None => (None, None),
        Some(s) if s.starts_with("at://") => {
            let did = s
                .strip_prefix("at://")
                .and_then(|rest| rest.split('/').next())
                .filter(|d| d.starts_with("did:"))
                .ok_or_else(|| format!("subject AT-URI {s:?} missing DID authority"))?
                .to_string();
            (Some(did), Some(s.to_string()))
        }
        Some(s) if s.starts_with("did:") => (Some(s.to_string()), None),
        Some(s) => return Err(format!("subject {s:?} is neither a DID nor an AT-URI")),
    };

    let types = p.types.as_deref().and_then(|s| {
        let v: Vec<String> = s
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();
        if v.is_empty() { None } else { Some(v) }
    });

    let created_after_ms = match p.created_after.as_deref() {
        None => None,
        Some(s) => Some(parse_rfc3339_to_ms(s)?),
    };
    let created_before_ms = match p.created_before.as_deref() {
        None => None,
        Some(s) => Some(parse_rfc3339_to_ms(s)?),
    };

    Ok(ParsedParams {
        subject_did,
        subject_uri,
        include_all_user_records: p.include_all_user_records.unwrap_or(false),
        types,
        created_by: p.created_by,
        descending,
        created_after_ms,
        created_before_ms,
        limit,
        cursor,
    })
}

fn parse_rfc3339_to_ms(s: &str) -> Result<i64, String> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    let dt = OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|_| format!("malformed RFC-3339 timestamp: {s:?}"))?;
    let unix_ms = dt.unix_timestamp_nanos() / 1_000_000;
    Ok(unix_ms as i64)
}

// ==========================================================================
// Page query
// ==========================================================================

/// Single page query. Filters at SQL: Ozone-eligible audit
/// actions, optional subject / createdBy / date / cursor. LEFT
/// JOIN handles both audit-action shapes (recorded uses
/// audit_log_id FK; revoked uses CAST(target AS INTEGER) since
/// the revocation row's target is the revoked action_id as a
/// string).
async fn fetch_page(
    pool: &Pool<Sqlite>,
    parsed: &ParsedParams,
) -> sqlx::Result<Vec<AuditEventRow>> {
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        r#"SELECT
             a.id           AS audit_id,
             a.action       AS audit_action,
             a.actor_did    AS actor_did,
             a.created_at   AS created_at,
             sa.action_type AS subject_action_type,
             sa.subject_did AS subject_did,
             sa.subject_uri AS subject_uri,
             sa.notes       AS subject_notes,
             sa.duration    AS subject_duration,
             sa.reason_codes AS subject_reason_codes,
             a.reason       AS audit_reason
           FROM audit_log a
           LEFT JOIN subject_actions sa ON
             (a.action = 'subject_action_recorded' AND sa.audit_log_id = a.id)
             OR (a.action = 'subject_action_revoked' AND sa.id = CAST(a.target AS INTEGER))
           WHERE a.action IN ("#,
    );
    let mut sep = qb.separated(", ");
    for action in OZONE_ELIGIBLE_ACTIONS {
        sep.push_bind(*action);
    }
    qb.push(")");

    if let Some(did) = &parsed.subject_did {
        qb.push(" AND sa.subject_did = ").push_bind(did.clone());
        // Account-level subject + includeAllUserRecords=false →
        // exact match (subject_uri IS NULL).
        if parsed.subject_uri.is_none() && !parsed.include_all_user_records {
            qb.push(" AND sa.subject_uri IS NULL");
        }
    }
    if let Some(uri) = &parsed.subject_uri {
        qb.push(" AND sa.subject_uri = ").push_bind(uri.clone());
    }
    if let Some(actor) = &parsed.created_by {
        qb.push(" AND a.actor_did = ").push_bind(actor.clone());
    }
    if let Some(after_ms) = parsed.created_after_ms {
        qb.push(" AND a.created_at >= ").push_bind(after_ms);
    }
    if let Some(before_ms) = parsed.created_before_ms {
        qb.push(" AND a.created_at <= ").push_bind(before_ms);
    }
    if let Some(c) = &parsed.cursor {
        let comparator = if parsed.descending { "<" } else { ">" };
        qb.push(format!(" AND a.id {comparator} "))
            .push_bind(c.cursor_id);
    }

    let order = if parsed.descending { "DESC" } else { "ASC" };
    qb.push(format!(" ORDER BY a.id {order} LIMIT "))
        .push_bind((parsed.limit + 1) as i64);

    let rows = qb
        .build_query_as::<(
            i64,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )>()
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                audit_id,
                audit_action,
                actor_did,
                created_at,
                subject_action_type,
                subject_did,
                subject_uri,
                subject_notes,
                subject_duration,
                subject_reason_codes,
                audit_reason,
            )| AuditEventRow {
                audit_id,
                audit_action,
                actor_did,
                created_at,
                subject_action_type,
                subject_did,
                subject_uri,
                subject_notes,
                subject_duration,
                subject_reason_codes_json: subject_reason_codes,
                audit_reason_json: audit_reason,
            },
        )
        .collect())
}

// ==========================================================================
// Output serialization
// ==========================================================================

fn serialize_view(p: ProjectedModEvent) -> ModEventView {
    ModEventView {
        id: p.id,
        event: p.event,
        subject: p.subject,
        subject_blob_cids: Vec::new(),
        created_by: p.created_by,
        created_at: epoch_ms_to_rfc3339(p.created_at),
    }
}

fn epoch_ms_to_rfc3339(ms: i64) -> String {
    crate::writer::rfc3339_from_epoch_ms(ms)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00.000Z"))
}

// ==========================================================================
// Error helpers
// ==========================================================================

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

    fn empty_params() -> QueryEventsParams {
        QueryEventsParams::default()
    }

    // ===== Filter rejection =====

    #[test]
    fn unsupported_added_labels_filter_rejected() {
        let p = QueryEventsParams {
            added_labels: Some("spam".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("addedLabels"), "{err}");
    }

    #[test]
    fn unsupported_comment_filter_rejected() {
        let p = QueryEventsParams {
            comment: Some("foo".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("comment"), "{err}");
    }

    #[test]
    fn unsupported_has_comment_filter_rejected() {
        let p = QueryEventsParams {
            has_comment: Some(true),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("hasComment"), "{err}");
    }

    #[test]
    fn unsupported_report_types_filter_rejected() {
        let p = QueryEventsParams {
            report_types: Some("spam".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("reportTypes"), "{err}");
    }

    #[test]
    fn invalid_sort_direction_rejected() {
        let p = QueryEventsParams {
            sort_direction: Some("upside-down".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("sortDirection"), "{err}");
    }

    // ===== Limit =====

    #[test]
    fn default_limit_is_50() {
        let p = parse_params(empty_params()).unwrap();
        assert_eq!(p.limit, 50);
    }

    #[test]
    fn limit_capped_at_100() {
        let p = QueryEventsParams {
            limit: Some(101),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("100"), "{err}");
    }

    #[test]
    fn limit_zero_rejected() {
        let p = QueryEventsParams {
            limit: Some(0),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("at least 1"), "{err}");
    }

    // ===== Subject parsing =====

    #[test]
    fn account_level_subject_parses_to_did_only() {
        let p = QueryEventsParams {
            subject: Some("did:plc:abc".into()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert_eq!(parsed.subject_did.as_deref(), Some("did:plc:abc"));
        assert!(parsed.subject_uri.is_none());
    }

    #[test]
    fn record_level_subject_parses_to_did_plus_uri() {
        let p = QueryEventsParams {
            subject: Some("at://did:plc:author/c/r".into()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert_eq!(parsed.subject_did.as_deref(), Some("did:plc:author"));
        assert_eq!(
            parsed.subject_uri.as_deref(),
            Some("at://did:plc:author/c/r")
        );
    }

    #[test]
    fn malformed_subject_rejected() {
        let p = QueryEventsParams {
            subject: Some("not-a-did-or-uri".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("DID"), "{err}");
    }

    // ===== Types parsing =====

    #[test]
    fn types_split_on_comma() {
        let p = QueryEventsParams {
            types: Some(
                "tools.ozone.moderation.defs#modEventLabel,tools.ozone.moderation.defs#modEventTakedown".into(),
            ),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        let v = parsed.types.unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.iter().any(|t| t.ends_with("modEventLabel")));
        assert!(v.iter().any(|t| t.ends_with("modEventTakedown")));
    }

    #[test]
    fn empty_types_yields_none() {
        let p = QueryEventsParams {
            types: Some("".into()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert!(parsed.types.is_none());
    }

    // ===== Date filter =====

    #[test]
    fn rfc3339_lower_bound_parses() {
        let p = QueryEventsParams {
            created_after: Some("2026-01-01T00:00:00Z".into()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        // Just verify it parsed to some i64 (epoch-ms). 2026-01-01
        // is well after epoch.
        assert!(parsed.created_after_ms.unwrap() > 1_700_000_000_000);
    }

    #[test]
    fn malformed_date_rejected() {
        let p = QueryEventsParams {
            created_after: Some("not-rfc-3339".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("RFC-3339"), "{err}");
    }

    // ===== include_all_user_records =====

    #[test]
    fn include_all_user_records_defaults_to_false() {
        let p = parse_params(empty_params()).unwrap();
        assert!(!p.include_all_user_records);
    }

    #[test]
    fn include_all_user_records_true_passes_through() {
        let p = QueryEventsParams {
            include_all_user_records: Some(true),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert!(parsed.include_all_user_records);
    }

    // ===== Cursor =====

    #[test]
    fn cursor_round_trip() {
        let c = Cursor { cursor_id: 42 };
        let encoded = c.encode();
        let decoded = Cursor::decode(&encoded).unwrap();
        assert_eq!(decoded.cursor_id, 42);
    }

    #[test]
    fn malformed_cursor_rejected() {
        assert!(Cursor::decode("not-base64-!!!").is_err());
    }

    #[test]
    fn cursor_with_invalid_json_rejected() {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-json");
        assert!(Cursor::decode(&bytes).is_err());
    }
}
