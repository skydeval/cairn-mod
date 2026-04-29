//! `tools.ozone.moderation.queryStatuses` handler body (#97, v1.7).
//!
//! Phase D's third handler. First read-only NSID. Returns a
//! paginated list of `subjectStatusView`s projected from
//! cairn-mod's `subject_actions` history (plus `labels` for tags
//! and `reports` for `lastReportedAt`).
//!
//! The translation logic — folding action history into the
//! current-state view — lives in
//! [`crate::xrpc_gateway::handlers::projections::subject_status`];
//! this module is the IO + filter + pagination layer.
//!
//! # v1.7 supported filters
//!
//! Per the prompt, the v1.7 surface implements the subset that
//! maps cleanly to cairn-mod's data:
//!
//! - `subject` (DID for account-level, AT-URI for record-level)
//! - `limit` (capped at 100)
//! - `cursor` (opaque, base64url-encoded JSON; see the `Cursor`
//!   struct in this module)
//! - `sortDirection` (`asc` / `desc`)
//! - `takendown` (filter to currently-takendown or not)
//! - `tags` (subjects with at least one matching active label)
//! - `appealed` (cairn-mod has no appeal flow → `appealed=true`
//!   always returns empty; `appealed=false` is a no-op)
//!
//! Other filters (`comment`, `reportedAfter`, `reportedBefore`,
//! `reviewState`, `ignoreSubjects`, `lastReviewedBy`) return 400
//! `InvalidRequest` rather than silently ignoring — silent ignore
//! is a footgun. Operators get a precise error naming which
//! filter is unsupported.
//!
//! # Pagination
//!
//! Cursor format: base64url(JSON `{updated_at_ms, subject_did,
//! subject_uri}`). Lex-comparable with the page query's
//! `(MAX(created_at), subject_did, COALESCE(subject_uri, ''))`
//! sort key. Stable across data churn — a concurrent INSERT that
//! changes the absolute order doesn't invalidate an in-flight
//! cursor; the worst case is duplicate rows surfaced across pages
//! (acceptable for v1.7).
//!
//! # Why N+1 per page is acceptable
//!
//! For each subject in the page, two follow-up queries run:
//!
//! 1. The active-labels lookup (per-subject — same shape as
//!    `crate::server::strike_state::load_active_labels`).
//! 2. The last-reported lookup (`MAX(reports.created_at)` for the
//!    subject).
//!
//! With `limit ≤ 100`, that's ~200 small queries per request —
//! within v1.7's expected scale. Bulk-fetching across the page is
//! a v1.8 optimization if profiling shows it's needed.

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
use super::projections::subject_status::{
    ProjectedSubjectStatus, SubjectActionRow, project_subject_status,
};

/// Maximum `limit` cairn-mod accepts on a single page. Matches
/// Ozone's documented per-page ceiling.
const MAX_LIMIT: u32 = 100;

/// Default `limit` when the caller doesn't supply one.
const DEFAULT_LIMIT: u32 = 50;

// ==========================================================================
// Wire types — input
// ==========================================================================

/// Query-param shape for `tools.ozone.moderation.queryStatuses`.
///
/// Field-by-field v1.7 disposition is documented on each field;
/// callers passing unsupported fields get 400 `InvalidRequest`
/// naming the field. Silent ignore is a footgun (operators expect
/// filters to filter); explicit rejection is the preferred
/// posture.
///
/// Axum's `Query<...>` extractor uses `serde_urlencoded`. Array
/// fields (`tags`, `ignoreSubjects`) are passed as
/// repeated query keys — `?tags=spam&tags=harassment` — and use
/// the `serde(default)` + custom helper to flatten.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct QueryStatusesParams {
    /// Filter to a single subject (DID for account-level, AT-URI
    /// for record-level). Supported in v1.7.
    #[serde(default)]
    pub subject: Option<String>,
    /// Substring search on comment. **Not supported in v1.7** →
    /// 400.
    #[serde(default)]
    pub comment: Option<String>,
    /// Date filter. **Not supported in v1.7** → 400.
    #[serde(default)]
    pub reported_after: Option<String>,
    /// Date filter. **Not supported in v1.7** → 400.
    #[serde(default)]
    pub reported_before: Option<String>,
    /// Filter by review state. **Not supported in v1.7** → 400
    /// (cairn-mod has only `#reviewClosed`).
    #[serde(default)]
    pub review_state: Option<String>,
    /// Excluded subjects. **Not supported in v1.7** → 400.
    #[serde(default)]
    pub ignore_subjects: Option<String>,
    /// Filter by reviewer DID. **Not supported in v1.7** → 400.
    #[serde(default)]
    pub last_reviewed_by: Option<String>,
    /// Sort key. v1.7 only accepts `lastReviewedAt` — anything
    /// else is 400.
    #[serde(default)]
    pub sort_field: Option<String>,
    /// `asc` / `desc`. Default `desc`. Other values → 400.
    #[serde(default)]
    pub sort_direction: Option<String>,
    /// Filter to currently-takendown subjects. Supported in v1.7.
    #[serde(default)]
    pub takendown: Option<bool>,
    /// Filter to appealed subjects. cairn-mod has no appeal flow;
    /// `true` returns empty, `false` is a no-op (the default
    /// state). Supported (degenerately) in v1.7.
    #[serde(default)]
    pub appealed: Option<bool>,
    /// Page size. v1.7 caps at 100 (the constant `MAX_LIMIT` in
    /// this module).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Opaque pagination cursor — base64url-encoded JSON of
    /// `(updated_at_ms, subject_did, subject_uri)`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Filter to subjects with at least one of these labels
    /// active. Comma-separated string in v1.7 (axum's
    /// `Query`+`serde_urlencoded` doesn't natively support repeated
    /// array params — operators pass `?tags=spam,harassment`).
    #[serde(default)]
    pub tags: Option<String>,
}

// ==========================================================================
// Wire types — output
// ==========================================================================

/// Response body. Matches Ozone's `queryStatuses` output:
/// `subjectStatuses` is an array of `subjectStatusView`; `cursor`
/// is opaque and present iff there are more pages.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryStatusesResponse {
    /// Opaque pagination cursor for the next page. Absent on the
    /// final page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Projected per-subject status views — see
    /// [`SubjectStatusView`].
    pub subject_statuses: Vec<SubjectStatusView>,
}

/// Wire shape of one row in `subjectStatuses` per Ozone's
/// `tools.ozone.moderation.defs#subjectStatusView`.
///
/// Field-by-field projection rationale lives in
/// [`crate::xrpc_gateway::handlers::projections::subject_status`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectStatusView {
    /// Stable per-subject identifier within this deployment. Maps
    /// to the most-recent `subject_actions.id` for the subject.
    pub id: i64,
    /// Discriminated subject (`repoRef` or `strongRef`).
    pub subject: Value,
    /// Empty in v1.7 (cairn-mod doesn't track blob CIDs).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject_blob_cids: Vec<String>,
    /// RFC-3339 Z. Most-recent action's `created_at`.
    pub updated_at: String,
    /// RFC-3339 Z. Earliest action's `created_at`.
    pub created_at: String,
    /// Always `tools.ozone.moderation.defs#reviewClosed` in v1.7.
    pub review_state: String,
    /// Most-recent action's `notes`. Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Most-recent action's `actor_did`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reviewed_by: Option<String>,
    /// Most-recent action's `created_at` (RFC-3339 Z).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reviewed_at: Option<String>,
    /// `MAX(reports.created_at)` for this subject. Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reported_at: Option<String>,
    /// Currently-takendown flag.
    pub takendown: bool,
    /// Always `false` in v1.7.
    pub appealed: bool,
    /// Active label vals for the subject.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

// ==========================================================================
// Cursor
// ==========================================================================

/// Opaque pagination cursor. Encoded as base64url(JSON) on the
/// wire. The fields mirror the page query's sort key:
///
/// - `updated_at_ms` — the page row's `MAX(created_at)`
/// - `subject_did` — the page row's subject_did
/// - `subject_uri` — the page row's subject_uri (empty string for
///   account-level)
///
/// Stability: the next page is "rows where (updated_at,
/// subject_did, subject_uri) is strictly greater/less than the
/// cursor tuple, depending on sort direction". A concurrent INSERT
/// that creates a row with the same updated_at_ms but a smaller
/// subject_did would be skipped on the next page (acceptable for
/// v1.7's scale and consistency model — clients re-sync at their
/// own cadence).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cursor {
    updated_at_ms: i64,
    subject_did: String,
    subject_uri: String,
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

/// Handler entry point. Wired into the gateway router by
/// [`crate::xrpc_gateway::router::build_router`] for
/// `GET /xrpc/tools.ozone.moderation.queryStatuses`.
///
/// Pipeline:
/// 1. Reject unsupported filters with 400 `InvalidRequest`.
/// 2. Parse `cursor` (if present) + `tags` (split on `,`) + sort
///    direction.
/// 3. Build the page query with optional WHERE clauses for the
///    supported filters.
/// 4. For each row in the page, do per-subject lookups for tags +
///    last_reported_at.
/// 5. Project each into [`SubjectStatusView`] and return with a
///    next-page cursor if `LIMIT+1` rows came back.
pub(crate) async fn handler(
    Extension(state): Extension<XrpcGatewayState>,
    Extension(_claims): Extension<XrpcAuthClaims>,
    Query(params): Query<QueryStatusesParams>,
) -> Response {
    let parsed = match parse_params(params) {
        Ok(p) => p,
        Err(msg) => return invalid_request(msg),
    };

    // Appealed=true always returns empty (cairn-mod has no appeal
    // flow; no subject is ever appealed). Short-circuit before
    // any DB IO.
    if parsed.appealed == Some(true) {
        return Json(QueryStatusesResponse {
            cursor: None,
            subject_statuses: Vec::new(),
        })
        .into_response();
    }

    let page = match fetch_page(&state.pool, &parsed).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "xrpc_gateway queryStatuses: page query failed");
            return internal_server_error();
        }
    };

    let mut views = Vec::with_capacity(page.rows.len());
    for row in &page.rows {
        let actions = match fetch_actions_for_subject(
            &state.pool,
            &row.subject_did,
            row.subject_uri.as_deref(),
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    subject = row.subject_did,
                    "xrpc_gateway queryStatuses: per-subject actions query failed"
                );
                return internal_server_error();
            }
        };
        let tags = match load_active_label_vals(
            &state.pool,
            &row.subject_did,
            row.subject_uri.as_deref(),
            &state.service_did,
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = %e, "xrpc_gateway queryStatuses: tags query failed");
                return internal_server_error();
            }
        };
        let last_reported_at =
            match load_last_reported_at(&state.pool, &row.subject_did, row.subject_uri.as_deref())
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "xrpc_gateway queryStatuses: last_reported_at query failed"
                    );
                    return internal_server_error();
                }
            };

        // Apply tags filter post-fetch — the SQL page query
        // returned the row, but the operator may want to narrow
        // by tag. Cheaper than a HAVING-EXISTS in the page query;
        // documented as "may return fewer than `limit` per page".
        if let Some(tag_filter) = &parsed.tags
            && !tag_filter.is_empty()
            && !tags.iter().any(|t| tag_filter.iter().any(|f| f == t))
        {
            continue;
        }

        let projected = project_subject_status(
            &row.subject_did,
            row.subject_uri.as_deref(),
            &actions,
            tags,
            last_reported_at,
        );
        views.push(serialize_view(projected));
    }

    let cursor = if page.has_more {
        page.rows.last().map(|r| {
            Cursor {
                updated_at_ms: r.latest_created_at,
                subject_did: r.subject_did.clone(),
                subject_uri: r.subject_uri.clone().unwrap_or_default(),
            }
            .encode()
        })
    } else {
        None
    };

    Json(QueryStatusesResponse {
        cursor,
        subject_statuses: views,
    })
    .into_response()
}

// ==========================================================================
// Param parsing
// ==========================================================================

#[derive(Debug)]
struct ParsedParams {
    subject_did: Option<String>,
    subject_uri: Option<String>,
    limit: u32,
    cursor: Option<Cursor>,
    descending: bool,
    takendown: Option<bool>,
    appealed: Option<bool>,
    tags: Option<Vec<String>>,
}

fn parse_params(p: QueryStatusesParams) -> Result<ParsedParams, String> {
    // Reject unsupported filters explicitly.
    if p.comment.is_some() {
        return Err("filter 'comment' is not supported in v1.7".to_string());
    }
    if p.reported_after.is_some() {
        return Err("filter 'reportedAfter' is not supported in v1.7".to_string());
    }
    if p.reported_before.is_some() {
        return Err("filter 'reportedBefore' is not supported in v1.7".to_string());
    }
    if p.review_state.is_some() {
        return Err("filter 'reviewState' is not supported in v1.7".to_string());
    }
    if p.ignore_subjects.is_some() {
        return Err("filter 'ignoreSubjects' is not supported in v1.7".to_string());
    }
    if p.last_reviewed_by.is_some() {
        return Err("filter 'lastReviewedBy' is not supported in v1.7".to_string());
    }

    // sortField: only lastReviewedAt is supported.
    if let Some(sf) = &p.sort_field
        && sf != "lastReviewedAt"
    {
        return Err(format!(
            "sortField '{sf}' is not supported in v1.7; only 'lastReviewedAt' is accepted"
        ));
    }

    // sortDirection: asc/desc, default desc.
    let descending = match p.sort_direction.as_deref() {
        None | Some("desc") => true,
        Some("asc") => false,
        Some(other) => {
            return Err(format!(
                "sortDirection '{other}' is invalid; expected 'asc' or 'desc'"
            ));
        }
    };

    // limit: default 50, max 100, min 1.
    let limit = match p.limit {
        None => DEFAULT_LIMIT,
        Some(0) => return Err("limit must be at least 1".to_string()),
        Some(n) if n > MAX_LIMIT => {
            return Err(format!("limit {n} exceeds maximum {MAX_LIMIT}"));
        }
        Some(n) => n,
    };

    // cursor.
    let cursor = match p.cursor.as_deref() {
        Some(s) => Some(Cursor::decode(s)?),
        None => None,
    };

    // subject: DID → account-level filter (subject_uri IS NULL);
    // AT-URI → record-level filter (subject_uri = uri).
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

    // tags: comma-separated → Vec<String>. Empty after split → None.
    let tags = match p.tags.as_deref() {
        None => None,
        Some(s) => {
            let v: Vec<String> = s
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            if v.is_empty() { None } else { Some(v) }
        }
    };

    Ok(ParsedParams {
        subject_did,
        subject_uri,
        limit,
        cursor,
        descending,
        takendown: p.takendown,
        appealed: p.appealed,
        tags,
    })
}

// ==========================================================================
// Page query
// ==========================================================================

#[derive(Debug)]
struct PageRow {
    subject_did: String,
    subject_uri: Option<String>,
    /// `MAX(created_at)` for the (subject_did, subject_uri) group.
    /// Used for cursor encoding only — the projection re-fetches
    /// the full per-subject action history so it can compute
    /// `earliest_action` itself.
    latest_created_at: i64,
}

#[derive(Debug)]
struct Page {
    rows: Vec<PageRow>,
    has_more: bool,
}

/// Page query: distinct (subject_did, subject_uri) groups from
/// `subject_actions`, with min/max created_at aggregates. Ordered
/// by `latest_created_at` (ASC or DESC per
/// `parsed.descending`). Filters: optional `subject` /
/// `takendown` / `cursor`. Tags filter is applied post-fetch in
/// the handler (one-time correlation against the per-subject
/// active-labels lookup).
async fn fetch_page(pool: &Pool<Sqlite>, parsed: &ParsedParams) -> sqlx::Result<Page> {
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        r#"SELECT
             subject_did,
             subject_uri,
             MAX(created_at) AS latest_created_at
           FROM subject_actions
           WHERE 1=1"#,
    );

    if let Some(did) = &parsed.subject_did {
        qb.push(" AND subject_did = ").push_bind(did.clone());
    }
    match parsed.subject_uri.as_deref() {
        Some(uri) => {
            qb.push(" AND subject_uri = ").push_bind(uri.to_string());
        }
        None if parsed.subject_did.is_some() => {
            // Account-level filter: parent did matches and
            // subject_uri IS NULL.
            qb.push(" AND subject_uri IS NULL");
        }
        None => {}
    }

    qb.push(
        r#"
           GROUP BY subject_did, subject_uri
           HAVING 1=1"#,
    );

    if let Some(td) = parsed.takendown {
        if td {
            qb.push(
                r#" AND EXISTS (
                       SELECT 1 FROM subject_actions sa2
                       WHERE sa2.subject_did = subject_actions.subject_did
                         AND (sa2.subject_uri IS subject_actions.subject_uri
                              OR (sa2.subject_uri IS NULL AND subject_actions.subject_uri IS NULL))
                         AND sa2.action_type = 'takedown'
                         AND sa2.revoked_at IS NULL
                   )"#,
            );
        } else {
            qb.push(
                r#" AND NOT EXISTS (
                       SELECT 1 FROM subject_actions sa2
                       WHERE sa2.subject_did = subject_actions.subject_did
                         AND (sa2.subject_uri IS subject_actions.subject_uri
                              OR (sa2.subject_uri IS NULL AND subject_actions.subject_uri IS NULL))
                         AND sa2.action_type = 'takedown'
                         AND sa2.revoked_at IS NULL
                   )"#,
            );
        }
    }

    if let Some(c) = &parsed.cursor {
        let comparator = if parsed.descending { "<" } else { ">" };
        // Tuple compare: (latest, did, uri-or-empty) vs (cursor's
        // values). Coalesce subject_uri to '' for stable
        // lex-comparison with the cursor's empty-string sentinel.
        qb.push(format!(
            " AND (MAX(created_at), subject_did, COALESCE(subject_uri, '')) {comparator} ("
        ));
        qb.push_bind(c.updated_at_ms);
        qb.push(", ");
        qb.push_bind(c.subject_did.clone());
        qb.push(", ");
        qb.push_bind(c.subject_uri.clone());
        qb.push(")");
    }

    let order = if parsed.descending { "DESC" } else { "ASC" };
    qb.push(format!(
        " ORDER BY latest_created_at {order}, subject_did {order}, subject_uri {order}"
    ));

    // Fetch limit+1 to detect "has more".
    qb.push(" LIMIT ").push_bind((parsed.limit + 1) as i64);

    let mut rows: Vec<PageRow> = qb
        .build_query_as::<(String, Option<String>, i64)>()
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(subject_did, subject_uri, latest_created_at)| PageRow {
            subject_did,
            subject_uri,
            latest_created_at,
        })
        .collect();

    let has_more = rows.len() > parsed.limit as usize;
    if has_more {
        rows.truncate(parsed.limit as usize);
    }
    Ok(Page { rows, has_more })
}

// ==========================================================================
// Per-subject lookups
// ==========================================================================

async fn fetch_actions_for_subject(
    pool: &Pool<Sqlite>,
    subject_did: &str,
    subject_uri: Option<&str>,
) -> sqlx::Result<Vec<SubjectActionRow>> {
    // Fetch all rows for the (subject_did, subject_uri) tuple so
    // the projection has the full history. The page is small
    // (limit ≤ 100) and per-subject histories are typically
    // short; not worth optimizing.
    let rows = match subject_uri {
        Some(uri) => sqlx::query!(
            r#"SELECT
                     id              AS "id!: i64",
                     action_type     AS "action_type!: String",
                     actor_did       AS "actor_did!: String",
                     notes,
                     revoked_at,
                     created_at      AS "created_at!: i64"
                   FROM subject_actions
                   WHERE subject_did = ?1 AND subject_uri = ?2
                   ORDER BY id ASC"#,
            subject_did,
            uri,
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| SubjectActionRow {
            id: r.id,
            action_type: r.action_type,
            actor_did: r.actor_did,
            notes: r.notes,
            revoked_at: r.revoked_at,
            created_at: r.created_at,
        })
        .collect(),
        None => sqlx::query!(
            r#"SELECT
                     id              AS "id!: i64",
                     action_type     AS "action_type!: String",
                     actor_did       AS "actor_did!: String",
                     notes,
                     revoked_at,
                     created_at      AS "created_at!: i64"
                   FROM subject_actions
                   WHERE subject_did = ?1 AND subject_uri IS NULL
                   ORDER BY id ASC"#,
            subject_did,
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| SubjectActionRow {
            id: r.id,
            action_type: r.action_type,
            actor_did: r.actor_did,
            notes: r.notes,
            revoked_at: r.revoked_at,
            created_at: r.created_at,
        })
        .collect(),
    };
    Ok(rows)
}

/// Distinct active label vals for the subject. Mirrors the
/// active-label semantic from
/// `crate::server::strike_state::load_active_labels`: for each
/// `(src, uri, val)` tuple, the most-recent row by `seq`
/// determines active vs negated.
async fn load_active_label_vals(
    pool: &Pool<Sqlite>,
    subject_did: &str,
    subject_uri: Option<&str>,
    service_did: &str,
) -> sqlx::Result<Vec<String>> {
    // labels.uri is the subject's at:// URI for record-level
    // labels and the bare DID for account-level.
    let label_uri = subject_uri.unwrap_or(subject_did);
    let rows = sqlx::query!(
        r#"SELECT DISTINCT l1.val AS "val!: String"
           FROM labels l1
           WHERE l1.src = ?1 AND l1.uri = ?2
             AND l1.seq = (
                 SELECT MAX(l2.seq) FROM labels l2
                 WHERE l2.src = l1.src AND l2.uri = l1.uri AND l2.val = l1.val
             )
             AND l1.neg = 0
           ORDER BY l1.val ASC"#,
        service_did,
        label_uri,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.val).collect())
}

async fn load_last_reported_at(
    pool: &Pool<Sqlite>,
    subject_did: &str,
    subject_uri: Option<&str>,
) -> sqlx::Result<Option<String>> {
    // reports.created_at is RFC-3339 TEXT (per migration 0001).
    // Match account-level reports to account-level subjects
    // (subject_uri IS NULL on both sides) and record-level to
    // record-level (subject_uri = uri).
    let row = match subject_uri {
        Some(uri) => sqlx::query!(
            r#"SELECT MAX(created_at) AS "last_reported_at: String"
                   FROM reports
                   WHERE subject_did = ?1 AND subject_uri = ?2"#,
            subject_did,
            uri,
        )
        .fetch_optional(pool)
        .await?
        .and_then(|r| r.last_reported_at),
        None => sqlx::query!(
            r#"SELECT MAX(created_at) AS "last_reported_at: String"
                   FROM reports
                   WHERE subject_did = ?1 AND subject_uri IS NULL"#,
            subject_did,
        )
        .fetch_optional(pool)
        .await?
        .and_then(|r| r.last_reported_at),
    };
    Ok(row)
}

// ==========================================================================
// Output serialization
// ==========================================================================

fn serialize_view(p: ProjectedSubjectStatus) -> SubjectStatusView {
    SubjectStatusView {
        id: p.id,
        subject: p.subject,
        subject_blob_cids: Vec::new(),
        updated_at: epoch_ms_to_rfc3339(p.updated_at),
        created_at: epoch_ms_to_rfc3339(p.created_at),
        review_state: p.review_state,
        comment: p.comment,
        last_reviewed_by: p.last_reviewed_by,
        last_reviewed_at: p.last_reviewed_at.map(epoch_ms_to_rfc3339),
        last_reported_at: p.last_reported_at,
        takendown: p.takendown,
        appealed: p.appealed,
        tags: p.tags,
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

    fn empty_params() -> QueryStatusesParams {
        QueryStatusesParams::default()
    }

    // ===== Filter rejection =====

    #[test]
    fn unsupported_comment_filter_rejected() {
        let p = QueryStatusesParams {
            comment: Some("foo".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("comment"), "{err}");
    }

    #[test]
    fn unsupported_reported_after_filter_rejected() {
        let p = QueryStatusesParams {
            reported_after: Some("2026-01-01".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("reportedAfter"), "{err}");
    }

    #[test]
    fn unsupported_review_state_filter_rejected() {
        let p = QueryStatusesParams {
            review_state: Some("open".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("reviewState"), "{err}");
    }

    #[test]
    fn invalid_sort_field_rejected() {
        let p = QueryStatusesParams {
            sort_field: Some("createdAt".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("sortField"), "{err}");
    }

    #[test]
    fn invalid_sort_direction_rejected() {
        let p = QueryStatusesParams {
            sort_direction: Some("sideways".into()),
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
        let p = QueryStatusesParams {
            limit: Some(200),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("100"), "{err}");
    }

    #[test]
    fn limit_zero_rejected() {
        let p = QueryStatusesParams {
            limit: Some(0),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("at least 1"), "{err}");
    }

    // ===== Subject parsing =====

    #[test]
    fn account_level_subject_parses_to_did_only() {
        let p = QueryStatusesParams {
            subject: Some("did:plc:abc".into()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert_eq!(parsed.subject_did.as_deref(), Some("did:plc:abc"));
        assert!(parsed.subject_uri.is_none());
    }

    #[test]
    fn record_level_subject_parses_to_did_plus_uri() {
        let p = QueryStatusesParams {
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
        let p = QueryStatusesParams {
            subject: Some("https://example.com".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("DID"), "{err}");
    }

    #[test]
    fn at_uri_without_did_authority_rejected() {
        let p = QueryStatusesParams {
            subject: Some("at://example.com/c/r".into()),
            ..empty_params()
        };
        let err = parse_params(p).unwrap_err();
        assert!(err.contains("DID authority"), "{err}");
    }

    // ===== Tags parsing =====

    #[test]
    fn tags_split_on_comma() {
        let p = QueryStatusesParams {
            tags: Some("spam,harassment,nsfw".into()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert_eq!(
            parsed.tags.as_deref(),
            Some(
                &[
                    "spam".to_string(),
                    "harassment".to_string(),
                    "nsfw".to_string()
                ][..]
            )
        );
    }

    #[test]
    fn empty_tags_string_yields_none() {
        let p = QueryStatusesParams {
            tags: Some("".into()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert!(parsed.tags.is_none());
    }

    #[test]
    fn tags_with_whitespace_trimmed() {
        let p = QueryStatusesParams {
            tags: Some("spam, harassment ,nsfw".into()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert_eq!(
            parsed.tags.as_deref(),
            Some(
                &[
                    "spam".to_string(),
                    "harassment".to_string(),
                    "nsfw".to_string()
                ][..]
            )
        );
    }

    // ===== Cursor encoding =====

    #[test]
    fn cursor_round_trip_is_stable() {
        let c = Cursor {
            updated_at_ms: 1_700_000_000_000,
            subject_did: "did:plc:abc".into(),
            subject_uri: "at://did:plc:abc/c/r".into(),
        };
        let encoded = c.encode();
        let decoded = Cursor::decode(&encoded).unwrap();
        assert_eq!(decoded.updated_at_ms, c.updated_at_ms);
        assert_eq!(decoded.subject_did, c.subject_did);
        assert_eq!(decoded.subject_uri, c.subject_uri);
    }

    #[test]
    fn cursor_round_trip_with_empty_uri() {
        // Account-level subjects use empty-string subject_uri in
        // the cursor.
        let c = Cursor {
            updated_at_ms: 1_700_000_000_000,
            subject_did: "did:plc:abc".into(),
            subject_uri: "".into(),
        };
        let encoded = c.encode();
        let decoded = Cursor::decode(&encoded).unwrap();
        assert_eq!(decoded.subject_uri, "");
    }

    #[test]
    fn malformed_cursor_rejected() {
        let err = Cursor::decode("not-base64-!!!").unwrap_err();
        assert!(err.contains("base64") || err.contains("malformed"), "{err}");
    }

    #[test]
    fn cursor_with_invalid_json_payload_rejected() {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-json");
        let err = Cursor::decode(&bytes).unwrap_err();
        assert!(err.contains("json") || err.contains("malformed"), "{err}");
    }

    #[test]
    fn cursor_round_trip_via_param_parsing() {
        // End-to-end: encode a cursor, pass through QueryParams,
        // and parse_params decodes it back to the same struct.
        let c = Cursor {
            updated_at_ms: 1_700_000_000_000,
            subject_did: "did:plc:abc".into(),
            subject_uri: "".into(),
        };
        let p = QueryStatusesParams {
            cursor: Some(c.encode()),
            ..empty_params()
        };
        let parsed = parse_params(p).unwrap();
        assert_eq!(
            parsed.cursor.as_ref().map(|c| c.updated_at_ms),
            Some(1_700_000_000_000)
        );
    }
}
