//! `tools.cairn.admin.listPendingActions` handler (§F22 / #77).
//!
//! Read surface for the `pending_policy_actions` table (#70,
//! populated by mode=flag rule firings in #73, resolved via #74 /
//! #75 / cascaded via #76). Newest-first (`ORDER BY id DESC`),
//! opaque cursor pagination on the trailing row's `id` — same
//! idiom as `listSubjectHistory`. Mod or Admin role.
//!
//! Cursor convention: opaque base64url of the last row's `id`,
//! shared with the other v1.4+ admin list endpoints via
//! [`crate::server::xrpc::encode_cursor`].
//!
//! `SubjectNotFound` (404) fires when the `subject` filter is
//! provided and no `pending_policy_actions` row has ever been
//! recorded for that DID — distinct from "the resolution filter
//! excluded all rows" (which returns 200 with an empty `actions`
//! array). The existence check is a single-row EXISTS.

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{QueryBuilder, Sqlite};

use super::common::{AdminError, AdminState, verify_and_authorize};
use super::pending_action_view::{
    PendingActionEntry, PendingActionRow, project, subject_has_pending_actions,
};
use crate::server::xrpc::{decode_cursor, encode_cursor};

const LXM: &str = "tools.cairn.admin.listPendingActions";
const DEFAULT_LIMIT: i64 = 50;
const MIN_LIMIT: i64 = 1;
const MAX_LIMIT: i64 = 250;
const DEFAULT_RESOLUTION: &str = "pending";

/// Parsed `resolution` query parameter. The lexicon's
/// `knownValues` constrains this to three string literals; the
/// handler validates incoming values against the same set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolutionFilter {
    Pending,
    Confirmed,
    Dismissed,
}

impl ResolutionFilter {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "confirmed" => Some(Self::Confirmed),
            "dismissed" => Some(Self::Dismissed),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Params {
    subject: Option<String>,
    resolution: ResolutionFilter,
    limit: i64,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    actions: Vec<PendingActionEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(e) = verify_and_authorize(&state, &headers, LXM).await {
        return e.into_response();
    }

    let params = match parse_params(query.as_deref().unwrap_or("")) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let cursor_id = match &params.cursor {
        None => i64::MAX,
        Some(c) => match decode_cursor(c) {
            Ok(n) => n,
            Err(_) => return AdminError::InvalidRequest("malformed cursor").into_response(),
        },
    };

    // SubjectNotFound check: only when the subject filter is
    // supplied. Distinguishes "never had a pending" (404) from
    // "has pendings but the resolution filter excluded them all"
    // (200 + empty array). Without a subject filter the endpoint
    // is operator-side queue scanning — no 404 makes sense there.
    if let Some(subject) = &params.subject {
        match subject_has_pending_actions(&state.pool, subject).await {
            Ok(true) => {}
            Ok(false) => return AdminError::SubjectNotFound.into_response(),
            Err(_) => return AdminError::Internal.into_response(),
        }
    }

    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT id, subject_did, subject_uri, action_type, duration_ms,
                reason_codes, triggered_by_policy_rule, triggered_at,
                triggering_action_id, resolution, resolved_at,
                resolved_by_did, confirmed_action_id
         FROM pending_policy_actions
         WHERE id < ",
    );
    qb.push_bind(cursor_id);
    if let Some(subject) = &params.subject {
        qb.push(" AND subject_did = ");
        qb.push_bind(subject.clone());
    }
    match params.resolution {
        ResolutionFilter::Pending => {
            qb.push(" AND resolution IS NULL");
        }
        ResolutionFilter::Confirmed => {
            qb.push(" AND resolution = 'confirmed'");
        }
        ResolutionFilter::Dismissed => {
            qb.push(" AND resolution = 'dismissed'");
        }
    }
    qb.push(" ORDER BY id DESC LIMIT ");
    qb.push_bind(params.limit + 1);

    let rows: Vec<PendingActionRow> = match qb
        .build_query_as::<PendingActionRow>()
        .fetch_all(&state.pool)
        .await
    {
        Ok(r) => r,
        Err(_) => return AdminError::Internal.into_response(),
    };

    let (returned, next_cursor) = if rows.len() as i64 > params.limit {
        let mut trimmed = rows;
        trimmed.truncate(params.limit as usize);
        let last_id = trimmed.last().expect("trimmed non-empty").id;
        (trimmed, Some(encode_cursor(last_id)))
    } else {
        (rows, None)
    };

    let mut actions = Vec::with_capacity(returned.len());
    for row in returned {
        match project(row) {
            Ok(e) => actions.push(e),
            Err(_) => return AdminError::Internal.into_response(),
        }
    }

    Json(Output {
        actions,
        cursor: next_cursor,
    })
    .into_response()
}

fn parse_params(raw: &str) -> Result<Params, AdminError> {
    let mut subject: Option<String> = None;
    let mut resolution_str: Option<String> = None;
    let mut limit: i64 = DEFAULT_LIMIT;
    let mut cursor: Option<String> = None;

    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        match k.as_ref() {
            "subject" if !v.is_empty() => subject = Some(v.into_owned()),
            "resolution" if !v.is_empty() => resolution_str = Some(v.into_owned()),
            "limit" => {
                let n = v
                    .parse::<i64>()
                    .map_err(|_| AdminError::InvalidRequest("limit must be integer"))?;
                if !(MIN_LIMIT..=MAX_LIMIT).contains(&n) {
                    return Err(AdminError::InvalidRequest("limit out of range"));
                }
                limit = n;
            }
            "cursor" if !v.is_empty() => cursor = Some(v.into_owned()),
            _ => {}
        }
    }

    if let Some(ref s) = subject
        && !s.starts_with("did:")
    {
        return Err(AdminError::InvalidRequest("subject must be a DID"));
    }

    let resolution_owned = resolution_str.unwrap_or_else(|| DEFAULT_RESOLUTION.to_string());
    let resolution = ResolutionFilter::parse(&resolution_owned).ok_or(
        AdminError::InvalidRequest("resolution must be pending, confirmed, or dismissed"),
    )?;

    Ok(Params {
        subject,
        resolution,
        limit,
        cursor,
    })
}
