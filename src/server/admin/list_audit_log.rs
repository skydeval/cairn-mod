//! `tools.cairn.admin.listAuditLog` handler (§F12 — admin-role-only).
//!
//! Read-side for the audit log whose write-side lives in `writer.rs` and
//! the per-action handlers (`apply_label`, `negate_label`, `resolve_report`,
//! `flag_reporter`). Newest-first (`ORDER BY id DESC`), same cursor idiom
//! as listReports.
//!
//! Query-param validation is strict on purpose: unknown `action` or
//! `outcome` values return `InvalidRequest` rather than silently matching
//! zero rows. This forces clients to stay in sync with the audit
//! taxonomy and surfaces typos during development.

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{QueryBuilder, Sqlite};

use crate::writer::{AUDIT_ACTION_VALUES, AUDIT_OUTCOME_VALUES, parse_rfc3339_ms};

use super::audit_view::{AuditEntry, AuditRow, project};
use super::common::{AdminError, AdminState, verify_and_authorize_admin_only};
use crate::server::xrpc::{decode_cursor, encode_cursor};

const LXM: &str = "tools.cairn.admin.listAuditLog";
const DEFAULT_LIMIT: i64 = 50;
const MIN_LIMIT: i64 = 1;
const MAX_LIMIT: i64 = 250;

#[derive(Debug, Default)]
struct Params {
    actor: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    since_ms: Option<i64>,
    until_ms: Option<i64>,
    limit: i64,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    entries: Vec<AuditEntry>,
}

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(e) = verify_and_authorize_admin_only(&state, &headers, LXM).await {
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

    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT id, created_at, action, actor_did, target, target_cid, outcome, reason,
                prev_hash, row_hash
         FROM audit_log
         WHERE id < ",
    );
    qb.push_bind(cursor_id);
    if let Some(a) = &params.actor {
        qb.push(" AND actor_did = ");
        qb.push_bind(a.clone());
    }
    if let Some(a) = &params.action {
        qb.push(" AND action = ");
        qb.push_bind(a.clone());
    }
    if let Some(o) = &params.outcome {
        qb.push(" AND outcome = ");
        qb.push_bind(o.clone());
    }
    if let Some(s) = params.since_ms {
        qb.push(" AND created_at >= ");
        qb.push_bind(s);
    }
    if let Some(u) = params.until_ms {
        qb.push(" AND created_at <= ");
        qb.push_bind(u);
    }
    qb.push(" ORDER BY id DESC LIMIT ");
    qb.push_bind(params.limit + 1);

    let rows: Vec<AuditRow> = match qb.build_query_as::<AuditRow>().fetch_all(&state.pool).await {
        Ok(r) => r,
        Err(_) => return AdminError::Internal.into_response(),
    };

    let (returned, next_cursor) = if rows.len() as i64 > params.limit {
        let mut trimmed = rows;
        trimmed.truncate(params.limit as usize);
        let last_id = trimmed
            .last()
            .expect("trimmed non-empty since rows > limit")
            .id;
        (trimmed, Some(encode_cursor(last_id)))
    } else {
        (rows, None)
    };

    let mut entries = Vec::with_capacity(returned.len());
    for row in returned {
        match project(row) {
            Ok(e) => entries.push(e),
            // A bad stored timestamp is an internal corruption — the
            // writer clamps/validates on the way in. Surface as 500
            // rather than leaking the row id in an InvalidRequest.
            Err(_) => return AdminError::Internal.into_response(),
        }
    }

    Json(Output {
        cursor: next_cursor,
        entries,
    })
    .into_response()
}

fn parse_params(raw: &str) -> Result<Params, AdminError> {
    let mut p = Params {
        limit: DEFAULT_LIMIT,
        ..Default::default()
    };
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        match k.as_ref() {
            "actor" if !v.is_empty() => p.actor = Some(v.into_owned()),
            "action" if !v.is_empty() => {
                if !AUDIT_ACTION_VALUES.contains(&v.as_ref()) {
                    // Anti-leak: don't enumerate allowed values here.
                    return Err(AdminError::InvalidRequest("invalid action"));
                }
                p.action = Some(v.into_owned());
            }
            "outcome" if !v.is_empty() => {
                if !AUDIT_OUTCOME_VALUES.contains(&v.as_ref()) {
                    return Err(AdminError::InvalidRequest("invalid outcome"));
                }
                p.outcome = Some(v.into_owned());
            }
            "since" if !v.is_empty() => {
                let ms = parse_rfc3339_ms(v.as_ref())
                    .map_err(|_| AdminError::InvalidRequest("malformed since"))?;
                p.since_ms = Some(ms);
            }
            "until" if !v.is_empty() => {
                let ms = parse_rfc3339_ms(v.as_ref())
                    .map_err(|_| AdminError::InvalidRequest("malformed until"))?;
                p.until_ms = Some(ms);
            }
            "limit" => {
                let n = v
                    .parse::<i64>()
                    .map_err(|_| AdminError::InvalidRequest("limit must be integer"))?;
                if !(MIN_LIMIT..=MAX_LIMIT).contains(&n) {
                    return Err(AdminError::InvalidRequest("limit out of range"));
                }
                p.limit = n;
            }
            "cursor" if !v.is_empty() => p.cursor = Some(v.into_owned()),
            _ => {}
        }
    }
    if let (Some(s), Some(u)) = (p.since_ms, p.until_ms)
        && s > u
    {
        // Anti-leak: no timestamps echoed back.
        return Err(AdminError::InvalidRequest("since must be <= until"));
    }
    Ok(p)
}
