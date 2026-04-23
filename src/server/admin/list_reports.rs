//! `tools.cairn.admin.listReports` handler.
//!
//! Paginated listing of reports with optional `status` + `reportedBy`
//! filters. **Newest-first** (`ORDER BY id DESC`) — admin triage UX
//! wants the latest reports at the top, distinguishing this endpoint
//! from the ASC cursor semantics of queryLabels / listLabels.
//!
//! Response uses `ReportListEntry` which by construction OMITS the
//! `reason` text (§F11: report body never returned by public
//! endpoints; `getReport` is the only fetch that carries it).

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{QueryBuilder, Sqlite};

use crate::report::Report;

use super::common::{AdminError, AdminState, verify_and_authorize};
use super::report_view::{ReportListEntry, project_for_list};
use crate::server::xrpc::{decode_cursor, encode_cursor};

const LXM: &str = "tools.cairn.admin.listReports";
const DEFAULT_LIMIT: i64 = 50;
const MIN_LIMIT: i64 = 1;
const MAX_LIMIT: i64 = 250;

#[derive(Debug, Default)]
struct Params {
    status: Option<String>,
    reported_by: Option<String>,
    limit: i64,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    reports: Vec<ReportListEntry>,
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

    // DESC pagination: the cursor is the last id RETURNED, and the
    // next page selects rows with `id < cursor`. Initial request
    // (no cursor) selects all rows; we model this as an i64::MAX
    // sentinel so the same `id < ?` expression handles both cases.
    let cursor_id = match &params.cursor {
        None => i64::MAX,
        Some(c) => match decode_cursor(c) {
            Ok(n) => n,
            Err(_) => return AdminError::InvalidRequest("malformed cursor").into_response(),
        },
    };

    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT id, created_at, reported_by, reason_type, reason,
                subject_type, subject_did, subject_uri, subject_cid,
                status, resolved_at, resolved_by, resolution_label, resolution_reason
         FROM reports
         WHERE id < ",
    );
    qb.push_bind(cursor_id);
    if let Some(s) = &params.status {
        qb.push(" AND status = ");
        qb.push_bind(s.clone());
    }
    if let Some(rb) = &params.reported_by {
        qb.push(" AND reported_by = ");
        qb.push_bind(rb.clone());
    }
    qb.push(" ORDER BY id DESC LIMIT ");
    qb.push_bind(params.limit + 1);

    let rows: Vec<Report> = match qb.build_query_as::<Report>().fetch_all(&state.pool).await {
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

    let reports: Vec<ReportListEntry> = returned.into_iter().map(project_for_list).collect();

    Json(Output {
        cursor: next_cursor,
        reports,
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
            "status" if !v.is_empty() => {
                if v != "pending" && v != "resolved" {
                    return Err(AdminError::InvalidRequest(
                        "status must be pending or resolved",
                    ));
                }
                p.status = Some(v.into_owned());
            }
            "reportedBy" if !v.is_empty() => p.reported_by = Some(v.into_owned()),
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
    Ok(p)
}
