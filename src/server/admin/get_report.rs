//! `tools.cairn.admin.getReport` handler.
//!
//! Single-report fetch. This is the **only** admin read endpoint
//! that returns the report's `reason` text; §F11 classifies the
//! body as sensitive and reserves its exposure to admin-authenticated
//! fetches. The type system enforces this via `ReportDetail` vs
//! `ReportListEntry` — see `report_view.rs`.

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::report::{Report, ReportStatus};

use super::common::{AdminError, AdminState, verify_and_authorize};
use super::report_view::project_for_fetch;

const LXM: &str = "tools.cairn.admin.getReport";

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(e) = verify_and_authorize(&state, &headers, LXM).await {
        return e.into_response();
    }

    let id = match parse_id(query.as_deref().unwrap_or("")) {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };

    let row = sqlx::query_as!(
        Report,
        r#"SELECT
             id                 AS "id!: i64",
             created_at         AS "created_at!: String",
             reported_by        AS "reported_by!: String",
             reason_type        AS "reason_type!: String",
             reason,
             subject_type       AS "subject_type!: String",
             subject_did        AS "subject_did!: String",
             subject_uri,
             subject_cid,
             status             AS "status!: ReportStatus",
             resolved_at,
             resolved_by,
             resolution_label,
             resolution_reason
           FROM reports WHERE id = ?1"#,
        id,
    )
    .fetch_optional(&state.pool)
    .await;

    match row {
        Ok(Some(report)) => Json(project_for_fetch(report)).into_response(),
        Ok(None) => AdminError::ReportNotFound.into_response(),
        Err(_) => AdminError::Internal.into_response(),
    }
}

fn parse_id(raw: &str) -> Result<i64, AdminError> {
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        if k.as_ref() == "id" {
            return v
                .parse::<i64>()
                .map_err(|_| AdminError::InvalidRequest("id must be integer"));
        }
    }
    Err(AdminError::InvalidRequest("id required"))
}
