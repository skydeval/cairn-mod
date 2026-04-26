//! `tools.cairn.admin.getAuditLog` handler (#26, §F12 admin-role-only).
//!
//! Single-row counterpart to `listAuditLog`. Read-only; writes no
//! `audit_log` row — fetching the log is a transparency operation,
//! not a moderation event. Mod-role callers receive 403 with the same
//! posture as `listAuditLog`.
//!
//! `AuditEntryNotFound` mirrors `getReport`'s `ReportNotFound`:
//! resource-lookup-by-opaque-id surfaces a typed 404 rather than a
//! generic `InvalidRequest`, which lets CLI/operator tooling branch
//! on the error without parsing message text.
//!
//! Reuses `audit_view::AuditRow`/`project` so list and get agree on
//! wire shape, including the RFC-3339 `createdAt` formatter and the
//! opaque `reason` passthrough documented on `AUDIT_REASON_*` in
//! `crate::writer`.

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use super::audit_view::{AuditRow, project};
use super::common::{AdminError, AdminState, verify_and_authorize_admin_only};

const LXM: &str = "tools.cairn.admin.getAuditLog";

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(e) = verify_and_authorize_admin_only(&state, &headers, LXM).await {
        return e.into_response();
    }

    let id = match parse_id(query.as_deref().unwrap_or("")) {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };

    let row = sqlx::query_as!(
        AuditRow,
        r#"SELECT
             id          AS "id!: i64",
             created_at  AS "created_at!: i64",
             action      AS "action!: String",
             actor_did   AS "actor_did!: String",
             target,
             target_cid,
             outcome     AS "outcome!: String",
             reason,
             prev_hash,
             row_hash
           FROM audit_log WHERE id = ?1"#,
        id,
    )
    .fetch_optional(&state.pool)
    .await;

    match row {
        Ok(Some(r)) => match project(r) {
            Ok(entry) => Json(entry).into_response(),
            // Stored timestamp out of range — internal corruption; the
            // writer clamps on the way in. Surface as 500 rather than
            // leaking the row id in InvalidRequest, matching
            // listAuditLog's posture.
            Err(_) => AdminError::Internal.into_response(),
        },
        Ok(None) => AdminError::AuditEntryNotFound.into_response(),
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
