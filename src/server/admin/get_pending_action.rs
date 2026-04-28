//! `tools.cairn.admin.getPendingAction` handler (§F22 / #77).
//!
//! Single-row read for the `pending_policy_actions` table.
//! Returns the full pending row including resolution state and
//! cross-references (`triggeringActionId` to the precipitating
//! subject_actions row; `confirmedActionId` to the materialized
//! action when resolution is 'confirmed'). Mod or Admin role.

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use super::common::{AdminError, AdminState, verify_and_authorize};
use super::pending_action_view::{PendingActionRow, project};

const LXM: &str = "tools.cairn.admin.getPendingAction";

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(e) = verify_and_authorize(&state, &headers, LXM).await {
        return e.into_response();
    }

    let pending_id = match parse_pending_id(query.as_deref().unwrap_or("")) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let row: Option<PendingActionRow> = match sqlx::query_as!(
        PendingActionRow,
        r#"SELECT
             id                       AS "id!: i64",
             subject_did              AS "subject_did!: String",
             subject_uri,
             action_type              AS "action_type!: String",
             duration_ms,
             reason_codes             AS "reason_codes!: String",
             triggered_by_policy_rule AS "triggered_by_policy_rule!: String",
             triggered_at             AS "triggered_at!: i64",
             triggering_action_id     AS "triggering_action_id!: i64",
             resolution,
             resolved_at,
             resolved_by_did,
             confirmed_action_id
           FROM pending_policy_actions
           WHERE id = ?1"#,
        pending_id,
    )
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return AdminError::Internal.into_response(),
    };

    let row = match row {
        Some(r) => r,
        None => return AdminError::PendingActionNotFound.into_response(),
    };

    let entry = match project(row) {
        Ok(e) => e,
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(entry).into_response()
}

fn parse_pending_id(raw: &str) -> Result<i64, AdminError> {
    let mut pending_id: Option<i64> = None;
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        if k.as_ref() == "pendingId" {
            let n = v
                .parse::<i64>()
                .map_err(|_| AdminError::InvalidRequest("pendingId must be integer"))?;
            pending_id = Some(n);
        }
    }
    pending_id.ok_or(AdminError::InvalidRequest("pendingId is required"))
}
