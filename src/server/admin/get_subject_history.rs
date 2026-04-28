//! `tools.cairn.admin.getSubjectHistory` handler (#52 / read-half
//! of #53).
//!
//! Read surface for the `subject_actions` table introduced in #46
//! and populated by the recorder from #51. Newest-first
//! (`ORDER BY id DESC`), opaque cursor pagination on the trailing
//! row's `id` — same idiom as `listAuditLog` / `listReports`. Mod
//! or Admin role.
//!
//! Cursor convention: opaque base64url of the last row's `id`.
//! v1.4 has no scheduled actions (effective_at == created_at on
//! every row), so id-ordering is equivalent to effective_at-
//! ordering. If scheduled actions land later, the cursor encoding
//! gains a tuple shape; today's clients are forward-compatible
//! because the cursor is always opaque.
//!
//! `SubjectNotFound` (404) fires when the subject_did has never
//! been actioned — distinct from "actioned but filtered to empty"
//! (which returns 200 with an empty `actions` array). The
//! existence check is a single-row EXISTS; the partial index on
//! `subject_actions(subject_did)` makes it O(1).

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{QueryBuilder, Sqlite};

use crate::writer::parse_rfc3339_ms;

use super::common::{AdminError, AdminState, verify_and_authorize};
use super::subject_action_view::{SubjectActionEntry, SubjectActionRow, project};
use crate::server::strike_state::subject_has_history;
use crate::server::xrpc::{decode_cursor, encode_cursor};

const LXM: &str = "tools.cairn.admin.getSubjectHistory";
const DEFAULT_LIMIT: i64 = 50;
const MIN_LIMIT: i64 = 1;
const MAX_LIMIT: i64 = 250;

#[derive(Debug, Default)]
struct Params {
    subject: String,
    subject_uri: Option<String>,
    since_ms: Option<i64>,
    include_revoked: bool,
    limit: i64,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    actions: Vec<SubjectActionEntry>,
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

    // Existence check before the page query. Distinguishes
    // "never actioned" (404) from "filtered to empty" (200 + []).
    match subject_has_history(&state.pool, &params.subject).await {
        Ok(true) => {}
        Ok(false) => return AdminError::SubjectNotFound.into_response(),
        Err(_) => return AdminError::Internal.into_response(),
    }

    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT id, subject_did, subject_uri, actor_did, action_type, reason_codes,
                duration, effective_at, expires_at, notes, report_ids,
                strike_value_base, strike_value_applied, was_dampened,
                strikes_at_time_of_action, revoked_at, revoked_by_did, revoked_reason,
                audit_log_id, created_at, actor_kind, triggered_by_policy_rule
         FROM subject_actions
         WHERE subject_did = ",
    );
    qb.push_bind(params.subject.clone());
    qb.push(" AND id < ");
    qb.push_bind(cursor_id);
    if let Some(uri) = &params.subject_uri {
        qb.push(" AND subject_uri = ");
        qb.push_bind(uri.clone());
    }
    if let Some(s) = params.since_ms {
        qb.push(" AND effective_at >= ");
        qb.push_bind(s);
    }
    if !params.include_revoked {
        qb.push(" AND revoked_at IS NULL");
    }
    qb.push(" ORDER BY id DESC LIMIT ");
    qb.push_bind(params.limit + 1);

    let rows: Vec<SubjectActionRow> = match qb
        .build_query_as::<SubjectActionRow>()
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
            // Schema corruption (malformed JSON / out-of-range
            // timestamp). Surface as 500 — the writer enforces
            // valid input, so a parse failure here is internal.
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
    let mut p = Params {
        limit: DEFAULT_LIMIT,
        include_revoked: true, // lexicon default
        ..Default::default()
    };
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        match k.as_ref() {
            "subject" if !v.is_empty() => p.subject = v.into_owned(),
            "subjectUri" if !v.is_empty() => p.subject_uri = Some(v.into_owned()),
            "since" if !v.is_empty() => {
                let ms = parse_rfc3339_ms(v.as_ref())
                    .map_err(|_| AdminError::InvalidRequest("malformed since"))?;
                p.since_ms = Some(ms);
            }
            "includeRevoked" if !v.is_empty() => {
                p.include_revoked = match v.as_ref() {
                    "true" | "1" => true,
                    "false" | "0" => false,
                    _ => {
                        return Err(AdminError::InvalidRequest(
                            "includeRevoked must be true or false",
                        ));
                    }
                };
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
    if p.subject.is_empty() {
        return Err(AdminError::InvalidRequest("subject is required"));
    }
    if !p.subject.starts_with("did:") {
        return Err(AdminError::InvalidRequest("subject must be a DID"));
    }
    Ok(p)
}
