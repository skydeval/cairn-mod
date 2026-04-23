//! `tools.cairn.admin.listLabels` handler.
//!
//! Admin-view of the labels history. Unlike the public
//! `com.atproto.label.queryLabels` (#6) which returns a point-in-time
//! view (latest-per-tuple, apply only, non-expired), this endpoint
//! exposes:
//!
//! - **Negation visibility** via `includeNegated` — when false
//!   (default), returns rows whose latest event for their tuple is
//!   still an apply; when true, returns every row matching the
//!   filters (including negation events).
//! - **Expiry visibility** via `includeExpired` — when false,
//!   filters out rows whose `exp` has passed.
//! - **Actor filter** — join audit_log on `(actor_did, target=uri,
//!   created_at)`; `labels.created_at` and `audit_log.created_at`
//!   are set to the same epoch-ms in the writer's atomic INSERT,
//!   so exact-equality on integer ms pins exactly the audit row
//!   for each label.
//!
//! Cursor: shared base64url(seq) codec from `crate::server::xrpc`.

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{QueryBuilder, Sqlite};
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;

use crate::label::Label;

use super::common::{AdminError, AdminState, verify_and_authorize};
use crate::server::xrpc::{decode_cursor, encode_cursor};

const LXM: &str = "tools.cairn.admin.listLabels";
const DEFAULT_LIMIT: i64 = 50;
const MIN_LIMIT: i64 = 1;
const MAX_LIMIT: i64 = 250;

const CTS_FORMAT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

#[derive(Debug, Default)]
struct Params {
    uri: Option<String>,
    val: Option<String>,
    actor: Option<String>,
    include_negated: bool,
    include_expired: bool,
    limit: i64,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    labels: Vec<AdminLabelJson>,
}

/// Admin-view label projection. Parallels the public `LabelJson`
/// from `src/server/query.rs` but retains negation/expired rows and
/// carries `seq` so operators can correlate with subscribeLabels
/// cursors. `sig` still uses ATProto typed-bytes.
#[derive(Debug, Serialize)]
struct AdminLabelJson {
    seq: i64,
    ver: i64,
    src: String,
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<String>,
    val: String,
    #[serde(skip_serializing_if = "is_false")]
    neg: bool,
    cts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<String>,
    sig: TypedBytes,
}

#[derive(Debug, Serialize)]
struct TypedBytes {
    #[serde(rename = "$bytes")]
    bytes: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl AdminLabelJson {
    fn from(seq: i64, label: Label) -> Self {
        use base64::Engine as _;
        let sig_bytes = label
            .sig
            .expect("admin labels come from storage and have sig");
        Self {
            seq,
            ver: label.ver,
            src: label.src,
            uri: label.uri,
            cid: label.cid,
            val: label.val,
            neg: label.neg,
            cts: label.cts,
            exp: label.exp,
            sig: TypedBytes {
                bytes: base64::engine::general_purpose::STANDARD.encode(sig_bytes),
            },
        }
    }
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

    let cursor_seq = match &params.cursor {
        None => 0_i64,
        Some(c) => match decode_cursor(c) {
            Ok(n) => n,
            Err(_) => return AdminError::InvalidRequest("malformed cursor").into_response(),
        },
    };

    let now_rfc3339 = match rfc3339_now() {
        Ok(s) => s,
        Err(()) => return AdminError::Internal.into_response(),
    };

    // Build SQL with QueryBuilder — filter cardinality (uri/val/actor
    // optionality, two boolean toggles) doesn't fit query!'s static
    // string; same load-bearing-dynamic-shape rationale as query.rs.
    // Safety: every user-controlled value goes through push_bind.
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT l.seq, l.ver, l.src, l.uri, l.cid, l.val, l.neg, l.cts, l.exp, l.sig
         FROM labels l
         WHERE l.seq > ",
    );
    qb.push_bind(cursor_seq);

    if let Some(uri) = &params.uri {
        qb.push(" AND l.uri = ");
        qb.push_bind(uri.clone());
    }
    if let Some(val) = &params.val {
        qb.push(" AND l.val = ");
        qb.push_bind(val.clone());
    }
    if let Some(actor) = &params.actor {
        // CROSS-MODULE INVARIANT: the actor filter relies on
        // `labels.created_at == audit_log.created_at` (integer ms,
        // same wall-clock value set inside one transaction). See
        // `src/writer.rs::Writer::handle_apply` and `handle_negate` —
        // both bind `let created_at = wall_now_ms;` and then pass
        // that identical value into the `labels` INSERT and the
        // `audit_log` INSERT. If a future writer refactor timestamps
        // these independently (separate `epoch_ms_now()` calls, or
        // distinct fields), this EXISTS subquery silently starts
        // returning the wrong rows. The writer-side comments flag
        // this; the join below is the read-side party to the same
        // invariant.
        qb.push(
            " AND EXISTS (
              SELECT 1 FROM audit_log a
              WHERE a.actor_did = ",
        );
        qb.push_bind(actor.clone());
        qb.push(
            "
                AND a.target = l.uri
                AND a.created_at = l.created_at
                AND a.action IN ('label_applied', 'label_negated')
            )",
        );
    }
    if !params.include_expired {
        qb.push(" AND (l.exp IS NULL OR l.exp > ");
        qb.push_bind(now_rfc3339);
        qb.push(")");
    }
    if !params.include_negated {
        // Hide rows whose latest event for the tuple is a negation —
        // matches subscribeLabels replay semantics (§F4). The
        // negation row itself is also hidden because its own `neg=1`
        // makes the following NOT(neg=1 AND ...) trivially true
        // only for apply rows; we add an explicit neg=0 check.
        qb.push(
            " AND l.neg = 0
             AND NOT EXISTS (
                 SELECT 1 FROM labels l2
                 WHERE l2.src = l.src AND l2.uri = l.uri AND l2.val = l.val
                   AND l2.neg = 1 AND l2.seq > l.seq
             )",
        );
    }

    qb.push(" ORDER BY l.seq ASC LIMIT ");
    qb.push_bind(params.limit + 1);

    let rows: Vec<LabelRow> = match qb.build_query_as::<LabelRow>().fetch_all(&state.pool).await {
        Ok(r) => r,
        Err(_) => return AdminError::Internal.into_response(),
    };

    let (returned, next_cursor) = if rows.len() as i64 > params.limit {
        let mut trimmed = rows;
        trimmed.truncate(params.limit as usize);
        let last_seq = trimmed
            .last()
            .expect("trimmed non-empty since rows > limit")
            .seq;
        (trimmed, Some(encode_cursor(last_seq)))
    } else {
        (rows, None)
    };

    let labels: Vec<AdminLabelJson> = returned
        .into_iter()
        .filter_map(|row| {
            let sig: [u8; 64] = row.sig.as_slice().try_into().ok()?;
            Some(AdminLabelJson::from(
                row.seq,
                Label {
                    ver: row.ver,
                    src: row.src,
                    uri: row.uri,
                    cid: row.cid,
                    val: row.val,
                    neg: row.neg != 0,
                    cts: row.cts,
                    exp: row.exp,
                    sig: Some(sig),
                },
            ))
        })
        .collect();

    Json(Output {
        cursor: next_cursor,
        labels,
    })
    .into_response()
}

#[derive(sqlx::FromRow)]
struct LabelRow {
    seq: i64,
    ver: i64,
    src: String,
    uri: String,
    cid: Option<String>,
    val: String,
    neg: i64,
    cts: String,
    exp: Option<String>,
    sig: Vec<u8>,
}

fn parse_params(raw: &str) -> Result<Params, AdminError> {
    let mut p = Params {
        limit: DEFAULT_LIMIT,
        ..Default::default()
    };
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        match k.as_ref() {
            "uri" if !v.is_empty() => p.uri = Some(v.into_owned()),
            "val" if !v.is_empty() => p.val = Some(v.into_owned()),
            "actor" if !v.is_empty() => p.actor = Some(v.into_owned()),
            "includeNegated" => p.include_negated = parse_bool(&v),
            "includeExpired" => p.include_expired = parse_bool(&v),
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
            _ => { /* ignore unknown query params */ }
        }
    }
    Ok(p)
}

fn parse_bool(s: &str) -> bool {
    matches!(s, "true" | "1")
}

fn rfc3339_now() -> Result<String, ()> {
    let dt = OffsetDateTime::now_utc();
    let formatted = dt.format(&CTS_FORMAT).map_err(|_| ())?;
    Ok(format!("{formatted}Z"))
}
