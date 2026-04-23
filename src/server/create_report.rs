//! `com.atproto.moderation.createReport` intake handler (§F11).
//!
//! Pipeline, in order:
//!
//! 1. **CORS gate**: non-browser (no `Origin`) OK; browser `Origin` must
//!    be in the operator-configured allowlist. Mismatched origins get
//!    `403 Forbidden` — cross-origin preflight effectively blocks the
//!    submission at the browser layer (§F11 explicit).
//! 2. **Auth**: `verify_service_auth` with `expected_lxm =
//!    "com.atproto.moderation.createReport"`. Failure → `401
//!    AuthenticationRequired`, generic body.
//! 3. **Parse body** into [`CreateReportInput`]. Malformed JSON → `400
//!    InvalidRequest`.
//! 4. **Static validation**: `reasonType` in allowlist, `reason` length
//!    ≤ 2KB (§F11 — see comment at the check), `subject` parses as one
//!    of the two union variants.
//! 5. **Disk guard** (§F11): if the SQLite file exceeds
//!    `disk_size_limit_bytes`, return `500 InternalServerError` with a
//!    generic message. Label emission on the writer path is unaffected.
//! 6. **Suppression check**: `suppressed_reporters` lookup on the
//!    verified `iss`. Hit → `429 RateLimitExceeded`, indistinguishable
//!    from a legitimate rate limit response per §12 non-enumeration.
//! 7. **Per-DID rate limit**: count recent rows in `reports` with
//!    `reported_by = iss` and `created_at >= now - window`. Exceeded →
//!    `429`.
//! 8. **Global pending cap**: count `status = 'pending'` rows. Exceeded
//!    → `429`.
//! 9. **INSERT** into `reports`, read back the assigned `id`, format the
//!    response per the stock lexicon.
//!
//! Error bodies: `{ "error": "<Name>", "message": "<generic>" }`. Per §4
//! non-enumeration, messages don't reveal which check failed — e.g. a
//! rate-limited caller and a suppressed caller both see the same `429`
//! with the same body.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;

use crate::auth::AuthContext;

/// Configuration knobs for the createReport endpoint. Defaults track
/// §F11 values; operators override via config file.
#[derive(Debug, Clone)]
pub struct CreateReportConfig {
    /// Per-DID rolling rate-limit count (§F11: 10/hour).
    pub per_did_limit: u32,
    /// Per-DID rolling window (§F11: 1 hour).
    pub per_did_window: Duration,
    /// Global cap on rows with `status='pending'` (§F11: 10_000).
    pub global_pending_cap: u32,
    /// SQLite DB file size beyond which intake returns a generic error
    /// (§F11: 5 GiB default).
    pub disk_size_limit_bytes: u64,
    /// Path to the SQLite DB file for the disk-guard `fs::metadata`
    /// lookup.
    pub db_path: PathBuf,
    /// Browser Origins that are accepted when present on a request.
    /// Default empty list — all Origin-bearing requests get 403.
    /// Non-browser callers (no Origin header) are always accepted.
    pub cors_allowed_origins: Vec<String>,
    /// Hard cap on HTTP request body bytes. Defense against oversized
    /// requests independent of the reason-length validation. 32 KiB is
    /// generous for a well-formed createReport payload.
    pub max_body_bytes: usize,
}

impl Default for CreateReportConfig {
    fn default() -> Self {
        Self {
            per_did_limit: 10,
            per_did_window: Duration::from_secs(3600),
            global_pending_cap: 10_000,
            disk_size_limit_bytes: 5 * 1024 * 1024 * 1024,
            db_path: PathBuf::new(),
            cors_allowed_origins: Vec::new(),
            max_body_bytes: 32 * 1024,
        }
    }
}

/// §F11 caps the `reason` field at 2 KB. The stock lexicon allows up
/// to 20 KB (`maxLength: 20000`). Cairn is deliberately stricter:
/// 10 000 pending reports × 20 KB reason = 200 MB worst-case memory,
/// vs 20 MB at 2 KB. Preserve this stricter value unless §F11 changes.
const REASON_MAX_BYTES: usize = 2048;

/// `reasonType` values Cairn accepts per §F11 literal. The lexicon's
/// `knownValues` includes additional `tools.ozone.report.defs#reason*`
/// granular categories; widening Cairn's allowlist to those is a
/// post-v1 decision that requires choosing semantics for audit
/// categorization and `resolveReport` label selection. Do NOT widen
/// this set without an explicit design-doc update to §F11.
const ACCEPTED_REASON_TYPES: &[&str] = &[
    "com.atproto.moderation.defs#reasonSpam",
    "com.atproto.moderation.defs#reasonViolation",
    "com.atproto.moderation.defs#reasonMisleading",
    "com.atproto.moderation.defs#reasonSexual",
    "com.atproto.moderation.defs#reasonRude",
    "com.atproto.moderation.defs#reasonOther",
];

/// RFC-3339 Z with ms precision, matching the wire form the writer
/// uses for `cts`. `reports.created_at` / `.resolved_at` are the same
/// format for lexicographic comparability against skill-based windows.
const CTS_FORMAT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

// ---------- Wire types ----------

#[derive(Debug, Deserialize)]
pub(super) struct CreateReportInput {
    #[serde(rename = "reasonType")]
    reason_type: String,
    subject: Subject,
    reason: Option<String>,
    /// Stock lexicon's `modTool` is accepted and ignored. Lexicon also
    /// permits unknown-to-us fields for forward-compatibility; `serde`
    /// ignores unknown fields by default (we don't set
    /// `deny_unknown_fields`).
    #[serde(rename = "modTool", default)]
    #[allow(dead_code)]
    mod_tool: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub(super) enum Subject {
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    Repo { did: String },
    #[serde(rename = "com.atproto.repo.strongRef")]
    Strong { uri: String, cid: String },
}

#[derive(Debug, Serialize)]
pub(super) struct CreateReportOutput {
    id: i64,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "reasonType")]
    reason_type: String,
    subject: serde_json::Value,
    #[serde(rename = "reportedBy")]
    reported_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct XrpcErrorBody {
    error: &'static str,
    message: &'static str,
}

/// Shared body for every 429 response. §12 non-enumeration: suppression
/// and rate-limit hits MUST be indistinguishable.
const RATE_LIMIT_BODY: XrpcErrorBody = XrpcErrorBody {
    error: "RateLimitExceeded",
    message: "rate limit exceeded",
};

/// §F11 "reason cap" — message deliberately omits the threshold so an
/// attacker scanning for the limit can't binary-search it from error
/// responses. The value IS in public source; leaking it in API
/// responses is a minor but free concession we don't make.
const REASON_TOO_LONG_BODY: XrpcErrorBody = XrpcErrorBody {
    error: "InvalidRequest",
    message: "reason exceeds maximum length",
};

// ---------- Router + state ----------

/// Per-route application state. Keep this local to create_report.rs so
/// the admin endpoints (#15-17) can attach their own State types with
/// `Router::merge` rather than sharing one giant state enum.
#[derive(Clone)]
pub(super) struct AppState {
    pub pool: Pool<Sqlite>,
    pub auth: Arc<AuthContext>,
    pub config: Arc<CreateReportConfig>,
}

/// Build a Router exposing only `/xrpc/com.atproto.moderation.createReport`.
/// Compose via `Router::merge` with subscribe/query/admin routers.
pub fn create_report_router(
    pool: Pool<Sqlite>,
    auth: Arc<AuthContext>,
    config: CreateReportConfig,
) -> Router {
    let state = AppState {
        pool,
        auth,
        config: Arc::new(config),
    };
    Router::new()
        .route(
            "/xrpc/com.atproto.moderation.createReport",
            post(post_handler).options(preflight_handler),
        )
        .layer(Extension(state))
}

// ---------- Handlers ----------

async fn post_handler(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. CORS gate. Origin present + not-in-allowlist → 403.
    if let Some(reject) = check_cors(&state.config, &headers) {
        return reject;
    }

    // Total body length guard — cheaper than routing to body extraction.
    if body.len() > state.config.max_body_bytes {
        return xrpc_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "InvalidRequest",
            "request body too large",
        );
    }

    // 2. Auth. Parse Bearer token from Authorization header.
    let token = match headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => return auth_required(),
    };
    let caller = match state
        .auth
        .verify_service_auth(token, "com.atproto.moderation.createReport")
        .await
    {
        Ok(v) => v,
        Err(_) => return auth_required(),
    };

    // 3. Parse body.
    let input: CreateReportInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return xrpc_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "malformed request body",
            );
        }
    };

    // 4. Static validation.
    if !ACCEPTED_REASON_TYPES.contains(&input.reason_type.as_str()) {
        return xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "unsupported reasonType",
        );
    }
    if let Some(reason) = &input.reason
        && reason.len() > REASON_MAX_BYTES
    {
        // See REASON_TOO_LONG_BODY comment for why we don't include the
        // exact cap in the message.
        return (StatusCode::BAD_REQUEST, Json(REASON_TOO_LONG_BODY)).into_response();
    }
    let (subject_type, subject_did, subject_uri, subject_cid) = match &input.subject {
        Subject::Repo { did } => {
            if !did.starts_with("did:") {
                return xrpc_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "subject.did malformed",
                );
            }
            ("account", did.clone(), None, None)
        }
        Subject::Strong { uri, cid } => {
            if !uri.starts_with("at://") || cid.is_empty() {
                return xrpc_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "subject malformed",
                );
            }
            let did = match extract_did_from_at_uri(uri) {
                Some(d) => d.to_owned(),
                None => {
                    return xrpc_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        "subject.uri missing DID authority",
                    );
                }
            };
            ("record", did, Some(uri.clone()), Some(cid.clone()))
        }
    };

    // 5. Disk guard.
    if let Ok(meta) = std::fs::metadata(&state.config.db_path)
        && meta.len() >= state.config.disk_size_limit_bytes
    {
        return xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "service temporarily unavailable",
        );
    }

    // 6. Suppression check. §12: same response as rate-limit.
    let suppressed: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM suppressed_reporters WHERE did = ?1",
        caller.iss
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    if suppressed > 0 {
        return rate_limited();
    }

    // 7. Per-DID rate limit. Rolling window via RFC-3339 Z comparison
    // against the indexed (reported_by, created_at) tuple.
    let window_start = match rfc3339_minus_secs(state.config.per_did_window.as_secs() as i64) {
        Ok(s) => s,
        Err(()) => {
            return xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "service temporarily unavailable",
            );
        }
    };
    let recent: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM reports WHERE reported_by = ?1 AND created_at >= ?2",
        caller.iss,
        window_start
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    if recent >= state.config.per_did_limit as i64 {
        return rate_limited();
    }

    // 8. Global pending cap.
    let pending: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM reports WHERE status = 'pending'")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    if pending >= state.config.global_pending_cap as i64 {
        return rate_limited();
    }

    // 9. INSERT + response.
    let created_at = match rfc3339_now() {
        Ok(s) => s,
        Err(()) => {
            return xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "service temporarily unavailable",
            );
        }
    };
    let insert_result = sqlx::query_scalar!(
        "INSERT INTO reports (
             created_at, reported_by, reason_type, reason,
             subject_type, subject_did, subject_uri, subject_cid, status
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending')
         RETURNING id",
        created_at,
        caller.iss,
        input.reason_type,
        input.reason,
        subject_type,
        subject_did,
        subject_uri,
        subject_cid,
    )
    .fetch_one(&state.pool)
    .await;
    let id = match insert_result {
        Ok(id) => id,
        Err(_) => {
            return xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "service temporarily unavailable",
            );
        }
    };

    let subject_json = subject_to_json(&input.subject);
    let out = CreateReportOutput {
        id,
        created_at,
        reason_type: input.reason_type,
        subject: subject_json,
        reported_by: caller.iss,
        reason: input.reason,
    };

    let mut resp = (StatusCode::OK, Json(out)).into_response();
    attach_cors_headers(&mut resp, &state.config, &headers);
    resp
}

/// Handles CORS preflight (OPTIONS). Browsers send this before a POST
/// with JSON content type; approving the preflight controls whether
/// the actual POST is even attempted.
async fn preflight_handler(Extension(state): Extension<AppState>, headers: HeaderMap) -> Response {
    let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) else {
        // Preflight without Origin is a browser protocol error; reject.
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    if !state
        .config
        .cors_allowed_origins
        .iter()
        .any(|a| a == origin)
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut resp = StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    h.insert(
        "access-control-allow-origin",
        HeaderValue::from_str(origin).unwrap_or(HeaderValue::from_static("")),
    );
    h.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("POST"),
    );
    h.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("content-type, authorization"),
    );
    h.insert("vary", HeaderValue::from_static("Origin"));
    resp
}

// ---------- Helpers ----------

fn check_cors(config: &CreateReportConfig, headers: &HeaderMap) -> Option<Response> {
    let origin = headers.get("origin").and_then(|v| v.to_str().ok())?;
    if config.cors_allowed_origins.iter().any(|a| a == origin) {
        None
    } else {
        Some(StatusCode::FORBIDDEN.into_response())
    }
}

fn attach_cors_headers(resp: &mut Response, config: &CreateReportConfig, req_headers: &HeaderMap) {
    let Some(origin) = req_headers.get("origin").and_then(|v| v.to_str().ok()) else {
        return;
    };
    if !config.cors_allowed_origins.iter().any(|a| a == origin) {
        return;
    }
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(origin) {
        h.insert("access-control-allow-origin", v);
    }
    h.insert("vary", HeaderValue::from_static("Origin"));
}

fn auth_required() -> Response {
    xrpc_error(
        StatusCode::UNAUTHORIZED,
        "AuthenticationRequired",
        "authentication required",
    )
}

fn rate_limited() -> Response {
    (StatusCode::TOO_MANY_REQUESTS, Json(RATE_LIMIT_BODY)).into_response()
}

fn xrpc_error(status: StatusCode, error: &'static str, message: &'static str) -> Response {
    (status, Json(XrpcErrorBody { error, message })).into_response()
}

fn extract_did_from_at_uri(uri: &str) -> Option<&str> {
    uri.strip_prefix("at://")
        .and_then(|rest| rest.split('/').next())
        .filter(|did| did.starts_with("did:"))
}

fn rfc3339_now() -> Result<String, ()> {
    let dt = OffsetDateTime::now_utc();
    let formatted = dt.format(&CTS_FORMAT).map_err(|_| ())?;
    Ok(format!("{formatted}Z"))
}

fn rfc3339_minus_secs(secs: i64) -> Result<String, ()> {
    let dt = OffsetDateTime::now_utc() - Duration::from_secs(secs.max(0) as u64);
    let formatted = dt.format(&CTS_FORMAT).map_err(|_| ())?;
    Ok(format!("{formatted}Z"))
}

fn subject_to_json(s: &Subject) -> serde_json::Value {
    match s {
        Subject::Repo { did } => serde_json::json!({
            "$type": "com.atproto.admin.defs#repoRef",
            "did": did,
        }),
        Subject::Strong { uri, cid } => serde_json::json!({
            "$type": "com.atproto.repo.strongRef",
            "uri": uri,
            "cid": cid,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_did_accepts_valid_at_uri() {
        let did = extract_did_from_at_uri("at://did:plc:abc/col/rkey").unwrap();
        assert_eq!(did, "did:plc:abc");
    }

    #[test]
    fn extract_did_rejects_non_at_uri() {
        assert!(extract_did_from_at_uri("https://example.com").is_none());
    }

    #[test]
    fn extract_did_rejects_non_did_authority() {
        // An AT-URI must have `did:...` in its authority; anything else
        // is malformed regardless of whether the rest parses.
        assert!(extract_did_from_at_uri("at://example.com/foo").is_none());
    }

    #[test]
    fn reason_types_allowlist_pins_f11_literal_set() {
        // Compile-time pinned size: if someone adds a reason type, they
        // have to bump this test deliberately — matches §F11's "widen
        // only via design-doc update" policy.
        assert_eq!(ACCEPTED_REASON_TYPES.len(), 6);
    }
}
