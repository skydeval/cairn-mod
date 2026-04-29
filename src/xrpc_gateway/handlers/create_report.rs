//! `com.atproto.moderation.createReport` handler body (#96, v1.7).
//!
//! Phase D's second handler. PDS-signed inbound flow per §A10:
//! upstream PDSes forward user-filed reports here, and cairn-mod
//! inserts a row into the existing `reports` table — the same
//! table the user-direct intake at
//! `crate::server::create_report` (the user-direct intake module) writes into. From there,
//! cairn-mod's existing report-resolution surface (§F11/§F12/§F17
//! — admin XRPC + CLI) handles the row unchanged.
//!
//! # Auth path differs from emitEvent
//!
//! Per §A10 + bsky-PDS findings §4.3: the JWT is signed by **the
//! PDS**, not the originating user. `claims.iss` is the PDS's DID;
//! the originating user's DID is asserted on the wire as the
//! `reportedBy` field. cairn-mod cannot cryptographically verify
//! that assertion — operators trust upstream PDSes by adding them
//! to `xrpc_trusted_pdses`. The membership middleware (refactored
//! from #94) routes this NSID to `is_trusted_pds` so the gate is
//! the PDS's DID, not the reporter's.
//!
//! # No translation table for reasonType
//!
//! cairn-mod's `reports.reason_type` column stores the lexicon's
//! `$type` string verbatim ("`com.atproto.moderation.defs#reasonSpam`",
//! etc.) — see `crate::server::create_report` (the user-direct intake module)'s
//! `ACCEPTED_REASON_TYPES`. The gateway uses the same allowlist:
//! the mapping is the identity function.
//!
//! # No rate-limiting / suppression / disk-guard on this path
//!
//! The user-direct intake at `crate::server::create_report` (the user-direct intake module)
//! applies per-DID rate limits, a suppression list, a global
//! pending cap, and a disk guard before INSERT. The gateway path
//! intentionally does NOT replicate those: per §A10 the trust
//! gate is xrpc_trusted_pdses membership (operators only add
//! upstream PDSes they trust), and per-PDS rate limiting is a
//! deferred v1.8 concern. If an operator wants the user-direct
//! gates, they can keep their PDS off `xrpc_trusted_pdses` and
//! point clients at the user-direct route instead.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;

use crate::xrpc_gateway::XrpcAuthClaims;

use super::XrpcGatewayState;

/// `reasonType` allowlist — identical to the user-direct path's
/// `crate::server::create_report` (the user-direct intake module) allowlist (§F11). Widening
/// here without widening there would surface PDS-forwarded reports
/// the user-direct intake rejects, which is operator-confusing.
/// Keep these two arrays in lockstep.
const ACCEPTED_REASON_TYPES: &[&str] = &[
    "com.atproto.moderation.defs#reasonSpam",
    "com.atproto.moderation.defs#reasonViolation",
    "com.atproto.moderation.defs#reasonMisleading",
    "com.atproto.moderation.defs#reasonSexual",
    "com.atproto.moderation.defs#reasonRude",
    "com.atproto.moderation.defs#reasonOther",
];

/// §F11's reason-length cap. Same constant as the user-direct
/// path; mirroring rather than re-exporting because that module's
/// helper is `pub(super)`-scoped to the server router.
const REASON_MAX_BYTES: usize = 2048;

/// RFC-3339 Z with ms precision, matching the wire form
/// `reports.created_at` uses everywhere else in the codebase
/// (writer's audit cts, the user-direct intake's reply, etc).
const CTS_FORMAT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

// ==========================================================================
// Wire types — input
// ==========================================================================

/// Wire shape of `com.atproto.moderation.createReport`'s request body
/// when forwarded by an upstream PDS.
///
/// Compared to the user-direct intake's `CreateReportInput`
/// (in `src/server/create_report.rs`): the body carries an explicit
/// `reportedBy` field. The user-direct path derives `reportedBy`
/// from `claims.iss` (the user authenticates to their own PDS,
/// then to cairn-mod, with the same DID). The gateway path's
/// `claims.iss` is the PDS — the user identity must come from the
/// body.
#[derive(Debug, Deserialize)]
pub struct CreateReportRequest {
    /// Lexicon `$type` string identifying the reason (e.g.,
    /// `"com.atproto.moderation.defs#reasonSpam"`). Must be in
    /// the allowlist.
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    /// Optional moderator-facing free-form rationale. Capped at
    /// 2 KB.
    #[serde(default)]
    pub reason: Option<String>,
    /// Discriminated subject — account-level (`repoRef`) or
    /// per-record (`strongRef`).
    pub subject: ReportSubject,
    /// DID the PDS asserts originated this report. Stored verbatim
    /// in `reports.reported_by`. cairn-mod cannot cryptographically
    /// verify this; trust comes from the PDS's own membership in
    /// `xrpc_trusted_pdses` (§A10, threat-model §4.9).
    #[serde(rename = "reportedBy")]
    pub reported_by: String,
}

/// Discriminated subject. v1.7 accepts both account-level
/// (`repoRef`) and per-record (`strongRef`) subjects — unlike
/// emitEvent, which only accepts `repoRef`. Reports against
/// specific records are a normal user flow ("report this post").
#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub enum ReportSubject {
    /// Account-level subject. Maps to
    /// `reports.subject_type='account'` with the account DID in
    /// `subject_did`.
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    RepoRef {
        /// The reported account's DID.
        did: String,
    },

    /// Per-record subject. Maps to `reports.subject_type='record'`;
    /// the parent repo DID is extracted from the AT-URI's
    /// authority and stored in `subject_did`, with the URI + CID
    /// preserved in `subject_uri` / `subject_cid`.
    #[serde(rename = "com.atproto.repo.strongRef")]
    StrongRef {
        /// AT-URI of the reported record (e.g.,
        /// `at://did:plc:abc/app.bsky.feed.post/rkey`).
        uri: String,
        /// CID of the reported record's content.
        cid: String,
    },
}

// ==========================================================================
// Wire types — output
// ==========================================================================

/// Response shape per `com.atproto.moderation.defs#reportView`.
/// Echoes the request's `reasonType` / `reason` / `subject` /
/// `reportedBy` and adds the just-inserted row's `id` +
/// `createdAt`.
#[derive(Debug, Serialize)]
pub struct ReportView {
    /// `reports.id` of the just-inserted row.
    pub id: i64,
    /// Echoed lexicon `$type` reason.
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    /// Echoed optional rationale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Echoed subject — same JSON bytes the caller sent (preserves
    /// any forward-compat fields cairn-mod doesn't recognize).
    pub subject: Value,
    /// Echoed asserted reporter DID.
    #[serde(rename = "reportedBy")]
    pub reported_by: String,
    /// RFC-3339-Z timestamp the writer assigned at INSERT time.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

// ==========================================================================
// Handler
// ==========================================================================

/// Handler entry point. Wired into the gateway router by
/// [`crate::xrpc_gateway::router::build_router`] for
/// `POST /xrpc/com.atproto.moderation.createReport`.
///
/// Pipeline:
/// 1. Parse the request body. Malformed JSON → 400 `InvalidRequest`.
/// 2. Validate `reasonType` against the allowlist + `reason`
///    length cap. Failure → 400.
/// 3. Validate the subject discriminator (DID syntax, AT-URI
///    syntax, CID non-empty). Failure → 400.
/// 4. Validate `reportedBy` is DID-shaped — defense-in-depth so a
///    malformed PDS-asserted DID can't poison the table.
/// 5. INSERT into `reports` and read back the assigned `id`.
/// 6. Build the [`ReportView`] response, echoing the original
///    `subject` bytes from the parsed input.
pub(crate) async fn handler(
    Extension(state): Extension<XrpcGatewayState>,
    Extension(_claims): Extension<XrpcAuthClaims>,
    body: Bytes,
) -> Response {
    let req: CreateReportRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return invalid_request(format!("malformed request body: {e}")),
    };

    if !ACCEPTED_REASON_TYPES.contains(&req.reason_type.as_str()) {
        return invalid_request(format!("unsupported reasonType: {}", req.reason_type));
    }

    if let Some(reason) = &req.reason
        && reason.len() > REASON_MAX_BYTES
    {
        return invalid_request("reason exceeds maximum length".to_string());
    }

    if !req.reported_by.starts_with("did:") {
        return invalid_request(format!("reportedBy {:?} is not a DID", req.reported_by));
    }

    let translated = match translate_subject(&req.subject) {
        Ok(t) => t,
        Err(msg) => return invalid_request(msg),
    };

    let created_at = match rfc3339_now() {
        Ok(s) => s,
        Err(()) => {
            tracing::error!("xrpc_gateway createReport: rfc3339 formatting failed");
            return internal_server_error();
        }
    };

    let id = match insert_report(&state.pool, &req, &translated, &created_at).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(
                error = %e,
                "xrpc_gateway createReport: reports INSERT failed"
            );
            return internal_server_error();
        }
    };

    let view = ReportView {
        id,
        reason_type: req.reason_type,
        reason: req.reason,
        subject: subject_to_json(&req.subject),
        reported_by: req.reported_by,
        created_at,
    };
    (StatusCode::OK, Json(view)).into_response()
}

// ==========================================================================
// Helpers
// ==========================================================================

/// Internal projection of a [`ReportSubject`] into the columns the
/// `reports` table requires. Mirrors the user-direct intake's
/// translation at `crate::server::create_report` (the user-direct intake module) line 282–313.
#[derive(Debug)]
struct TranslatedSubject {
    subject_type: &'static str,
    subject_did: String,
    subject_uri: Option<String>,
    subject_cid: Option<String>,
}

fn translate_subject(subject: &ReportSubject) -> Result<TranslatedSubject, String> {
    match subject {
        ReportSubject::RepoRef { did } => {
            if !did.starts_with("did:") {
                return Err(format!("subject.did {did:?} is not a DID"));
            }
            Ok(TranslatedSubject {
                subject_type: "account",
                subject_did: did.clone(),
                subject_uri: None,
                subject_cid: None,
            })
        }
        ReportSubject::StrongRef { uri, cid } => {
            if !uri.starts_with("at://") {
                return Err(format!("subject.uri {uri:?} is not an AT-URI"));
            }
            if cid.is_empty() {
                return Err("subject.cid must be non-empty".to_string());
            }
            let did = extract_did_from_at_uri(uri)
                .ok_or_else(|| format!("subject.uri {uri:?} missing DID authority"))?
                .to_string();
            Ok(TranslatedSubject {
                subject_type: "record",
                subject_did: did,
                subject_uri: Some(uri.clone()),
                subject_cid: Some(cid.clone()),
            })
        }
    }
}

async fn insert_report(
    pool: &Pool<Sqlite>,
    req: &CreateReportRequest,
    translated: &TranslatedSubject,
    created_at: &str,
) -> sqlx::Result<i64> {
    let subject_type = translated.subject_type;
    sqlx::query_scalar!(
        r#"INSERT INTO reports (
             created_at, reported_by, reason_type, reason,
             subject_type, subject_did, subject_uri, subject_cid, status
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending')
         RETURNING id as "id!: i64""#,
        created_at,
        req.reported_by,
        req.reason_type,
        req.reason,
        subject_type,
        translated.subject_did,
        translated.subject_uri,
        translated.subject_cid,
    )
    .fetch_one(pool)
    .await
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

fn subject_to_json(s: &ReportSubject) -> Value {
    match s {
        ReportSubject::RepoRef { did } => serde_json::json!({
            "$type": "com.atproto.admin.defs#repoRef",
            "did": did,
        }),
        ReportSubject::StrongRef { uri, cid } => serde_json::json!({
            "$type": "com.atproto.repo.strongRef",
            "uri": uri,
            "cid": cid,
        }),
    }
}

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
    use serde_json::json;

    // ===== reasonType allowlist =====

    #[test]
    fn accepted_reason_types_match_user_direct_intake() {
        // Same allowlist size + entries as the user-direct intake's
        // ACCEPTED_REASON_TYPES (src/server/create_report.rs).
        // Drift would silently accept on one path while rejecting
        // on the other. Pinned at 6.
        assert_eq!(ACCEPTED_REASON_TYPES.len(), 6);
        for t in [
            "com.atproto.moderation.defs#reasonSpam",
            "com.atproto.moderation.defs#reasonViolation",
            "com.atproto.moderation.defs#reasonMisleading",
            "com.atproto.moderation.defs#reasonSexual",
            "com.atproto.moderation.defs#reasonRude",
            "com.atproto.moderation.defs#reasonOther",
        ] {
            assert!(ACCEPTED_REASON_TYPES.contains(&t), "missing {t}");
        }
    }

    // ===== translate_subject =====

    #[test]
    fn translate_repo_ref_subject() {
        let s = ReportSubject::RepoRef {
            did: "did:plc:account".into(),
        };
        let t = translate_subject(&s).unwrap();
        assert_eq!(t.subject_type, "account");
        assert_eq!(t.subject_did, "did:plc:account");
        assert!(t.subject_uri.is_none());
        assert!(t.subject_cid.is_none());
    }

    #[test]
    fn translate_strong_ref_extracts_did_authority() {
        let s = ReportSubject::StrongRef {
            uri: "at://did:plc:author/app.bsky.feed.post/abc".into(),
            cid: "bafy123".into(),
        };
        let t = translate_subject(&s).unwrap();
        assert_eq!(t.subject_type, "record");
        assert_eq!(t.subject_did, "did:plc:author");
        assert_eq!(
            t.subject_uri.as_deref(),
            Some("at://did:plc:author/app.bsky.feed.post/abc")
        );
        assert_eq!(t.subject_cid.as_deref(), Some("bafy123"));
    }

    #[test]
    fn translate_repo_ref_rejects_non_did_authority() {
        let s = ReportSubject::RepoRef {
            did: "not-a-did".into(),
        };
        let err = translate_subject(&s).unwrap_err();
        assert!(err.contains("not a DID"), "{err}");
    }

    #[test]
    fn translate_strong_ref_rejects_https_uri() {
        let s = ReportSubject::StrongRef {
            uri: "https://example.com/post".into(),
            cid: "bafy".into(),
        };
        let err = translate_subject(&s).unwrap_err();
        assert!(err.contains("AT-URI"), "{err}");
    }

    #[test]
    fn translate_strong_ref_rejects_empty_cid() {
        let s = ReportSubject::StrongRef {
            uri: "at://did:plc:a/c/r".into(),
            cid: "".into(),
        };
        let err = translate_subject(&s).unwrap_err();
        assert!(err.contains("cid"), "{err}");
    }

    #[test]
    fn translate_strong_ref_rejects_uri_without_did_authority() {
        let s = ReportSubject::StrongRef {
            uri: "at://example.com/c/r".into(),
            cid: "bafy".into(),
        };
        let err = translate_subject(&s).unwrap_err();
        assert!(err.contains("DID authority"), "{err}");
    }

    // ===== Subject deserialization =====

    #[test]
    fn deserialize_repo_ref_subject() {
        let v = json!({
            "$type": "com.atproto.admin.defs#repoRef",
            "did": "did:plc:abc"
        });
        let s: ReportSubject = serde_json::from_value(v).unwrap();
        assert!(matches!(s, ReportSubject::RepoRef { did } if did == "did:plc:abc"));
    }

    #[test]
    fn deserialize_strong_ref_subject() {
        let v = json!({
            "$type": "com.atproto.repo.strongRef",
            "uri": "at://did:plc:abc/c/r",
            "cid": "bafy"
        });
        let s: ReportSubject = serde_json::from_value(v).unwrap();
        match s {
            ReportSubject::StrongRef { uri, cid } => {
                assert_eq!(uri, "at://did:plc:abc/c/r");
                assert_eq!(cid, "bafy");
            }
            other => panic!("expected StrongRef, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_full_request_round_trip() {
        let body = json!({
            "reasonType": "com.atproto.moderation.defs#reasonSpam",
            "reason": "looks like spam",
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": "did:plc:target",
            },
            "reportedBy": "did:plc:reporter",
        });
        let req: CreateReportRequest = serde_json::from_value(body).unwrap();
        assert_eq!(req.reason_type, "com.atproto.moderation.defs#reasonSpam");
        assert_eq!(req.reason.as_deref(), Some("looks like spam"));
        assert_eq!(req.reported_by, "did:plc:reporter");
    }

    // ===== AT-URI helper =====

    #[test]
    fn extract_did_from_at_uri_basic() {
        assert_eq!(
            extract_did_from_at_uri("at://did:plc:abc/c/r"),
            Some("did:plc:abc")
        );
        assert_eq!(extract_did_from_at_uri("https://x"), None);
        assert_eq!(extract_did_from_at_uri("at://example.com/c/r"), None);
    }
}
