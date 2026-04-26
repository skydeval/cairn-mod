//! `tools.cairn.admin.flagReporter` handler.
//!
//! Writes directly to `suppressed_reporters` + `audit_log` in one
//! transaction. Does NOT go through the writer task — no label
//! sequence allocation, no cts clamp, no broadcast. §F5's
//! single-writer invariant is about label emission specifically;
//! non-label admin writes with bounded transactional scope don't
//! need to serialize through it.
//!
//! Semantics per §F11 + §F9:
//! - `suppressed: true` — INSERT OR REPLACE into
//!   `suppressed_reporters` + audit `reporter_flagged`.
//! - `suppressed: false` — DELETE from `suppressed_reporters`
//!   (silently no-op if not present) + audit `reporter_unflagged`.
//!   §E (confirmed) — idempotent; the audit row is the record of
//!   operator intent regardless of prior state.

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::writer::build_flag_reporter_audit_reason;

use super::common::{AdminError, AdminState, verify_and_authorize};

const LXM: &str = "tools.cairn.admin.flagReporter";

#[derive(Debug, Deserialize)]
struct Input {
    did: String,
    suppressed: bool,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {}

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let admin = match verify_and_authorize(&state, &headers, LXM).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let input: Input = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return AdminError::InvalidRequest("malformed request body").into_response(),
    };
    if !input.did.starts_with("did:") {
        return AdminError::InvalidRequest("did must start with did:").into_response();
    }

    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(_) => return AdminError::Internal.into_response(),
    };

    let now_ms = crate::writer::epoch_ms_now();
    let audit_reason =
        build_flag_reporter_audit_reason(&input.did, input.suppressed, input.reason.as_deref());

    if input.suppressed {
        // Upsert: a DID may be flagged multiple times without error
        // (each flag becomes the current record). `suppressed_by`
        // and `suppressed_at` reflect the MOST RECENT flag.
        let res = sqlx::query!(
            "INSERT INTO suppressed_reporters (did, suppressed_by, suppressed_at, reason)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(did) DO UPDATE SET
                 suppressed_by = excluded.suppressed_by,
                 suppressed_at = excluded.suppressed_at,
                 reason = excluded.reason",
            input.did,
            admin.caller_did,
            now_ms,
            input.reason,
        )
        .execute(&mut *tx)
        .await;
        if res.is_err() {
            return AdminError::Internal.into_response();
        }

        let res = crate::audit::append::append_in_tx(
            &mut tx,
            &crate::audit::append::AuditRowForAppend {
                created_at: now_ms,
                action: "reporter_flagged".into(),
                actor_did: admin.caller_did.clone(),
                target: Some(input.did.clone()),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await;
        if res.is_err() {
            return AdminError::Internal.into_response();
        }
    } else {
        // Idempotent unflag — DELETE of a nonexistent row is a no-op
        // in SQLite. The audit row below still lands, preserving the
        // operator-intent record regardless of prior state.
        let res = sqlx::query!("DELETE FROM suppressed_reporters WHERE did = ?1", input.did)
            .execute(&mut *tx)
            .await;
        if res.is_err() {
            return AdminError::Internal.into_response();
        }

        let res = crate::audit::append::append_in_tx(
            &mut tx,
            &crate::audit::append::AuditRowForAppend {
                created_at: now_ms,
                action: "reporter_unflagged".into(),
                actor_did: admin.caller_did.clone(),
                target: Some(input.did.clone()),
                target_cid: None,
                outcome: "success".into(),
                reason: Some(audit_reason),
            },
        )
        .await;
        if res.is_err() {
            return AdminError::Internal.into_response();
        }
    }

    if tx.commit().await.is_err() {
        return AdminError::Internal.into_response();
    }

    Json(Output {}).into_response()
}
