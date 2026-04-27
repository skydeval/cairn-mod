//! Scaffolding shared across every `tools.cairn.admin.*` handler:
//! role resolution from the `moderators` table, CORS "reject any
//! Origin" for server-to-server-only endpoints, a unified
//! [`AdminError`] taxonomy, and the combined auth+CORS+role gate
//! every handler runs first.
//!
//! §F12's "service auth on every admin endpoint … role-based
//! authorization" is implemented here once, not in each handler.

use std::sync::Arc;

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{Pool, Sqlite};

use crate::auth::AuthContext;
use crate::moderators::Role;
use crate::writer::WriterHandle;

use super::AdminConfig;

/// Auth + role + CORS outcome for a single admin request. Handlers
/// read `caller_did` for audit attribution and branch on `role` for
/// finer authorization (e.g., listAuditLog requires Admin).
#[derive(Debug, Clone)]
pub(super) struct VerifiedAdmin {
    pub caller_did: String,
    pub role: Role,
    /// DID-document verification method id that signed the JWT. Kept
    /// here so write-side handlers can include it in audit entries
    /// without re-deriving it.
    #[allow(dead_code)]
    pub key_id: String,
}

/// Shared state every admin handler receives via `Extension`.
/// Per-handler modules then borrow the pieces they need.
#[derive(Clone)]
pub(super) struct AdminState {
    pub pool: Pool<Sqlite>,
    pub writer: WriterHandle,
    pub auth: Arc<AuthContext>,
    pub config: Arc<AdminConfig>,
    /// Resolved [strike_policy] (#48). The strikes read endpoint
    /// (#52 / read-half of #53) consults the threshold, decay
    /// shape, and decay_window_days when projecting the strike-state
    /// envelope. Same instance the writer task holds (cloned at
    /// admin_router construction).
    pub strike_policy: Arc<crate::moderation::policy::StrikePolicy>,
}

/// Error taxonomy for admin endpoints. Variants carry **only**
/// whatever information the handler already computed — nothing that
/// would reveal a per-case reason to the client, per §4
/// non-enumeration. The `IntoResponse` impl below produces the
/// XRPC-convention body `{ "error": "<Name>", "message": "<generic>" }`.
#[derive(Debug)]
pub(super) enum AdminError {
    AuthenticationRequired,
    Forbidden,
    InvalidRequest(&'static str),
    /// Owned-string variant of `InvalidRequest` for messages that
    /// can't be `'static` (e.g., dynamic validation errors from the
    /// writer's input checks). Same 400 status / `InvalidRequest`
    /// XRPC error code; the variant just owns the body.
    InvalidRequestOwned(String),
    /// Declared in lexicons/tools/cairn/admin/negateLabel.json.
    LabelNotFound,
    /// Declared in lexicons/tools/cairn/admin/{getReport,resolveReport}.json.
    ReportNotFound,
    /// Declared in lexicons/tools/cairn/admin/getAuditLog.json.
    AuditEntryNotFound,
    /// Declared in lexicons/tools/cairn/admin/{applyLabel,resolveReport}.json.
    /// Message MUST NOT enumerate the allowed label values — same
    /// anti-leak principle as #14's reason-length guard.
    InvalidLabelValue,
    /// Declared in lexicons/tools/cairn/admin/recordAction.json (#51).
    InvalidReason,
    /// Declared in lexicons/tools/cairn/admin/recordAction.json (#51).
    InvalidActionType,
    /// Declared in lexicons/tools/cairn/admin/recordAction.json (#51).
    DurationRequired,
    /// Declared in lexicons/tools/cairn/admin/recordAction.json (#51).
    DurationNotAllowed,
    /// Declared in lexicons/tools/cairn/admin/recordAction.json (#51).
    SubjectUriMismatch,
    /// Declared in lexicons/tools/cairn/admin/revokeAction.json (#51).
    ActionNotFound,
    /// Declared in lexicons/tools/cairn/admin/revokeAction.json (#51).
    ActionAlreadyRevoked,
    /// Declared in lexicons/tools/cairn/admin/confirmPendingAction.json (#74).
    PendingActionNotFound,
    /// Declared in lexicons/tools/cairn/admin/confirmPendingAction.json (#74).
    PendingAlreadyResolved,
    /// Declared in lexicons/tools/cairn/admin/confirmPendingAction.json (#74).
    SubjectTakendown,
    /// Declared in lexicons/tools/cairn/admin/getSubjectHistory.json
    /// + getSubjectStrikes.json (#52 / read-half of #53).
    SubjectNotFound,
    Internal,
}

/// Error body for static-message variants. Static `&str` lets the
/// majority of error responses skip an allocation. The
/// owned-message variants below wrap an [`OwnedErrorBody`].
#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: &'static str,
}

/// Error body for variants that carry a runtime-formatted message
/// (e.g., [`AdminError::InvalidRequestOwned`]).
#[derive(Serialize)]
struct OwnedErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        // Owned-message variants take a different early-exit path so
        // ErrorBody can stay `'static`-only.
        if let AdminError::InvalidRequestOwned(msg) = self {
            return (
                StatusCode::BAD_REQUEST,
                Json(OwnedErrorBody {
                    error: "InvalidRequest",
                    message: msg,
                }),
            )
                .into_response();
        }

        let (status, body) = match self {
            AdminError::InvalidRequestOwned(_) => unreachable!("handled above"),
            AdminError::AuthenticationRequired => (
                StatusCode::UNAUTHORIZED,
                ErrorBody {
                    error: "AuthenticationRequired",
                    message: "authentication required",
                },
            ),
            AdminError::Forbidden => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "Forbidden",
                    message: "forbidden",
                },
            ),
            AdminError::InvalidRequest(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "InvalidRequest",
                    message: msg,
                },
            ),
            AdminError::LabelNotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "LabelNotFound",
                    message: "no applied label for the given tuple",
                },
            ),
            AdminError::ReportNotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "ReportNotFound",
                    message: "report not found",
                },
            ),
            AdminError::AuditEntryNotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "AuditEntryNotFound",
                    message: "audit entry not found",
                },
            ),
            AdminError::InvalidLabelValue => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "InvalidLabelValue",
                    message: "label value not accepted by this labeler",
                },
            ),
            AdminError::InvalidReason => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "InvalidReason",
                    message: "reason identifier not declared in [moderation_reasons]",
                },
            ),
            AdminError::InvalidActionType => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "InvalidActionType",
                    message: "type must be one of warning / note / temp_suspension / indef_suspension / takedown",
                },
            ),
            AdminError::DurationRequired => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "DurationRequired",
                    message: "duration is required for type=temp_suspension",
                },
            ),
            AdminError::DurationNotAllowed => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "DurationNotAllowed",
                    message: "duration is only valid for type=temp_suspension",
                },
            ),
            AdminError::SubjectUriMismatch => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "SubjectUriMismatch",
                    message: "subject URI repo does not match subject_did",
                },
            ),
            AdminError::ActionNotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "ActionNotFound",
                    message: "subject action not found",
                },
            ),
            AdminError::ActionAlreadyRevoked => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "ActionAlreadyRevoked",
                    message: "subject action is already revoked",
                },
            ),
            AdminError::PendingActionNotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "PendingActionNotFound",
                    message: "pending policy action not found",
                },
            ),
            AdminError::PendingAlreadyResolved => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "PendingAlreadyResolved",
                    message: "pending policy action is already resolved",
                },
            ),
            AdminError::SubjectTakendown => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "SubjectTakendown",
                    message: "subject is already taken down; confirm not permitted",
                },
            ),
            AdminError::SubjectNotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "SubjectNotFound",
                    message: "no actions recorded for subject",
                },
            ),
            AdminError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "InternalServerError",
                    message: "service temporarily unavailable",
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

/// Combined gate: CORS → auth → role. Every admin handler calls this
/// as its first step.
///
/// CORS posture (§F12 + §5 admin context): admin endpoints are for
/// server-to-server and CLI use. A request with any `Origin` header
/// implies a browser, which we reject outright — 403, no allowlist.
/// Non-`Origin` requests proceed to auth.
pub(super) async fn verify_and_authorize(
    state: &AdminState,
    headers: &HeaderMap,
    lxm: &str,
) -> Result<VerifiedAdmin, AdminError> {
    // 1. CORS: admin API is not for browsers. Presence of Origin is
    // reason enough to reject before paying auth cost.
    if headers.contains_key("origin") {
        return Err(AdminError::Forbidden);
    }

    // 2. Auth.
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(AdminError::AuthenticationRequired)?;

    let caller = state
        .auth
        .verify_service_auth(token, lxm)
        .await
        .map_err(|_| AdminError::AuthenticationRequired)?;

    // 3. Role lookup. Per §F12 non-enumeration: "no such moderator"
    // and "wrong role" both return 403 — the client can't distinguish
    // them from each other or from "valid auth, method not permitted."
    let row = sqlx::query!("SELECT role FROM moderators WHERE did = ?1", caller.iss)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| AdminError::Internal)?;

    let role = match row.as_ref().map(|r| r.role.as_str()) {
        Some("admin") => Role::Admin,
        Some("mod") => Role::Mod,
        Some(_) => return Err(AdminError::Internal), // CHECK violation — shouldn't happen
        None => return Err(AdminError::Forbidden),
    };

    Ok(VerifiedAdmin {
        caller_did: caller.iss,
        role,
        key_id: caller.key_id,
    })
}

/// Admin-only variant — used by listAuditLog. Mod role gets 403 just
/// like an unknown caller would.
pub(super) async fn verify_and_authorize_admin_only(
    state: &AdminState,
    headers: &HeaderMap,
    lxm: &str,
) -> Result<VerifiedAdmin, AdminError> {
    let v = verify_and_authorize(state, headers, lxm).await?;
    if v.role != Role::Admin {
        return Err(AdminError::Forbidden);
    }
    Ok(v)
}
