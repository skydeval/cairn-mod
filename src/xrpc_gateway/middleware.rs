//! Tower middleware for inbound JWT verification (#93, v1.7).
//!
//! Wraps the entire xrpc_gateway router. Auth verification runs
//! BEFORE NSID dispatch, so cryptographically-valid-but-mismatched
//! JWTs are rejected at this layer rather than reaching the
//! (still-stub in v1.7) handlers.
//!
//! # Pass-through for unknown NSIDs
//!
//! When the request URL doesn't match an allowlisted NSID, the
//! middleware **passes the request through without auth**. The
//! router's fallback handler then returns 501 with the standard
//! envelope (per #92).
//!
//! Trade-off: an attacker can probe NSID liveness via "send no
//! auth, see 401-vs-501". Acceptable for v1.7 because the NSID
//! set is hard-coded — a probe-based discovery just yields the
//! same set anyone could read from cairn-mod's public source.
//! The alternative (uniform 401 for everything) would force the
//! middleware to know the full router shape, which couples
//! layers we want kept separable.
//!
//! # Replay defense
//!
//! NOT implemented in this middleware. #94 adds a sibling layer
//! that runs the replay-cache check + `xrpc_known_callers`
//! membership gate. Composition order will matter (auth must run
//! first so an unauthenticated probe can't pollute the replay
//! cache); flagging for #94.
//!
//! # Claims surface
//!
//! On verification success, the middleware sets a request
//! extension carrying [`crate::xrpc_gateway::XrpcAuthClaims`].
//! #95-#98 handlers will consume it via axum's
//! `Extension<XrpcAuthClaims>` extractor:
//!
//! ```rust,ignore
//! async fn handle_emit_event(
//!     Extension(claims): Extension<XrpcAuthClaims>,
//!     // ...other extractors...
//! ) -> Response {
//!     // claims.iss is the originating user's DID
//! }
//! ```

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{Pool, Sqlite};

use crate::xrpc_gateway::Nsid;
use crate::xrpc_gateway::auth::{XrpcAuthClaims, XrpcAuthService};
use crate::xrpc_gateway::error::XrpcAuthError;
use crate::xrpc_gateway::membership;
use crate::xrpc_gateway::nsid::extract_nsid_from_request_uri;
use crate::xrpc_gateway::replay::{ReplayCheck, XrpcReplayCache};

/// Middleware body, applied by [`crate::xrpc_gateway::router::build_router`]
/// via `axum::middleware::from_fn_with_state(auth_service,
/// xrpc_auth_middleware)`.
///
/// `pub(crate)` rather than wrapped in a typed `Layer` factory:
/// `axum::middleware::FromFnLayer`'s type signature with explicit
/// async-fn pointer types is brittle across axum minor versions.
/// Routing this through `from_fn_with_state` at the call site
/// keeps the type plumbing inside axum's stable surface.
pub(crate) async fn xrpc_auth_middleware(
    State(auth_service): State<Arc<XrpcAuthService>>,
    mut req: Request,
    next: Next,
) -> Response {
    // 1. Extract NSID. If the URL isn't `/xrpc/<allowlisted>`,
    // pass through — the router's fallback will return 501. The
    // middleware doesn't second-guess the router's NSID surface.
    let Some(nsid) = extract_nsid_from_request_uri(req.uri()) else {
        return next.run(req).await;
    };

    // 2. Extract Bearer token from Authorization header.
    let token = match extract_bearer_token(&req) {
        Ok(t) => t,
        Err(e) => return auth_error_response(&e),
    };

    // 3. Verify. Auth-failure short-circuits with the appropriate
    // 401 / 403 envelope.
    let claims = match auth_service.verify(token, nsid).await {
        Ok(c) => c,
        Err(e) => {
            // Log at WARN per the auth-error surface convention.
            // The Display impl on XrpcAuthError carries enough
            // context (issuer DID, NSID, etc.) for forensic
            // correlation without leaking secrets.
            tracing::warn!(
                error = %e,
                "xrpc_gateway auth verification failed"
            );
            return auth_error_response(&e);
        }
    };

    // 4. Stash claims as a request extension so the handler can
    // pick them up via `Extension<XrpcAuthClaims>`. #95-#98 will
    // do exactly this.
    req.extensions_mut().insert(claims);

    next.run(req).await
}

/// Pull the bearer token out of the `Authorization: Bearer <jwt>`
/// header.
fn extract_bearer_token(req: &Request) -> Result<&str, XrpcAuthError> {
    let header_value = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(XrpcAuthError::MissingOrMalformedAuthHeader)?;
    let header_str = header_value
        .to_str()
        .map_err(|_| XrpcAuthError::MissingOrMalformedAuthHeader)?;
    let token = header_str
        .strip_prefix("Bearer ")
        .ok_or(XrpcAuthError::MissingOrMalformedAuthHeader)?;
    if token.is_empty() {
        return Err(XrpcAuthError::MissingOrMalformedAuthHeader);
    }
    Ok(token)
}

/// Render an [`XrpcAuthError`] into the XRPC error envelope
/// response. Reuses the same JSON wire shape as #91/#92's 501/405
/// envelopes (`{"error": ..., "message": ...}`) with the auth-
/// specific status code from
/// [`XrpcAuthError::http_status`] and code from
/// [`XrpcAuthError::xrpc_error_code`].
fn auth_error_response(err: &XrpcAuthError) -> Response {
    let body = AuthErrorEnvelope {
        error: err.xrpc_error_code(),
        message: err.to_string(),
    };
    (err.http_status(), axum::Json(body)).into_response()
}

/// Wire shape of the auth-error envelope. Identical fields to
/// #91/#92's `XrpcErrorEnvelope`, but a separate type so the
/// `error` field can be `&'static str` (the static codes from
/// [`XrpcAuthError::xrpc_error_code`]) without coupling to
/// router.rs's envelope.
#[derive(Serialize)]
struct AuthErrorEnvelope {
    error: &'static str,
    message: String,
}

// ===========================================================================
// Membership middleware (#94)
// ===========================================================================

/// Tower middleware body that gates inbound requests by per-NSID
/// membership.
///
/// Runs AFTER [`xrpc_auth_middleware`] (so it has
/// [`XrpcAuthClaims`] in the request extensions). Runs BEFORE
/// [`xrpc_replay_middleware`] (so unauthorized callers don't
/// pollute the replay cache).
///
/// For [`Nsid::ComAtprotoModerationCreateReport`]: checks
/// `claims.iss` against `xrpc_trusted_pdses` (the JWT issuer is
/// the PDS forwarding the report).
///
/// For the `tools.ozone.moderation.*` NSIDs: checks `claims.iss`
/// against `xrpc_known_callers` (the JWT issuer is the
/// originating user / moderator).
///
/// On membership-miss: 403 Forbidden with envelope code
/// `"AccountTakedown"` per the bsky-PDS / ATProto convention for
/// "credential is valid but you're not authorized for this
/// resource". Operators see the actual reason in the WARN log
/// line; the wire envelope stays uniform across the gateway's
/// 403 surface.
///
/// `pub(crate)` and applied via
/// `axum::middleware::from_fn_with_state` at the router build
/// site. Not exposed as a typed `Layer` factory for the same
/// reason as [`xrpc_auth_middleware`] (axum's `FromFnLayer` type
/// signature is brittle across minor versions).
pub(crate) async fn xrpc_membership_middleware(
    State(pool): State<Pool<Sqlite>>,
    req: Request,
    next: Next,
) -> Response {
    // Pass through paths the gateway router won't dispatch
    // (unknown NSID → router fallback returns 501). The auth
    // middleware uses the same "skip on unknown NSID" pattern;
    // membership inherits.
    let Some(nsid) = extract_nsid_from_request_uri(req.uri()) else {
        return next.run(req).await;
    };

    // Pull the auth-set claims from the request extensions.
    // Reaching membership-middleware without claims means the
    // auth middleware is composed wrong (or not at all) — fail
    // closed with a 401 rather than silently bypassing.
    let Some(claims) = req.extensions().get::<XrpcAuthClaims>() else {
        tracing::error!(
            nsid = nsid.as_path_segment(),
            "xrpc_gateway membership middleware: no XrpcAuthClaims extension found. \
             auth middleware is not composed correctly — failing closed."
        );
        return auth_error_response(&XrpcAuthError::MissingOrMalformedAuthHeader);
    };
    let iss = claims.iss.clone();

    let allowed = match nsid {
        Nsid::ComAtprotoModerationCreateReport => membership::is_trusted_pds(&pool, &iss).await,
        Nsid::ToolsOzoneModerationEmitEvent
        | Nsid::ToolsOzoneModerationQueryStatuses
        | Nsid::ToolsOzoneModerationQueryEvents => membership::is_known_caller(&pool, &iss).await,
    };

    match allowed {
        Ok(true) => next.run(req).await,
        Ok(false) => {
            tracing::warn!(
                iss = iss,
                nsid = nsid.as_path_segment(),
                "xrpc_gateway membership: issuer not authorized for this NSID"
            );
            membership_forbidden_response(&iss, nsid)
        }
        Err(e) => {
            // DB query failure. Fail closed with a 403 — better
            // to over-reject than to under-reject. Operators see
            // the cause in the ERROR log.
            tracing::error!(
                error = %e,
                iss = iss,
                nsid = nsid.as_path_segment(),
                "xrpc_gateway membership: lookup failed; failing closed"
            );
            membership_forbidden_response(&iss, nsid)
        }
    }
}

fn membership_forbidden_response(iss: &str, nsid: Nsid) -> Response {
    let body = AuthErrorEnvelope {
        // bsky-PDS / ATProto convention for "valid credential,
        // not authorized for this resource" per findings §6.3 is
        // `AccountTakedown` in the takedown-related responses
        // and a more general `NotAuthorized` elsewhere. v1.7
        // uses `AccountTakedown` here because the gateway's
        // membership table semantics ("this DID isn't on our
        // allowlist") match how bsky-PDS surfaces moderation
        // gating to clients.
        error: "AccountTakedown",
        message: format!(
            "issuer {iss} is not authorized for {}",
            nsid.as_path_segment()
        ),
    };
    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
}

// ===========================================================================
// Replay middleware (#94)
// ===========================================================================

/// Tower middleware body that deduplicates inbound JWTs by
/// `(iss, jti)`.
///
/// Runs AFTER auth + membership (so only fully-authorized
/// requests consume cache slots — keeps the cache small and
/// reduces abuse surface).
///
/// On replay detection: 400 Bad Request with envelope code
/// `"ExpiredToken"` per the principle established in #93:
/// minimize information leakage in wire envelopes. Operators see
/// "replay detected" in logs; callers see "token no longer
/// accepted" — same UX outcome (mint a fresh token + retry).
///
/// `pub(crate)` and applied via
/// `axum::middleware::from_fn_with_state`.
pub(crate) async fn xrpc_replay_middleware(
    State(cache): State<Arc<XrpcReplayCache>>,
    req: Request,
    next: Next,
) -> Response {
    // Pass through unknown NSIDs (consistent with the auth +
    // membership pass-through behavior).
    if extract_nsid_from_request_uri(req.uri()).is_none() {
        return next.run(req).await;
    }

    let Some(claims) = req.extensions().get::<XrpcAuthClaims>() else {
        // Reaching replay-middleware without claims means the
        // auth middleware didn't run (composition bug). Fail
        // closed at 401 — same posture as the membership
        // middleware. Defense-in-depth.
        tracing::error!(
            "xrpc_gateway replay middleware: no XrpcAuthClaims extension found. \
             auth middleware is not composed correctly — failing closed."
        );
        return auth_error_response(&XrpcAuthError::MissingOrMalformedAuthHeader);
    };

    let outcome = cache.check_and_insert(&claims.iss, &claims.jti);
    match outcome {
        ReplayCheck::Novel => next.run(req).await,
        ReplayCheck::Replay => {
            tracing::warn!(
                iss = claims.iss,
                jti = claims.jti,
                "xrpc_gateway replay: (iss, jti) already seen within TTL"
            );
            replay_response(&claims.iss, &claims.jti)
        }
    }
}

fn replay_response(iss: &str, jti: &str) -> Response {
    let body = AuthErrorEnvelope {
        error: "ExpiredToken",
        message: format!("token jti {jti} for issuer {iss} is no longer accepted"),
    };
    (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    //! Middleware unit tests cover the bearer-token extraction
    //! edge cases. Full request → response flow (which exercises
    //! the middleware via the actual axum router) is in
    //! `crate::xrpc_gateway::router::tests`.

    use super::*;

    fn req_with_auth(value: &str) -> Request {
        Request::builder()
            .uri("/xrpc/tools.ozone.moderation.emitEvent")
            .header(header::AUTHORIZATION, value)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn req_no_auth() -> Request {
        Request::builder()
            .uri("/xrpc/tools.ozone.moderation.emitEvent")
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[test]
    fn extract_bearer_recognizes_well_formed_header() {
        let req = req_with_auth("Bearer eyJhbGc.eyJpc3M.signature");
        assert_eq!(
            extract_bearer_token(&req).unwrap(),
            "eyJhbGc.eyJpc3M.signature"
        );
    }

    #[test]
    fn extract_bearer_rejects_missing_header() {
        let req = req_no_auth();
        assert!(matches!(
            extract_bearer_token(&req),
            Err(XrpcAuthError::MissingOrMalformedAuthHeader)
        ));
    }

    #[test]
    fn extract_bearer_rejects_wrong_scheme() {
        let req = req_with_auth("Basic dXNlcjpwYXNz");
        assert!(matches!(
            extract_bearer_token(&req),
            Err(XrpcAuthError::MissingOrMalformedAuthHeader)
        ));
    }

    #[test]
    fn extract_bearer_rejects_empty_token() {
        let req = req_with_auth("Bearer ");
        assert!(matches!(
            extract_bearer_token(&req),
            Err(XrpcAuthError::MissingOrMalformedAuthHeader)
        ));
    }

    #[test]
    fn extract_bearer_rejects_non_ascii_header() {
        // Authorization headers with non-ASCII bytes are
        // illegitimate per RFC 7235; HeaderValue::to_str fails
        // and we surface as MalformedAuthHeader.
        let req = Request::builder()
            .uri("/xrpc/tools.ozone.moderation.emitEvent")
            .header(
                header::AUTHORIZATION,
                axum::http::HeaderValue::from_bytes(b"Bearer \xff\xff").unwrap(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(matches!(
            extract_bearer_token(&req),
            Err(XrpcAuthError::MissingOrMalformedAuthHeader)
        ));
    }
}
