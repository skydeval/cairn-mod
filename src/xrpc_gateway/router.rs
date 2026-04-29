//! Router for the inbound XRPC gateway (#91 skeleton, #92
//! NSID allowlist + per-handler dispatch).
//!
//! Mounts at `/xrpc/<nsid>` on cairn-mod's HTTP listener when
//! [`XrpcGatewayConfig`] is `Some(_)`. v1.7 ships the named-but-
//! unimplemented stubs for the four allowlisted NSIDs (per §A6 /
//! [`crate::xrpc_gateway::Nsid`]); request bodies arrive in
//! #95-#98.
//!
//! # NSID surface
//!
//! Per §A7, the v1.7 NSID set is hard-coded in
//! [`crate::xrpc_gateway::Nsid`] (not config-extensible). Routes:
//!
//! | Path | Method | Stub returns |
//! |------|--------|--------------|
//! | `/xrpc/com.atproto.moderation.createReport` | POST | 501 (body in #96) |
//! | `/xrpc/tools.ozone.moderation.emitEvent` | POST | 501 (body in #95) |
//! | `/xrpc/tools.ozone.moderation.queryStatuses` | GET | 501 (body in #97) |
//! | `/xrpc/tools.ozone.moderation.queryEvents` | GET | 501 (body in #98) |
//! | other `/xrpc/*` | any | 501 via fallback (`MethodNotImplemented`) |
//! | known NSID + wrong method | other | 405 (`MethodNotAllowed`) |
//!
//! All five non-success outcomes use the **same XRPC error
//! envelope** (`{"error": ..., "message": ...}`) per bsky findings
//! §6.3 / §A7's envelope-fidelity goal. Bytes are
//! `application/json`; status codes differ by outcome.
//!
//! # Future-cycle hooks
//!
//! - **#93** — tower middleware for ATProto service-auth JWT
//!   verification. Inserts above the per-route handlers so auth
//!   failures short-circuit before NSID dispatch.
//! - **#94** — tower middleware for replay-cache + known-callers
//!   gating. Same insertion point as #93.
//! - **#95-#98** — per-NSID handler bodies. Replace the 501
//!   stubs.

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;

use crate::xrpc_gateway::Nsid;
use crate::xrpc_gateway::auth::XrpcAuthService;
use crate::xrpc_gateway::config::XrpcGatewayConfig;
use crate::xrpc_gateway::middleware::xrpc_auth_middleware;

/// Build the inbound XRPC gateway router.
///
/// Returns an [`axum::Router`] with one route per allowlisted
/// NSID (each restricted to its expected HTTP method) plus a
/// fallback handler for unrecognized `/xrpc/*` paths. Non-`/xrpc/*`
/// paths are not handled by this router — callers compose with
/// [`mod@crate::serve`]'s existing routers via `.merge(...)` so
/// non-gateway routes fall through to cairn-mod's existing 404
/// handling.
///
/// `_config` is accepted but not yet consulted — its fields are
/// indirectly applied via the auth service constructed alongside
/// it in [`mod@crate::serve`]. #94 will hook directly into the
/// `replay_cache_ttl` field for the replay-cache middleware
/// composed alongside the auth layer.
///
/// `auth_service` wraps the auth verification surface from #93.
/// Applied as a tower layer (`axum::middleware::from_fn_with_state`)
/// so it runs BEFORE NSID dispatch — auth failures short-circuit
/// at the layer boundary; cryptographically-valid-but-mismatched
/// JWTs never reach the (still-stub) handlers.
pub fn build_router(config: XrpcGatewayConfig, auth_service: Arc<XrpcAuthService>) -> Router {
    build_routes_only(config).layer(axum::middleware::from_fn_with_state(
        auth_service,
        xrpc_auth_middleware,
    ))
}

/// The router's NSID routes + fallbacks **without** the auth
/// middleware. Used by:
/// - The public [`build_router`], which wraps this with the auth
///   layer for production.
/// - Tests of the post-auth router shape (501/405/fallback
///   behavior) that don't want the auth layer in the way.
///
/// `pub(crate)` so the in-crate tests can construct the inner
/// router without bringing up the auth surface; production callers
/// always go through [`build_router`].
pub(crate) fn build_routes_only(_config: XrpcGatewayConfig) -> Router {
    Router::new()
        .route(
            "/xrpc/com.atproto.moderation.createReport",
            post(handle_create_report).fallback(handle_method_not_allowed),
        )
        .route(
            "/xrpc/tools.ozone.moderation.emitEvent",
            post(handle_emit_event).fallback(handle_method_not_allowed),
        )
        .route(
            "/xrpc/tools.ozone.moderation.queryStatuses",
            get(handle_query_statuses).fallback(handle_method_not_allowed),
        )
        .route(
            "/xrpc/tools.ozone.moderation.queryEvents",
            get(handle_query_events).fallback(handle_method_not_allowed),
        )
        .fallback(handle_unknown_nsid)
}

// ===========================================================================
// Per-NSID handler stubs
// ===========================================================================
//
// All four return 501 with NSID-specific envelope wording. Real
// bodies land in #95-#98. The handler signatures take no
// extractors yet — #95-#98 will grow them to extract the request
// body (or query params, for the GET handlers) and produce real
// response shapes. Keeping the signatures minimal here so #93's
// auth middleware can compose without extractor-collision
// surprises.

async fn handle_create_report() -> Response {
    method_not_implemented_response(Nsid::ComAtprotoModerationCreateReport.as_path_segment())
}

async fn handle_emit_event() -> Response {
    method_not_implemented_response(Nsid::ToolsOzoneModerationEmitEvent.as_path_segment())
}

async fn handle_query_statuses() -> Response {
    method_not_implemented_response(Nsid::ToolsOzoneModerationQueryStatuses.as_path_segment())
}

async fn handle_query_events() -> Response {
    method_not_implemented_response(Nsid::ToolsOzoneModerationQueryEvents.as_path_segment())
}

// ===========================================================================
// Fallback handlers
// ===========================================================================

/// Fallback for `/xrpc/<unknown-nsid>` — paths whose NSID isn't
/// on the v1.7 allowlist. Returns 501 with the standard
/// `MethodNotImplemented` envelope.
///
/// The `Request` extractor gives us the URI; we pull the path
/// segment after `/xrpc/` for the envelope's message. If the path
/// doesn't have an `/xrpc/` prefix at all, fall back to
/// `<unknown>` in the message — defense-in-depth, since this
/// fallback is mounted as the gateway's fallback and only
/// triggers when no specific route matched.
async fn handle_unknown_nsid(req: Request) -> Response {
    let path = req.uri().path();
    let nsid = path.strip_prefix("/xrpc/").unwrap_or("<unknown>");
    if nsid.is_empty() || nsid == "<unknown>" {
        // Path didn't have the /xrpc/<nsid> shape at all. cairn-mod
        // doesn't generally expect this branch — the gateway is
        // mounted with a /xrpc/* prefix conceptually — but log
        // for telemetry and emit the standard envelope so an
        // operator probing weird paths still gets a useful
        // response.
        tracing::warn!(
            path = %path,
            "xrpc_gateway: unknown NSID — no /xrpc/ prefix on request"
        );
        return method_not_implemented_response("<unknown>");
    }
    tracing::warn!(
        nsid = nsid,
        "xrpc_gateway: unknown NSID — not on v1.7 allowlist (§A7)"
    );
    method_not_implemented_response(nsid)
}

/// Per-MethodRouter fallback fired when an allowlisted NSID's
/// path matches but the HTTP method doesn't (e.g., GET against
/// createReport, POST against queryStatuses). Returns 405 with
/// the XRPC-shape envelope.
///
/// Extracts the NSID from the URI for the envelope message;
/// extracts the method for the log line.
async fn handle_method_not_allowed(req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path();
    let nsid = path.strip_prefix("/xrpc/").unwrap_or("<unknown>");
    tracing::warn!(
        nsid,
        method = %method,
        "xrpc_gateway: HTTP method not allowed for this NSID"
    );
    method_not_allowed_response(nsid, &method)
}

// ===========================================================================
// XRPC envelopes
// ===========================================================================

/// Build the 501 `MethodNotImplemented` envelope.
///
/// Per bsky findings §6.3 / §A7's envelope-fidelity goal: HTTP
/// 501 with body
/// `{"error": "MethodNotImplemented", "message": "Method <nsid> is not implemented"}`.
/// `pub(crate)` so #95-#98 can reuse if a handler decides to stub
/// itself out for a deferred sub-feature; v1.7 only uses it via
/// the catch-all stubs in this file.
pub(crate) fn method_not_implemented_response(nsid: &str) -> Response {
    let body = XrpcErrorEnvelope {
        error: "MethodNotImplemented",
        message: format!("Method {nsid} is not implemented"),
    };
    (StatusCode::NOT_IMPLEMENTED, axum::Json(body)).into_response()
}

/// Build the 405 `MethodNotAllowed` envelope.
///
/// XRPC error shape with `error = "MethodNotAllowed"`, status
/// 405. Matches the same JSON wrapper shape as the 501 envelope
/// for operator consistency. bsky-PDS's exact 405 envelope wasn't
/// captured in the findings doc as of #92's research (verified
/// against §6.3); this matches the XRPC-spec error shape (which
/// §6.3 describes as the universal error envelope) and Phase B
/// verification flagged it for confirmation against staging.
fn method_not_allowed_response(nsid: &str, method: &Method) -> Response {
    let body = XrpcErrorEnvelope {
        error: "MethodNotAllowed",
        message: format!("HTTP {method} not allowed for NSID {nsid}"),
    };
    (StatusCode::METHOD_NOT_ALLOWED, axum::Json(body)).into_response()
}

/// Wire shape of the XRPC error envelope. Field order in the
/// JSON output is determined by the [`Serialize`] impl, which
/// follows struct-field order; pinning here so wire bytes don't
/// drift across cycles.
#[derive(Serialize)]
struct XrpcErrorEnvelope {
    error: &'static str,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn fixture_config() -> XrpcGatewayConfig {
        XrpcGatewayConfig {
            enabled: true,
            service_did: "did:web:cairn.example.com".into(),
            clock_skew_tolerance: Duration::from_secs(30),
            replay_cache_ttl: Duration::from_secs(90),
        }
    }

    /// Bind the router to a local ephemeral port and return the
    /// reqwest base URL. Same pattern admin_labels.rs uses.
    async fn spawn_for_test(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service()).await.ok();
        });
        format!("http://{addr}")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    // ====== Allowlisted NSIDs return 501 on the correct method =====

    #[tokio::test]
    async fn allowlisted_nsids_return_501_with_correct_method() {
        let url = spawn_for_test(build_routes_only(fixture_config())).await;
        let cases: &[(reqwest::Method, &str)] = &[
            (reqwest::Method::POST, "com.atproto.moderation.createReport"),
            (reqwest::Method::POST, "tools.ozone.moderation.emitEvent"),
            (reqwest::Method::GET, "tools.ozone.moderation.queryStatuses"),
            (reqwest::Method::GET, "tools.ozone.moderation.queryEvents"),
        ];
        for (method, nsid) in cases {
            let res = client()
                .request(method.clone(), format!("{url}/xrpc/{nsid}"))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), 501, "{nsid} via {method}");
            let body: serde_json::Value = res.json().await.unwrap();
            assert_eq!(
                body.get("error").and_then(|v| v.as_str()),
                Some("MethodNotImplemented"),
                "{nsid}"
            );
            assert!(
                body.get("message")
                    .and_then(|v| v.as_str())
                    .is_some_and(|m| m.contains(*nsid)),
                "{nsid}: envelope message should name the NSID"
            );
        }
    }

    // ====== Wrong method on a known NSID returns 405 =====

    #[tokio::test]
    async fn wrong_method_on_known_nsid_returns_405_envelope() {
        let url = spawn_for_test(build_routes_only(fixture_config())).await;
        // POST-only NSIDs hit with GET; GET-only NSIDs hit with POST.
        let cases: &[(reqwest::Method, &str)] = &[
            (reqwest::Method::GET, "com.atproto.moderation.createReport"),
            (reqwest::Method::GET, "tools.ozone.moderation.emitEvent"),
            (
                reqwest::Method::POST,
                "tools.ozone.moderation.queryStatuses",
            ),
            (reqwest::Method::POST, "tools.ozone.moderation.queryEvents"),
        ];
        for (method, nsid) in cases {
            let res = client()
                .request(method.clone(), format!("{url}/xrpc/{nsid}"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                res.status().as_u16(),
                405,
                "{nsid} via {method} (wrong method)"
            );
            let body: serde_json::Value = res.json().await.unwrap();
            assert_eq!(
                body.get("error").and_then(|v| v.as_str()),
                Some("MethodNotAllowed"),
                "{nsid}"
            );
            let msg = body.get("message").and_then(|v| v.as_str()).unwrap();
            assert!(msg.contains(nsid), "405 envelope names the NSID: {msg}");
        }
    }

    // ====== Unknown NSID falls through to 501 =====

    #[tokio::test]
    async fn unknown_nsid_returns_501_via_fallback() {
        let url = spawn_for_test(build_routes_only(fixture_config())).await;
        for nsid in [
            "tools.ozone.moderation.somethingElse",
            "tools.ozone.moderation.emitEventV2",
            "com.atproto.moderation.deleteReport",
            "com.atproto.server.createSession",
            "com.example.foo",
        ] {
            let res = client()
                .post(format!("{url}/xrpc/{nsid}"))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), 501, "{nsid}");
            let body: serde_json::Value = res.json().await.unwrap();
            assert_eq!(
                body.get("error").and_then(|v| v.as_str()),
                Some("MethodNotImplemented"),
                "{nsid}"
            );
            let msg = body.get("message").and_then(|v| v.as_str()).unwrap();
            assert!(
                msg.contains(nsid),
                "fallback envelope names the NSID: {msg}"
            );
        }
    }

    // ====== Case sensitivity: capitalized NSID falls through =====

    #[tokio::test]
    async fn case_mismatch_falls_through_to_unknown_nsid() {
        // ATProto NSIDs are case-sensitive. The router's exact-
        // path match is also case-sensitive (axum 0.8 default),
        // so capitalized variants do NOT route to the named
        // handler — they hit the unknown-NSID fallback instead.
        let url = spawn_for_test(build_routes_only(fixture_config())).await;
        let res = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.EmitEvent"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status().as_u16(),
            501,
            "capitalized NSID should NOT match named route"
        );
        // The envelope's message reflects the actual capitalized
        // path so an operator can see the typo / case-mismatch.
        let body: serde_json::Value = res.json().await.unwrap();
        let msg = body.get("message").and_then(|v| v.as_str()).unwrap();
        assert!(msg.contains("EmitEvent"), "{msg}");
    }

    // ====== Non-/xrpc paths fall through (404) =====

    #[tokio::test]
    async fn non_xrpc_path_falls_through_to_404() {
        // The gateway's named routes all start with /xrpc/; the
        // fallback handles /xrpc/<anything-else>. A path with no
        // /xrpc prefix... gets handled by the fallback too (since
        // axum's fallback fires for ANY unmatched route). We
        // produce a 501 envelope but the path lacks the /xrpc/
        // prefix, so the message uses the placeholder. In
        // production this branch is unreachable because cairn-mod
        // composes the gateway with .merge(...) against other
        // routers that handle their own paths; this test pins the
        // standalone-router behavior for unit-level confidence.
        let url = spawn_for_test(build_routes_only(fixture_config())).await;
        let res = client().get(format!("{url}/health")).send().await.unwrap();
        assert_eq!(res.status().as_u16(), 501);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("MethodNotImplemented")
        );
    }

    // ====== Pin the full envelope shape (#92's deferred-from-#91 byte-shape) =====

    #[tokio::test]
    async fn envelope_shape_is_two_field_xrpc_error_object() {
        // bsky findings §6.3 documents the XRPC error envelope as
        // a two-field JSON object (`error` + `message`). Pin the
        // exact field set here so a future drift (e.g., adding a
        // `code` field) is a deliberate decision made through
        // this test.
        let url = spawn_for_test(build_routes_only(fixture_config())).await;
        let res = client()
            .post(format!("{url}/xrpc/com.atproto.moderation.createReport"))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        let obj = body.as_object().expect("response body is a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from(["error", "message"]),
            "envelope must contain exactly `error` and `message` fields"
        );
    }

    // ====== Sync helper-shape tests =====

    #[test]
    fn method_not_implemented_envelope_status_is_501() {
        let response = method_not_implemented_response("foo.bar.baz");
        assert_eq!(response.status().as_u16(), 501);
    }

    #[test]
    fn method_not_allowed_envelope_status_is_405() {
        let response = method_not_allowed_response("foo.bar.baz", &Method::GET);
        assert_eq!(response.status().as_u16(), 405);
    }

    // ===========================================================================
    // #93: through-the-middleware integration tests
    // ===========================================================================
    //
    // These tests build the FULL `build_router(config, auth_service)` —
    // the auth layer is in the request path. They exercise the auth
    // middleware's pass-through (unknown NSID), short-circuit (missing /
    // bad / wrong-claim auth), and success-then-handler-stub flows.
    //
    // Test fixtures (JWT builder, mock resolver, fixed clock) live in
    // `crate::xrpc_gateway::test_fixtures` so the auth-unit and
    // router-integration surfaces share the same key material.

    use crate::xrpc_gateway::test_fixtures as fx;

    /// Spin up the full authenticated router + return its base URL.
    async fn spawn_authed() -> String {
        let auth = fx::build_service();
        let router = build_router(fx::fixture_config(), auth);
        spawn_for_test(router).await
    }

    fn auth_header(jwt: &str) -> String {
        format!("Bearer {jwt}")
    }

    #[tokio::test]
    async fn missing_authorization_header_returns_401_authrequired() {
        let url = spawn_authed().await;
        let res = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 401);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("AuthRequired")
        );
    }

    #[tokio::test]
    async fn malformed_authorization_header_returns_401() {
        let url = spawn_authed().await;
        // Wrong scheme.
        let res = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", "Basic dXNlcjpwYXNz")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 401);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("AuthRequired")
        );
    }

    #[tokio::test]
    async fn unknown_nsid_path_passes_through_auth_to_router_fallback() {
        // Per #93's design: middleware skips auth for unknown
        // NSIDs and lets the router's fallback return 501. The
        // auth header is ignored on unknown paths — a probe-by-
        // 401-vs-501 trade-off the prompt explicitly accepts.
        let url = spawn_authed().await;
        let jwt = fx::build_jwt(
            &fx::valid_claims("tools.ozone.moderation.emitEvent"),
            "ES256K",
        );
        let res = client()
            .post(format!("{url}/xrpc/com.example.unknown"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 501);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("MethodNotImplemented")
        );
    }

    #[tokio::test]
    async fn valid_jwt_for_known_nsid_reaches_handler_stub_501() {
        let url = spawn_authed().await;
        let jwt = fx::build_jwt(
            &fx::valid_claims("tools.ozone.moderation.emitEvent"),
            "ES256K",
        );
        let res = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        // Auth passes, request reaches the handler, handler is
        // still a #92 stub returning MethodNotImplemented.
        assert_eq!(res.status().as_u16(), 501);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("MethodNotImplemented")
        );
    }

    #[tokio::test]
    async fn valid_jwt_for_known_nsid_with_wrong_method_returns_405_after_auth() {
        let url = spawn_authed().await;
        let jwt = fx::build_jwt(
            &fx::valid_claims("tools.ozone.moderation.emitEvent"),
            "ES256K",
        );
        // emitEvent is POST-only; GET it with valid auth → auth
        // passes, MethodRouter fallback fires with 405.
        let res = client()
            .get(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 405);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("MethodNotAllowed")
        );
    }

    #[tokio::test]
    async fn jwt_with_audience_mismatch_returns_403_invalidtoken() {
        let url = spawn_authed().await;
        let mut claims = fx::valid_claims("tools.ozone.moderation.emitEvent");
        claims["aud"] = serde_json::json!("did:web:other.example.com");
        let jwt = fx::build_jwt(&claims, "ES256K");
        let res = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 403);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("InvalidToken")
        );
    }

    #[tokio::test]
    async fn jwt_with_lxm_mismatching_url_returns_403() {
        let url = spawn_authed().await;
        // JWT's lxm claims emitEvent; URL is queryStatuses.
        let jwt = fx::build_jwt(
            &fx::valid_claims("tools.ozone.moderation.emitEvent"),
            "ES256K",
        );
        let res = client()
            .get(format!("{url}/xrpc/tools.ozone.moderation.queryStatuses"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 403);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("InvalidToken")
        );
    }

    #[tokio::test]
    async fn expired_jwt_returns_403_expiredtoken() {
        let url = spawn_authed().await;
        let mut claims = fx::valid_claims("tools.ozone.moderation.emitEvent");
        // Past `clock_skew_tolerance` (30s); deterministic via
        // the fixed-time clock injected into XrpcAuthService.
        claims["exp"] = serde_json::json!(fx::FIXED_NOW - 100);
        let jwt = fx::build_jwt(&claims, "ES256K");
        let res = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 403);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("ExpiredToken")
        );
    }

    #[tokio::test]
    async fn jwt_with_alg_none_returns_401_invalidtoken() {
        // alg=none is the load-bearing JWT-vuln vector. Pin that
        // it surfaces via the auth middleware as 401 InvalidToken
        // (not as a successful pass-through that reaches the
        // handler).
        let url = spawn_authed().await;
        let jwt = fx::build_jwt(
            &fx::valid_claims("tools.ozone.moderation.emitEvent"),
            "none",
        );
        let res = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 401);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("InvalidToken")
        );
    }
}
