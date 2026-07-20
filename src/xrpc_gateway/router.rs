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
//! [`crate::xrpc_gateway::Nsid`] (not config-extensible). The
//! gateway router mounts three of the four NSIDs; createReport
//! is intentionally not mounted here (#102 — the user-direct
//! `crate::server::create_report::create_report_router` is the
//! single mount point for that NSID and dispatches to the gateway-
//! path handler when the JWT issuer is in `xrpc_trusted_pdses`).
//!
//! | Path | Method | Handler |
//! |------|--------|---------|
//! | `/xrpc/tools.ozone.moderation.emitEvent` | POST | `handlers::emit_event` (#95) |
//! | `/xrpc/tools.ozone.moderation.queryStatuses` | GET | `handlers::query_statuses` (#97) |
//! | `/xrpc/tools.ozone.moderation.queryEvents` | GET | `handlers::query_events` (#98) |
//! | other `/xrpc/*` | any | 501 via fallback (`MethodNotImplemented`) |
//! | known NSID + wrong method | other | 405 (`MethodNotAllowed`) |
//!
//! `Nsid::CreateReport` remains in the
//! NSID enum because the membership middleware's NSID-aware
//! dispatch still references it (different membership table for
//! createReport vs the tools.ozone NSIDs); the gateway router
//! just doesn't route to it.
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

use axum::Extension;
use axum::Router;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use sqlx::{Pool, Sqlite};

use crate::xrpc_gateway::auth::XrpcAuthService;
use crate::xrpc_gateway::config::XrpcGatewayConfig;
use crate::xrpc_gateway::handlers::{XrpcGatewayState, emit_event, query_events, query_statuses};
use crate::xrpc_gateway::middleware::{
    xrpc_auth_middleware, xrpc_membership_middleware, xrpc_replay_middleware,
};
use crate::xrpc_gateway::replay::XrpcReplayCache;

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
pub fn build_router(
    config: XrpcGatewayConfig,
    auth_service: Arc<XrpcAuthService>,
    pool: Pool<Sqlite>,
    replay_cache: Arc<XrpcReplayCache>,
    handler_state: XrpcGatewayState,
) -> Router {
    // Layer composition order is **security-load-bearing**. Per
    // §A8.1: auth runs first (innermost), membership second,
    // replay third (outermost). axum's `Layer` composition is
    // LIFO — the layer applied LAST in code runs FIRST in the
    // request path... wait, that's the opposite. Let's be
    // explicit:
    //
    // axum docs: "applying a `Layer` to a `Router` wraps the
    // router; the wrapping layer runs FIRST when the request
    // arrives." So `.layer(A).layer(B)` means B runs first
    // (outer), then A (inner).
    //
    // We want: auth → membership → replay (auth runs first).
    // So apply in reverse: layer(auth) first, then layer(membership),
    // then layer(replay). Replay is the outer-most and runs LAST
    // — which is what we want, since only fully-authorized
    // requests should consume cache slots.
    //
    // Wait that contradicts itself. Let me re-derive.
    //
    // Actually axum's behavior: `.layer(L)` wraps `R` such that
    // `L` is the outer service. When a request arrives, it hits
    // `L` first; `L` calls `next.run(req)` which delegates to
    // `R`. So the layer applied LAST in code is called LAST
    // around the inner. Multiple `.layer` calls compose:
    //
    //     R.layer(A)      -> A wraps R
    //     R.layer(A).layer(B) -> B wraps (A wraps R)
    //
    // Request flow: B → A → R. So B (outermost) runs first.
    //
    // To get auth → membership → replay → handler order:
    //     handler        = R
    //     R.layer(replay)  -> replay wraps R; replay runs first
    //                         (we DON'T want this)
    //
    // We want auth FIRST, so auth must be the outermost wrap:
    //     R.layer(replay).layer(membership).layer(auth)
    //
    // Reading: handler R is wrapped by replay, then by membership,
    // then by auth. Request hits auth first; auth → membership
    // → replay → handler. ✓
    let _ = config; // reserved for future-cycle config plumbing
    routes()
        .layer(Extension(handler_state))
        .layer(axum::middleware::from_fn_with_state(
            replay_cache,
            xrpc_replay_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            pool,
            xrpc_membership_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            auth_service,
            xrpc_auth_middleware,
        ))
}

/// The bare per-NSID routes + fallbacks. Inlined into
/// [`build_router`] (which wraps this with auth + membership +
/// replay middleware + the `XrpcGatewayState` `Extension` layer
/// the handlers extract from).
///
/// Pre-#98 this surface was exposed as `build_routes_only` for
/// in-crate tests of the no-middleware shape (501/405/fallback
/// behavior). After #98, every handler requires `XrpcGatewayState`
/// from the layered router, so the no-middleware variant is no
/// longer testable in isolation. The remaining test surface lives
/// in `tests/xrpc_gateway_*.rs` (full-stack) and the in-crate
/// router tests below (full-stack with fixture state).
fn routes() -> Router {
    // createReport is NOT mounted here (#102). The user-direct
    // router at `crate::server::create_report` is the single mount
    // point for `/xrpc/com.atproto.moderation.createReport`; that
    // handler dispatches to the gateway-path logic (per #96, now
    // in `crate::xrpc_gateway::handlers::create_report::dispatch_pds_forwarded_report`)
    // when the JWT issuer is in `xrpc_trusted_pdses`. Mounting on
    // both routers panicked at startup via `Router::merge`'s
    // duplicate-route detector. The membership middleware's
    // NSID-aware dispatch retains the `Nsid::CreateReport`
    // arm — the variant is still part of the closed enum even
    // though the gateway router doesn't route to it.
    Router::new()
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

// `com.atproto.moderation.createReport` — NOT mounted here as of
// #102. See the `routes()` function comment for the dispatch-
// not-mount rationale; the handler lives at the user-direct
// `crate::server::create_report::create_report_router` and
// dispatches into `crate::xrpc_gateway::handlers::create_report::dispatch_pds_forwarded_report`
// when membership in `xrpc_trusted_pdses` confirms the JWT issuer.
// emitEvent / queryStatuses / queryEvents below are unaffected by
// #102 — they have no user-direct equivalent and stay mounted
// on the gateway router.

// `tools.ozone.moderation.emitEvent` — body in
// [`crate::xrpc_gateway::handlers::emit_event`] (#95).
async fn handle_emit_event(
    state: Extension<XrpcGatewayState>,
    claims: Extension<crate::xrpc_gateway::XrpcAuthClaims>,
    body: axum::body::Bytes,
) -> Response {
    emit_event::handler(state, claims, body).await
}

// `tools.ozone.moderation.queryStatuses` — body in
// [`crate::xrpc_gateway::handlers::query_statuses`] (#97).
async fn handle_query_statuses(
    state: Extension<XrpcGatewayState>,
    claims: Extension<crate::xrpc_gateway::XrpcAuthClaims>,
    params: axum::extract::Query<query_statuses::QueryStatusesParams>,
) -> Response {
    query_statuses::handler(state, claims, params).await
}

// `tools.ozone.moderation.queryEvents` — body in
// [`crate::xrpc_gateway::handlers::query_events`] (#98).
async fn handle_query_events(
    state: Extension<XrpcGatewayState>,
    claims: Extension<crate::xrpc_gateway::XrpcAuthClaims>,
    params: axum::extract::Query<query_events::QueryEventsParams>,
) -> Response {
    query_events::handler(state, claims, params).await
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
    use tokio::net::TcpListener;

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

    // ====== Wrong method on a known NSID returns 405 =====

    #[tokio::test]
    async fn wrong_method_on_known_nsid_returns_405_envelope() {
        // Post-#98: build_routes_only is retired. These tests run
        // through the full layered router (spawn_authed); the
        // wrong-method case requires a valid JWT since the auth
        // middleware runs before route matching for allowlisted
        // NSIDs. The MethodRouter's per-route fallback fires
        // post-auth + post-membership + post-replay.
        let url = spawn_authed().await;
        // POST-only NSIDs hit with GET; GET-only NSIDs hit with POST.
        // createReport is excluded post-#102: it's no longer
        // mounted on the gateway router (the user-direct router
        // owns the mount + dispatches to the gateway path via
        // membership check). A GET to createReport now lands on the
        // gateway router's unknown-NSID fallback (501); separate
        // test coverage for that path lives in
        // tests/xrpc_gateway_create_report.rs.
        let cases: &[(reqwest::Method, &str)] = &[
            (reqwest::Method::GET, "tools.ozone.moderation.emitEvent"),
            (
                reqwest::Method::POST,
                "tools.ozone.moderation.queryStatuses",
            ),
            (reqwest::Method::POST, "tools.ozone.moderation.queryEvents"),
        ];
        for (i, (method, nsid)) in cases.iter().enumerate() {
            // The fx::valid_claims fixture hardcodes jti to
            // "jti-fixture-1"; vary per iteration so the replay
            // middleware doesn't reject the second-and-onwards
            // requests as duplicates.
            let mut claims = fx::valid_claims(nsid);
            claims["jti"] = serde_json::json!(format!("jti-wrong-method-{i}"));
            let jwt = fx::build_jwt(&claims, "ES256K");
            let res = client()
                .request(method.clone(), format!("{url}/xrpc/{nsid}"))
                .header("authorization", auth_header(&jwt))
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
        // Post-#98: layered router. Auth / membership / replay
        // middleware all pass through requests whose URI doesn't
        // match an allowlisted NSID — no auth header needed for
        // these tests.
        let url = spawn_authed().await;
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
        let url = spawn_authed().await;
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
        let url = spawn_authed().await;
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
        //
        // Routes through the unknown-NSID fallback (auth /
        // membership / replay middleware all pass through unknown
        // NSIDs, so no JWT is needed).
        let url = spawn_authed().await;
        let res = client()
            .post(format!("{url}/xrpc/com.example.unknown"))
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
        let pool = fx::build_test_pool().await;
        let cache = fx::build_replay_cache();
        let state = fx::build_handler_state(pool.clone()).await;
        let router = build_router(fx::fixture_config(), auth, pool, cache, state);
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
    async fn valid_jwt_for_known_nsid_reaches_handler_with_empty_body_returns_400() {
        // Post-#95: emitEvent has a real handler. Empty body parses
        // as malformed JSON; handler returns 400 InvalidRequest.
        // Pre-#95 this used to assert 501 from the stub; the test
        // still proves "auth passed and the request reached the
        // handler", just with a different shape.
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
        assert_eq!(res.status().as_u16(), 400);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("InvalidRequest")
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

    // ===========================================================================
    // #94: membership + replay middleware integration tests
    // ===========================================================================
    //
    // The full layered router exercises auth → membership → replay
    // → handler. Each test below sets up a pool + replay cache to
    // target a specific layer's branch.

    use crate::xrpc_gateway::{
        XrpcReplayCache, add_known_caller, add_trusted_pds, revoke_known_caller,
    };
    use std::time::Duration as StdDuration;

    /// Build a router with a custom pool (i.e. caller controls
    /// membership-table seeds) but the standard auth + replay
    /// fixtures.
    async fn spawn_with_pool(pool: sqlx::Pool<sqlx::Sqlite>) -> String {
        let auth = fx::build_service();
        let cache = fx::build_replay_cache();
        let state = fx::build_handler_state(pool.clone()).await;
        let router = build_router(fx::fixture_config(), auth, pool, cache, state);
        spawn_for_test(router).await
    }

    /// Empty in-memory pool (no rows in either membership table).
    async fn empty_pool() -> sqlx::Pool<sqlx::Sqlite> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xrpc-test-empty.db");
        let pool = crate::storage::open(&path).await.unwrap();
        Box::leak(Box::new(dir));
        pool
    }

    #[tokio::test]
    async fn known_caller_in_table_can_call_emit_event() {
        // Issuer is in xrpc_known_callers. emitEvent passes
        // membership and reaches the handler. With an empty body
        // the handler returns 400 InvalidRequest (post-#95); the
        // important assertion is that membership did NOT
        // short-circuit at 403.
        let pool = empty_pool().await;
        add_known_caller(&pool, fx::ISSUER_DID, Some("test"), "did:plc:m")
            .await
            .unwrap();
        let url = spawn_with_pool(pool).await;
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
        assert_eq!(res.status().as_u16(), 400);
    }

    #[tokio::test]
    async fn unknown_caller_emit_event_returns_403() {
        // Issuer NOT in xrpc_known_callers. emitEvent → 403.
        let pool = empty_pool().await;
        let url = spawn_with_pool(pool).await;
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
        assert_eq!(res.status().as_u16(), 403);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("AccountTakedown")
        );
    }

    // The trusted-PDS createReport happy path and untrusted-PDS
    // 403 path are both moved to tests/xrpc_gateway_create_report.rs
    // post-#102 — createReport is no longer mounted on the gateway
    // router (the user-direct router is the single mount point and
    // dispatches via membership check). The full-stack tests in
    // the integration test file exercise both branches end-to-end;
    // verifying them through the gateway-only fixture here would
    // pin behavior we explicitly retired.
    //
    // What remains testable from inside this file: that POST to
    // createReport via the gateway router falls through to the
    // unknown-NSID 501 fallback, since createReport isn't a route
    // on this router anymore.
    #[tokio::test]
    async fn create_report_falls_through_to_unknown_nsid_on_gateway_router() {
        // Per #102: createReport is intentionally NOT mounted on
        // the gateway router. With valid auth + valid membership
        // (build_test_pool seeds both tables), the request passes
        // all three middleware layers and hits the router's
        // unknown-NSID fallback at route dispatch — confirming the
        // route truly isn't there. (The user-direct mount +
        // dispatch happens at the composed top-level cairn-mod
        // router, not this gateway-only fixture.)
        let url = spawn_authed().await;
        let jwt = fx::build_jwt(
            &fx::valid_claims("com.atproto.moderation.createReport"),
            "ES256K",
        );
        let res = client()
            .post(format!("{url}/xrpc/com.atproto.moderation.createReport"))
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
    async fn cross_table_isolation_trusted_pds_cannot_call_emit_event() {
        // The same DID as a trusted PDS is NOT a known caller.
        // Trying to call emitEvent (which checks
        // xrpc_known_callers) → 403. Correct trust separation:
        // PDS-trust and user-trust are different.
        let pool = empty_pool().await;
        add_trusted_pds(&pool, fx::ISSUER_DID, None, "did:plc:m")
            .await
            .unwrap();
        let url = spawn_with_pool(pool).await;
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
        assert_eq!(res.status().as_u16(), 403);
    }

    #[tokio::test]
    async fn revoked_known_caller_returns_403() {
        let pool = empty_pool().await;
        add_known_caller(&pool, fx::ISSUER_DID, None, "did:plc:m")
            .await
            .unwrap();
        revoke_known_caller(&pool, fx::ISSUER_DID, "did:plc:m")
            .await
            .unwrap();
        let url = spawn_with_pool(pool).await;
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
        assert_eq!(res.status().as_u16(), 403);
    }

    #[tokio::test]
    async fn replay_second_request_with_same_jti_returns_400_expiredtoken() {
        // Membership-allowed caller; valid JWT; but replayed.
        // First call: passes through to the handler. Body is empty
        // so the handler returns 400 InvalidRequest (post-#95) —
        // but the replay cache is updated regardless because the
        // middleware records the jti BEFORE handing off to the
        // handler. Second call (same jti): 400 ExpiredToken from
        // the replay middleware.
        let pool = empty_pool().await;
        add_known_caller(&pool, fx::ISSUER_DID, None, "did:plc:m")
            .await
            .unwrap();
        let url = spawn_with_pool(pool).await;
        let jwt = fx::build_jwt(
            &fx::valid_claims("tools.ozone.moderation.emitEvent"),
            "ES256K",
        );

        let res1 = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res1.status().as_u16(), 400, "first call reaches handler");
        let body1: serde_json::Value = res1.json().await.unwrap();
        assert_eq!(
            body1.get("error").and_then(|v| v.as_str()),
            Some("InvalidRequest")
        );

        let res2 = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res2.status().as_u16(), 400, "replay must short-circuit");
        let body: serde_json::Value = res2.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("ExpiredToken")
        );
    }

    #[tokio::test]
    async fn layer_order_unauthorized_request_does_not_pollute_replay_cache() {
        // Composition order is security-load-bearing: an
        // unauthenticated request should NEVER reach the replay
        // cache. Verify by sending a no-auth request and then a
        // valid request with the same (eventually-known) jti —
        // the valid one should succeed, proving the cache was
        // never touched by the unauthorized one.
        let pool = empty_pool().await;
        add_known_caller(&pool, fx::ISSUER_DID, None, "did:plc:m")
            .await
            .unwrap();
        let auth = fx::build_service();
        let cache = Arc::new(XrpcReplayCache::new(StdDuration::from_secs(90)));
        let state = fx::build_handler_state(pool.clone()).await;
        let router = build_router(fx::fixture_config(), auth, pool, cache.clone(), state);
        let url = spawn_for_test(router).await;

        // No auth header → 401. Cache untouched.
        let res = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 401);

        // Now valid request with whatever jti from a fresh JWT.
        // Should succeed (cache had no entry from the bad request).
        let jwt = fx::build_jwt(
            &fx::valid_claims("tools.ozone.moderation.emitEvent"),
            "ES256K",
        );
        let res2 = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        // 400 InvalidRequest (handler reached) — cache wasn't
        // poisoned by the prior 401. ExpiredToken would mean replay.
        assert_eq!(res2.status().as_u16(), 400);
        let body: serde_json::Value = res2.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("InvalidRequest")
        );
    }

    #[tokio::test]
    async fn layer_order_unauthorized_membership_does_not_pollute_replay_cache() {
        // Same defense for the membership layer: an
        // authenticated-but-not-authorized caller's jti should
        // NEVER end up in the replay cache. Otherwise a future
        // operator who adds the caller to xrpc_known_callers
        // would see their first request rejected as a "replay".
        let pool = empty_pool().await; // empty: caller not in any table
        let url = spawn_with_pool(pool.clone()).await;
        let jwt = fx::build_jwt(
            &fx::valid_claims("tools.ozone.moderation.emitEvent"),
            "ES256K",
        );

        // Membership rejects → 403. Cache untouched.
        let res1 = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        assert_eq!(res1.status().as_u16(), 403);

        // Now operator adds the caller. With the same jti the
        // request should now succeed — cache wasn't poisoned.
        add_known_caller(&pool, fx::ISSUER_DID, None, "did:plc:m")
            .await
            .unwrap();
        let res2 = client()
            .post(format!("{url}/xrpc/tools.ozone.moderation.emitEvent"))
            .header("authorization", auth_header(&jwt))
            .send()
            .await
            .unwrap();
        // Post-#95: handler returns 400 InvalidRequest for an
        // empty body. The important assertion is "not 400
        // ExpiredToken" — that would indicate a poisoned cache.
        assert_eq!(
            res2.status().as_u16(),
            400,
            "after grant, same jti should pass through (cache wasn't poisoned)"
        );
        let body: serde_json::Value = res2.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("InvalidRequest")
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
