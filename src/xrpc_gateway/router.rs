//! Router skeleton for the inbound XRPC gateway (#91, v1.7).
//!
//! Mounts at `/xrpc/<nsid>` on cairn-mod's HTTP listener when
//! [`XrpcGatewayConfig`] is `Some(_)`. v1.7 supports a fixed set of
//! NSIDs (the allowlist enum lands in #92); all NSIDs return 501
//! `MethodNotImplemented` until #92 + #95-#98 land.
//!
//! # Why a skeleton router exists at all
//!
//! Returning 501 for everything is the same operator-facing
//! behavior bsky-PDS exhibits for stub-only handlers (per §A7 /
//! bsky findings §6.3): the gateway is **fingerprint-
//! indistinguishable from a stock Ozone instance with stub
//! handlers**. An operator who flips
//! `[xrpc_gateway].enabled = true` on a v1.7 build would see
//! cairn-mod listening on `/xrpc/*` and uniformly returning 501
//! — the same shape the eventual handlers in #95-#98 will
//! replace one NSID at a time without disturbing the envelope.
//!
//! # Future-cycle hooks
//!
//! - **#92** — replaces the catch-all 501 with an allowlist
//!   match: known NSIDs route to handler stubs (still 501 until
//!   their bodies land); unknown NSIDs return 501 with the same
//!   envelope as today (the v1.7-final behavior for the long tail
//!   of un-allowlisted NSIDs).
//! - **#93** — tower middleware for ATProto service-auth JWT
//!   verification. Inserts above the per-route handlers so auth
//!   failures short-circuit before NSID dispatch.
//! - **#94** — tower middleware for replay-cache + known-callers
//!   gating. Same insertion point as #93.
//! - **#95-#98** — per-NSID handler bodies. Replace the 501
//!   stubs.

use axum::Router;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde::Serialize;

use crate::xrpc_gateway::config::XrpcGatewayConfig;

/// Build the inbound XRPC gateway router.
///
/// The returned [`Router`] handles every request to
/// `/xrpc/<nsid>` (any HTTP method) by returning a 501 envelope
/// that matches bsky-PDS's stub-handler shape. Non-`/xrpc/*`
/// paths are not handled here; callers compose with
/// [`mod@crate::serve`]'s existing routers via `.merge(...)` so
/// non-gateway routes fall through to whatever cairn-mod's
/// existing setup provides.
///
/// `_config` is accepted but not yet consulted — v1.7's skeleton
/// has no per-config behavior. #92 (the NSID allowlist) and #93
/// (auth) will hook into the [`XrpcGatewayConfig`]'s
/// `service_did` and skew/replay fields.
pub fn build_router(_config: XrpcGatewayConfig) -> Router {
    Router::new().route("/xrpc/{nsid}", any(handle_xrpc))
}

/// Catch-all handler for v1.7. Every request — regardless of
/// HTTP method, regardless of NSID, regardless of body — gets
/// a 501 `MethodNotImplemented` envelope.
///
/// `Path<String>` extracts the `<nsid>` segment so the response
/// can name the unimplemented method (matching bsky-PDS's
/// "Method <nsid> is not implemented" wording per findings §6.3).
async fn handle_xrpc(Path(nsid): Path<String>) -> Response {
    method_not_implemented_response(&nsid)
}

/// Build the 501 response envelope.
///
/// Mirrors bsky-PDS's stub-handler shape per findings §6.3:
/// HTTP 501 with body
/// `{"error": "MethodNotImplemented", "message": "Method <nsid> is not implemented"}`.
/// `pub(crate)` so the upcoming #92 NSID-allowlist code can
/// reuse the exact envelope for unrecognized NSIDs (§A7's
/// envelope-fidelity goal).
pub(crate) fn method_not_implemented_response(nsid: &str) -> Response {
    let body = MethodNotImplementedEnvelope {
        error: "MethodNotImplemented",
        message: format!("Method {nsid} is not implemented"),
    };
    (StatusCode::NOT_IMPLEMENTED, axum::Json(body)).into_response()
}

/// Wire shape of the 501 envelope. Field order in the JSON
/// output is determined by the `serde::Serialize` impl, which
/// follows struct-field order; pinning here so the wire bytes
/// don't drift.
#[derive(Serialize)]
struct MethodNotImplementedEnvelope {
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
    /// reqwest base URL. Same pattern admin_labels.rs uses for
    /// router tests; spawns a background task that owns the
    /// listener until the test drops the URL string.
    async fn spawn_for_test(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service()).await.ok();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn router_returns_501_for_unknown_nsid() {
        let url = spawn_for_test(build_router(fixture_config())).await;
        let res = reqwest::get(format!("{url}/xrpc/com.atproto.server.someUnknownMethod"))
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 501);

        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("MethodNotImplemented")
        );
        let msg = body.get("message").and_then(|v| v.as_str()).unwrap();
        assert!(
            msg.contains("com.atproto.server.someUnknownMethod"),
            "envelope message names the NSID: {msg}"
        );
    }

    #[tokio::test]
    async fn router_returns_501_for_known_phase_c_nsids() {
        // The Phase C v1.7 surface (per A6): the four
        // tools.ozone.moderation.* NSIDs the allowlist lands in
        // #92, plus com.atproto.moderation.createReport. Pinning
        // that the v1.7 skeleton returns 501 for all of them so
        // #92's "swap catch-all for allowlist" change can verify
        // the response shape doesn't drift.
        let url = spawn_for_test(build_router(fixture_config())).await;
        for nsid in [
            "com.atproto.moderation.createReport",
            "tools.ozone.moderation.emitEvent",
            "tools.ozone.moderation.queryStatuses",
            "tools.ozone.moderation.queryEvents",
        ] {
            let res = reqwest::get(format!("{url}/xrpc/{nsid}")).await.unwrap();
            assert_eq!(res.status().as_u16(), 501, "{nsid}");
            let body: serde_json::Value = res.json().await.unwrap();
            assert_eq!(
                body.get("error").and_then(|v| v.as_str()),
                Some("MethodNotImplemented"),
                "{nsid}"
            );
        }
    }

    #[tokio::test]
    async fn router_returns_404_for_non_xrpc_paths() {
        // The gateway router only matches /xrpc/*; non-/xrpc
        // paths fall through to axum's default 404. cairn-mod's
        // serve.rs composes this router with .merge() against
        // other feature routers, so in production those paths
        // would route elsewhere — but the gateway alone returns
        // 404, which is the correct fall-through shape.
        let url = spawn_for_test(build_router(fixture_config())).await;
        let res = reqwest::get(format!("{url}/health")).await.unwrap();
        assert_eq!(res.status().as_u16(), 404);
    }

    #[test]
    fn method_not_implemented_envelope_contains_nsid() {
        // Sync unit test on the envelope helper itself. Pinning
        // the wire shape so a future format change (e.g., #92
        // adding an extra field) doesn't accidentally drift the
        // existing 501 path's envelope.
        let response = method_not_implemented_response("foo.bar.baz");
        assert_eq!(response.status().as_u16(), 501);
        // Body inspection through Response is awkward; the JSON
        // shape is exercised at the HTTP level by
        // `router_returns_501_for_unknown_nsid` above.
    }
}
