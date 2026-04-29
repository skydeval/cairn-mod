//! Errors that arise inside the inbound XRPC gateway (#91, v1.7).
//!
//! Distinct from [`crate::pds_admin::BackendError`] (which is the
//! **outbound** PDS-admin direction): these are inbound-direction
//! failures that surface inside cairn-mod when a request comes in
//! over `/xrpc/<nsid>`.
//!
//! v1.7's variants are minimal — auth / replay-cache / membership
//! variants land in #93 / #94 as those features are wired in. This
//! issue ships only the structural error type so the router
//! skeleton has a clean error path without forward-declaring
//! variants whose semantics aren't yet concrete.

/// Errors from the inbound XRPC gateway.
///
/// These variants are used **for structured logging**, not as
/// HTTP response types — the operator-facing wire response is the
/// XRPC error envelope (`{"error": ..., "message": ...}`)
/// produced by [`crate::xrpc_gateway::router`]. The error enum
/// gives the WARN/ERROR log lines a consistent Display surface so
/// log aggregators can match on the variant name.
///
/// Subsequent issues grow this set: `AuthFailed(String)` (#93),
/// `ReplayDetected(String)` (#94), per-handler errors (#95+).
#[derive(Debug, thiserror::Error)]
pub enum XrpcGatewayError {
    /// The gateway was disabled when the request arrived.
    /// Reaching this is a routing bug — when
    /// [`crate::xrpc_gateway::config::XrpcGatewayConfig::enabled`]
    /// is `false`, [`mod@crate::serve`] does NOT mount the
    /// gateway router at all, so requests to `/xrpc/*` fall through
    /// to cairn-mod's existing 404 handler. Defense-in-depth so
    /// future-cycle work (a hot-reload toggle, a multi-tenant
    /// per-route gating layer) doesn't accidentally let a disabled
    /// gateway serve traffic.
    #[error("xrpc_gateway disabled — request should not have been routed here")]
    GatewayDisabled,

    /// The request's path is `/xrpc/<nsid>` but `<nsid>` is not
    /// on cairn-mod's hard-coded v1.7 allowlist (the four entries
    /// in [`crate::xrpc_gateway::Nsid`]). Per §A7, the surface is
    /// not config-extensible. Operators get a 501 envelope on the
    /// wire; cairn-mod logs at WARN with this variant so noise
    /// from probes / scanners surfaces in operator-visible
    /// telemetry.
    #[error("NSID not on v1.7 allowlist: {0}")]
    UnknownNsid(String),

    /// The request's NSID is on the allowlist but the HTTP method
    /// doesn't match the NSID's expected method (e.g., GET on
    /// createReport). Caller gets a 405 envelope on the wire;
    /// cairn-mod logs at WARN. Reaching this in production
    /// suggests a misconfigured upstream proxy or a buggy
    /// client — bsky-PDS itself sends correct methods.
    #[error("HTTP method {method} not allowed for NSID {nsid}")]
    MethodNotAllowed {
        /// Allowlisted NSID the request targeted.
        nsid: &'static str,
        /// HTTP method the request actually used.
        method: String,
    },
}
