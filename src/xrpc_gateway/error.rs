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
/// Initial scope is purely structural; subsequent issues add
/// `AuthFailed(String)` (#93), `ReplayDetected(String)` (#94), and
/// per-handler errors (#95+).
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
}
