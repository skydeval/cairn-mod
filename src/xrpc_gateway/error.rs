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

    /// Handler-level rejection of a structurally-parsed request:
    /// malformed JSON body, unsupported event subtype, `createdBy`
    /// not equal to `claims.iss`, a Takedown reversal targeting a
    /// subject with no active takedown, etc. Caller gets a 400
    /// envelope with code `InvalidRequest`; the carried message is
    /// the operator-facing detail.
    ///
    /// Per #95 (and following), this variant is per-handler-flavored
    /// — the gateway's auth / membership / replay layers have their
    /// own variants ([`XrpcAuthError`], membership's wire envelope)
    /// and don't surface as `InvalidRequest`.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Catch-all for handler-internal failures the operator can't
    /// fix from the call site (writer task shut down, DB query
    /// failure, JSON serialization of the response envelope, etc).
    /// Caller gets a 500 envelope with code `InternalServerError`;
    /// cairn-mod logs the underlying cause at ERROR for operator
    /// triage.
    #[error("internal server error")]
    InternalServerError,
}

/// Errors from inbound JWT verification (#93, §A8).
///
/// Distinct from [`XrpcGatewayError`] because the failure mode +
/// HTTP-status / XRPC-error-code mapping is auth-specific. Used by
/// [`crate::xrpc_gateway::auth::XrpcAuthService::verify`] and
/// surfaced to clients via the auth middleware in
/// [`crate::xrpc_gateway::middleware`].
///
/// HTTP status mapping per §A8 (and matching ATProto's auth
/// conventions):
/// - **401 Unauthorized** — credential is missing, malformed, or
///   cryptographically invalid (the caller hasn't proven who they
///   are).
/// - **403 Forbidden** — credential is cryptographically valid
///   but doesn't authorize this specific request (audience,
///   method binding, or expiry mismatch).
///
/// XRPC error codes follow ATProto convention: `AuthRequired` for
/// missing credentials, `InvalidToken` for everything else,
/// `ExpiredToken` for the specific expired-credential case.
#[derive(Debug, thiserror::Error)]
pub enum XrpcAuthError {
    /// Bearer token absent or malformed `Authorization` header.
    #[error("missing or malformed Authorization header")]
    MissingOrMalformedAuthHeader,

    /// JWT structure invalid (not three base64url-encoded segments
    /// separated by dots, or one of the segments is unparseable
    /// JSON, or a required claim is missing).
    #[error("invalid JWT structure: {0}")]
    InvalidJwtStructure(String),

    /// JWT header's `alg` is not on cairn-mod's allowlist.
    /// cairn-mod accepts ES256K only, matching `crate::auth`'s
    /// outbound surface.
    #[error("unsupported JWT algorithm: {0}; only ES256K is accepted")]
    UnsupportedAlgorithm(String),

    /// DID resolution failed — network error, NXDOMAIN, malformed
    /// DID document, etc. Includes the issuer for log correlation.
    #[error("failed to resolve issuer DID {iss}: {reason}")]
    DidResolutionFailed {
        /// Issuer DID from the JWT's `iss` claim.
        iss: String,
        /// Human-readable reason from the underlying resolver.
        reason: String,
    },

    /// Issuer's DID document has no usable `#atproto` verification
    /// method. Either the fragment isn't present, or it's present
    /// but unparseable (wrong key type, malformed multibase, etc.).
    #[error("issuer DID {iss} has no usable #atproto verification method: {reason}")]
    NoVerificationMethod {
        /// Issuer DID.
        iss: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Cryptographic signature verification failed against the
    /// issuer's resolved pubkey. The credential is malformed —
    /// caller hasn't proven they hold the corresponding private
    /// key.
    #[error("JWT signature verification failed for issuer {iss}")]
    SignatureVerificationFailed {
        /// Issuer DID.
        iss: String,
    },

    /// `aud` claim doesn't match cairn-mod's xrpc_gateway service
    /// DID. The credential is cryptographically valid but was
    /// minted for a different audience.
    #[error("audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch {
        /// Service DID cairn-mod expected (from
        /// [`crate::xrpc_gateway::config::XrpcGatewayConfig::service_did`]).
        expected: String,
        /// Audience claim the JWT actually carried.
        actual: String,
    },

    /// `lxm` claim doesn't match the request's URL NSID. Distinct
    /// from [`Self::LxmNotAllowlisted`]: the JWT was crafted for a
    /// **different valid v1.7 endpoint** than the one being
    /// requested.
    #[error("method mismatch: lxm claim {lxm} does not match request NSID {nsid}")]
    MethodMismatch {
        /// `lxm` claim from the JWT.
        lxm: String,
        /// NSID derived from the request URL.
        nsid: String,
    },

    /// `lxm` is a syntactically-valid NSID but isn't on cairn-mod's
    /// v1.7 allowlist. Distinct from [`Self::MethodMismatch`]: the
    /// JWT was crafted for an endpoint cairn-mod **doesn't
    /// support**, vs one it supports but the URL points at a
    /// different one.
    #[error("lxm claim {lxm} is not on the v1.7 NSID allowlist")]
    LxmNotAllowlisted {
        /// `lxm` claim from the JWT.
        lxm: String,
    },

    /// `exp` has passed (accounting for the configured
    /// [`crate::xrpc_gateway::config::XrpcGatewayConfig::clock_skew_tolerance`]).
    #[error("JWT expired at {exp}; now is {now}")]
    Expired {
        /// `exp` claim from the JWT (Unix seconds).
        exp: i64,
        /// Current time when the check ran (Unix seconds).
        now: i64,
    },
}

impl XrpcAuthError {
    /// HTTP status code for the response envelope.
    ///
    /// 401 for "you haven't proven who you are" failures
    /// (missing/malformed credential, sig fail, alg-rejected).
    /// 403 for "you've proven who you are but this credential
    /// doesn't authorize this request" failures (claim mismatches,
    /// expiry).
    ///
    /// The split lets operators distinguish "client needs to send
    /// credentials" from "client's credentials are valid but
    /// scoped wrong" in monitoring dashboards.
    pub fn http_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::MissingOrMalformedAuthHeader
            | Self::InvalidJwtStructure(_)
            | Self::UnsupportedAlgorithm(_)
            | Self::DidResolutionFailed { .. }
            | Self::NoVerificationMethod { .. }
            | Self::SignatureVerificationFailed { .. } => StatusCode::UNAUTHORIZED,

            Self::AudienceMismatch { .. }
            | Self::MethodMismatch { .. }
            | Self::LxmNotAllowlisted { .. }
            | Self::Expired { .. } => StatusCode::FORBIDDEN,
        }
    }

    /// XRPC-envelope `error` field. Follows ATProto convention:
    /// `AuthRequired` for missing credentials, `ExpiredToken` for
    /// the specific expired-credential case, `InvalidToken` for
    /// everything else (malformed structure, sig fail, claim
    /// mismatch).
    ///
    /// More-specific codes (`AudienceMismatch`,
    /// `MethodMismatch`) are NOT used in v1.7 because bsky-PDS's
    /// own surface uses `InvalidToken` uniformly for these per
    /// findings §6.3 — matching their convention preserves
    /// fingerprint indistinguishability.
    pub fn xrpc_error_code(&self) -> &'static str {
        match self {
            Self::MissingOrMalformedAuthHeader => "AuthRequired",
            Self::Expired { .. } => "ExpiredToken",
            Self::InvalidJwtStructure(_)
            | Self::UnsupportedAlgorithm(_)
            | Self::DidResolutionFailed { .. }
            | Self::NoVerificationMethod { .. }
            | Self::SignatureVerificationFailed { .. }
            | Self::AudienceMismatch { .. }
            | Self::MethodMismatch { .. }
            | Self::LxmNotAllowlisted { .. } => "InvalidToken",
        }
    }
}
