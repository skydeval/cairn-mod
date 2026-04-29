//! [`PdsAdminBackend`] trait + error types + opaque action-id
//! newtype (§F23, #84, v1.7).
//!
//! Type-only foundation issue. The trait is what
//! `OzoneBackend` (#86–#90) will implement; v1.8+ adds
//! `LocusBackend` and potentially others. This issue
//! intentionally ships no implementations, no HTTP code, no
//! audit-table integration, and no recordAction-pipeline call
//! sites — those are #85 / #86+ / #87+ in dependency order.
//!
//! See A2 in `.design-notes/v1_7-architectural-decisions.md`
//! for the trait shape rationale; A5 for the
//! `apply_label`/`negate_label` `Unsupported` posture on
//! `OzoneBackend`.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::types::Subject;

/// Backend-specific identifier for a recorded enforcement
/// action.
///
/// Different backends return different identifier shapes:
/// - **Aurora-Locus** (v1.8+, per Aurora findings §7) returns
///   an auto-incrementing `INTEGER moderation_id`.
/// - **bsky-PDS** (v1.7's `OzoneBackend`)'s
///   `com.atproto.admin.updateSubjectStatus` returns no id at
///   all; the backend implementation synthesizes one
///   client-side (e.g., a UUID or a `(timestamp, subject)`
///   tuple — chosen at #86 implementation time).
///
/// cairn-mod's audit log treats the value as opaque; only the
/// backend that issued it can interpret it. Stored as `String`
/// for serialization simplicity; backends may encode structured
/// data (e.g., JSON) when needed.
///
/// # Construction
///
/// Construction is explicit via [`Self::new`]. There's
/// deliberately no `From<String>` blanket impl — backend
/// boundaries should be unambiguous in code review (a `.into()`
/// at a backend's response-mapping site is harder to grep for
/// than a `BackendActionId::new(...)`).
///
/// # Equality and hashing
///
/// `Eq + Hash` is intentional: v1.8+ retry logic and the audit
/// table's lookup paths use this type as a `HashMap` /
/// `HashSet` key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BackendActionId(String);

impl BackendActionId {
    /// Wrap a backend-issued identifier string. The caller is
    /// responsible for any backend-specific normalization
    /// (e.g., trimming whitespace, lowercasing hex) before
    /// construction.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the underlying identifier as a `&str`. Use this
    /// at consumer sites (audit-row construction, log lines)
    /// rather than `Display` when the value is being stored or
    /// matched programmatically — `as_str` is grep-friendlier
    /// than `to_string()`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BackendActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Errors that can occur when calling a [`PdsAdminBackend`]
/// method.
///
/// Backends map their wire-level errors into these variants.
/// The audit log (#85) records the variant + any contained
/// message; the recordAction pipeline (#87+) decides whether to
/// retry, surface, or log-and-continue based on the variant.
///
/// # Mapping guidance for implementations
///
/// - **Network-layer failures** (DNS, TCP, TLS, timeout) →
///   [`Self::Network`]. Treat as transient at the call site;
///   the recordAction pipeline may decide to log-and-continue
///   per A13.
/// - **Auth failures** (401 / 403, expired credentials,
///   insufficient role) → [`Self::Auth`]. Non-transient; don't
///   retry without operator intervention.
/// - **Backend rate limiting** (429) → [`Self::RateLimited`].
///   Pass through any `Retry-After` hint the backend provided.
/// - **State conflicts** (already-takendown account on
///   `takedown_account`, not-takendown on `restore_account`) →
///   [`Self::Conflict`]. The pipeline may treat as a no-op
///   success or a real error depending on context.
/// - **Backend error envelopes without a specific variant** →
///   [`Self::RemoteError`] with verbatim code + message for
///   audit forensics.
/// - **Pre-call validation failures** (malformed request
///   constructed by cairn-mod itself) → [`Self::Validation`].
///   Should be rare in production; usually a cairn-mod-side
///   bug.
/// - **Unsupported method** → [`Self::Unsupported`]. Should
///   never reach the recordAction pipeline if #83's action_map
///   validation runs correctly; if it does, the operator
///   misconfigured.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The backend does not support this method on this PDS.
    /// Example: `OzoneBackend::apply_label` (per A5 — labels
    /// stay native to cairn-mod's `subscribeLabels`).
    ///
    /// This variant is config-time-detectable; the
    /// recordAction pipeline should never see it at runtime if
    /// the action_map validation in #83 ran correctly. If it
    /// does, that's a bug — log loudly and surface to the
    /// operator.
    #[error("backend does not support this operation: {0}")]
    Unsupported(&'static str),

    /// Network-layer failure (DNS, TCP, TLS, timeout).
    /// Transient by default — the recordAction pipeline may
    /// decide to log-and-continue per A13's "fail loud, let the
    /// operator decide" posture; v1.8 may add automatic retry.
    #[error("network error: {0}")]
    Network(String),

    /// Authentication or authorization failure. Either the
    /// configured credentials are wrong, the credentials' role
    /// is insufficient, or the credentials expired.
    /// Non-transient: don't retry without operator
    /// intervention.
    #[error("backend auth error: {0}")]
    Auth(String),

    /// Backend signaled rate limiting. `retry_after_seconds`
    /// carries the backend's hint when one was provided
    /// (typically via a `Retry-After` HTTP header).
    #[error(
        "backend rate limited: {message}{}",
        retry_after_seconds.map(|s| format!(" (retry after {s}s)")).unwrap_or_default()
    )]
    RateLimited {
        /// Backend-supplied or client-synthesized message
        /// describing the rate-limit context.
        message: String,
        /// Optional retry hint in seconds.
        retry_after_seconds: Option<u32>,
    },

    /// The action conflicts with the backend's current state.
    /// Examples: trying to `restore_account` an account that
    /// isn't taken down; trying to `takedown_account` an
    /// account that's already taken down. The recordAction
    /// pipeline may treat this as a no-op success or a real
    /// error depending on context.
    #[error("backend state conflict: {0}")]
    Conflict(String),

    /// Backend returned an error envelope cairn-mod doesn't
    /// have a specific variant for. Carries the backend's error
    /// code and message verbatim for audit-log forensics.
    #[error("backend remote error: code={code} message={message}")]
    RemoteError {
        /// Backend-supplied error code (typically the value of
        /// XRPC's `error` field, or an HTTP status reason
        /// phrase).
        code: String,
        /// Backend-supplied human-readable message.
        message: String,
    },

    /// Request validation failed before the call could be
    /// made. Distinct from [`Self::Conflict`] (post-call) —
    /// `Validation` means the call was malformed at
    /// construction time. Should be rare in production; usually
    /// indicates a cairn-mod-side bug.
    #[error("backend validation error: {0}")]
    Validation(String),
}

/// Metadata returned from a successful backend probe (#90, §A15).
///
/// v1.7's surface is intentionally minimal — just enough for
/// operator-facing startup logs ("your `[pds_admin.ozone]` is
/// reachable and accepts the configured admin credentials"). v1.8
/// may grow this into capability negotiation when LocusBackend
/// lands and the `Locus`/`Ozone` runtime selector needs to know
/// what each backend supports.
///
/// The probe runs once at startup. Failure does not block startup
/// (per A15); the backend's first real call from the recordAction
/// dispatch retries naturally. The probe's value is the
/// fast-feedback loop: an operator who misconfigures
/// `admin_password_env` learns at boot rather than on the first
/// actual moderation action.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    /// Stable backend identifier. v1.7 only emits `"ozone"`
    /// (bsky-PDS); v1.8 will add `"locus"` (Aurora-Locus). Used
    /// in operator-facing log lines and future v1.8 capability
    /// dispatch.
    pub backend_name: &'static str,

    /// PDS endpoint that was probed. The full URL operators see
    /// in their config; helpful for "wait, we hit which PDS?"
    /// diagnostics during multi-instance rollouts.
    pub pds_url: String,

    /// Backend-reported version, if available. **`None` for
    /// `OzoneBackend` in v1.7** — bsky-PDS's
    /// `com.atproto.server.describeServer` doesn't expose a
    /// version field as of the responses cairn-mod has been
    /// validated against. v1.8's LocusBackend may populate it.
    pub detected_version: Option<String>,

    /// Free-form capability strings the backend reported.
    /// **Empty for v1.7.** Reserved for v1.8's capability
    /// negotiation: `OzoneBackend` would report `"takedown"`,
    /// `"label-emit"`, etc.; the runtime can then short-circuit
    /// dispatch entries the backend doesn't claim to support.
    pub capabilities: Vec<String>,
}

/// Errors from constructing a backend at startup.
///
/// Distinct from [`BackendError`] (which is per-call): these
/// are configuration-time failures that prevent a backend from
/// existing in the first place. v1.7 only has one variant
/// ([`Self::HttpClient`]) since `OzoneBackend::new` only owns
/// HTTP-client construction; v1.8's `LocusBackend` will likely
/// add variants for JWT-secret resolution and other key-material
/// loading.
#[derive(Debug, thiserror::Error)]
pub enum BackendInitError {
    /// `reqwest::Client::builder().build()` failed. Almost
    /// always a TLS/runtime configuration problem; in practice
    /// reqwest's defaults don't fail on supported platforms,
    /// but the fallible signature is preserved so a future
    /// custom-CA / custom-DNS configuration path can surface
    /// errors cleanly.
    #[error("failed to build HTTP client: {0}")]
    HttpClient(String),
}

/// Trait implemented by PDS-side enforcement backends.
///
/// v1.7 ships one implementation: `OzoneBackend` for bsky-PDS
/// (#86–#90). v1.8+ adds `LocusBackend` for Aurora-Locus and
/// potentially others.
///
/// Methods are async because every implementation involves
/// network I/O. Implementations must be `Send + Sync` for use
/// across the recordAction pipeline's async boundaries.
///
/// # Method semantics
///
/// - [`takedown_account`](Self::takedown_account) and
///   [`suspend_account`](Self::suspend_account) are
///   **mutating**; they record an action on the backend and
///   return its identifier for later reversal via
///   [`restore_account`](Self::restore_account).
/// - [`restore_account`](Self::restore_account) is the
///   inverse; it requires the prior action's
///   [`BackendActionId`] so the backend can look up the
///   original action's details.
/// - [`apply_label`](Self::apply_label) and
///   [`negate_label`](Self::negate_label) exist for backends
///   that own label distribution (Aurora-Locus, future Rust
///   PDSes). For backends where cairn-mod's own
///   `subscribeLabels` (§F4) is the label distribution surface
///   (bsky-PDS), these methods return
///   [`BackendError::Unsupported`]. See A5 in v1.7
///   architectural decisions.
///
/// # Error handling
///
/// Implementations map wire-level errors into [`BackendError`]
/// variants. The recordAction pipeline (#87+) decides
/// retry/surface/log-and-continue based on the variant. See the
/// [`BackendError`] doc-comment for per-variant mapping
/// guidance.
///
/// # Startup probe
///
/// [`probe`](Self::probe) runs once at server startup (per §A15).
/// Failure does not block startup — the operator-actionable
/// signal is logged and the first real call retries.
#[async_trait]
pub trait PdsAdminBackend: Send + Sync {
    /// Take down an account at the PDS side. Records an
    /// enforcement action on the backend and returns its
    /// identifier for later reversal.
    ///
    /// `reason` is a backend-facing rationale (the operator's
    /// `[moderation_reasons]` identifier, or a
    /// `[pds_admin.action_map]`-mapped string); `notes` is
    /// optional moderator-facing free text.
    ///
    /// `precipitating_action_id` is the `subject_actions(id)` of
    /// the cairn-mod-side action that triggered this call. Some
    /// backends (notably bsky-PDS, which returns no action id of
    /// its own) embed it into the synthesized
    /// [`BackendActionId`] so a later [`Self::restore_account`]
    /// call can find the original; others (Aurora-Locus, v1.8+)
    /// pass it through to a backend-side `ref` field. Adopted in
    /// #87 with the `OzoneBackend::takedown_account` body —
    /// implementations that don't need it ignore the parameter.
    async fn takedown_account(
        &self,
        did: &str,
        reason: &str,
        notes: Option<&str>,
        precipitating_action_id: i64,
    ) -> Result<BackendActionId, BackendError>;

    /// Suspend an account at the PDS side, optionally with a
    /// duration hint. Semantics vary by backend: bsky-PDS
    /// expresses suspension via takedown with a scheduled lift
    /// (which v1.7 doesn't yet implement —
    /// `with_lift_after = true` is rejected at config-load per
    /// #83); Aurora-Locus has a distinct `suspendUntil` shape
    /// per Aurora findings §7.
    ///
    /// `duration_days` is the operator's intended suspension
    /// length. `None` means "suspend until manually restored."
    /// `precipitating_action_id` follows the same convention as
    /// [`Self::takedown_account`].
    async fn suspend_account(
        &self,
        did: &str,
        reason: &str,
        duration_days: Option<u32>,
        notes: Option<&str>,
        precipitating_action_id: i64,
    ) -> Result<BackendActionId, BackendError>;

    /// Restore (un-takedown / un-suspend) an account at the
    /// PDS side. Requires the prior action's
    /// [`BackendActionId`] so the backend can look up the
    /// original action's details (some backends require this;
    /// others ignore the parameter).
    async fn restore_account(
        &self,
        did: &str,
        prior_action_id: &BackendActionId,
        reason: &str,
    ) -> Result<(), BackendError>;

    /// Apply a label at the PDS side.
    ///
    /// **Not implemented by `OzoneBackend` in v1.7** (#89):
    /// cairn-mod's labels stay native to its `subscribeLabels`
    /// surface. `OzoneBackend::apply_label` returns
    /// [`BackendError::Unsupported`] at runtime; #83's
    /// action_map validation emits a config-load warning when
    /// an action_map entry routes to this method.
    ///
    /// `expires_days` is an optional expiry hint mirroring
    /// `subject_actions.expires_at` for `temp_suspension`-
    /// derived labels.
    async fn apply_label(
        &self,
        subject: &Subject,
        val: &str,
        expires_days: Option<u32>,
    ) -> Result<(), BackendError>;

    /// Negate a previously-applied label at the PDS side.
    /// Same `Unsupported` posture as
    /// [`apply_label`](Self::apply_label) for `OzoneBackend` in
    /// v1.7.
    async fn negate_label(&self, subject: &Subject, val: &str) -> Result<(), BackendError>;

    /// Probe the configured backend at startup (§A15, #90).
    ///
    /// Performs a single non-mutating request to verify the
    /// backend is reachable and authenticated. Failure is logged
    /// but does **not** block cairn-mod startup — the PDS-admin
    /// bridge will retry on the first real call from the
    /// recordAction dispatch (per §A13's "fail loud, let the
    /// operator decide" posture).
    ///
    /// Implementations should:
    /// - use a non-mutating endpoint (GET, not POST), so a
    ///   misconfigured probe never accidentally takes down an
    ///   account at startup;
    /// - authenticate exactly as production calls do, so an
    ///   auth failure here means a real auth failure (not a
    ///   probe-specific quirk operators have to debug separately);
    /// - return [`ProbeReport`] with whatever metadata the
    ///   backend exposes on success — version, capabilities, etc.
    ///   v1.7 leaves both `Some(version)` and a non-empty
    ///   capabilities list to v1.8 LocusBackend; v1.7's
    ///   `OzoneBackend` returns the minimal report ("we reached
    ///   bsky-PDS at the configured URL with the configured
    ///   credentials").
    ///
    /// v1.7's `OzoneBackend` uses
    /// `com.atproto.server.describeServer` (per bsky-PDS findings).
    /// v1.8's `LocusBackend` will use Aurora-Locus's equivalent
    /// describe endpoint.
    async fn probe(&self) -> Result<ProbeReport, BackendError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the trait is `Send + Sync`.
    /// Used so the trait can cross async boundaries in the
    /// recordAction pipeline (#87+) and so trait objects can
    /// be shared between writer-task callers via
    /// `Arc<dyn PdsAdminBackend>`. The body is empty because
    /// the bound is checked by the type checker at the
    /// signature level; calling this function would link to a
    /// no-op.
    #[allow(dead_code)]
    fn _assert_pds_admin_backend_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn PdsAdminBackend>();
    }

    /// Compile-time assertion that errors cross async
    /// boundaries cleanly. Required so `Result<_, BackendError>`
    /// is a valid `Future::Output`.
    #[allow(dead_code)]
    fn _assert_backend_error_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BackendError>();
    }

    /// Compile-time assertion that the action-id newtype
    /// satisfies the bounds required by v1.8+ retry logic and
    /// the audit-table's lookup paths.
    #[allow(dead_code)]
    fn _assert_backend_action_id_clone_eq_hash() {
        fn assert_traits<T: Clone + Eq + std::hash::Hash>() {}
        assert_traits::<BackendActionId>();
    }

    #[test]
    fn backend_action_id_round_trip() {
        let id = BackendActionId::new("backend-12345");
        assert_eq!(id.as_str(), "backend-12345");
        assert_eq!(format!("{id}"), "backend-12345");
    }

    #[test]
    fn backend_action_id_eq_and_hash_consistent() {
        // Manual sanity: two ids constructed from equal strings
        // compare equal and hash identically — required for the
        // type to function as a HashMap key.
        let a = BackendActionId::new("xyz");
        let b = BackendActionId::new(String::from("xyz"));
        assert_eq!(a, b);
        let mut map: std::collections::HashMap<BackendActionId, u32> =
            std::collections::HashMap::new();
        map.insert(a, 1);
        assert_eq!(map.get(&b), Some(&1));
    }

    #[test]
    fn backend_action_id_serde_roundtrip() {
        let id = BackendActionId::new("backend-abc");
        let json = serde_json::to_string(&id).unwrap();
        let back: BackendActionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn backend_error_unsupported_renders() {
        let e = BackendError::Unsupported("OzoneBackend::apply_label");
        assert_eq!(
            format!("{e}"),
            "backend does not support this operation: OzoneBackend::apply_label"
        );
    }

    #[test]
    fn backend_error_network_renders() {
        let e = BackendError::Network("connection refused".into());
        assert_eq!(format!("{e}"), "network error: connection refused");
    }

    #[test]
    fn backend_error_auth_renders() {
        let e = BackendError::Auth("HTTP 401".into());
        assert_eq!(format!("{e}"), "backend auth error: HTTP 401");
    }

    #[test]
    fn backend_error_rate_limited_with_retry_after_renders() {
        let e = BackendError::RateLimited {
            message: "too many requests".into(),
            retry_after_seconds: Some(60),
        };
        assert_eq!(
            format!("{e}"),
            "backend rate limited: too many requests (retry after 60s)"
        );
    }

    #[test]
    fn backend_error_rate_limited_without_retry_after_renders() {
        let e = BackendError::RateLimited {
            message: "throttled".into(),
            retry_after_seconds: None,
        };
        assert_eq!(format!("{e}"), "backend rate limited: throttled");
    }

    #[test]
    fn backend_error_conflict_renders() {
        let e = BackendError::Conflict("subject already taken down".into());
        assert_eq!(
            format!("{e}"),
            "backend state conflict: subject already taken down"
        );
    }

    #[test]
    fn backend_error_remote_error_renders() {
        let e = BackendError::RemoteError {
            code: "InvalidRequest".into(),
            message: "subject not a DID".into(),
        };
        assert_eq!(
            format!("{e}"),
            "backend remote error: code=InvalidRequest message=subject not a DID"
        );
    }

    #[test]
    fn backend_error_validation_renders() {
        let e = BackendError::Validation("missing required field".into());
        assert_eq!(
            format!("{e}"),
            "backend validation error: missing required field"
        );
    }
}
