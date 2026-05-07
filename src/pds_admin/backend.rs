//! [`PdsAdminBackend`] trait + error types + opaque action-id
//! newtype (§F23, #84).
//!
//! The trait shape is what `OzoneBackend` (#86–#90) implements;
//! v1.8+ adds a Rust PDS backend and potentially others. This
//! module owns the type-level foundation: trait surface,
//! [`BackendError`] variant set, structured-failure-log shape, and
//! the opaque [`BackendActionId`] newtype.
//!
//! See A2 in `.design-notes/v1_7-architectural-decisions.md` for
//! the trait-shape rationale; A5 for the
//! `apply_label`/`negate_label` posture (now
//! [`BackendError::ArchitecturallyForbidden`] per the §F4
//! invariant — see [`F4_INVARIANT_REASON`]).

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

/// Canonical reason text returned by both backends when a label
/// method is called.
///
/// cairn-mod's `subscribeLabels` (§F4) is the canonical label
/// distribution surface to the network. Emitting labels via the
/// upstream PDS would create a duplicate emission path with
/// audit-trail divergence — no operator action can make that the
/// right thing to do, so it's rejected at the trait surface as
/// [`BackendError::ArchitecturallyForbidden`] regardless of which
/// backend the upstream PDS uses.
///
/// The constant is pinned by content-based assertions (see the
/// `f4_invariant_tests` module) rather than by byte length: a
/// reviewer changing the *meaning* of the constant — e.g.,
/// swapping "subscribeLabels" for some other surface — fails CI.
/// Length pins are reserved for vocabulary constants where length
/// tracks semantics, which this isn't.
pub const F4_INVARIANT_REASON: &str = "cairn-mod's subscribeLabels (§F4) is the canonical label-distribution surface to the network; \
     emitting labels via the upstream PDS would create a duplicate emission path with audit-trail divergence";

/// Errors that can occur when calling a [`PdsAdminBackend`]
/// method.
///
/// The variant set is **closed at seven** for the v1.8 series:
/// dashboards, structured-log queries, and operator filters
/// pivot on [`Self::variant_name`] (which is also the
/// `error_category` value written to `pds_admin_audit`), so
/// adding a variant is a coordinated cross-release change. New
/// failure modes that don't obviously fit one of the seven map
/// to the closest variant with a `[sub_classification=Name ...]`
/// marker prepended to the inner string; the
/// [`Self::retry_after_seconds`] / [`Self::error_code`]
/// accessors parse those markers back out for callers that need
/// the structured side-channel data.
///
/// # Variant operator affordances
///
/// Each variant maps to a single operator-actionable disposition:
///
/// - [`Self::Transient`] → "try again later" (user-actionable on
///   time, not on configuration). Maps to `outcome = 'network'`
///   (or `'rate_limited'` when the inner string carries a
///   `[sub_classification=RateLimited ...]` marker).
/// - [`Self::Validation`] → "check your input" (user-actionable
///   on the call shape). Maps to `outcome = 'validation'`.
/// - [`Self::Terminal`] → "the upstream rejected this; investigate
///   state" (user-actionable on data state). Maps to
///   `outcome = 'terminal'` for the bare case, `'conflict'` /
///   `'remote_error'` when the inner string carries the
///   corresponding sub-classification marker.
/// - [`Self::Auth`] → "credentials problem" (operator-actionable
///   on configuration). Maps to `outcome = 'auth'`.
/// - [`Self::CapabilityNotAdvertised`] → "your PDS doesn't
///   currently advertise this; could change on refresh"
///   (operator-actionable on PDS configuration). Maps to
///   `outcome = 'validation'`. Reserved for the v1.8+ Rust PDS
///   backend; v1.7 / v1.8.1 do not produce this variant from
///   `OzoneBackend`.
/// - [`Self::Unsupported`] → "switch backends if you need this"
///   (operator-actionable on cairn-mod configuration). Maps to
///   `outcome = 'unsupported'`. Carries no inner payload —
///   method context lives in the structured-log
///   [`BackendFailureLog::method`] field, not in the variant.
/// - [`Self::ArchitecturallyForbidden`] → "no backend will ever
///   do this; cairn-mod's design forbids it" (no operator
///   action; explanatory). Maps to `outcome = 'unsupported'`;
///   the `error_category` distinguishes it from
///   [`Self::Unsupported`].
///
/// # Mapping guidance for implementations
///
/// Implementations map wire-level errors into these variants per
/// the HTTP-status + sub-classification rules:
///
/// - **Transport-layer failures** (DNS, TCP, TLS, timeout) →
///   [`Self::Transient`]. Treat as retryable in principle.
/// - **HTTP 5xx** → [`Self::Transient`].
/// - **HTTP 429** → [`Self::Transient`] with
///   `[sub_classification=RateLimited retry_after_seconds=N]` (or
///   `[sub_classification=RateLimited]` when the upstream did not
///   supply a hint) prepended to the message.
/// - **HTTP 401 / 403, OAuth refresh failure** → [`Self::Auth`].
/// - **HTTP 400 / 422 (request-shape problems)** →
///   [`Self::Validation`].
/// - **HTTP 404 / 409 / 410 (upstream-state problems)** →
///   [`Self::Terminal`]. Use
///   `[sub_classification=Conflict]` for the previously-named
///   "state conflict" cases (already-takendown account on
///   takedown_account; not-takendown on restore_account).
/// - **Backend error envelopes without a specific status
///   classification** → variant chosen by status code, with
///   `[sub_classification=RemoteError code=X]` prepended so
///   forensics retain the wire-level `error` field.
/// - **A trait method whose implementation doesn't speak the
///   dialect at all** → [`Self::Unsupported`]. Method context
///   lives in [`BackendFailureLog::method`].
/// - **A trait method whose call would violate cairn-mod's
///   architectural invariants** → [`Self::ArchitecturallyForbidden`].
///   Both backends on label methods, per [`F4_INVARIANT_REASON`].
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Network-level or otherwise-transient backend failure.
    /// Operator affordance: "try again later". Carries
    /// `[sub_classification=RateLimited retry_after_seconds=N]`
    /// for HTTP-429 cases — see [`Self::retry_after_seconds`].
    #[error("transient backend error: {0}")]
    Transient(String),

    /// Request-level failure: the call shape was wrong or
    /// upstream rejected the payload semantically. Operator
    /// affordance: "check your input".
    #[error("validation error: {0}")]
    Validation(String),

    /// Upstream-state failure that is not retryable and not a
    /// request-shape problem (HTTP 404/409/410, etc.). Operator
    /// affordance: "the upstream rejected this; investigate
    /// state". Carries `[sub_classification=Conflict]` for the
    /// previously-named state-conflict cases (already-takendown,
    /// not-takendown) and
    /// `[sub_classification=RemoteError code=X]` when forensics
    /// retain a wire-level error code.
    #[error("terminal backend error: {0}")]
    Terminal(String),

    /// Authentication or authorization failure (HTTP 401/403,
    /// OAuth refresh failure, expired admin credentials, etc.).
    /// Operator affordance: "credentials problem".
    #[error("backend auth error: {0}")]
    Auth(String),

    /// A capability-gated trait method was called when the
    /// cached `CapabilitySet` did not advertise the backing
    /// capability. Reserved for the v1.8+ Rust PDS backend;
    /// `OzoneBackend` does not produce this variant. Operator
    /// affordance: "your PDS doesn't currently advertise this;
    /// could change on refresh".
    #[error("capability not advertised by PDS: {0}")]
    CapabilityNotAdvertised(String),

    /// The trait method exists per the trait shape, but this
    /// backend doesn't speak the dialect at all (a
    /// Rust-PDS-specific method called against `OzoneBackend`,
    /// or a v1.7 trait method on a Rust-PDS backend before the
    /// dialect lifts). Operator affordance: "switch backends if
    /// you need this". Method context lives in
    /// [`BackendFailureLog::method`].
    #[error("method unsupported by this backend")]
    Unsupported,

    /// cairn-mod's design forbids this method on this backend
    /// regardless of capability advertisement or dialect. The
    /// §F4 architectural invariant is the canonical example
    /// (label methods on either backend; see
    /// [`F4_INVARIANT_REASON`]). Operator affordance: "no
    /// backend will ever do this; cairn-mod's design forbids
    /// it".
    #[error("method architecturally forbidden: {0}")]
    ArchitecturallyForbidden(String),
}

impl BackendError {
    /// Stable variant tag, used as the `error_category` value in
    /// `pds_admin_audit` and as a low-cardinality dashboard
    /// pivot. Returns one of exactly seven `&'static str`
    /// values — variant cardinality is the contract.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Transient(_) => "Transient",
            Self::Validation(_) => "Validation",
            Self::Terminal(_) => "Terminal",
            Self::Auth(_) => "Auth",
            Self::CapabilityNotAdvertised(_) => "CapabilityNotAdvertised",
            Self::Unsupported => "Unsupported",
            Self::ArchitecturallyForbidden(_) => "ArchitecturallyForbidden",
        }
    }

    /// Inner message for variants that carry one; `""` for
    /// [`Self::Unsupported`] (which is intentionally
    /// payload-less). Suitable as an `error_message` value in
    /// structured logs and audit rows.
    pub fn message(&self) -> &str {
        match self {
            Self::Transient(s)
            | Self::Validation(s)
            | Self::Terminal(s)
            | Self::Auth(s)
            | Self::CapabilityNotAdvertised(s)
            | Self::ArchitecturallyForbidden(s) => s.as_str(),
            Self::Unsupported => "",
        }
    }

    /// Parse the `retry_after_seconds=N` value out of a
    /// `[sub_classification=RateLimited ...]` marker prepended
    /// to a [`Self::Transient`] message. Best-effort: returns
    /// `None` for variants that don't carry the marker, for
    /// `RateLimited` markers without a `retry_after_seconds=`
    /// segment, and for non-numeric values.
    ///
    /// The marker convention is part of how v1.7's structured
    /// `RateLimited.retry_after_seconds` field survives the
    /// migration to v1.8.1's seven-variant taxonomy. Operators
    /// querying for retry-hint data continue to get it via this
    /// accessor; the audit-writer also uses it to populate the
    /// `retry_after_seconds` audit-row column.
    pub fn retry_after_seconds(&self) -> Option<u32> {
        let msg = match self {
            Self::Transient(s) => s.as_str(),
            _ => return None,
        };
        let after_open = msg.strip_prefix("[sub_classification=RateLimited")?;
        // After "[sub_classification=RateLimited" we expect either:
        //   - "]"          (no retry-after metadata)
        //   - " retry_after_seconds=N]"
        //   - " retry_after_seconds=N foo=bar]" (future-proof)
        let inside = after_open.strip_prefix(' ')?;
        let (marker_body, _rest) = inside.split_once(']')?;
        for kv in marker_body.split_whitespace() {
            if let Some(value) = kv.strip_prefix("retry_after_seconds=") {
                return value.parse::<u32>().ok();
            }
        }
        None
    }

    /// Parse the `code=X` value out of a
    /// `[sub_classification=RemoteError code=X]` marker prepended
    /// to a [`Self::Transient`], [`Self::Validation`], or
    /// [`Self::Terminal`] message. Best-effort: returns `None`
    /// for variants that don't carry the marker and for markers
    /// without a `code=` segment.
    ///
    /// The marker convention preserves v1.7's structured
    /// `RemoteError.code` field across the migration to v1.8.1's
    /// seven-variant taxonomy. The audit-writer uses this
    /// accessor to populate the `error_code` audit-row column.
    pub fn error_code(&self) -> Option<&str> {
        let msg = match self {
            Self::Transient(s) | Self::Validation(s) | Self::Terminal(s) => s.as_str(),
            _ => return None,
        };
        let after_open = msg.strip_prefix("[sub_classification=RemoteError")?;
        let inside = after_open.strip_prefix(' ')?;
        let (marker_body, _rest) = inside.split_once(']')?;
        for kv in marker_body.split_whitespace() {
            if let Some(value) = kv.strip_prefix("code=") {
                return Some(value);
            }
        }
        None
    }
}

/// Structured-failure-log shape emitted by every backend-method
/// `Err` return through [`log_backend_failure`].
///
/// Field set is stable across the v1.8 series. `error_category`
/// is the [`BackendError::variant_name`] (low-cardinality;
/// dashboard contract); `error_message` is the inner string;
/// `retry_after_seconds` and `error_code` carry the structured
/// side-channel data parsed from `[sub_classification=...]`
/// markers when present. Operators querying structured logs
/// pivot on `error_category`; sub-classification queries match
/// substrings of `error_message`.
#[derive(Serialize)]
pub struct BackendFailureLog<'a> {
    /// Logging scope — the cairn-mod subsystem the failure
    /// originated in. Always `"pds_admin_backend"` for failures
    /// surfaced through this helper.
    pub scope: &'static str,
    /// Stable backend identifier: `"ozone"` for `OzoneBackend`,
    /// `"rust"` for the v1.8+ Rust PDS backend.
    pub backend: &'static str,
    /// Trait method the failure came from
    /// (`"takedown_account"`, `"describe_capabilities"`, etc.).
    /// Method context for [`BackendError::Unsupported`] lives
    /// here, not in the variant payload.
    pub method: &'static str,
    /// Variant-tag string per [`BackendError::variant_name`].
    /// One of seven values; locked across the v1.8 series.
    pub error_category: &'static str,
    /// Inner message per [`BackendError::message`]. Empty
    /// string for [`BackendError::Unsupported`].
    pub error_message: &'a str,
    /// Retry-After hint in seconds, parsed from the
    /// `[sub_classification=RateLimited retry_after_seconds=N]`
    /// marker on a `Transient` variant. `None` when the variant
    /// carries no marker or no hint.
    pub retry_after_seconds: Option<u32>,
    /// Wire-level error code, parsed from the
    /// `[sub_classification=RemoteError code=X]` marker on a
    /// `Transient`/`Validation`/`Terminal` variant. `None`
    /// otherwise.
    pub error_code: Option<&'a str>,
    /// Wall-clock epoch milliseconds when the failure was
    /// observed.
    pub timestamp_epoch_ms: i64,
    /// Upstream request-id when one is available (X-Request-Id
    /// header, OAuth correlation token, etc.). Operators
    /// correlating cairn-mod logs with upstream PDS logs match
    /// on this field.
    pub correlation_id: Option<&'a str>,
}

/// Emit a [`BackendFailureLog`] line via cairn-mod's existing
/// structured-logging infrastructure (`tracing` JSON output).
///
/// Builds the log shape from the supplied [`BackendError`] —
/// `error_category` and `error_message` come from the variant
/// accessors; `retry_after_seconds` / `error_code` come from the
/// marker-parsing accessors. The caller supplies stable backend
/// identification (`"ozone"` / `"rust"`), the method name, the
/// optional correlation id, and a wall-clock timestamp in
/// epoch-ms.
///
/// Emission is at WARN level; consumers who want a per-variant
/// severity should match on the variant before this helper or
/// supplement with their own log line. (Severity selection lives
/// at the call site so the helper stays variant-agnostic — the
/// dispatch path's `log_call_outcome` in
/// [`crate::pds_admin::dispatch`] is the canonical example.)
pub fn log_backend_failure(
    backend: &'static str,
    method: &'static str,
    error: &BackendError,
    correlation_id: Option<&str>,
    timestamp_epoch_ms: i64,
) {
    let log = BackendFailureLog {
        scope: "pds_admin_backend",
        backend,
        method,
        error_category: error.variant_name(),
        error_message: error.message(),
        retry_after_seconds: error.retry_after_seconds(),
        error_code: error.error_code(),
        timestamp_epoch_ms,
        correlation_id,
    };
    // Serialization is infallible for the field shape (all primitives or
    // owned strings); fall back to a plain log line if the JSON encoder
    // somehow disagrees rather than panicking inside an error path.
    match serde_json::to_string(&log) {
        Ok(json) => tracing::warn!(target: "pds_admin_backend", "{json}"),
        Err(e) => tracing::warn!(
            target: "pds_admin_backend",
            backend,
            method,
            error_category = %log.error_category,
            error_message = %log.error_message,
            "failed to serialize BackendFailureLog: {e}"
        ),
    }
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
/// (#86–#90). v1.8+ adds a Rust PDS backend and potentially others.
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
///   [`negate_label`](Self::negate_label) return
///   [`BackendError::ArchitecturallyForbidden`] on every backend
///   per the §F4 invariant — cairn-mod's own `subscribeLabels`
///   is the canonical label-distribution surface; emitting
///   labels via the upstream PDS would create a duplicate
///   emission path with audit-trail divergence. See
///   [`F4_INVARIANT_REASON`].
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
    /// Returns [`BackendError::ArchitecturallyForbidden`] on
    /// every backend per the §F4 invariant — cairn-mod's
    /// `subscribeLabels` (§F4) is the canonical
    /// label-distribution surface to the network; emitting
    /// labels via the upstream PDS would create a duplicate
    /// emission path with audit-trail divergence. The reason
    /// string is [`F4_INVARIANT_REASON`].
    ///
    /// `expires_days` is an optional expiry hint mirroring
    /// `subject_actions.expires_at` for `temp_suspension`-
    /// derived labels. The parameter is preserved for trait
    /// shape compatibility even though the canonical
    /// implementation rejects the call before reading it.
    async fn apply_label(
        &self,
        subject: &Subject,
        val: &str,
        expires_days: Option<u32>,
    ) -> Result<(), BackendError>;

    /// Negate a previously-applied label at the PDS side.
    /// Same `ArchitecturallyForbidden` posture as
    /// [`apply_label`](Self::apply_label) — cairn-mod's
    /// `subscribeLabels` is the canonical surface.
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
mod f4_invariant_tests {
    use super::F4_INVARIANT_REASON;

    #[test]
    fn f4_invariant_reason_contains_section_anchor() {
        assert!(
            F4_INVARIANT_REASON.contains("§F4"),
            "F4_INVARIANT_REASON must reference the §F4 architectural-section anchor"
        );
    }

    #[test]
    fn f4_invariant_reason_contains_canonical_surface_name() {
        assert!(
            F4_INVARIANT_REASON.contains("subscribeLabels"),
            "F4_INVARIANT_REASON must name subscribeLabels as the canonical surface"
        );
    }
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

    // ===== BackendError variant rendering =====

    #[test]
    fn backend_error_transient_renders() {
        let e = BackendError::Transient("connection refused".into());
        assert_eq!(
            format!("{e}"),
            "transient backend error: connection refused"
        );
    }

    #[test]
    fn backend_error_validation_renders() {
        let e = BackendError::Validation("missing required field".into());
        assert_eq!(format!("{e}"), "validation error: missing required field");
    }

    #[test]
    fn backend_error_terminal_renders() {
        let e = BackendError::Terminal("subject not found".into());
        assert_eq!(format!("{e}"), "terminal backend error: subject not found");
    }

    #[test]
    fn backend_error_auth_renders() {
        let e = BackendError::Auth("HTTP 401".into());
        assert_eq!(format!("{e}"), "backend auth error: HTTP 401");
    }

    #[test]
    fn backend_error_capability_not_advertised_renders() {
        let e = BackendError::CapabilityNotAdvertised("tools.aurora.foo".into());
        assert_eq!(
            format!("{e}"),
            "capability not advertised by PDS: tools.aurora.foo"
        );
    }

    #[test]
    fn backend_error_unsupported_renders() {
        let e = BackendError::Unsupported;
        assert_eq!(format!("{e}"), "method unsupported by this backend");
    }

    #[test]
    fn backend_error_architecturally_forbidden_renders() {
        let e = BackendError::ArchitecturallyForbidden(F4_INVARIANT_REASON.to_string());
        let rendered = format!("{e}");
        assert!(rendered.starts_with("method architecturally forbidden:"));
        assert!(rendered.contains("§F4"));
        assert!(rendered.contains("subscribeLabels"));
    }

    // ===== variant_name + message accessors =====

    #[test]
    fn variant_name_returns_seven_stable_strings() {
        let cases: Vec<(BackendError, &'static str)> = vec![
            (BackendError::Transient("x".into()), "Transient"),
            (BackendError::Validation("x".into()), "Validation"),
            (BackendError::Terminal("x".into()), "Terminal"),
            (BackendError::Auth("x".into()), "Auth"),
            (
                BackendError::CapabilityNotAdvertised("x".into()),
                "CapabilityNotAdvertised",
            ),
            (BackendError::Unsupported, "Unsupported"),
            (
                BackendError::ArchitecturallyForbidden("x".into()),
                "ArchitecturallyForbidden",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.variant_name(), expected);
        }
    }

    #[test]
    fn message_returns_inner_string_or_empty_for_unsupported() {
        assert_eq!(BackendError::Transient("a".into()).message(), "a");
        assert_eq!(BackendError::Validation("b".into()).message(), "b");
        assert_eq!(BackendError::Terminal("c".into()).message(), "c");
        assert_eq!(BackendError::Auth("d".into()).message(), "d");
        assert_eq!(
            BackendError::CapabilityNotAdvertised("e".into()).message(),
            "e"
        );
        assert_eq!(BackendError::Unsupported.message(), "");
        assert_eq!(
            BackendError::ArchitecturallyForbidden("f".into()).message(),
            "f"
        );
    }

    // ===== retry_after_seconds accessor =====

    #[test]
    fn retry_after_seconds_parses_marker_with_value() {
        let e = BackendError::Transient(
            "[sub_classification=RateLimited retry_after_seconds=60] throttled".into(),
        );
        assert_eq!(e.retry_after_seconds(), Some(60));
    }

    #[test]
    fn retry_after_seconds_returns_none_for_marker_without_value() {
        let e = BackendError::Transient("[sub_classification=RateLimited] throttled".into());
        assert_eq!(e.retry_after_seconds(), None);
    }

    #[test]
    fn retry_after_seconds_returns_none_for_other_variants() {
        let e = BackendError::Validation(
            "[sub_classification=RateLimited retry_after_seconds=60] x".into(),
        );
        assert_eq!(e.retry_after_seconds(), None);
        let e = BackendError::Auth("HTTP 401".into());
        assert_eq!(e.retry_after_seconds(), None);
        assert_eq!(BackendError::Unsupported.retry_after_seconds(), None);
    }

    #[test]
    fn retry_after_seconds_returns_none_for_non_numeric() {
        let e = BackendError::Transient(
            "[sub_classification=RateLimited retry_after_seconds=soon] x".into(),
        );
        assert_eq!(e.retry_after_seconds(), None);
    }

    #[test]
    fn retry_after_seconds_returns_none_for_no_marker() {
        let e = BackendError::Transient("plain transient error".into());
        assert_eq!(e.retry_after_seconds(), None);
    }

    // ===== error_code accessor =====

    #[test]
    fn error_code_parses_terminal_marker() {
        let e =
            BackendError::Terminal("[sub_classification=RemoteError code=BAD_THING] failed".into());
        assert_eq!(e.error_code(), Some("BAD_THING"));
    }

    #[test]
    fn error_code_parses_validation_marker() {
        let e = BackendError::Validation(
            "[sub_classification=RemoteError code=InvalidRequest] x".into(),
        );
        assert_eq!(e.error_code(), Some("InvalidRequest"));
    }

    #[test]
    fn error_code_parses_transient_marker() {
        let e =
            BackendError::Transient("[sub_classification=RemoteError code=ServiceDown] x".into());
        assert_eq!(e.error_code(), Some("ServiceDown"));
    }

    #[test]
    fn error_code_returns_none_for_no_marker() {
        let e = BackendError::Terminal("plain terminal error".into());
        assert_eq!(e.error_code(), None);
    }

    #[test]
    fn error_code_returns_none_for_other_variants() {
        let e = BackendError::Auth("[sub_classification=RemoteError code=X] x".into());
        assert_eq!(e.error_code(), None);
        assert_eq!(BackendError::Unsupported.error_code(), None);
    }

    #[test]
    fn error_code_returns_none_for_marker_without_code() {
        let e = BackendError::Terminal("[sub_classification=RemoteError] x".into());
        assert_eq!(e.error_code(), None);
    }

    // ===== BackendFailureLog construction shape =====

    #[test]
    fn backend_failure_log_serializes_with_all_fields() {
        let err = BackendError::Transient(
            "[sub_classification=RateLimited retry_after_seconds=30] slow".into(),
        );
        let log = BackendFailureLog {
            scope: "pds_admin_backend",
            backend: "ozone",
            method: "takedown_account",
            error_category: err.variant_name(),
            error_message: err.message(),
            retry_after_seconds: err.retry_after_seconds(),
            error_code: err.error_code(),
            timestamp_epoch_ms: 1_700_000_000_000,
            correlation_id: Some("req-abc"),
        };
        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("\"scope\":\"pds_admin_backend\""));
        assert!(json.contains("\"backend\":\"ozone\""));
        assert!(json.contains("\"method\":\"takedown_account\""));
        assert!(json.contains("\"error_category\":\"Transient\""));
        assert!(json.contains("\"retry_after_seconds\":30"));
        assert!(json.contains("\"correlation_id\":\"req-abc\""));
    }

    #[test]
    fn backend_failure_log_handles_unsupported_with_empty_message() {
        let err = BackendError::Unsupported;
        let log = BackendFailureLog {
            scope: "pds_admin_backend",
            backend: "rust",
            method: "takedown_account",
            error_category: err.variant_name(),
            error_message: err.message(),
            retry_after_seconds: err.retry_after_seconds(),
            error_code: err.error_code(),
            timestamp_epoch_ms: 0,
            correlation_id: None,
        };
        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("\"error_category\":\"Unsupported\""));
        assert!(json.contains("\"error_message\":\"\""));
        assert!(json.contains("\"retry_after_seconds\":null"));
        assert!(json.contains("\"correlation_id\":null"));
    }
}
