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
//! invariant — see [`LABEL_BRIDGE_INVARIANT_REASON`]).

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::rust::action_types::{
    ActionResponse, AppealDecision, BlobSubject, ReportResolution, SubjectStatus,
};
use super::rust::audit_types::{
    AuditEntryLookup, AuditTrailFilter, AuditTrailPage, AuroraAuditEntry,
};
use super::rust::batch_types::BatchOutcome;
use super::rust::ops_types::{
    FederationStatusResponse, InstanceMetrics, RuntimeSetting, SetRuntimeSettingOutcome,
};
use super::rust::read_types::{
    AppealDetail, AppealView, EventWithContext, ListAppealsFilter, PaginatedResponse,
    QueryEventsFilter, QueryStatusesFilter, StatusWithContext, SubjectContextResponse,
    SubjectHistoryFilter,
};
use super::rust::stream_types::StreamFrame;
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
///   client-side (`ozone:{did}:{precipitating_action_id}` per
///   `synthesize_action_id`).
///
/// cairn-mod's audit log treats the value as opaque; only the
/// backend that issued it can interpret it. The wire string
/// stored in `pds_admin_audit.backend_action_id` is unchanged
/// across the v1.7→v1.8+ shape evolution — the variant tag is
/// a Rust-only concern.
///
/// # Variants
///
/// - [`Self::PerEvent`] — single-event action (one emitEvent
///   call, one `updateSubjectStatus`). v1.7's
///   `OzoneBackend::synthesize_action_id` returns this.
/// - [`Self::PerBatch`] — batch action covering multiple
///   subjects. First constructed in v1.8.7: the dispatch
///   layer stamps batch-shaped audit rows (dedicated
///   `tools.aurora.admin.batch*` dispatches and multi-subject
///   `emitEvent` dispatches) with `PerBatch(event_id)`. The
///   payload is Aurora's batch event id — the same join key
///   cross-verify uses, stored bare via the variant-agnostic
///   [`Self::as_str`].
///
/// v1.7-stored values are all per-event by construction
/// (v1.7 has no batch concept). The future schema migration
/// adding an `action_id_kind` column to `pds_admin_audit`
/// (chainlink #110) backfills existing rows to `'PerEvent'`
/// and lets the writer dispatch by variant for new rows.
///
/// # Construction
///
/// [`Self::new`] is the v1.7-compat constructor — equivalent
/// to `Self::PerEvent(id.into())` and used by every existing
/// call site without needing a per-call-site update for the
/// variant migration. Direct variant construction
/// (`BackendActionId::PerEvent(...)` /
/// `BackendActionId::PerBatch(...)`) is also fine and
/// preferred at sites that mean to be explicit about the
/// kind. There's deliberately no `From<String>` blanket impl
/// — backend boundaries should be unambiguous in code review.
///
/// # Wire serialization
///
/// `Serialize` and `Deserialize` round-trip the inner string
/// only — no variant discriminator. This keeps the
/// `pds_admin_audit.backend_action_id` column's TEXT shape
/// hash-stable across v1.7-state rows and v1.8.1-written rows
/// (the unified hash chain reads the column as `&str` and
/// would notice a serialization-shape change). Deserialization
/// always produces [`Self::PerEvent`]; the variant tag for
/// PerBatch travels via a separate column added by the
/// chainlink-#110 migration, not through the action-id
/// serialization itself.
///
/// # Equality and hashing
///
/// `Eq + Hash` is intentional: v1.8+ retry logic and the
/// audit table's lookup paths use this type as a `HashMap` /
/// `HashSet` key. `PerEvent("x")` and `PerBatch("x")` compare
/// **unequal** despite having the same wire string — the
/// variant tag participates in equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BackendActionId {
    /// Single-event action — one upstream call, one identifier.
    /// v1.7's `OzoneBackend` produces this exclusively.
    PerEvent(String),
    /// Batch action covering multiple subjects. Reserved in
    /// v1.8.1; first constructed in v1.8.7 by the dispatch
    /// layer's batch arms (one audit row per batch, payload =
    /// Aurora's batch event id). Deserialization from the audit
    /// column still rehydrates as [`Self::PerEvent`] — the
    /// column carries no variant discriminator (see the
    /// wire-serialization section above).
    PerBatch(String),
}

impl BackendActionId {
    /// Wrap a backend-issued identifier as a per-event action.
    /// v1.7-compat constructor — equivalent to
    /// `Self::PerEvent(id.into())`. The caller is responsible
    /// for any backend-specific normalization (trimming
    /// whitespace, lowercasing hex) before construction.
    ///
    /// Use this at v1.7-shaped call sites (every current
    /// caller); use the explicit variant constructor at v1.8.7+
    /// call sites that introduce batch identifiers.
    pub fn new(id: impl Into<String>) -> Self {
        Self::PerEvent(id.into())
    }

    /// Borrow the underlying identifier as a `&str`,
    /// regardless of variant. Use at consumer sites
    /// (audit-row construction, log lines) rather than
    /// [`fmt::Display`] when the value is being stored or
    /// matched programmatically — `as_str` is grep-friendlier
    /// than `to_string()`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::PerEvent(s) | Self::PerBatch(s) => s.as_str(),
        }
    }
}

impl fmt::Display for BackendActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for BackendActionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BackendActionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::PerEvent(s))
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
/// `label_bridge_invariant_tests` module) rather than by byte length: a
/// reviewer changing the *meaning* of the constant — e.g.,
/// swapping "subscribeLabels" for some other surface — fails CI.
/// Length pins are reserved for vocabulary constants where length
/// tracks semantics, which this isn't.
pub const LABEL_BRIDGE_INVARIANT_REASON: &str = "cairn-mod's subscribeLabels (§F4) is the canonical label-distribution surface to the network; \
     emitting labels via the upstream PDS would create a duplicate emission path with audit-trail divergence";

/// Inner discriminator for [`BackendError::KryphocronDecodeFailed`]
/// (v1.8.13).
///
/// Kept as a single `BackendError` variant with a two-case inner
/// enum so the `error_category` telemetry tag stays one
/// low-cardinality value (`"KryphocronDecodeFailed"`) rather than
/// fanning the taxonomy out with per-failure-mode variants.
///
/// - [`Self::CodecIdUnknown`]: cairn-mod's own pre-check found the
///   record's stored `encodedContentCodec` differs from the
///   installed codec's id (`laquna/0.2`). Aurora never surfaces
///   this to an unauthorized reader (its HTTP-410 skew path is
///   authorized-only), and laquna's `decode` does not verify the
///   codec id, so the comparison is cairn-mod's responsibility.
/// - [`Self::CodecError`]: laquna's `decode` (or the fallible
///   `EncodedRecord` input construction) returned a structural
///   error. laquna collapses every internal decode failure to a
///   single `Malformed`, so no finer caller-visible taxonomy
///   exists to mirror.
#[derive(Debug, thiserror::Error)]
pub enum KryphocronDecodeError {
    /// Stored codec id differs from the installed codec id; the
    /// record is unreadable by this deployment (skew).
    #[error("codec id unknown: stored={stored}, installed={installed}")]
    CodecIdUnknown {
        /// The `encodedContentCodec` the record was stored under.
        stored: String,
        /// The codec id cairn-mod has installed (`laquna/0.2`).
        installed: String,
    },
    /// laquna's decode call (or `EncodedRecord`/`DecodeContext`
    /// input construction) failed structurally.
    #[error("codec decode error: {0}")]
    CodecError(String),
}

/// Errors that can occur when calling a [`PdsAdminBackend`]
/// method.
///
/// The variant set is **closed at eight** for the v1.8 series
/// (seven through v1.8.12; `KryphocronDecodeFailed` added at
/// v1.8.13): dashboards, structured-log queries, and operator
/// filters pivot on [`Self::variant_name`] (which is also the
/// `error_category` value written to `pds_admin_audit`), so
/// adding a variant is a coordinated cross-release change. New
/// failure modes that don't obviously fit one of the eight map
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
///   Both backends on label methods, per [`LABEL_BRIDGE_INVARIANT_REASON`].
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
    /// [`LABEL_BRIDGE_INVARIANT_REASON`]). Operator affordance: "no
    /// backend will ever do this; cairn-mod's design forbids
    /// it".
    #[error("method architecturally forbidden: {0}")]
    ArchitecturallyForbidden(String),

    /// Client-side decode of a private kryphocron record failed
    /// (v1.8.13). Carries a [`KryphocronDecodeError`] discriminating
    /// codec-id skew from a structural decode error. Terminal-class:
    /// the record is unreadable by this deployment, so there is no
    /// retry affordance. Only the Rust PDS backend produces this
    /// variant, and only on the report-flow decode path gated by the
    /// `kryphocron-read` opt-in.
    #[error("kryphocron decode failed: {0}")]
    KryphocronDecodeFailed(#[from] KryphocronDecodeError),
}

impl BackendError {
    /// Stable variant tag, used as the `error_category` value in
    /// `pds_admin_audit` and as a low-cardinality dashboard
    /// pivot. Returns one of exactly eight `&'static str`
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
            Self::KryphocronDecodeFailed(_) => "KryphocronDecodeFailed",
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
            // The inner discriminator carries the detail; `message()`
            // returns a borrowable `&str`, so hand back the codec
            // error string directly, or a stable marker for the skew
            // case (whose structured stored/installed pair is already
            // in the `#[error]` Display and audit context).
            Self::KryphocronDecodeFailed(KryphocronDecodeError::CodecError(s)) => s.as_str(),
            Self::KryphocronDecodeFailed(KryphocronDecodeError::CodecIdUnknown { .. }) => {
                "codec id unknown"
            }
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
    /// One of eight values; locked across the v1.8 series.
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

    /// v1.8.12: present when kryphocron consumption is enabled.
    /// `None` when `[pds_admin.rust.kryphocron].enabled = false`,
    /// even if the upstream advertises kryphocron capabilities —
    /// the `Option` state is how probe output distinguishes
    /// "advertised but operator declined" from "advertised and
    /// codec-ready" (design §7.1). Always `None` for
    /// `OzoneBackend`.
    pub kryphocron: Option<KryphocronProbeState>,
}

/// Kryphocron substrate state surfaced through [`ProbeReport`]
/// (v1.8.12, design §7.1). Detection only — the codec this
/// reports on is instantiated at boot but never invoked until
/// v1.8.13's decode work.
#[derive(Debug, Clone)]
pub struct KryphocronProbeState {
    /// Codec identifier from the instantiated codec —
    /// `"laquna/0.2"` at kryphocron 0.3.1 (stable across
    /// byte-compatible laquna-internals bumps; v1.8.13's skew
    /// check compares stored `encodedContentCodec` against it).
    pub codec_id: String,
    /// Seed-derivation policy the codec was constructed with.
    /// v1.8.12 always builds `Codec::default()`, whose policy is
    /// `DidNsidRkey`; the policy is not readable back off the
    /// codec instance, so this reports the by-construction value.
    pub seed_policy: &'static str,
    /// Codec built and ready for v1.8.13 decode. Always `true`
    /// when this struct is present at v1.8.12 (`Codec::default()`
    /// is infallible); carried explicitly so later releases can
    /// report constructed-but-not-ready without changing the
    /// output shape.
    pub decode_ready: bool,
}

/// Response shape of `com.atproto.repo.getRecord` (v1.8.13).
///
/// The generic atproto record-read shape: an AT-URI, an optional
/// CID (some PDS implementations omit it for legacy records), and
/// the opaque record `value`. The `value` is a `serde_json::Value`
/// pass-through — getRecord returns per-collection record JSON with
/// no single upstream contract struct to mirror, so callers read
/// the fields they need out of `value` by key (v1.8.10 LB-3
/// pass-through posture). For a private kryphocron record the
/// report-flow decode path reads `value["encodedContent"]`,
/// `value["encodedContentCodec"]`, `value["encodedContentGeneration"]`,
/// and `value["text"]`.
///
/// Defined in the backend layer (not reusing the CLI's identically
/// shaped `cli::pds::GetRecordResponse`) because `cli` depends on
/// `pds_admin`, so importing that type into the trait would invert
/// the layering. The shape is the reuse; the home is the honest one.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GetRecordResponse {
    /// AT-URI of the record (`at://<did>/<collection>/<rkey>`).
    pub uri: String,
    /// Content-address id at fetch time; optional per the lexicon.
    #[serde(default)]
    pub cid: Option<String>,
    /// The opaque record body. Callers deserialize / read by key.
    pub value: serde_json::Value,
}

/// Errors from constructing a backend at startup.
///
/// Distinct from [`BackendError`] (which is per-call): these
/// are configuration-time failures that prevent a backend from
/// existing in the first place. v1.7 had one variant
/// ([`Self::HttpClient`]) since `OzoneBackend::new` only owns
/// HTTP-client construction; v1.8.1 adds [`Self::Rust`] for the
/// Rust backend's key-material loading and DID validation.
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
    /// Rust-backend construction failed (v1.8.1): signing-key
    /// env var missing/malformed, or a DID failed the syntactic
    /// check. The inner string is the operator-facing detail,
    /// naming the field or env var that failed.
    #[error("rust backend initialization failed: {0}")]
    Rust(String),
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
///   [`LABEL_BRIDGE_INVARIANT_REASON`].
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

    /// Take down a single record at the PDS side (v1.8.2, §4.1).
    ///
    /// `subject` must be record-shaped: `at_uri` present and —
    /// for the Rust backend, whose wire shape
    /// (`com.atproto.repo.strongRef`) requires a CID — `cid`
    /// present. Implementations reject a `subject` missing the
    /// coordinates they need with [`BackendError::Validation`]
    /// rather than coercing to an account-level action.
    ///
    /// `precipitating_action_id` follows the same convention as
    /// [`Self::takedown_account`].
    async fn takedown_record(
        &self,
        subject: &Subject,
        reason: &str,
        notes: Option<&str>,
        precipitating_action_id: i64,
    ) -> Result<BackendActionId, BackendError>;

    /// Apply a label at the PDS side.
    ///
    /// Returns [`BackendError::ArchitecturallyForbidden`] on
    /// every backend per the §F4 invariant — cairn-mod's
    /// `subscribeLabels` (§F4) is the canonical
    /// label-distribution surface to the network; emitting
    /// labels via the upstream PDS would create a duplicate
    /// emission path with audit-trail divergence. The reason
    /// string is [`LABEL_BRIDGE_INVARIANT_REASON`].
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

    /// Permanently delete an account at the PDS side (v1.8.5) —
    /// `emitEvent{DeleteAccount}`. **Admin+ role floor upstream**
    /// (Aurora `check_role`: `DeleteAccount | SendEmail`);
    /// an under-privileged service DID surfaces
    /// [`BackendError::Auth`] from the upstream 403.
    /// `precipitating_action_id` is the local `subject_actions`
    /// row id (same convention as [`Self::takedown_account`]).
    async fn delete_account(
        &self,
        did: &str,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Quarantine a blob (v1.8.5) — `emitEvent{QuarantineBlob}`
    /// with a `com.atproto.admin.defs#repoBlobRef` subject.
    /// Moderator+ upstream.
    async fn quarantine_blob(
        &self,
        subject: &BlobSubject,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Restore a quarantined blob (v1.8.5) —
    /// `emitEvent{RestoreBlob}`. Returns `()` as a deliberate
    /// v1.8.2-symmetry choice matching [`Self::restore_account`]:
    /// Aurora does return an event id, and it is deliberately
    /// discarded at this boundary (correlate restores via the
    /// audit-chain query paths). `prior_action_id` is
    /// trait-boundary vocabulary only — nothing rides the wire
    /// (Aurora's `RestoreBlob` is a unit variant).
    async fn restore_blob(
        &self,
        subject: &BlobSubject,
        prior_action_id: &BackendActionId,
        rationale: &str,
    ) -> Result<(), BackendError>;

    /// Permanently delete a blob (v1.8.5) —
    /// `emitEvent{DeleteBlob}`. **Moderator+** upstream (R1 LB-B:
    /// Aurora's Admin gate covers `DeleteAccount | SendEmail`,
    /// not `DeleteBlob`).
    async fn delete_blob(
        &self,
        subject: &BlobSubject,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Resolve a report (v1.8.5) — `emitEvent{ResolveReport}`.
    /// `subject` must be the **exact subject of the report**
    /// (full union — reports can target accounts, records, or
    /// blobs); Aurora validates `report_id` against `subjects[0]`
    /// by variant AND identifier and 400s on mismatch.
    async fn resolve_report(
        &self,
        subject: &Subject,
        report_id: i64,
        resolution: ReportResolution,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Dismiss a report without action (v1.8.5) —
    /// `emitEvent{DismissReport}`. Same subject-validation
    /// contract as [`Self::resolve_report`].
    async fn dismiss_report(
        &self,
        subject: &Subject,
        report_id: i64,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Resolve an appeal (v1.8.5) — `emitEvent{ResolveAppeal}`.
    /// `subject` must match the appeal's target, which Aurora
    /// resolves through three FK paths (moderation → account,
    /// report → any variant, quarantine → blob) — appeals are
    /// NOT account-only, hence the full union here.
    /// `AppealDecision::Approve` triggers Aurora's cascade: the
    /// original action reverses and its event id arrives in
    /// [`ActionResponse::cascading_actions`].
    async fn resolve_appeal(
        &self,
        subject: &Subject,
        appeal_id: i64,
        decision: AppealDecision,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Escalate an appeal (v1.8.5) — `emitEvent{EscalateAppeal}`.
    /// Same subject contract as [`Self::resolve_appeal`].
    async fn escalate_appeal(
        &self,
        subject: &Subject,
        appeal_id: i64,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Send a moderation email to an account (v1.8.5) —
    /// `emitEvent{SendEmail}`. **Admin+ role floor upstream**
    /// (email access is Admin-tier per Aurora's role model).
    /// `subject` is the email subject line (Aurora's wire field
    /// name); the recipient rides the subjects array. Upstream
    /// failure modes: recipient with no email on file → 400 →
    /// [`BackendError::Validation`]; mailer failure rolls the
    /// upstream transaction back (no event recorded).
    async fn send_email(
        &self,
        did: &str,
        template: Option<&str>,
        subject: &str,
        body: &str,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Set an account's moderation status (v1.8.5) —
    /// `emitEvent{UpdateSubjectStatus}`. Account-dimension
    /// tri-state only (Aurora rejects non-repo subjects):
    /// [`SubjectStatus::Takedown`] / [`SubjectStatus::Deactivated`]
    /// / [`SubjectStatus::Active`].
    async fn update_subject_status(
        &self,
        did: &str,
        status: SubjectStatus,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Read the upstream PDS's moderation event stream (v1.8.3,
    /// §4.1) — `tools.aurora.moderator.queryEvents` on the Rust
    /// backend. Non-mutating; writes no `pds_admin_audit` row.
    ///
    /// `filter` narrows by event type / actor / subject / time
    /// range; `cursor` and `limit` ride Aurora's standard
    /// pagination (`limit` default 50, capped at 100 upstream).
    /// `OzoneBackend` returns [`BackendError::Unsupported`] —
    /// the Ozone read surface is not colocated with bsky-PDS and
    /// v1.7's config has no separate Ozone-service URL.
    async fn query_events(
        &self,
        filter: QueryEventsFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PaginatedResponse<EventWithContext>, BackendError>;

    /// Read the upstream PDS's per-DID moderation status rows
    /// (v1.8.3, §4.1) — `tools.aurora.moderator.queryStatuses` on
    /// the Rust backend. Account-scoped only on Aurora's side
    /// (record/blob filters yield empty results upstream). Same
    /// non-mutating / `Unsupported`-on-Ozone posture as
    /// [`Self::query_events`].
    async fn query_statuses(
        &self,
        filter: QueryStatusesFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PaginatedResponse<StatusWithContext>, BackendError>;

    /// Fetch a single moderation event by id (v1.8.4) —
    /// `tools.aurora.moderator.getEvent` on the Rust backend.
    /// Returns the same [`EventWithContext`] shape `query_events`
    /// items use (Aurora returns the identical struct). Gates on
    /// the shared `moderator-activity` family. Unknown ids map to
    /// [`BackendError::Terminal`] (upstream 404).
    async fn get_event(&self, event_id: i64) -> Result<EventWithContext, BackendError>;

    /// Fetch contextual metadata for a subject **DID** (v1.8.4) —
    /// `tools.aurora.moderator.getSubjectContext`. Account-scoped
    /// query parameter (plain DID; Aurora has no record/blob
    /// addressing on this endpoint). Gates on `subject-context`.
    async fn get_subject_context(&self, did: &str) -> Result<SubjectContextResponse, BackendError>;

    /// Fetch a subject DID's moderation-action history (v1.8.4) —
    /// `tools.aurora.moderator.getSubjectHistory`. The history is
    /// **action rows** ([`StatusWithContext`], the same shape
    /// `query_statuses` uses), not events. Gates on
    /// `subject-history`.
    async fn get_subject_history(
        &self,
        did: &str,
        filter: SubjectHistoryFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PaginatedResponse<StatusWithContext>, BackendError>;

    /// List appeals with filters and pagination (v1.8.4) —
    /// `tools.aurora.moderator.listAppeals`. Gates on `appeals`.
    async fn list_appeals(
        &self,
        filter: ListAppealsFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PaginatedResponse<AppealView>, BackendError>;

    /// Fetch a single appeal with its lifecycle timeline (v1.8.4)
    /// — `tools.aurora.moderator.getAppeal`. Returns
    /// [`AppealDetail`] (list-view fields flattened + `timeline`),
    /// a distinct type from [`AppealView`]. Gates on `appeals`
    /// (shared with [`Self::list_appeals`]).
    async fn get_appeal(&self, appeal_id: i64) -> Result<AppealDetail, BackendError>;

    /// Fetch a page of Aurora's hash-chained audit trail (v1.8.6)
    /// — `tools.aurora.admin.getAuditTrail`. Gates on the
    /// `audit-trail` capability family. The response carries
    /// Aurora's own whole-chain verify verdict; independent Path A
    /// re-verification is the caller's job (see
    /// `crate::pds_admin::rust::upstream_verify`).
    async fn get_audit_trail(
        &self,
        filter: AuditTrailFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<AuditTrailPage, BackendError>;

    /// Fetch a single Aurora audit-chain entry by id or by
    /// `current_hash` (v1.8.6) — `tools.aurora.admin.getAuditEntry`.
    /// Shares the `audit-trail` gate (Aurora leaves this endpoint
    /// bare-role-gated; cairn-mod gates both audit reads on one
    /// family per v2 LB-1). Unknown ids/hashes map to
    /// [`BackendError::Terminal`] (upstream 404).
    async fn get_audit_entry(
        &self,
        lookup: &AuditEntryLookup,
    ) -> Result<AuroraAuditEntry, BackendError>;

    /// Take down up to [`super::rust::batch_types::MAX_BATCH_SIZE`]
    /// accounts in one atomic upstream transaction (v1.8.7) —
    /// `tools.aurora.admin.batchTakedownAccounts`. Moderator+
    /// upstream; gated on the `batch-takedown` capability family
    /// (**OperatorOptIn** — the Rust backend additionally requires
    /// an operator `pinned_versions` entry, §8.1).
    ///
    /// Whole-batch atomicity per Aurora's contract: partial
    /// success is unobservable — any per-subject failure aborts
    /// the entire upstream transaction and surfaces the failing
    /// index/identifier in the mapped error's message.
    /// `precipitating_action_id` is the local batch intent row id
    /// (v1.8.5 convention).
    async fn batch_takedown_accounts(
        &self,
        dids: &[String],
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<BatchOutcome, BackendError>;

    /// Suspend up to `MAX_BATCH_SIZE` accounts atomically
    /// (v1.8.7) — `tools.aurora.admin.batchSuspendAccounts`.
    /// **Indefinite-only**: Aurora's batch-suspend wire has no
    /// duration field, so the trait deliberately takes none.
    /// Same gate/atomicity contract as
    /// [`Self::batch_takedown_accounts`].
    async fn batch_suspend_accounts(
        &self,
        dids: &[String],
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<BatchOutcome, BackendError>;

    /// Restore up to `MAX_BATCH_SIZE` accounts atomically
    /// (v1.8.7) — `tools.aurora.admin.batchRestoreAccounts`.
    ///
    /// **Trait-only in v1.8.7 (LB-A)**: no CLI subcommand, no
    /// recordAction writer path, no local `subject_actions` /
    /// `pds_admin_audit` row — the method dispatches directly to
    /// Aurora for programmatic callers. cairn-mod's shipped
    /// restore semantics ride the revoke flow (`revoke_action` +
    /// `dispatch_after_revoke_action`), which is single-target;
    /// extending it to batch shape is deferred to a future
    /// batch-revoke design cycle. No prior-action parameter:
    /// Aurora reverses each DID's *current* state server-side
    /// (same non-transmission as [`Self::restore_account`]), and
    /// no `precipitating_action_id` because there is no local
    /// intent row.
    async fn batch_restore_accounts(
        &self,
        dids: &[String],
        rationale: &str,
    ) -> Result<BatchOutcome, BackendError>;

    /// Take down up to `MAX_BATCH_SIZE` records **URI-level** in
    /// one atomic upstream transaction (v1.8.7) —
    /// `tools.aurora.admin.batchTakedownRecords`. Takes bare
    /// AT-URIs (not CID-anchored subjects): Aurora's documented
    /// empty-CID cascade convention makes each entry a takedown
    /// of *all versions* at that URI. The convention is scoped to
    /// this endpoint exclusively — CID-level batch takedowns
    /// belong on [`Self::takedown_record_many`] (v2 §3.3).
    async fn batch_takedown_records(
        &self,
        uris: &[String],
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<BatchOutcome, BackendError>;

    /// Multi-subject [`Self::delete_account`] (v1.8.7) — one
    /// `emitEvent{DeleteAccount}` with an N-element subjects
    /// array. Cap
    /// [`super::rust::batch_types::MAX_SUBJECTS_DELETE_ACCOUNT`]
    /// (10, the tightest multi-subject cap). Admin+ role floor
    /// upstream, `mod-events-emit` family — multi-subject is a
    /// shape modifier on the already-gated verb, not a new
    /// capability (v2 §8.2).
    async fn delete_account_many(
        &self,
        dids: &[String],
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Multi-subject [`Self::quarantine_blob`] (v1.8.7). Cap
    /// [`super::rust::batch_types::MAX_SUBJECTS_DEFAULT`] (50).
    async fn quarantine_blob_many(
        &self,
        subjects: &[BlobSubject],
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Multi-subject [`Self::restore_blob`] (v1.8.7). Cap 50.
    /// Unit-result per the restore symmetry; `prior_action_id` is
    /// one shared trait-boundary reference for the batch, ignored
    /// on the wire like its singular sibling's.
    async fn restore_blob_many(
        &self,
        subjects: &[BlobSubject],
        prior_action_id: &BackendActionId,
        rationale: &str,
    ) -> Result<(), BackendError>;

    /// Multi-subject [`Self::delete_blob`] (v1.8.7). Cap
    /// [`super::rust::batch_types::MAX_SUBJECTS_DELETE_BLOB`]
    /// (25).
    async fn delete_blob_many(
        &self,
        subjects: &[BlobSubject],
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Multi-subject [`Self::takedown_record`] (v1.8.7). Cap 50.
    /// **CID-required** on every subject (S-2): Aurora's
    /// multi-subject `TakedownRecord` arm performs no CID
    /// validation — an empty CID would flow through with
    /// undefined downstream semantics — so cairn-mod pre-rejects
    /// empty/absent CIDs with [`BackendError::Validation`].
    /// URI-level batch takedowns are exclusively
    /// [`Self::batch_takedown_records`] territory.
    async fn takedown_record_many(
        &self,
        subjects: &[Subject],
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Multi-subject [`Self::update_subject_status`] (v1.8.7) —
    /// one tri-state status applied to N accounts. Cap 50.
    async fn update_subject_status_many(
        &self,
        dids: &[String],
        status: SubjectStatus,
        rationale: &str,
        precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError>;

    /// Open the realtime moderation-event stream (v1.8.8) —
    /// `tools.aurora.admin.subscribeModEvents` WebSocket upgrade.
    /// Gated on the `mod-events-stream` capability family
    /// (**OperatorOptIn**: advertised AND pinned — the second
    /// consumer of the v1.8.7 pin-gate semantics).
    ///
    /// Returns a boxed frame stream — the first stream-returning
    /// method in this trait. `Pin<Box<dyn Stream …>>` rather than
    /// `impl Stream` because the trait is consumed as
    /// `Arc<dyn PdsAdminBackend>` (dyn-safety). Stream items are
    /// per-frame results; a transport failure surfaces as one
    /// final `Err(Transient)` item and the stream ends.
    ///
    /// `cursor` / `audit_chain_cursor` are the two independent
    /// resume positions (Aurora's event seq and chain seq are
    /// separate monotonic counters); `None` means live-only from
    /// the current tail. `audit_chain_cursor` is meaningful only
    /// when `include_audit_chain` is true.
    async fn subscribe_mod_events(
        &self,
        cursor: Option<i64>,
        audit_chain_cursor: Option<i64>,
        include_audit_chain: bool,
    ) -> Result<
        std::pin::Pin<
            Box<dyn futures_util::Stream<Item = Result<StreamFrame, BackendError>> + Send>,
        >,
        BackendError,
    >;

    /// Fetch aggregated instance metrics (v1.8.9) —
    /// `tools.aurora.ops.getInstanceMetrics`. Gates on the
    /// `instance-metrics` family (AutoAdvance). No role floor
    /// upstream beyond authentication. Absent optional fields
    /// mean "not instrumented", never zero.
    async fn get_instance_metrics(&self) -> Result<InstanceMetrics, BackendError>;

    /// Read one runtime setting (v1.8.9) —
    /// `tools.aurora.admin.getRuntimeSetting`. Gates on the
    /// `runtime-settings` family (**OperatorOptIn**, family-level:
    /// the read shares the write's pin). Unknown keys are a 200
    /// with `source: Default` upstream (no 404 path).
    /// `moderation-mode` reads are any-role; most other keys need
    /// Admin+ upstream (403 → [`BackendError::Auth`]).
    async fn get_runtime_setting(&self, key: &str) -> Result<RuntimeSetting, BackendError>;

    /// Write one runtime setting (v1.8.9) —
    /// `tools.aurora.admin.setRuntimeSetting`. Same family gate.
    /// SuperAdmin upstream (403 → `Auth`); Aurora's key allowlist
    /// + per-key value validation are authoritative (400 →
    /// `Validation` — cairn-mod deliberately validates nothing
    /// locally beyond a non-empty rationale). Returns the value
    /// diff + the upstream audit-chain entry id; there is no
    /// event id (setting writes emit no moderation event).
    async fn set_runtime_setting(
        &self,
        key: &str,
        value: &serde_json::Value,
        rationale: &str,
    ) -> Result<SetRuntimeSettingOutcome, BackendError>;

    /// v1.8.10 ops visibility reads — capability-bare upstream (no
    /// gate; availability is wire-discovered per F19; 404 →
    /// [`BackendError::Terminal`]). Seven return the upstream's
    /// ad-hoc JSON verbatim (`Value` pass-through — those bodies
    /// are handler-internal `json!` blocks with no contract
    /// structs; fabricated mirrors would break on upstream field
    /// tweaks). `get_federation_status` is the one typed response
    /// (camelCase wire). All Unsupported on Ozone.
    async fn get_system_health(&self) -> Result<serde_json::Value, BackendError>;
    /// See the group doc on [`Self::get_system_health`].
    async fn get_sequencer_status(&self) -> Result<serde_json::Value, BackendError>;
    /// See the group doc on [`Self::get_system_health`].
    async fn get_federation_status(&self) -> Result<FederationStatusResponse, BackendError>;
    /// See the group doc on [`Self::get_system_health`].
    async fn get_blob_statistics(&self) -> Result<serde_json::Value, BackendError>;
    /// See the group doc on [`Self::get_system_health`].
    async fn get_database_status(&self) -> Result<serde_json::Value, BackendError>;
    /// See the group doc on [`Self::get_system_health`].
    async fn get_resource_usage(&self) -> Result<serde_json::Value, BackendError>;
    /// See the group doc on [`Self::get_system_health`].
    async fn get_version_info(&self) -> Result<serde_json::Value, BackendError>;
    /// See the group doc on [`Self::get_system_health`].
    async fn get_system_metrics(&self) -> Result<serde_json::Value, BackendError>;

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

    /// Fetch a private kryphocron record and return its plaintext
    /// (v1.8.13). Called at report-ingest when a report's subject is a
    /// `tools.kryphocron.feed.postPrivate` record; the decoded
    /// plaintext is persisted on the report row so report-open is a
    /// pure read (no backend reach).
    ///
    /// The Rust backend: gates on the `kryphocron-read` opt-in, issues
    /// authenticated `com.atproto.repo.getRecord`, then branches — an
    /// authorized read returns server-side-decoded `text`
    /// ([`DecodeSource::AuroraServer`]); the normal unauthorized read
    /// returns `encodedContent`, which cairn-mod client-side-decodes
    /// with its installed `laquna/0.2` codec after a codec-id skew
    /// pre-check ([`DecodeSource::CairnClient`]). The combined
    /// fetch+decode lives in one method because the codec is private
    /// to the Rust backend. `OzoneBackend` returns
    /// [`BackendError::Unsupported`].
    async fn get_and_decode_kryphocron_record(
        &self,
        repo: &str,
        collection: &str,
        rkey: &str,
    ) -> Result<DecodedRecord, BackendError>;
}

/// Which decode path produced a [`DecodedRecord`] (v1.8.13).
/// Persisted to `reports.decode_source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeSource {
    /// Aurora returned server-side-decoded `text` (the requester was
    /// authorized on the record's audience — rare for cairn-mod).
    AuroraServer,
    /// cairn-mod client-side-decoded `encodedContent` with its
    /// installed codec (the normal unauthorized-read path).
    CairnClient,
}

impl DecodeSource {
    /// Wire string persisted to `reports.decode_source` (matches the
    /// migration 0014 CHECK constraint values).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuroraServer => "aurora_server",
            Self::CairnClient => "cairn_client",
        }
    }
}

/// A decoded private kryphocron record (v1.8.13). The plaintext is
/// persisted to `reports.decoded_plaintext`, the source to
/// `reports.decode_source`.
#[derive(Debug, Clone)]
pub struct DecodedRecord {
    /// Decoded record plaintext.
    pub plaintext: String,
    /// Which path produced [`Self::plaintext`].
    pub decode_source: DecodeSource,
}

#[cfg(test)]
mod label_bridge_invariant_tests {
    use super::LABEL_BRIDGE_INVARIANT_REASON;

    #[test]
    fn label_bridge_invariant_reason_contains_section_anchor() {
        assert!(
            LABEL_BRIDGE_INVARIANT_REASON.contains("§F4"),
            "LABEL_BRIDGE_INVARIANT_REASON must reference the §F4 architectural-section anchor"
        );
    }

    #[test]
    fn label_bridge_invariant_reason_contains_canonical_surface_name() {
        assert!(
            LABEL_BRIDGE_INVARIANT_REASON.contains("subscribeLabels"),
            "LABEL_BRIDGE_INVARIANT_REASON must name subscribeLabels as the canonical surface"
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

    #[test]
    fn backend_action_id_new_constructs_per_event() {
        // v1.7-compat constructor produces PerEvent — every existing
        // call site (synthesize_action_id, audit-row reads) gets the
        // PerEvent variant transparently.
        let id = BackendActionId::new("ozone:did:plc:abc:42");
        assert!(matches!(id, BackendActionId::PerEvent(_)));
    }

    #[test]
    fn backend_action_id_per_batch_as_str_returns_inner() {
        let id = BackendActionId::PerBatch("batch-7".to_string());
        assert_eq!(id.as_str(), "batch-7");
        assert_eq!(format!("{id}"), "batch-7");
    }

    #[test]
    fn backend_action_id_per_event_and_per_batch_compare_unequal() {
        // Variant tag participates in equality even when the inner
        // wire string is identical — required so HashMap lookups
        // don't conflate the two action shapes.
        let evt = BackendActionId::PerEvent("x".to_string());
        let batch = BackendActionId::PerBatch("x".to_string());
        assert_ne!(evt, batch);

        let mut map: std::collections::HashMap<BackendActionId, &'static str> =
            std::collections::HashMap::new();
        map.insert(evt.clone(), "single");
        map.insert(batch.clone(), "batched");
        assert_eq!(map.get(&evt), Some(&"single"));
        assert_eq!(map.get(&batch), Some(&"batched"));
    }

    #[test]
    fn backend_action_id_serializes_as_bare_string_no_variant_tag() {
        // Wire compatibility with v1.7's newtype shape — the
        // pds_admin_audit.backend_action_id column is a single
        // TEXT, hash-relevant; the variant tag must not leak.
        let evt = BackendActionId::PerEvent("ozone:did:x:1".to_string());
        let json = serde_json::to_string(&evt).unwrap();
        assert_eq!(json, "\"ozone:did:x:1\"");

        let batch = BackendActionId::PerBatch("ozone:batch:1".to_string());
        let json = serde_json::to_string(&batch).unwrap();
        assert_eq!(json, "\"ozone:batch:1\"");
    }

    #[test]
    fn backend_action_id_deserializes_string_as_per_event() {
        // Step 7's chainlink-#110 migration adds a discriminator
        // column so PerBatch can ride a separate channel; until
        // then, every wire deserialization produces PerEvent (the
        // v1.7-compat backfill rule).
        let id: BackendActionId = serde_json::from_str("\"ozone:did:x:1\"").unwrap();
        assert_eq!(id, BackendActionId::PerEvent("ozone:did:x:1".to_string()));
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
        let e = BackendError::ArchitecturallyForbidden(LABEL_BRIDGE_INVARIANT_REASON.to_string());
        let rendered = format!("{e}");
        assert!(rendered.starts_with("method architecturally forbidden:"));
        assert!(rendered.contains("§F4"));
        assert!(rendered.contains("subscribeLabels"));
    }

    // ===== variant_name + message accessors =====

    #[test]
    fn variant_name_returns_eight_stable_strings() {
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
            (
                BackendError::KryphocronDecodeFailed(KryphocronDecodeError::CodecError("x".into())),
                "KryphocronDecodeFailed",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(err.variant_name(), *expected);
        }

        // Compiler backstop (S-2 fold): this exhaustive destructure
        // has no wildcard, so adding a ninth `BackendError` variant
        // fails to compile here until the case list above is also
        // extended. Keeps the `cases` vec — which enumerates by
        // construction and would otherwise pass silently at the wrong
        // cardinality — honest about the true variant count.
        let sample = BackendError::Unsupported;
        match sample {
            BackendError::Transient(_)
            | BackendError::Validation(_)
            | BackendError::Terminal(_)
            | BackendError::Auth(_)
            | BackendError::CapabilityNotAdvertised(_)
            | BackendError::Unsupported
            | BackendError::ArchitecturallyForbidden(_)
            | BackendError::KryphocronDecodeFailed(_) => {}
        }
        assert_eq!(cases.len(), 8, "BackendError cardinality is eight");
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
