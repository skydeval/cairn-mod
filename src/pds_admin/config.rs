//! Runtime config types + resolver for the PDS-admin outbound
//! bridge (§F23, #83, v1.7).
//!
//! The TOML projection types live in [`crate::config`] alongside
//! the rest of the operator-facing config schema; this module
//! holds the validated runtime equivalents that the future
//! `OzoneBackend` (#86) and audit integration (#85) consume.
//!
//! # Validation rules (per §A11 of the v1.7 architectural decisions)
//!
//! - When `[pds_admin].enabled = true`, exactly one backend
//!   subsection must be present. v1.7 supports `[pds_admin.ozone]`
//!   only; `[pds_admin.locus]` is reserved for v1.8 and rejected
//!   here with a v1.8-pointer message. Any other subsection name
//!   (including typos) is rejected with `"backend not supported in
//!   v1.7: <name>"`.
//! - `[pds_admin.ozone].pds_url` parses via [`url::Url::parse`]
//!   and **must use the `https` scheme**. http URLs are rejected
//!   unconditionally in v1.7 (no dev-mode escape hatch ships in
//!   #83).
//! - `[pds_admin.ozone].admin_password_env` names an env var that
//!   must be set and non-empty at config load. The value is
//!   resolved into [`AdminPassword`] (a redacting newtype) at
//!   load time; subsequent env mutations don't affect the running
//!   process.
//! - `[pds_admin.ozone].request_timeout_seconds` defaults to 10;
//!   valid range 1..=60 inclusive.
//! - `[pds_admin.action_map]` must cover every cairn-mod action
//!   type (`takedown`, `temp_suspension`, `indef_suspension`,
//!   `warning`, `note`). Missing keys → error listing the missing
//!   types.
//! - Each action_map value is one of `takedown_account` /
//!   `suspend_account` / `restore_account` / `apply_label` /
//!   `negate_label` / `skip`. Unknown methods → error.
//! - `apply_label` / `negate_label` are syntactically valid but
//!   the v1.7 `OzoneBackend` (#89) returns `Unsupported` for them
//!   at runtime. The resolver emits a `tracing::warn!` at config
//!   load to surface the mismatch to operators.
//! - The `{ method, with_lift_after }` table form is only valid
//!   for `temp_suspension`; setting it on any other action type
//!   is rejected. **`with_lift_after = true` is rejected at
//!   config load in v1.7** with a v1.8-pointer message — cairn-mod
//!   has no deferred-execution layer today (only `tokio::time::interval`
//!   recurring foreground tasks).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::moderation::types::ActionType;

/// All five cairn-mod action types in canonical order. The
/// resolver checks every entry as an action_map key.
const REQUIRED_ACTION_TYPES: &[ActionType] = &[
    ActionType::Takedown,
    ActionType::IndefSuspension,
    ActionType::TempSuspension,
    ActionType::Warning,
    ActionType::Note,
    // v1.8.5: the ten backend-dispatched verbs. Same coverage rule
    // as v1.7 — every action type must be mapped explicitly (map
    // to the same-named method, or "skip" to keep the verb
    // CLI-recordable without PDS dispatch). Operators upgrading to
    // v1.8 extend [pds_admin.action_map] with these ten entries.
    ActionType::DeleteAccount,
    ActionType::QuarantineBlob,
    ActionType::RestoreBlob,
    ActionType::DeleteBlob,
    ActionType::ResolveReport,
    ActionType::DismissReport,
    ActionType::ResolveAppeal,
    ActionType::EscalateAppeal,
    ActionType::SendEmail,
    ActionType::UpdateSubjectStatus,
];

/// Resolved PDS-admin policy. Built once at startup via
/// [`Self::from_config`]; subsequent code consults the resolved
/// fields without re-parsing TOML.
#[derive(Debug, Clone)]
pub struct PdsAdminPolicy {
    /// `false` (default) — bridge is off; the recordAction path
    /// does not consult any backend. `true` — bridge is on; the
    /// resolved [`Self::backend`] is `Some(_)` and the
    /// [`Self::action_map`] covers every cairn-mod action type.
    pub enabled: bool,
    /// Resolved backend config. `None` when [`Self::enabled`] is
    /// `false` (operators may declare `[pds_admin.ozone]` while
    /// disabled for forward-compat — those values are validated
    /// per-block but not surfaced here). When [`Self::enabled`]
    /// is `true`, this is `Some(_)`.
    pub backend: Option<PdsAdminBackendConfig>,
    /// Resolved action-type → backend-method mapping. Empty when
    /// disabled; covers every cairn-mod action type
    /// (`takedown`, `temp_suspension`, `indef_suspension`,
    /// `warning`, `note`) when enabled.
    pub action_map: BTreeMap<ActionType, ActionMapEntry>,
}

/// Backend selector. v1.7 has only [`Self::Ozone`]; v1.8.1
/// adds [`Self::Rust`] for Aurora-Locus and other ATProto
/// Rust PDSes. The resolver enforces the truth table over
/// `(backend selector, ozone block, rust block)`; downstream
/// consumers match on this enum to dispatch.
#[derive(Debug, Clone)]
pub enum PdsAdminBackendConfig {
    /// bsky-PDS backend (the v1.7 default).
    Ozone(OzoneBackendConfig),
    /// Rust-PDS backend (v1.8.1+). Inspector-only in v1.8.1
    /// per the audit-divergence acknowledgment posture; v1.8.2
    /// lifts the restriction once protocol parity ships.
    Rust(Box<RustBackendConfig>),
}

/// Resolved bsky-PDS backend config.
#[derive(Debug, Clone)]
pub struct OzoneBackendConfig {
    /// Parsed PDS base URL. Always `https` in v1.7.
    pub pds_url: url::Url,
    /// Admin Basic-auth password resolved from the env var
    /// named by `admin_password_env` at config load. Wrapped
    /// for redacting Debug + zero-on-drop.
    pub admin_password: AdminPassword,
    /// Per-request HTTP timeout. Clamped to 1..=60 seconds at
    /// validation; the runtime value is the operator's choice or
    /// the default of 10s.
    pub request_timeout: Duration,
}

/// Resolved Rust-PDS backend config.
///
/// Built from [`crate::config::PdsAdminRustToml`] by the
/// resolver. v1.8.1 shape: ES256K service-auth identity fields
/// (the OAuth-model residue — `client_id`/`client_secret`/
/// `scopes` — was dropped before ever shipping to a live
/// deployment), plus refresh cadence, capability declarations,
/// and the audit-divergence acknowledgment flag that gates the
/// v1.8.1 inspector-only posture.
///
/// The signing key itself is deliberately NOT resolved here —
/// config holds only the env-var *name*
/// ([`Self::service_signing_key_env`]); `RustBackend::new` reads
/// and parses the key material at construction so key bytes
/// never sit in the resolved-config layer.
#[derive(Debug, Clone)]
pub struct RustBackendConfig {
    /// Parsed PDS base URL. TOML wire key: `url`.
    pub pds_url: url::Url,
    /// cairn-mod's service DID — the `iss` of every minted
    /// service-auth JWT. Literal, not env-indirected: DIDs are
    /// not secrets.
    pub service_did: String,
    /// Name of the env var holding the hex-encoded secp256k1
    /// private key. The `_env` indirection mirrors the
    /// [`AdminPassword`] pattern for secret material.
    pub service_signing_key_env: String,
    /// Where cairn-mod's DID doc is resolvable, when the DID
    /// method needs an operator-supplied URL (`did:web`
    /// typically does; `did:plc` resolves via the PLC
    /// directory). Informational at v1.8.1 — Aurora does the
    /// resolving, not cairn-mod.
    pub service_did_document_url: Option<url::Url>,
    /// The target PDS's service DID — the `aud` of every minted
    /// JWT. Mandatory operator-configured; there is no
    /// discovery endpoint (umbrella §5.2).
    pub target_service_did: String,
    /// Per-request HTTP timeout. Default 30s; bounds 1s..=5m at
    /// validation.
    pub request_timeout: Duration,
    /// Cap-set refresh cadence. Default 1 hour; lower bound
    /// 10 seconds.
    pub capability_refresh_interval: Duration,
    /// Capability families the operator declared as required.
    /// Empty by default. Each entry is a non-empty wire
    /// string; typed validation against the
    /// [`super::CAPABILITY_CLASSIFICATIONS`] registry lands
    /// at the first capability-gated trait method consumer.
    pub required_capabilities: Vec<String>,
    /// Per-family pinned capability versions. Empty by
    /// default. Family names cross-validated against
    /// `required_capabilities` for consistency.
    pub pinned_versions: BTreeMap<String, String>,
    /// Parse+store at v1.8.1 — no runtime code path reads it.
    /// Default `true`. The consumer wires in at v1.8.6
    /// alongside audit-trail verification work (umbrella §5.2);
    /// accepted now so operators can pre-configure.
    pub verification_persist: bool,
    /// Operator's explicit acknowledgment of the v1.8.1
    /// inspector-only audit divergence. **Required `true`**
    /// when the bridge is enabled and this backend is
    /// selected; otherwise the
    /// [`validate_audit_divergence_acknowledgment`] gate
    /// rejects the configuration at startup. Self-removing
    /// across the v1.8 series: required v1.8.1, deprecated
    /// v1.8.2, removed v1.8.3.
    pub acknowledge_v1_8_1_audit_divergence: bool,
}

/// Resolver discriminator for the active backend.
///
/// Returned by [`resolve_backend`] over the truth table of
/// `(backend selector, ozone block, rust block)`. Distinct
/// from [`PdsAdminBackendConfig`] (which carries the resolved
/// config payload) because resolution is a pure function of
/// the TOML projection — the dispatch logic that builds the
/// payload runs after this discriminator is decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendSelection {
    /// bsky-PDS via [`crate::pds_admin::OzoneBackend`].
    Ozone,
    /// Rust PDS via the v1.8.1+ Rust backend (deferred
    /// implementation lands at Step 5 of v1.8.1).
    Rust,
}

/// Structured config-validation errors for the `[pds_admin]`
/// block.
///
/// Distinct from cairn-mod's top-level `Error` so test
/// assertions can match on variants directly. Converts to
/// `Error::Signing(format!("config: ..."))` for the
/// operator-facing surface (matching cairn-mod's existing
/// stringly-typed config error pattern).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PdsAdminConfigError {
    /// Both `[pds_admin.ozone]` and `[pds_admin.rust]` are
    /// present with no explicit `backend` selector.
    #[error(
        "config: [pds_admin] declares both `ozone` and `rust` subsections \
         but no `backend` selector — set `backend = \"ozone\"` or \
         `backend = \"rust\"` to disambiguate"
    )]
    AmbiguousBackend,
    /// `[pds_admin].enabled = true` but neither subsection is
    /// present.
    #[error(
        "config: [pds_admin].enabled = true but no backend subsection is present \
         (declare [pds_admin.ozone] or [pds_admin.rust])"
    )]
    NoBackendConfigured,
    /// `backend = "ozone"` but `[pds_admin.ozone]` is absent.
    #[error(
        "config: [pds_admin].backend = \"ozone\" requires [pds_admin.ozone] \
         to be declared"
    )]
    SelectorRequiresOzoneBlock,
    /// `backend = "rust"` but `[pds_admin.rust]` is absent.
    #[error(
        "config: [pds_admin].backend = \"rust\" requires [pds_admin.rust] \
         to be declared"
    )]
    SelectorRequiresRustBlock,
    /// `backend = "<value>"` is not one of the recognized
    /// strings. v1.8.1 accepts `"ozone"` or `"rust"`.
    #[error(
        "config: [pds_admin].backend = {0:?} is not a recognized backend \
         (expected \"ozone\" or \"rust\")"
    )]
    UnknownBackend(String),
    /// `backend = ""` — distinct from
    /// [`Self::UnknownBackend`] so accidental empty-string
    /// typos surface clearly.
    #[error(
        "config: [pds_admin].backend = \"\" is empty (set to \"ozone\" or \"rust\", \
         or remove the key for auto-detection)"
    )]
    EmptyBackendSelector,
    /// Per-block validation failure for `[pds_admin.ozone]`.
    /// The inner string carries the specific rule that
    /// failed.
    #[error("config: [pds_admin.ozone] is invalid: {0}")]
    OzoneBlockInvalid(String),
    /// Per-block validation failure for `[pds_admin.rust]`.
    /// The inner string carries the specific rule that
    /// failed.
    #[error("config: [pds_admin.rust] is invalid: {0}")]
    RustBlockInvalid(String),
    /// Unknown subsection or sibling key under `[pds_admin]`.
    /// The `block` is the parent section (e.g.
    /// `"pds_admin"`); the `key` is the offending name.
    #[error("config: [{block}] declares unknown sibling key {key:?}")]
    UnknownKey {
        /// Parent section name without brackets.
        block: String,
        /// Offending key name.
        key: String,
    },
    /// An env var named by `admin_password_env` /
    /// `service_signing_key_env` is unset or empty at process
    /// startup.
    #[error("config: env var ${0} is not set or is empty")]
    MissingEnvVar(String),
    /// A `[pds_admin.rust]` key that was removed in the v1.8.1
    /// service-auth rewrite (`client_id_env`,
    /// `client_secret_env`, `scopes`) is still present. The
    /// OAuth-shaped config never shipped to a live deployment;
    /// the error points operators at the replacement fields.
    #[error(
        "config: [pds_admin.rust].{0} was removed in v1.8.1 — RustBackend \
         authenticates via ES256K service-auth JWTs, not OAuth. Remove the key \
         and configure `service_did`, `service_signing_key_env`, and \
         `target_service_did` instead"
    )]
    RemovedOAuthField(&'static str),
    /// `capability_refresh_interval` resolves to less than
    /// the lower bound (10 seconds).
    #[error(
        "config: [pds_admin.rust].capability_refresh_interval = {0:?} is below \
         the lower bound of 10s"
    )]
    CapabilityRefreshIntervalTooShort(String),
    /// `capability_refresh_interval` is not a parseable
    /// duration string.
    #[error(
        "config: [pds_admin.rust].capability_refresh_interval = {0:?} is not a \
         valid duration (expected forms like \"10s\", \"5m\", \"1h\")"
    )]
    CapabilityRefreshIntervalUnparseable(String),
    /// `pinned_versions` references a family name that doesn't
    /// appear in `required_capabilities` (or vice versa). The
    /// inner strings carry the specific mismatch.
    #[error("config: [pds_admin.rust].pinned_versions / required_capabilities mismatch: {0}")]
    PinnedVersionMismatch(String),
    /// `[pds_admin.rust].acknowledge_v1_8_1_audit_divergence`
    /// is missing or `false` while the bridge is enabled with
    /// the Rust backend selected.
    #[error(
        "config: [pds_admin].enabled = true with backend = \"rust\" requires \
         [pds_admin.rust].acknowledge_v1_8_1_audit_divergence = true. \
         The v1.8.1 RustBackend is inspector-only — every dispatch produces \
         an audit-failure row until v1.8.2's protocol-parity work lands and \
         lifts this restriction along with the \
         acknowledge_v1_8_1_audit_divergence flag."
    )]
    AuditDivergenceAcknowledgmentRequired,
    /// `policy_automation` declares one or more rules in
    /// `mode = "auto"` while the bridge is enabled with the
    /// Rust backend. Auto-mode rules dispatch to the backend
    /// without operator confirmation; in v1.8.1's inspector-only
    /// posture this would silently produce audit-failure rows
    /// at every auto-fire. The inner vector carries the names
    /// of the offending rules.
    #[error(
        "config: [pds_admin].backend = \"rust\" is incompatible with \
         policy_automation rules in mode = \"auto\" (rules: {0:?}). \
         v1.8.2's protocol-parity work makes RustBackend functional and \
         lifts this restriction along with the \
         acknowledge_v1_8_1_audit_divergence flag."
    )]
    PolicyAutoModeIncompatibleWithInspectorRustBackend(Vec<String>),
    /// `[xrpc_gateway].enabled = true` while the bridge is
    /// enabled with the Rust backend. The inbound XRPC gateway
    /// dispatches into the recordAction path which would call
    /// the Rust backend; v1.8.1 rejects this combination at
    /// startup.
    #[error(
        "config: [pds_admin].backend = \"rust\" is incompatible with \
         [xrpc_gateway].enabled = true. v1.8.2's protocol-parity work makes \
         RustBackend functional and lifts this restriction along with the \
         acknowledge_v1_8_1_audit_divergence flag."
    )]
    XrpcGatewayIncompatibleWithInspectorRustBackend,
    /// `[pds_admin.locus]` is set — early-design name
    /// renamed to `[pds_admin.rust]` in v1.8.1.
    #[error(
        "config: [pds_admin.locus] was renamed to [pds_admin.rust] in v1.8.1; \
         move the subsection's contents under the new name"
    )]
    LocusBlockRenamed,
}

impl From<PdsAdminConfigError> for Error {
    fn from(e: PdsAdminConfigError) -> Self {
        // Match the v1.7 stringly-typed config-error pattern. Tests can
        // still match on the structured PdsAdminConfigError directly when
        // they call resolve_backend / validated_rust_from_toml /
        // validate_audit_divergence_acknowledgment without going through
        // the conversion.
        Error::Signing(e.to_string())
    }
}

/// Per-action-type entry in the resolved action_map. `Skip`
/// short-circuits the backend call for that action type; the
/// `Method` variant carries the resolved backend method enum.
///
/// v1.7's table form (`{ method, with_lift_after }`) collapses
/// into [`Self::Method`] here — `with_lift_after = false` (or
/// absent) is equivalent to the bare-string form, and
/// `with_lift_after = true` was rejected upstream at validation.
/// v1.8 will introduce a `MethodWithLift` variant when the
/// deferred-execution layer ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionMapEntry {
    /// Don't call the backend for this action type. The cairn-mod
    /// label emission still fires per `[label_emission]`; only
    /// the PDS-side enforcement is skipped.
    Skip,
    /// Call the named backend method.
    Method(BackendMethod),
}

/// Backend method enum. The set is fixed; the resolver rejects
/// any other string. `OzoneBackend` (#86–#90) implements three
/// of these (`TakedownAccount`, `SuspendAccount`, `RestoreAccount`)
/// against bsky-PDS's `com.atproto.admin.updateSubjectStatus`;
/// `ApplyLabel` and `NegateLabel` return `Unsupported` at runtime
/// per A5 (#89) — labels stay native to cairn-mod's
/// `subscribeLabels`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendMethod {
    /// Permanently take down the account at the PDS side.
    TakedownAccount,
    /// Suspend the account (semantics vary by backend; bsky-PDS
    /// expresses suspension via takedown with a scheduled lift,
    /// which v1.7 doesn't yet implement).
    SuspendAccount,
    /// Restore (un-takedown / un-suspend) the account.
    RestoreAccount,
    /// Apply a label at the PDS side. **Not implemented by
    /// `OzoneBackend` in v1.7** (#89): cairn-mod's labels stay
    /// native to its `subscribeLabels` surface. Mapping a
    /// cairn-mod action to this method is syntactically valid
    /// but emits a config-load warning so operators see the
    /// mismatch.
    ApplyLabel,
    /// Negate a previously-applied label at the PDS side. Same
    /// `Unsupported` posture as [`Self::ApplyLabel`].
    NegateLabel,
    /// Take down a single record at the PDS side (v1.8.2).
    /// Reached via explicit action_map route or by the dispatch
    /// layer's subject-shape auto-elevation from
    /// [`Self::TakedownAccount`] when the underlying
    /// `subject_actions` row targets a record with full
    /// coordinates (see `crate::pds_admin::dispatch`).
    TakedownRecord,
    // ---- v1.8.5 action-surface methods (migration 0010 extends
    // the pds_admin_audit.backend_method CHECK to match). All
    // dispatch through emitEvent on the Rust backend; OzoneBackend
    // returns Unsupported for all ten. ----
    /// Permanently delete the account (Admin+ upstream).
    DeleteAccount,
    /// Quarantine a blob.
    QuarantineBlob,
    /// Restore a quarantined blob (unit-result trait method — the
    /// upstream event id is deliberately discarded, matching
    /// [`Self::RestoreAccount`]).
    RestoreBlob,
    /// Permanently delete a blob (Moderator+ upstream — the Admin
    /// gate covers only DeleteAccount and SendEmail).
    DeleteBlob,
    /// Resolve an upstream report (row detail carries report id +
    /// resolution).
    ResolveReport,
    /// Dismiss an upstream report.
    DismissReport,
    /// Resolve an upstream appeal; approve cascades a reversal.
    ResolveAppeal,
    /// Escalate an upstream appeal.
    EscalateAppeal,
    /// Send a moderation email (Admin+ upstream).
    SendEmail,
    /// Set the account's upstream moderation status (tri-state).
    UpdateSubjectStatus,
}

impl BackendMethod {
    /// Parse the wire-string form. Returns `None` for unknown
    /// strings so the caller can surface a config-load error
    /// listing the allowed set. `pub(crate)` (and named `from_wire_str`
    /// rather than `from_str`) to dodge clippy's
    /// `should_implement_trait` lint while still letting #85's
    /// `pds_admin_audit` deserializer rehydrate stored
    /// `backend_method` strings from the DB. Matches the
    /// [`crate::policy::automation::PolicyMode`] precedent for
    /// internal-only enum parsers.
    pub(crate) fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "takedown_account" => Some(Self::TakedownAccount),
            "suspend_account" => Some(Self::SuspendAccount),
            "restore_account" => Some(Self::RestoreAccount),
            "apply_label" => Some(Self::ApplyLabel),
            "negate_label" => Some(Self::NegateLabel),
            "takedown_record" => Some(Self::TakedownRecord),
            "delete_account" => Some(Self::DeleteAccount),
            "quarantine_blob" => Some(Self::QuarantineBlob),
            "restore_blob" => Some(Self::RestoreBlob),
            "delete_blob" => Some(Self::DeleteBlob),
            "resolve_report" => Some(Self::ResolveReport),
            "dismiss_report" => Some(Self::DismissReport),
            "resolve_appeal" => Some(Self::ResolveAppeal),
            "escalate_appeal" => Some(Self::EscalateAppeal),
            "send_email" => Some(Self::SendEmail),
            "update_subject_status" => Some(Self::UpdateSubjectStatus),
            _ => None,
        }
    }

    /// Wire-string form. Inverse of the module-private
    /// `from_wire_str` parser; call sites that need a string
    /// for logs / audit context use this method.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::TakedownAccount => "takedown_account",
            Self::SuspendAccount => "suspend_account",
            Self::RestoreAccount => "restore_account",
            Self::ApplyLabel => "apply_label",
            Self::NegateLabel => "negate_label",
            Self::TakedownRecord => "takedown_record",
            Self::DeleteAccount => "delete_account",
            Self::QuarantineBlob => "quarantine_blob",
            Self::RestoreBlob => "restore_blob",
            Self::DeleteBlob => "delete_blob",
            Self::ResolveReport => "resolve_report",
            Self::DismissReport => "dismiss_report",
            Self::ResolveAppeal => "resolve_appeal",
            Self::EscalateAppeal => "escalate_appeal",
            Self::SendEmail => "send_email",
            Self::UpdateSubjectStatus => "update_subject_status",
        }
    }

    /// Whether `OzoneBackend` (the v1.7 backend) implements this
    /// method. Returns `false` for the label methods that
    /// `OzoneBackend` will reject at runtime per A5 (#89). The
    /// resolver uses this to emit a config-load warning when an
    /// action_map entry maps to an unimplemented method.
    pub fn is_implemented_by_ozone_v1_7(self) -> bool {
        match self {
            Self::TakedownAccount
            | Self::SuspendAccount
            | Self::RestoreAccount
            | Self::TakedownRecord => true,
            Self::ApplyLabel | Self::NegateLabel => false,
            // v1.8.5 methods: OzoneBackend returns Unsupported
            // (real bsky-PDS-admin mappings considered and
            // deferred post-v1.8).
            Self::DeleteAccount
            | Self::QuarantineBlob
            | Self::RestoreBlob
            | Self::DeleteBlob
            | Self::ResolveReport
            | Self::DismissReport
            | Self::ResolveAppeal
            | Self::EscalateAppeal
            | Self::SendEmail
            | Self::UpdateSubjectStatus => false,
        }
    }

    /// Whether the trait method for this backend method returns
    /// `Result<BackendActionId, BackendError>` (true) versus
    /// `Result<(), BackendError>` (false).
    ///
    /// Used by the dispatch path in [`crate::pds_admin::dispatch`]
    /// to project a backend-call result into the unified
    /// `Result<Option<BackendActionId>, BackendError>` shape that
    /// [`crate::pds_admin::audit::record_pds_admin_call`] expects.
    /// Per #87 — single-source the convention so call sites don't
    /// need to remember which methods carry an id.
    ///
    /// `takedown_account` and `suspend_account` synthesize a
    /// client-side id (per #87's `synthesize_action_id`) so they
    /// "return" one. `restore_account` takes a prior id and
    /// returns nothing semantically new. The label methods don't
    /// participate in the id surface.
    pub fn returns_action_id(self) -> bool {
        match self {
            Self::TakedownAccount | Self::SuspendAccount | Self::TakedownRecord => true,
            Self::RestoreAccount | Self::ApplyLabel | Self::NegateLabel => false,
            // v1.8.5: every new method returns ActionResponse
            // (whose event_id becomes the audit row's
            // backend_action_id) except RestoreBlob, whose trait
            // method is unit-result per restore_account symmetry.
            Self::DeleteAccount
            | Self::QuarantineBlob
            | Self::DeleteBlob
            | Self::ResolveReport
            | Self::DismissReport
            | Self::ResolveAppeal
            | Self::EscalateAppeal
            | Self::SendEmail
            | Self::UpdateSubjectStatus => true,
            Self::RestoreBlob => false,
        }
    }
}

/// Admin password newtype. Redacts in `Debug`; zeroes its
/// allocation on drop. Resolved once from the env var named by
/// `admin_password_env` at config load; v1.7 doesn't yet wire
/// the value into HTTP auth (that's #86).
///
/// The newtype enforces:
/// - `Debug` never prints the secret (just `AdminPassword(<redacted>)`).
/// - `Drop` zeroes the underlying bytes via [`zeroize`].
/// - No `Serialize` / `Deserialize` — the value comes from env,
///   not config files.
///
/// `Clone` is permitted (the password may be cloned into HTTP
/// client state when #86 lands); the cloned value is a new
/// allocation and zeros independently.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AdminPassword(String);

impl AdminPassword {
    /// Construct from a resolved env-var value (or a test
    /// fixture).
    ///
    /// In production the v1.7 resolver is the only call site;
    /// operator code outside the resolver shouldn't conjure
    /// admin passwords from arbitrary strings — the
    /// env-var-resolver path is what makes the
    /// `admin_password_env` indirection meaningful for #83's
    /// "no plaintext in TOML" posture. Promoted to `pub` so
    /// integration tests in `tests/ozone_backend.rs` (#87) can
    /// construct an [`OzoneBackendConfig`] for wiremock-backed
    /// tests without a per-test env-var dance.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Borrow the underlying password as a `&str` for use at the
    /// HTTP-auth boundary. Caller is responsible for not leaking
    /// the borrow into logs or error messages.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AdminPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AdminPassword").field(&"<redacted>").finish()
    }
}

impl PdsAdminPolicy {
    /// Build the policy from `cfg.pds_admin`. When the field is
    /// `None` (operator declared no `[pds_admin]` block), returns
    /// [`Self::defaults`] (engine off, no backend, empty action
    /// map). When `Some(_)`, applies the validation rules in the
    /// module docs and returns the resolved policy.
    pub fn from_config(cfg: &crate::config::Config) -> Result<Self> {
        let Some(toml) = cfg.pds_admin.as_ref() else {
            return Ok(Self::defaults());
        };
        // Wrap `std::env::var` in a closure so the HRTB on
        // `validated_from_toml`'s `F: Fn(&str) -> ...` bound
        // resolves cleanly. Passing the function item directly
        // pins the lifetime to a specific one rather than
        // higher-rank, which the bound can't accept.
        Self::validated_from_toml(toml, |name| std::env::var(name))
    }

    /// Test-only entry point that injects an env reader. The
    /// crate-wide `#![forbid(unsafe_code)]` rules out
    /// [`std::env::set_var`] in tests (it became `unsafe` in Rust
    /// 2024); injecting a reader closure lets tests verify the
    /// env-resolution code path without mutating process env.
    /// The public [`Self::from_config`] always uses
    /// [`std::env::var`].
    #[cfg(test)]
    pub(crate) fn from_config_with_env_reader<F>(
        cfg: &crate::config::Config,
        read_env: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> std::result::Result<String, std::env::VarError>,
    {
        let Some(toml) = cfg.pds_admin.as_ref() else {
            return Ok(Self::defaults());
        };
        Self::validated_from_toml(toml, read_env)
    }

    /// Default policy. Engine off; no backend; empty action map.
    /// The recordAction path consults `enabled` first and
    /// short-circuits without touching any other field.
    pub fn defaults() -> Self {
        Self {
            enabled: false,
            backend: None,
            action_map: BTreeMap::new(),
        }
    }

    fn validated_from_toml<F>(toml: &crate::config::PdsAdminConfigToml, read_env: F) -> Result<Self>
    where
        F: Fn(&str) -> std::result::Result<String, std::env::VarError>,
    {
        // Forward-compat: when `enabled = false`, validate per-
        // subsection but skip the cross-block rules. Operators
        // staging a config behind `enabled = false` should still
        // get told about typos / renamed keys / invalid blocks —
        // but they shouldn't be forced to fill in every action_map
        // entry just to typecheck the toggle off.
        reject_unsupported_backend_subsections(toml)?;

        // Per-block validation runs whether or not `enabled = true`,
        // so a staging config still gets URL / env-var / scope
        // checking. The resolved values only surface on the policy
        // when `enabled = true` and the resolver picks the matching
        // backend.
        let resolved_ozone = toml
            .ozone
            .as_ref()
            .map(|t| validated_ozone_from_toml(t, &read_env))
            .transpose()?;
        let resolved_rust = toml
            .rust
            .as_ref()
            .map(|t| validated_rust_from_toml(t, &read_env))
            .transpose()?;

        if !toml.enabled {
            return Ok(Self {
                enabled: false,
                backend: None,
                action_map: BTreeMap::new(),
            });
        }

        // enabled = true: resolve the active backend per the truth
        // table over (selector, ozone-present, rust-present), then
        // pick the resolved value matching the selection.
        let selection = resolve_backend(toml)?;
        let backend = match selection {
            BackendSelection::Ozone => {
                let ozone = resolved_ozone
                    .expect("resolve_backend returns Ozone only when [pds_admin.ozone] is present");
                PdsAdminBackendConfig::Ozone(ozone)
            }
            BackendSelection::Rust => {
                let rust = resolved_rust
                    .expect("resolve_backend returns Rust only when [pds_admin.rust] is present");
                PdsAdminBackendConfig::Rust(Box::new(rust))
            }
        };

        let action_map_toml = toml.action_map.as_ref().ok_or_else(|| {
            Error::Signing(
                "config: [pds_admin].enabled = true but [pds_admin.action_map] is absent \
                 (every cairn-mod action type must be mapped to a backend method or \"skip\")"
                    .into(),
            )
        })?;
        let action_map = validated_action_map(action_map_toml)?;

        Ok(Self {
            enabled: true,
            backend: Some(backend),
            action_map,
        })
    }
}

/// Resolve the active backend per the v1.8.1 truth table over
/// `(backend selector, ozone-present, rust-present)`.
///
/// Called only when `[pds_admin].enabled = true`; the
/// disabled short-circuit inside
/// [`PdsAdminPolicy::from_config`] runs first.
///
/// When the selector is set explicitly **and** both subsections
/// are present, the unselected subsection still validated
/// per-block (above), but its resolved value is logged as
/// "ignored, present but not selected" via `tracing::info!` and
/// not surfaced on the policy.
pub fn resolve_backend(
    toml: &crate::config::PdsAdminConfigToml,
) -> std::result::Result<BackendSelection, PdsAdminConfigError> {
    let ozone_present = toml.ozone.is_some();
    let rust_present = toml.rust.is_some();

    let selector_str: Option<&str> = toml.backend.as_deref();
    let selector = match selector_str {
        None => None,
        Some("") => return Err(PdsAdminConfigError::EmptyBackendSelector),
        Some("ozone") => Some(BackendSelection::Ozone),
        Some("rust") => Some(BackendSelection::Rust),
        Some(other) => return Err(PdsAdminConfigError::UnknownBackend(other.to_string())),
    };

    match (selector, ozone_present, rust_present) {
        // Auto-detect from the unique subsection.
        (None, true, false) => Ok(BackendSelection::Ozone),
        (None, false, true) => Ok(BackendSelection::Rust),
        (None, true, true) => Err(PdsAdminConfigError::AmbiguousBackend),
        (None, false, false) => Err(PdsAdminConfigError::NoBackendConfigured),

        // Explicit Ozone selector.
        (Some(BackendSelection::Ozone), true, false) => Ok(BackendSelection::Ozone),
        (Some(BackendSelection::Ozone), true, true) => {
            tracing::info!(
                target: "pds_admin_config",
                "config: [pds_admin].backend = \"ozone\" — [pds_admin.rust] is present \
                 and validated per-block but ignored at runtime"
            );
            Ok(BackendSelection::Ozone)
        }
        (Some(BackendSelection::Ozone), false, _) => {
            Err(PdsAdminConfigError::SelectorRequiresOzoneBlock)
        }

        // Explicit Rust selector.
        (Some(BackendSelection::Rust), false, true) => Ok(BackendSelection::Rust),
        (Some(BackendSelection::Rust), true, true) => {
            tracing::info!(
                target: "pds_admin_config",
                "config: [pds_admin].backend = \"rust\" — [pds_admin.ozone] is present \
                 and validated per-block but ignored at runtime"
            );
            Ok(BackendSelection::Rust)
        }
        (Some(BackendSelection::Rust), _, false) => {
            Err(PdsAdminConfigError::SelectorRequiresRustBlock)
        }
    }
}

/// Syntactic DID check shared by the `service_did` /
/// `target_service_did` validation rules: `did:` prefix,
/// non-empty method, non-empty method-specific identifier.
/// Resolution is deliberately not attempted — Aurora resolves
/// cairn-mod's DID doc when verifying a service-auth JWT.
fn validate_did_field(field: &str, value: &str) -> std::result::Result<(), PdsAdminConfigError> {
    if value.is_empty() {
        return Err(PdsAdminConfigError::RustBlockInvalid(format!(
            "`{field}` must be set (got empty string)"
        )));
    }
    let Some(rest) = value.strip_prefix("did:") else {
        return Err(PdsAdminConfigError::RustBlockInvalid(format!(
            "`{field}` = {value:?} is not a DID (expected `did:<method>:<identifier>`)"
        )));
    };
    match rest.split_once(':') {
        Some((method, identifier)) if !method.is_empty() && !identifier.is_empty() => Ok(()),
        _ => Err(PdsAdminConfigError::RustBlockInvalid(format!(
            "`{field}` = {value:?} lacks a DID method or identifier \
             (expected `did:<method>:<identifier>`)"
        ))),
    }
}

/// Validate `[pds_admin.rust]` per the v1.8.1 block-validity
/// rules and resolve into a [`RustBackendConfig`].
///
/// Validation rules:
/// - `url` parses via [`url::Url::parse`]; no scheme constraint
///   in v1.8.1 (the protocol-parity work that locks scheme posture
///   ships in v1.8.2).
/// - Removed v1.7-era OAuth keys (`client_id_env`,
///   `client_secret_env`, `scopes`) present in TOML surface as
///   [`PdsAdminConfigError::RemovedOAuthField`] naming the key.
/// - `service_did` and `target_service_did` pass the syntactic
///   DID check (`did:<method>:<identifier>`).
/// - `service_signing_key_env` is non-empty, matches the
///   env-var-name pattern (`[A-Z][A-Z_0-9]*`), and names an env
///   var that is set and non-empty at process startup. The key
///   *bytes* are parsed later by `RustBackend::new`, not here.
/// - `service_did_document_url` parses as a URL when present.
/// - `request_timeout` parses as a duration string (default
///   `"30s"`, bounds 1s..=5m).
/// - `capability_refresh_interval` parses as a duration string
///   (default `"1h"`, lower-bound `"10s"`).
/// - `required_capabilities` is structurally validated (each
///   entry non-empty, no duplicates); typed validation against
///   the [`super::CAPABILITY_CLASSIFICATIONS`] registry lands at
///   the first capability-gated trait method consumer.
/// - `pinned_versions` keys are family names (no `-vN` suffix);
///   values parse via [`super::CapabilityVersion::parse_suffix`];
///   each pinned family must also appear in
///   `required_capabilities` (mismatch surfaces as
///   [`PdsAdminConfigError::PinnedVersionMismatch`]).
fn validated_rust_from_toml<F>(
    toml: &crate::config::PdsAdminRustToml,
    read_env: &F,
) -> Result<RustBackendConfig>
where
    F: Fn(&str) -> std::result::Result<String, std::env::VarError>,
{
    use PdsAdminConfigError as E;

    let pds_url = url::Url::parse(&toml.url)
        .map_err(|e| E::RustBlockInvalid(format!("`url` is not a valid URL: {e}")))?;

    // Migration guard: the OAuth-shaped keys were removed in the
    // v1.8.1 service-auth rewrite. Named individually so the
    // operator-facing error points at the exact offending key.
    if toml.client_id_env.is_some() {
        return Err(E::RemovedOAuthField("client_id_env").into());
    }
    if toml.client_secret_env.is_some() {
        return Err(E::RemovedOAuthField("client_secret_env").into());
    }
    if toml.scopes.is_some() {
        return Err(E::RemovedOAuthField("scopes").into());
    }

    validate_did_field("service_did", &toml.service_did)?;
    validate_did_field("target_service_did", &toml.target_service_did)?;

    let key_env = &toml.service_signing_key_env;
    if key_env.is_empty() {
        return Err(E::RustBlockInvalid(
            "`service_signing_key_env` must name an env var (got empty string)".into(),
        )
        .into());
    }
    let valid_env_name = key_env
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
        && key_env
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !valid_env_name {
        return Err(E::RustBlockInvalid(format!(
            "`service_signing_key_env` = {key_env:?} is not a valid env-var name \
             (expected pattern [A-Z][A-Z_0-9]*)"
        ))
        .into());
    }
    // Presence check only — RustBackend::new parses the key bytes.
    let key_value = read_env(key_env).map_err(|_| E::MissingEnvVar(key_env.clone()))?;
    if key_value.is_empty() {
        return Err(E::MissingEnvVar(key_env.clone()).into());
    }

    let service_did_document_url = toml
        .service_did_document_url
        .as_deref()
        .map(|raw| {
            url::Url::parse(raw).map_err(|e| {
                E::RustBlockInvalid(format!(
                    "`service_did_document_url` is not a valid URL: {e}"
                ))
            })
        })
        .transpose()?;

    let timeout_str = toml.request_timeout.as_deref().unwrap_or("30s");
    let request_timeout = parse_duration_string(timeout_str).ok_or_else(|| {
        E::RustBlockInvalid(format!(
            "`request_timeout` = {timeout_str:?} is not a valid duration \
             (expected forms like \"30s\", \"2m\")"
        ))
    })?;
    if request_timeout < Duration::from_secs(1) || request_timeout > Duration::from_secs(300) {
        return Err(E::RustBlockInvalid(format!(
            "`request_timeout` = {timeout_str:?} is out of bounds (allowed range 1s..=5m)"
        ))
        .into());
    }

    let refresh_str = toml.capability_refresh_interval.as_deref().unwrap_or("1h");
    let refresh = parse_duration_string(refresh_str)
        .ok_or_else(|| E::CapabilityRefreshIntervalUnparseable(refresh_str.to_string()))?;
    if refresh < Duration::from_secs(10) {
        return Err(E::CapabilityRefreshIntervalTooShort(refresh_str.to_string()).into());
    }

    let required_capabilities = toml.required_capabilities.clone().unwrap_or_default();
    {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for cap in &required_capabilities {
            if cap.is_empty() {
                return Err(E::RustBlockInvalid(
                    "`required_capabilities` contains an empty string".into(),
                )
                .into());
            }
            if !seen.insert(cap.as_str()) {
                return Err(E::RustBlockInvalid(format!(
                    "`required_capabilities` contains duplicate entry {cap:?}"
                ))
                .into());
            }
        }
    }

    let pinned_versions = toml.pinned_versions.clone().unwrap_or_default();
    {
        // Each pinned key must (a) parse as a family name (no -vN
        // suffix) — we treat the key as the family name verbatim;
        // (b) have a value that parses via CapabilityVersion::parse_suffix;
        // (c) cross-validate: required_capabilities entries are wire
        // strings of the form "family-vN" where the family must match
        // a pinned key only if pinned. We surface mismatches as a
        // single PinnedVersionMismatch listing the symptom.
        for (family, version) in &pinned_versions {
            if family.is_empty() {
                return Err(
                    E::RustBlockInvalid("`pinned_versions` contains an empty key".into()).into(),
                );
            }
            if super::CapabilityVersion::parse_suffix(version).is_none() {
                return Err(E::RustBlockInvalid(format!(
                    "`pinned_versions[{family}]` = {version:?} is not a valid version suffix \
                     (expected forms like \"v1\", \"v17\")"
                ))
                .into());
            }
            // If required_capabilities is non-empty, the pinned family
            // must show up there. Empty required_capabilities means the
            // operator hasn't declared anything required, so a
            // pinned-but-not-required configuration is acceptable
            // (operators may pin a capability they discovered through
            // describeCapabilities but don't strictly require).
            if !required_capabilities.is_empty() {
                let has_match = required_capabilities.iter().any(|cap| {
                    super::parse_capability_string(cap)
                        .map(|(f, _)| f == *family)
                        .unwrap_or(false)
                        || cap == family
                });
                if !has_match {
                    return Err(E::PinnedVersionMismatch(format!(
                        "pinned family {family:?} does not appear in required_capabilities \
                         (declare it as required, or remove the pin)"
                    ))
                    .into());
                }
            }
        }
    }

    let verification_persist = toml.verification_persist.unwrap_or(true);
    let acknowledge_v1_8_1_audit_divergence =
        toml.acknowledge_v1_8_1_audit_divergence.unwrap_or(false);

    Ok(RustBackendConfig {
        pds_url,
        service_did: toml.service_did.clone(),
        service_signing_key_env: key_env.clone(),
        service_did_document_url,
        target_service_did: toml.target_service_did.clone(),
        request_timeout,
        capability_refresh_interval: refresh,
        required_capabilities,
        pinned_versions,
        verification_persist,
        acknowledge_v1_8_1_audit_divergence,
    })
}

/// Parse a human-readable duration string of the form
/// `"<integer><unit>"`, where unit is one of `s`, `m`, `h`.
/// Returns `None` for unparseable input. Used by
/// `validated_rust_from_toml` for `capability_refresh_interval`.
fn parse_duration_string(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = num_str.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

/// Validate the audit-divergence acknowledgment per v1.8.1's
/// inspector-only posture. **Canonical gate** for the
/// `[pds_admin].enabled = true + backend = "rust"` configuration.
///
/// Three independent enforcement parts, all of which must pass:
///
/// 1. The `acknowledge_v1_8_1_audit_divergence` flag on the
///    selected `[pds_admin.rust]` block must be `true`.
/// 2. No `policy_automation` rule may be in `mode = "auto"`
///    (auto-mode rules dispatch without operator confirmation;
///    in v1.8.1's inspector-only posture they would silently
///    produce audit-failure rows on every fire).
/// 3. `[xrpc_gateway].enabled` must not be `true` (the inbound
///    XRPC gateway would dispatch into the recordAction path
///    that calls the Rust backend).
///
/// Each violation surfaces as a distinct
/// [`PdsAdminConfigError`] variant; the v1.8.2-lifts footer in
/// each error's display string points operators at the future
/// release that drops the inspector-only posture.
///
/// Short-circuits on `enabled = false`: returns `Ok(())` without
/// inspecting any other field. Also short-circuits on
/// `backend = ozone` (the inspector-only posture is
/// rust-specific).
///
/// **EVERY config-validation entry point** (startup;
/// hypothetical hot-reload; hypothetical API-driven config
/// edits) MUST call this gate. Bypassing it would let an
/// operator stand up an inspector-only RustBackend that
/// silently corrupts the audit-trail. The function is the
/// canonical gate; do not duplicate its logic elsewhere.
pub fn validate_audit_divergence_acknowledgment(
    policy: &PdsAdminPolicy,
    policy_automation: Option<&crate::policy::automation::PolicyAutomationPolicy>,
    xrpc_gateway: Option<&crate::xrpc_gateway::XrpcGatewayConfig>,
) -> std::result::Result<(), PdsAdminConfigError> {
    if !policy.enabled {
        return Ok(());
    }
    let rust = match &policy.backend {
        Some(PdsAdminBackendConfig::Rust(r)) => r,
        _ => return Ok(()),
    };

    // Part 1: acknowledgment flag.
    if !rust.acknowledge_v1_8_1_audit_divergence {
        return Err(PdsAdminConfigError::AuditDivergenceAcknowledgmentRequired);
    }

    // Part 2: no auto-mode policy-automation rules.
    if let Some(pa) = policy_automation {
        let auto_rules: Vec<String> = pa
            .rules
            .iter()
            .filter(|(_, r)| r.mode == crate::policy::automation::PolicyMode::Auto)
            .map(|(name, _)| name.clone())
            .collect();
        if !auto_rules.is_empty() {
            return Err(
                PdsAdminConfigError::PolicyAutoModeIncompatibleWithInspectorRustBackend(auto_rules),
            );
        }
    }

    // Part 3: xrpc_gateway must not be enabled.
    if let Some(gw) = xrpc_gateway
        && gw.enabled
    {
        return Err(PdsAdminConfigError::XrpcGatewayIncompatibleWithInspectorRustBackend);
    }

    Ok(())
}

/// Whether the dispatch path's admin XRPC handlers should emit
/// the v1.8.1 RustBackend audit-divergence WARN at request-receive
/// time.
///
/// Returns `true` when the bridge is enabled with the Rust
/// backend selected. The actual WARN emission lives at the
/// dispatch site (Step 5 wires the call); this helper is the
/// canonical gating check, called from each handler before the
/// dispatch fires. Defense-in-depth: the
/// [`validate_audit_divergence_acknowledgment`] gate at startup
/// already rejects `backend = "rust"` + `xrpc_gateway.enabled =
/// true`, so this code path is unreachable in v1.8.1; the helper
/// is wired now so Step 5's dispatch-side emission has a single
/// gating point already in place.
pub fn should_warn_rust_backend_dispatch(policy: &PdsAdminPolicy) -> bool {
    matches!(
        (&policy.enabled, &policy.backend),
        (true, Some(PdsAdminBackendConfig::Rust(_)))
    )
}

/// Reject `[pds_admin.locus]` (renamed to `[pds_admin.rust]`)
/// and any other unrecognized sibling key under `[pds_admin]`.
/// Runs even when `enabled = false` so operators catch typos and
/// renamed-key migrations at config-load time, not at the
/// eventual flip to enabled.
fn reject_unsupported_backend_subsections(toml: &crate::config::PdsAdminConfigToml) -> Result<()> {
    if toml.locus.is_some() {
        return Err(PdsAdminConfigError::LocusBlockRenamed.into());
    }
    if let Some(unknown) = toml.other_backends.keys().next() {
        return Err(PdsAdminConfigError::UnknownKey {
            block: "pds_admin".to_string(),
            key: unknown.clone(),
        }
        .into());
    }
    Ok(())
}

fn validated_ozone_from_toml<F>(
    toml: &crate::config::PdsAdminOzoneToml,
    read_env: &F,
) -> Result<OzoneBackendConfig>
where
    F: Fn(&str) -> std::result::Result<String, std::env::VarError>,
{
    // pds_url: parse + https-only.
    let pds_url = url::Url::parse(&toml.pds_url).map_err(|e| {
        Error::Signing(format!(
            "config: [pds_admin.ozone].pds_url is not a valid URL: {e}"
        ))
    })?;
    if pds_url.scheme() != "https" {
        return Err(Error::Signing(format!(
            "config: [pds_admin.ozone].pds_url must use https scheme; got: {}",
            pds_url.scheme()
        )));
    }

    // admin_password_env: must be a non-empty env-var name; the
    // resolved env-var value must itself be non-empty.
    if toml.admin_password_env.is_empty() {
        return Err(Error::Signing(
            "config: [pds_admin.ozone].admin_password_env must name an env var \
             (got empty string)"
                .into(),
        ));
    }
    let env_value = read_env(&toml.admin_password_env).map_err(|_| {
        Error::Signing(format!(
            "config: env var ${} referenced by [pds_admin.ozone].admin_password_env is not set",
            toml.admin_password_env
        ))
    })?;
    if env_value.is_empty() {
        return Err(Error::Signing(format!(
            "config: env var ${} referenced by [pds_admin.ozone].admin_password_env is not set",
            toml.admin_password_env
        )));
    }

    // request_timeout_seconds: 1..=60 inclusive.
    if !(1..=60).contains(&toml.request_timeout_seconds) {
        return Err(Error::Signing(format!(
            "config: [pds_admin.ozone].request_timeout_seconds = {} is out of range (1..=60)",
            toml.request_timeout_seconds
        )));
    }

    Ok(OzoneBackendConfig {
        pds_url,
        admin_password: AdminPassword::new(env_value),
        request_timeout: Duration::from_secs(u64::from(toml.request_timeout_seconds)),
    })
}

fn validated_action_map(
    toml: &BTreeMap<String, crate::config::PdsAdminActionMapValueToml>,
) -> Result<BTreeMap<ActionType, ActionMapEntry>> {
    let mut resolved: BTreeMap<ActionType, ActionMapEntry> = BTreeMap::new();
    let mut warned_methods: BTreeSet<(ActionType, BackendMethod)> = BTreeSet::new();

    for (raw_key, raw_value) in toml {
        let action_type = ActionType::from_db_str(raw_key).ok_or_else(|| {
            Error::Signing(format!(
                "config: [pds_admin.action_map].{raw_key} is not a valid action_type \
                 (expected one of warning / note / temp_suspension / indef_suspension / takedown)"
            ))
        })?;

        let entry = match raw_value {
            crate::config::PdsAdminActionMapValueToml::Bare(s) => parse_method_string(s, || {
                format!("[pds_admin.action_map].{}", action_type.as_db_str())
            })?,
            crate::config::PdsAdminActionMapValueToml::Table(table) => {
                // Table form: validate `with_lift_after` gating
                // (only valid on temp_suspension; v1.7 rejects
                // `true` regardless).
                if table.with_lift_after && !matches!(action_type, ActionType::TempSuspension) {
                    return Err(Error::Signing(format!(
                        "config: [pds_admin.action_map].{} sets with_lift_after = true; \
                         this option is only valid for temp_suspension",
                        action_type.as_db_str()
                    )));
                }
                if table.with_lift_after {
                    return Err(Error::Signing(
                        "config: [pds_admin.action_map] with_lift_after = true requires a \
                         deferred-execution layer not present in v1.7; deferred to v1.8. \
                         Configure temp_suspension as bare \"takedown_account\" and lift \
                         manually via CLI in v1.7."
                            .into(),
                    ));
                }
                parse_method_string(&table.method, || {
                    format!("[pds_admin.action_map].{}.method", action_type.as_db_str())
                })?
            }
        };

        // Warning surface for the v1.7 OzoneBackend's unimplemented
        // label methods. Emit at most once per (action_type,
        // method) combination.
        if let ActionMapEntry::Method(method) = entry
            && matches!(method, BackendMethod::ApplyLabel | BackendMethod::NegateLabel)
            && warned_methods.insert((action_type, method))
        {
            tracing::warn!(
                "config: [pds_admin.action_map].{} maps to {}, but cairn-mod's §F4 \
                 architectural invariant forbids label methods on every PDS-admin backend; \
                 this action will not propagate to the PDS (returns \
                 BackendError::ArchitecturallyForbidden at runtime)",
                action_type.as_db_str(),
                method.as_wire_str(),
            );
        }

        resolved.insert(action_type, entry);
    }

    // Every action type must be mapped. Surface the full missing
    // set in one message rather than failing on the first.
    let missing: Vec<&'static str> = REQUIRED_ACTION_TYPES
        .iter()
        .filter(|at| !resolved.contains_key(at))
        .map(|at| at.as_db_str())
        .collect();
    if !missing.is_empty() {
        return Err(Error::Signing(format!(
            "config: [pds_admin.action_map] is missing entries for the following action types: \
             {} (every cairn-mod action type must be mapped; use \"skip\" to bypass the bridge \
             for an action type)",
            missing.join(", "),
        )));
    }

    Ok(resolved)
}

/// Parse a method-string value (the bare-string form, or the
/// `method` field of the table form). Accepts the documented set
/// plus `"skip"`; everything else is an error citing the path
/// supplied by `path_for_error`.
fn parse_method_string(s: &str, path_for_error: impl Fn() -> String) -> Result<ActionMapEntry> {
    if s == "skip" {
        return Ok(ActionMapEntry::Skip);
    }
    BackendMethod::from_wire_str(s)
        .map(ActionMapEntry::Method)
        .ok_or_else(|| {
            Error::Signing(format!(
                "config: {} is not a valid backend method: {:?} \
                 (expected one of takedown_account / suspend_account / restore_account / \
                 apply_label / negate_label / skip)",
                path_for_error(),
                s,
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, PdsAdminActionMapTableToml, PdsAdminActionMapValueToml, PdsAdminConfigToml,
        PdsAdminOzoneToml,
    };

    /// Test-only env var name carried in the test fixtures. The
    /// resolver consults the env reader injected via
    /// [`PdsAdminPolicy::from_config_with_env_reader`], not the
    /// process env, so this is just a label tying fixture to
    /// reader.
    const TEST_ENV_VAR: &str = "CAIRN_TEST_PDS_ADMIN_PASSWORD_FIXTURE";

    /// Build an env-reader closure that returns `value` for
    /// `TEST_ENV_VAR` and `NotPresent` for everything else.
    /// Lets tests exercise the env-resolution code path without
    /// mutating process env (which would require `unsafe` and
    /// crosses the crate's `#![forbid(unsafe_code)]`).
    fn env_reader_with_value(
        value: &str,
    ) -> impl Fn(&str) -> std::result::Result<String, std::env::VarError> + use<'_> {
        move |name: &str| -> std::result::Result<String, std::env::VarError> {
            if name == TEST_ENV_VAR {
                Ok(value.to_string())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        }
    }

    /// Env reader that returns `NotPresent` for every name —
    /// simulates an env where the operator-named password var
    /// isn't set.
    fn env_reader_unset(_name: &str) -> std::result::Result<String, std::env::VarError> {
        Err(std::env::VarError::NotPresent)
    }

    /// Resolve the policy with `env_value` injected as the value
    /// of `TEST_ENV_VAR`. Wraps
    /// [`PdsAdminPolicy::from_config_with_env_reader`] for the
    /// common test case.
    fn from_config_test(cfg: &Config, env_value: &str) -> Result<PdsAdminPolicy> {
        PdsAdminPolicy::from_config_with_env_reader(cfg, env_reader_with_value(env_value))
    }

    fn config_with_pds_admin(toml: PdsAdminConfigToml) -> Config {
        // Construct a minimal Config with the policy field
        // populated. Other fields use placeholder values; the
        // resolver only consults `pds_admin`.
        Config {
            service_did: "did:plc:test".into(),
            service_endpoint: "https://example.test".into(),
            bind_addr: crate::config::DEFAULT_BIND_ADDR.parse().unwrap(),
            db_path: "/tmp/cairn-test.db".into(),
            signing_key_path: "/tmp/cairn-test.key".into(),
            admin: Default::default(),
            labeler: None,
            operator: None,
            retention: Default::default(),
            moderation_reasons: None,
            strike_policy: None,
            label_emission: None,
            policy_automation: None,
            pds_admin: Some(toml),
            xrpc_gateway: None,
        }
    }

    fn full_action_map_skip_all() -> BTreeMap<String, PdsAdminActionMapValueToml> {
        let mut m = BTreeMap::new();
        for at in REQUIRED_ACTION_TYPES {
            m.insert(
                at.as_db_str().to_string(),
                PdsAdminActionMapValueToml::Bare("skip".into()),
            );
        }
        m
    }

    fn ozone_toml() -> PdsAdminOzoneToml {
        PdsAdminOzoneToml {
            pds_url: "https://bsky.example.test".into(),
            admin_password_env: TEST_ENV_VAR.into(),
            request_timeout_seconds: 10,
        }
    }

    // ============================================================
    // Disabled / absent block
    // ============================================================

    #[test]
    fn no_block_returns_disabled_defaults() {
        let mut cfg = config_with_pds_admin(PdsAdminConfigToml::default());
        cfg.pds_admin = None;
        let p = PdsAdminPolicy::from_config(&cfg).expect("disabled-default loads");
        assert!(!p.enabled);
        assert!(p.backend.is_none());
        assert!(p.action_map.is_empty());
    }

    #[test]
    fn enabled_false_with_subsections_validates_and_returns_disabled() {
        // Forward-compat: an operator may declare full subsections
        // while keeping enabled = false. The resolver still
        // validates per-block (so typos surface) but doesn't
        // require the action_map to be complete.
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: false,
            ozone: Some(ozone_toml()),
            action_map: None,
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let p = from_config_test(&cfg, "secret").expect("disabled-with-ozone loads");
        assert!(!p.enabled);
        assert!(p.backend.is_none());
    }

    // ============================================================
    // Enabled happy path
    // ============================================================

    #[test]
    fn enabled_with_full_config_resolves() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let p = from_config_test(&cfg, "secret-value").expect("full config loads");
        assert!(p.enabled);
        let PdsAdminBackendConfig::Ozone(ozone) = p.backend.as_ref().expect("backend present")
        else {
            panic!("expected Ozone backend, got {:?}", p.backend);
        };
        assert_eq!(ozone.pds_url.scheme(), "https");
        assert_eq!(ozone.pds_url.host_str(), Some("bsky.example.test"));
        assert_eq!(ozone.admin_password.as_str(), "secret-value");
        assert_eq!(ozone.request_timeout, Duration::from_secs(10));
        // All five action types present, all mapped to Skip.
        assert_eq!(p.action_map.len(), 5);
        for at in REQUIRED_ACTION_TYPES {
            assert_eq!(p.action_map.get(at), Some(&ActionMapEntry::Skip));
        }
    }

    #[test]
    fn enabled_with_method_mappings_resolves() {
        let mut m = full_action_map_skip_all();
        m.insert(
            "takedown".into(),
            PdsAdminActionMapValueToml::Bare("takedown_account".into()),
        );
        m.insert(
            "indef_suspension".into(),
            PdsAdminActionMapValueToml::Bare("takedown_account".into()),
        );
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(m),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let p = from_config_test(&cfg, "secret").expect("method mappings load");
        assert_eq!(
            p.action_map.get(&ActionType::Takedown),
            Some(&ActionMapEntry::Method(BackendMethod::TakedownAccount)),
        );
        assert_eq!(
            p.action_map.get(&ActionType::IndefSuspension),
            Some(&ActionMapEntry::Method(BackendMethod::TakedownAccount)),
        );
        assert_eq!(
            p.action_map.get(&ActionType::Warning),
            Some(&ActionMapEntry::Skip)
        );
    }

    #[test]
    fn enabled_with_table_form_no_lift_resolves() {
        // Table form with with_lift_after = false (or absent —
        // serde default) is equivalent to the bare-string form.
        let mut m = full_action_map_skip_all();
        m.insert(
            "temp_suspension".into(),
            PdsAdminActionMapValueToml::Table(PdsAdminActionMapTableToml {
                method: "takedown_account".into(),
                with_lift_after: false,
            }),
        );
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(m),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let p = from_config_test(&cfg, "secret").expect("table form no-lift loads");
        assert_eq!(
            p.action_map.get(&ActionType::TempSuspension),
            Some(&ActionMapEntry::Method(BackendMethod::TakedownAccount)),
        );
    }

    // ============================================================
    // Backend selection / unsupported subsections
    // ============================================================

    #[test]
    fn enabled_without_ozone_subsection_rejects() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: None,
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("no backend rejects");
        assert!(format!("{err}").contains("no backend subsection"));
    }

    #[test]
    fn locus_subsection_rejects_as_renamed() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: false, // even when disabled — typo / staging visibility
            backend: None,
            rust: None,
            ozone: None,
            action_map: None,
            locus: Some(serde_json::json!({"some_field": "value"})),
            other_backends: BTreeMap::new(),
        });
        let err = PdsAdminPolicy::from_config_with_env_reader(&cfg, env_reader_unset)
            .expect_err("locus rejects");
        let msg = format!("{err}");
        assert!(
            msg.contains("[pds_admin.locus] was renamed to [pds_admin.rust]"),
            "msg={msg}"
        );
    }

    #[test]
    fn unknown_backend_subsection_rejects() {
        let mut other = BTreeMap::new();
        other.insert("ozonee".to_string(), serde_json::json!({})); // typo
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: false,
            ozone: None,
            action_map: None,
            backend: None,
            rust: None,
            locus: None,
            other_backends: other,
        });
        let err = PdsAdminPolicy::from_config_with_env_reader(&cfg, env_reader_unset)
            .expect_err("unknown backend rejects");
        let msg = format!("{err}");
        assert!(
            msg.contains("[pds_admin] declares unknown sibling key \"ozonee\""),
            "msg={msg}"
        );
    }

    // ============================================================
    // Ozone backend validation
    // ============================================================

    #[test]
    fn pds_url_must_use_https() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(PdsAdminOzoneToml {
                pds_url: "http://bsky.example.test".into(),
                admin_password_env: TEST_ENV_VAR.into(),
                request_timeout_seconds: 10,
            }),
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("http rejects");
        let msg = format!("{err}");
        assert!(msg.contains("must use https scheme"), "msg={msg}");
        assert!(msg.contains("got: http"), "msg={msg}");
    }

    #[test]
    fn pds_url_malformed_rejects() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(PdsAdminOzoneToml {
                pds_url: "not a url".into(),
                admin_password_env: TEST_ENV_VAR.into(),
                request_timeout_seconds: 10,
            }),
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("bad url rejects");
        assert!(format!("{err}").contains("not a valid URL"));
    }

    #[test]
    fn admin_password_env_unset_rejects() {
        // Env var name that's intentionally NOT set during this
        // test. The resolver should fail with the documented
        // message shape.
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(PdsAdminOzoneToml {
                pds_url: "https://bsky.example.test".into(),
                admin_password_env: "CAIRN_TEST_PDS_ADMIN_NEVER_SET_8c9f1a".into(),
                request_timeout_seconds: 10,
            }),
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        // env_reader_unset returns NotPresent for every name —
        // simulates an env where the operator-named password var
        // isn't set.
        let err = PdsAdminPolicy::from_config_with_env_reader(&cfg, env_reader_unset)
            .expect_err("unset env rejects");
        let msg = format!("{err}");
        assert!(
            msg.contains("CAIRN_TEST_PDS_ADMIN_NEVER_SET_8c9f1a"),
            "msg={msg}"
        );
        assert!(msg.contains("is not set"), "msg={msg}");
    }

    #[test]
    fn admin_password_env_empty_rejects() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        // Inject an empty value for TEST_ENV_VAR; should still
        // reject as "is not set" per the documented message
        // shape.
        let err = from_config_test(&cfg, "").expect_err("empty env rejects");
        assert!(format!("{err}").contains("is not set"));
    }

    #[test]
    fn admin_password_env_name_empty_rejects() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(PdsAdminOzoneToml {
                pds_url: "https://bsky.example.test".into(),
                admin_password_env: "".into(),
                request_timeout_seconds: 10,
            }),
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = PdsAdminPolicy::from_config_with_env_reader(&cfg, env_reader_unset)
            .expect_err("empty env name rejects");
        assert!(format!("{err}").contains("must name an env var"));
    }

    #[test]
    fn request_timeout_below_range_rejects() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(PdsAdminOzoneToml {
                pds_url: "https://bsky.example.test".into(),
                admin_password_env: TEST_ENV_VAR.into(),
                request_timeout_seconds: 0,
            }),
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("0s timeout rejects");
        assert!(format!("{err}").contains("out of range"));
    }

    #[test]
    fn request_timeout_above_range_rejects() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(PdsAdminOzoneToml {
                pds_url: "https://bsky.example.test".into(),
                admin_password_env: TEST_ENV_VAR.into(),
                request_timeout_seconds: 61,
            }),
            action_map: Some(full_action_map_skip_all()),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("61s timeout rejects");
        assert!(format!("{err}").contains("out of range"));
    }

    // ============================================================
    // action_map validation
    // ============================================================

    #[test]
    fn action_map_missing_keys_rejects_listing_missing() {
        let mut m = BTreeMap::new();
        m.insert(
            "takedown".into(),
            PdsAdminActionMapValueToml::Bare("takedown_account".into()),
        );
        // Missing: indef_suspension, temp_suspension, warning, note
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(m),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("missing keys rejects");
        let msg = format!("{err}");
        assert!(msg.contains("missing entries"), "msg={msg}");
        assert!(msg.contains("indef_suspension"), "msg={msg}");
        assert!(msg.contains("temp_suspension"), "msg={msg}");
        assert!(msg.contains("warning"), "msg={msg}");
        assert!(msg.contains("note"), "msg={msg}");
        assert!(
            !msg.contains(": takedown,"),
            "takedown was supplied; msg={msg}"
        );
    }

    #[test]
    fn action_map_invalid_action_type_key_rejects() {
        let mut m = full_action_map_skip_all();
        m.insert(
            "spam".into(), // not a valid action_type
            PdsAdminActionMapValueToml::Bare("skip".into()),
        );
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(m),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("bad key rejects");
        assert!(format!("{err}").contains("not a valid action_type"));
    }

    #[test]
    fn action_map_unknown_method_rejects() {
        let mut m = full_action_map_skip_all();
        m.insert(
            "takedown".into(),
            PdsAdminActionMapValueToml::Bare("blast_account".into()),
        );
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(m),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("bad method rejects");
        let msg = format!("{err}");
        assert!(msg.contains("not a valid backend method"), "msg={msg}");
        assert!(msg.contains("blast_account"), "msg={msg}");
    }

    #[test]
    fn action_map_label_method_accepted_but_warns() {
        // apply_label / negate_label are syntactically valid (#83
        // accepts them); #89 makes OzoneBackend reject them at
        // runtime. The resolver succeeds and emits a tracing
        // warning we can't easily capture without a custom layer
        // — just assert the policy resolves.
        let mut m = full_action_map_skip_all();
        m.insert(
            "warning".into(),
            PdsAdminActionMapValueToml::Bare("apply_label".into()),
        );
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(m),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let p = from_config_test(&cfg, "secret").expect("apply_label accepts");
        assert_eq!(
            p.action_map.get(&ActionType::Warning),
            Some(&ActionMapEntry::Method(BackendMethod::ApplyLabel)),
        );
    }

    // ============================================================
    // with_lift_after gating
    // ============================================================

    #[test]
    fn action_map_with_lift_after_true_on_temp_suspension_rejects_v1_7() {
        let mut m = full_action_map_skip_all();
        m.insert(
            "temp_suspension".into(),
            PdsAdminActionMapValueToml::Table(PdsAdminActionMapTableToml {
                method: "takedown_account".into(),
                with_lift_after: true,
            }),
        );
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(m),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err =
            from_config_test(&cfg, "secret").expect_err("with_lift_after = true rejects in v1.7");
        let msg = format!("{err}");
        assert!(msg.contains("deferred-execution layer"), "msg={msg}");
        assert!(msg.contains("v1.8"), "msg={msg}");
    }

    #[test]
    fn action_map_with_lift_after_true_on_non_temp_rejects() {
        // The non-temp_suspension path errors first (with the
        // "only valid for temp_suspension" message), before the
        // v1.7 deferral check fires. Either error is correct;
        // pin the temp_suspension-specific one as documented.
        let mut m = full_action_map_skip_all();
        m.insert(
            "takedown".into(),
            PdsAdminActionMapValueToml::Table(PdsAdminActionMapTableToml {
                method: "takedown_account".into(),
                with_lift_after: true,
            }),
        );
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: Some(m),
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err =
            from_config_test(&cfg, "secret").expect_err("with_lift_after on takedown rejects");
        let msg = format!("{err}");
        assert!(msg.contains("only valid for temp_suspension"), "msg={msg}");
    }

    // ============================================================
    // Enabled but no action_map
    // ============================================================

    #[test]
    fn enabled_without_action_map_rejects() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            ozone: Some(ozone_toml()),
            action_map: None,
            backend: None,
            rust: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("missing action_map rejects");
        assert!(format!("{err}").contains("[pds_admin.action_map] is absent"));
    }

    // ============================================================
    // AdminPassword newtype
    // ============================================================

    #[test]
    fn admin_password_debug_redacts() {
        let pw = AdminPassword::new("very-secret-password".into());
        let dbg = format!("{pw:?}");
        assert!(!dbg.contains("very-secret-password"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn admin_password_as_str_returns_value() {
        let pw = AdminPassword::new("my-secret".into());
        assert_eq!(pw.as_str(), "my-secret");
    }

    // ============================================================
    // BackendMethod round-trip
    // ============================================================

    #[test]
    fn backend_method_string_roundtrip() {
        for m in [
            BackendMethod::TakedownAccount,
            BackendMethod::SuspendAccount,
            BackendMethod::RestoreAccount,
            BackendMethod::ApplyLabel,
            BackendMethod::NegateLabel,
        ] {
            assert_eq!(BackendMethod::from_wire_str(m.as_wire_str()), Some(m));
        }
    }

    #[test]
    fn backend_method_unknown_returns_none() {
        assert!(BackendMethod::from_wire_str("ban_user").is_none());
        assert!(BackendMethod::from_wire_str("").is_none());
        assert!(BackendMethod::from_wire_str("skip").is_none()); // skip is handled separately
    }

    // ============================================================
    // v1.8.1 — backend selector + Rust block + audit-divergence
    // ============================================================

    fn rust_toml() -> crate::config::PdsAdminRustToml {
        crate::config::PdsAdminRustToml {
            url: "https://rust-pds.example.test".into(),
            service_did: "did:web:cairn-mod.example.test".into(),
            service_signing_key_env: "RUST_SERVICE_SIGNING_KEY".into(),
            service_did_document_url: None,
            target_service_did: "did:web:rust-pds.example.test".into(),
            request_timeout: None,
            client_id_env: None,
            client_secret_env: None,
            scopes: None,
            capability_refresh_interval: None,
            required_capabilities: None,
            pinned_versions: None,
            verification_persist: None,
            acknowledge_v1_8_1_audit_divergence: None,
        }
    }

    /// Env reader that knows the rust block's signing-key env var
    /// and the ozone block's password env var. Used by tests that
    /// exercise either or both backends.
    fn rust_env_reader(name: &str) -> std::result::Result<String, std::env::VarError> {
        match name {
            // 64 hex chars — presence-checked at config load; only
            // RustBackend::new parses the bytes.
            "RUST_SERVICE_SIGNING_KEY" => {
                Ok("4242424242424242424242424242424242424242424242424242424242424242".into())
            }
            TEST_ENV_VAR => Ok("test-admin-password".into()),
            _ => Err(std::env::VarError::NotPresent),
        }
    }

    /// Resolve a config that may carry rust + ozone subsections.
    fn from_config_rust_test(cfg: &crate::config::Config) -> Result<PdsAdminPolicy> {
        PdsAdminPolicy::from_config_with_env_reader(cfg, rust_env_reader)
    }

    // ----- A. resolve_backend truth table -----

    #[test]
    fn resolve_backend_none_ozone_only_returns_ozone() {
        let toml = PdsAdminConfigToml {
            ozone: Some(ozone_toml()),
            ..Default::default()
        };
        assert_eq!(resolve_backend(&toml), Ok(BackendSelection::Ozone));
    }

    #[test]
    fn resolve_backend_none_rust_only_returns_rust() {
        let toml = PdsAdminConfigToml {
            rust: Some(rust_toml()),
            ..Default::default()
        };
        assert_eq!(resolve_backend(&toml), Ok(BackendSelection::Rust));
    }

    #[test]
    fn resolve_backend_none_both_returns_ambiguous() {
        let toml = PdsAdminConfigToml {
            ozone: Some(ozone_toml()),
            rust: Some(rust_toml()),
            ..Default::default()
        };
        assert_eq!(
            resolve_backend(&toml),
            Err(PdsAdminConfigError::AmbiguousBackend)
        );
    }

    #[test]
    fn resolve_backend_none_neither_returns_no_backend_configured() {
        let toml = PdsAdminConfigToml::default();
        assert_eq!(
            resolve_backend(&toml),
            Err(PdsAdminConfigError::NoBackendConfigured)
        );
    }

    #[test]
    fn resolve_backend_explicit_ozone_with_ozone_only() {
        let toml = PdsAdminConfigToml {
            backend: Some("ozone".into()),
            ozone: Some(ozone_toml()),
            ..Default::default()
        };
        assert_eq!(resolve_backend(&toml), Ok(BackendSelection::Ozone));
    }

    #[test]
    fn resolve_backend_explicit_ozone_with_both_resolves_ozone() {
        let toml = PdsAdminConfigToml {
            backend: Some("ozone".into()),
            ozone: Some(ozone_toml()),
            rust: Some(rust_toml()),
            ..Default::default()
        };
        assert_eq!(resolve_backend(&toml), Ok(BackendSelection::Ozone));
    }

    #[test]
    fn resolve_backend_explicit_ozone_with_rust_only_rejects() {
        let toml = PdsAdminConfigToml {
            backend: Some("ozone".into()),
            rust: Some(rust_toml()),
            ..Default::default()
        };
        assert_eq!(
            resolve_backend(&toml),
            Err(PdsAdminConfigError::SelectorRequiresOzoneBlock)
        );
    }

    #[test]
    fn resolve_backend_explicit_ozone_with_neither_rejects() {
        let toml = PdsAdminConfigToml {
            backend: Some("ozone".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_backend(&toml),
            Err(PdsAdminConfigError::SelectorRequiresOzoneBlock)
        );
    }

    #[test]
    fn resolve_backend_explicit_rust_with_rust_only() {
        let toml = PdsAdminConfigToml {
            backend: Some("rust".into()),
            rust: Some(rust_toml()),
            ..Default::default()
        };
        assert_eq!(resolve_backend(&toml), Ok(BackendSelection::Rust));
    }

    #[test]
    fn resolve_backend_explicit_rust_with_both_resolves_rust() {
        let toml = PdsAdminConfigToml {
            backend: Some("rust".into()),
            ozone: Some(ozone_toml()),
            rust: Some(rust_toml()),
            ..Default::default()
        };
        assert_eq!(resolve_backend(&toml), Ok(BackendSelection::Rust));
    }

    #[test]
    fn resolve_backend_explicit_rust_with_ozone_only_rejects() {
        let toml = PdsAdminConfigToml {
            backend: Some("rust".into()),
            ozone: Some(ozone_toml()),
            ..Default::default()
        };
        assert_eq!(
            resolve_backend(&toml),
            Err(PdsAdminConfigError::SelectorRequiresRustBlock)
        );
    }

    #[test]
    fn resolve_backend_explicit_rust_with_neither_rejects() {
        let toml = PdsAdminConfigToml {
            backend: Some("rust".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_backend(&toml),
            Err(PdsAdminConfigError::SelectorRequiresRustBlock)
        );
    }

    #[test]
    fn resolve_backend_unknown_selector_rejects() {
        let toml = PdsAdminConfigToml {
            backend: Some("rusty".into()),
            rust: Some(rust_toml()),
            ..Default::default()
        };
        assert_eq!(
            resolve_backend(&toml),
            Err(PdsAdminConfigError::UnknownBackend("rusty".into()))
        );
    }

    #[test]
    fn resolve_backend_empty_selector_rejects_distinctly() {
        let toml = PdsAdminConfigToml {
            backend: Some(String::new()),
            rust: Some(rust_toml()),
            ..Default::default()
        };
        assert_eq!(
            resolve_backend(&toml),
            Err(PdsAdminConfigError::EmptyBackendSelector)
        );
    }

    // ----- B. block-validity rules -----

    /// Construct a fully-valid Config with the rust block and full
    /// action map, with the ack flag set per `ack`.
    fn config_with_rust(rust: crate::config::PdsAdminRustToml) -> crate::config::Config {
        config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            backend: Some("rust".into()),
            ozone: None,
            rust: Some(rust),
            action_map: Some(full_action_map_skip_all()),
            locus: None,
            other_backends: BTreeMap::new(),
        })
    }

    #[test]
    fn rust_missing_url_rejects() {
        let mut t = rust_toml();
        t.url = String::new();
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("empty url rejects");
        assert!(format!("{err}").contains("[pds_admin.rust] is invalid"));
    }

    #[test]
    fn rust_missing_service_did_rejects() {
        let mut t = rust_toml();
        t.service_did = String::new();
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("empty service_did rejects");
        assert!(format!("{err}").contains("`service_did` must be set"));
    }

    #[test]
    fn rust_invalid_service_did_syntax_rejects() {
        for bad in [
            "cairn-mod.example.test",
            "did:",
            "did:web",
            "did:web:",
            "did::x",
        ] {
            let mut t = rust_toml();
            t.service_did = bad.into();
            let cfg = config_with_rust(t);
            let err =
                from_config_rust_test(&cfg).expect_err(&format!("service_did {bad:?} rejects"));
            assert!(
                format!("{err}").contains("service_did"),
                "error names the field for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn rust_invalid_target_service_did_rejects() {
        let mut t = rust_toml();
        t.target_service_did = "not-a-did".into();
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("bad target_service_did rejects");
        assert!(format!("{err}").contains("target_service_did"));
    }

    #[test]
    fn rust_removed_oauth_fields_reject_with_migration_error() {
        // Each removed key errors individually, naming the key and
        // the service-auth replacements (§4.5 migration path).
        let mut t = rust_toml();
        t.client_id_env = Some("RUST_CLIENT_ID".into());
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("client_id_env rejects");
        let msg = format!("{err}");
        assert!(
            msg.contains("client_id_env") && msg.contains("removed in v1.8.1"),
            "{msg}"
        );
        assert!(
            msg.contains("service_signing_key_env"),
            "points at replacements: {msg}"
        );

        let mut t = rust_toml();
        t.client_secret_env = Some("RUST_CLIENT_SECRET".into());
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("client_secret_env rejects");
        assert!(format!("{err}").contains("client_secret_env"));

        let mut t = rust_toml();
        t.scopes = Some(vec!["atproto:admin.moderation".into()]);
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("scopes rejects");
        assert!(format!("{err}").contains("scopes"));
    }

    #[test]
    fn rust_invalid_signing_key_env_name_rejects() {
        for bad in ["lowercase", "1STARTS_WITH_DIGIT", "HAS-DASH", "HAS SPACE"] {
            let mut t = rust_toml();
            t.service_signing_key_env = bad.into();
            let cfg = config_with_rust(t);
            let err = from_config_rust_test(&cfg).expect_err(&format!("env name {bad:?} rejects"));
            assert!(
                format!("{err}").contains("not a valid env-var name"),
                "{err}"
            );
        }
    }

    #[test]
    fn rust_bad_did_document_url_rejects() {
        let mut t = rust_toml();
        t.service_did_document_url = Some("not a url".into());
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("bad did-doc url rejects");
        assert!(format!("{err}").contains("service_did_document_url"));
    }

    #[test]
    fn rust_request_timeout_default_is_thirty_seconds() {
        let mut t = rust_toml();
        t.acknowledge_v1_8_1_audit_divergence = Some(true);
        let cfg = config_with_rust(t);
        let p = from_config_rust_test(&cfg).expect("default loads");
        let PdsAdminBackendConfig::Rust(rust) = p.backend.as_ref().unwrap() else {
            panic!("expected Rust backend");
        };
        assert_eq!(rust.request_timeout, Duration::from_secs(30));
    }

    #[test]
    fn rust_request_timeout_out_of_bounds_rejects() {
        for bad in ["0s", "6m", "301s"] {
            let mut t = rust_toml();
            t.request_timeout = Some(bad.into());
            let cfg = config_with_rust(t);
            let err =
                from_config_rust_test(&cfg).expect_err(&format!("request_timeout {bad:?} rejects"));
            assert!(format!("{err}").contains("out of bounds"), "{err}");
        }
        let mut t = rust_toml();
        t.request_timeout = Some("soonish".into());
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("unparseable rejects");
        assert!(format!("{err}").contains("not a valid duration"));
    }

    #[test]
    fn rust_request_timeout_bounds_accepted() {
        for (raw, secs) in [("1s", 1u64), ("5m", 300)] {
            let mut t = rust_toml();
            t.request_timeout = Some(raw.into());
            t.acknowledge_v1_8_1_audit_divergence = Some(true);
            let cfg = config_with_rust(t);
            let p = from_config_rust_test(&cfg).expect("in-bounds loads");
            let PdsAdminBackendConfig::Rust(rust) = p.backend.as_ref().unwrap() else {
                panic!("expected Rust backend");
            };
            assert_eq!(rust.request_timeout, Duration::from_secs(secs), "{raw}");
        }
    }

    #[test]
    fn rust_capability_refresh_interval_too_short_rejects() {
        let mut t = rust_toml();
        t.capability_refresh_interval = Some("5s".into());
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("5s rejects");
        assert!(format!("{err}").contains("below the lower bound"));
    }

    #[test]
    fn rust_capability_refresh_interval_lower_bound_accepted() {
        let mut t = rust_toml();
        t.capability_refresh_interval = Some("10s".into());
        t.acknowledge_v1_8_1_audit_divergence = Some(true);
        let cfg = config_with_rust(t);
        let p = from_config_rust_test(&cfg).expect("10s loads");
        let PdsAdminBackendConfig::Rust(rust) = p.backend.as_ref().unwrap() else {
            panic!("expected Rust backend");
        };
        assert_eq!(rust.capability_refresh_interval, Duration::from_secs(10));
    }

    #[test]
    fn rust_capability_refresh_interval_default_is_one_hour() {
        let mut t = rust_toml();
        t.acknowledge_v1_8_1_audit_divergence = Some(true);
        let cfg = config_with_rust(t);
        let p = from_config_rust_test(&cfg).expect("default loads");
        let PdsAdminBackendConfig::Rust(rust) = p.backend.as_ref().unwrap() else {
            panic!("expected Rust backend");
        };
        assert_eq!(rust.capability_refresh_interval, Duration::from_secs(3600));
    }

    #[test]
    fn rust_capability_refresh_interval_unparseable_rejects() {
        let mut t = rust_toml();
        t.capability_refresh_interval = Some("five hours".into());
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("unparseable rejects");
        assert!(format!("{err}").contains("not a valid duration"));
    }

    #[test]
    fn rust_pinned_versions_mismatch_rejects() {
        // Pinned family doesn't show up in required_capabilities.
        let mut t = rust_toml();
        t.required_capabilities = Some(vec!["other-family-v1".into()]);
        let mut pinned = BTreeMap::new();
        pinned.insert("missing-family".to_string(), "v2".to_string());
        t.pinned_versions = Some(pinned);
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("mismatch rejects");
        assert!(format!("{err}").contains("does not appear in required_capabilities"));
    }

    #[test]
    fn rust_missing_env_var_rejects() {
        let mut t = rust_toml();
        t.service_signing_key_env = "UNSET_VAR".into();
        let cfg = config_with_rust(t);
        let err = from_config_rust_test(&cfg).expect_err("unset env rejects");
        assert!(format!("{err}").contains("env var $UNSET_VAR"));
    }

    // ----- C. audit-divergence enforcement matrix -----
    //
    // These tests exercise validate_audit_divergence_acknowledgment
    // directly so they don't have to round-trip every TOML field.
    // Each builds a minimal PdsAdminPolicy + optional sibling configs.

    fn policy_rust(ack: bool) -> PdsAdminPolicy {
        PdsAdminPolicy {
            enabled: true,
            backend: Some(PdsAdminBackendConfig::Rust(Box::new(RustBackendConfig {
                pds_url: url::Url::parse("https://rust-pds.example.test").unwrap(),
                service_did: "did:web:cairn-mod.example.test".into(),
                service_signing_key_env: "RUST_SERVICE_SIGNING_KEY".into(),
                service_did_document_url: None,
                target_service_did: "did:web:rust-pds.example.test".into(),
                request_timeout: Duration::from_secs(30),
                capability_refresh_interval: Duration::from_secs(3600),
                required_capabilities: Vec::new(),
                pinned_versions: BTreeMap::new(),
                verification_persist: true,
                acknowledge_v1_8_1_audit_divergence: ack,
            }))),
            action_map: BTreeMap::new(),
        }
    }

    fn policy_ozone() -> PdsAdminPolicy {
        PdsAdminPolicy {
            enabled: true,
            backend: Some(PdsAdminBackendConfig::Ozone(OzoneBackendConfig {
                pds_url: url::Url::parse("https://bsky.example.test").unwrap(),
                admin_password: AdminPassword::new("secret".into()),
                request_timeout: Duration::from_secs(10),
            })),
            action_map: BTreeMap::new(),
        }
    }

    fn policy_disabled_rust() -> PdsAdminPolicy {
        PdsAdminPolicy {
            enabled: false,
            backend: None,
            action_map: BTreeMap::new(),
        }
    }

    fn auto_mode_rule(name: &str) -> crate::policy::automation::PolicyRule {
        crate::policy::automation::PolicyRule {
            name: name.to_string(),
            threshold_strikes: 1,
            action_type: crate::moderation::types::ActionType::Warning,
            mode: crate::policy::automation::PolicyMode::Auto,
            reason_codes: vec!["spam".into()],
            duration: None,
        }
    }

    fn flag_mode_rule(name: &str) -> crate::policy::automation::PolicyRule {
        crate::policy::automation::PolicyRule {
            name: name.to_string(),
            threshold_strikes: 1,
            action_type: crate::moderation::types::ActionType::Warning,
            mode: crate::policy::automation::PolicyMode::Flag,
            reason_codes: vec!["spam".into()],
            duration: None,
        }
    }

    fn policy_automation_with_rules(
        rules: Vec<(&str, crate::policy::automation::PolicyRule)>,
    ) -> crate::policy::automation::PolicyAutomationPolicy {
        let mut map = BTreeMap::new();
        for (name, rule) in rules {
            map.insert(name.to_string(), rule);
        }
        crate::policy::automation::PolicyAutomationPolicy {
            enabled: true,
            rules: map,
        }
    }

    #[test]
    fn divergence_rust_missing_ack_rejects() {
        let policy = policy_rust(false);
        let err = validate_audit_divergence_acknowledgment(&policy, None, None)
            .expect_err("missing ack rejects");
        assert_eq!(
            err,
            PdsAdminConfigError::AuditDivergenceAcknowledgmentRequired
        );
    }

    #[test]
    fn divergence_rust_with_ack_passes_alone() {
        let policy = policy_rust(true);
        validate_audit_divergence_acknowledgment(&policy, None, None)
            .expect("ack-only rust passes");
    }

    #[test]
    fn divergence_ozone_no_ack_passes() {
        // Rust-only rule: ozone backend bypasses every part of
        // the gate.
        let policy = policy_ozone();
        validate_audit_divergence_acknowledgment(&policy, None, None).expect("ozone bypasses gate");
    }

    #[test]
    fn divergence_disabled_short_circuits() {
        let policy = policy_disabled_rust();
        validate_audit_divergence_acknowledgment(&policy, None, None)
            .expect("disabled short-circuits");
    }

    #[test]
    fn divergence_rust_with_auto_mode_rule_rejects() {
        let policy = policy_rust(true);
        let pa = policy_automation_with_rules(vec![("strike-warn", auto_mode_rule("x"))]);
        let err = validate_audit_divergence_acknowledgment(&policy, Some(&pa), None)
            .expect_err("auto mode rejects");
        match err {
            PdsAdminConfigError::PolicyAutoModeIncompatibleWithInspectorRustBackend(rules) => {
                assert_eq!(rules, vec!["strike-warn".to_string()]);
            }
            other => panic!("expected PolicyAutoModeIncompatible, got {other:?}"),
        }
    }

    #[test]
    fn divergence_rust_with_flag_mode_only_passes() {
        // Flag-mode rules don't dispatch automatically; they
        // surface to the operator and pause for confirmation.
        // No conflict with inspector-only RustBackend.
        let policy = policy_rust(true);
        let pa = policy_automation_with_rules(vec![("strike-warn", flag_mode_rule("strike-warn"))]);
        validate_audit_divergence_acknowledgment(&policy, Some(&pa), None)
            .expect("flag-only passes");
    }

    fn enabled_xrpc_gateway() -> crate::xrpc_gateway::XrpcGatewayConfig {
        crate::xrpc_gateway::XrpcGatewayConfig {
            enabled: true,
            service_did: "did:plc:test".into(),
            clock_skew_tolerance: Duration::from_secs(30),
            replay_cache_ttl: Duration::from_secs(120),
        }
    }

    #[test]
    fn divergence_rust_with_xrpc_gateway_enabled_rejects() {
        let policy = policy_rust(true);
        let gw = enabled_xrpc_gateway();
        let err = validate_audit_divergence_acknowledgment(&policy, None, Some(&gw))
            .expect_err("xrpc_gateway enabled rejects");
        assert_eq!(
            err,
            PdsAdminConfigError::XrpcGatewayIncompatibleWithInspectorRustBackend
        );
    }

    #[test]
    fn divergence_rust_with_xrpc_gateway_absent_passes() {
        let policy = policy_rust(true);
        validate_audit_divergence_acknowledgment(&policy, None, None)
            .expect("xrpc_gateway absent passes");
    }

    // ----- D. enabled=false short-circuit -----

    #[test]
    fn enabled_false_with_invalid_rust_block_still_validates_per_block() {
        // Per-block validation runs even when disabled — empty url
        // surfaces at config-load.
        let mut t = rust_toml();
        t.url = String::new();
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: false,
            backend: None,
            ozone: None,
            rust: Some(t),
            action_map: None,
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_rust_test(&cfg).expect_err("empty url rejects even disabled");
        assert!(format!("{err}").contains("[pds_admin.rust] is invalid"));
    }

    #[test]
    fn v1_7_compat_no_backend_key_with_only_ozone_block_resolves_to_ozone() {
        // v1.7-style config: no `backend` key, only [pds_admin.ozone].
        // Loads cleanly under v1.8.1 and resolves to Ozone via
        // auto-detect.
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: true,
            backend: None,
            ozone: Some(ozone_toml()),
            rust: None,
            action_map: Some(full_action_map_skip_all()),
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let p = from_config_rust_test(&cfg).expect("v1.7-shape loads");
        assert!(p.enabled);
        assert!(matches!(p.backend, Some(PdsAdminBackendConfig::Ozone(_))));
    }

    // ----- should_warn_rust_backend_dispatch helper -----

    #[test]
    fn warn_helper_returns_true_when_enabled_rust() {
        assert!(should_warn_rust_backend_dispatch(&policy_rust(true)));
        assert!(should_warn_rust_backend_dispatch(&policy_rust(false)));
    }

    #[test]
    fn warn_helper_returns_false_when_ozone() {
        assert!(!should_warn_rust_backend_dispatch(&policy_ozone()));
    }

    #[test]
    fn warn_helper_returns_false_when_disabled() {
        assert!(!should_warn_rust_backend_dispatch(&policy_disabled_rust()));
    }
}
