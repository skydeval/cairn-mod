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

/// Backend selector. v1.7 has only [`Self::Ozone`]; v1.8 will
/// add a `Locus` variant. The resolver rejects `[pds_admin.locus]`
/// in v1.7 before this type sees it.
#[derive(Debug, Clone)]
pub enum PdsAdminBackendConfig {
    /// bsky-PDS backend (the v1.7 default and only option).
    Ozone(OzoneBackendConfig),
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
}

impl BackendMethod {
    /// Parse the wire-string form. Returns `None` for unknown
    /// strings so the caller can surface a config-load error
    /// listing the allowed set. Module-private to dodge clippy's
    /// `should_implement_trait` lint and to match the
    /// [`crate::policy::automation::PolicyMode`] precedent —
    /// later issues (#84, #86) can promote visibility if a
    /// crate-wide consumer needs the parser.
    fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "takedown_account" => Some(Self::TakedownAccount),
            "suspend_account" => Some(Self::SuspendAccount),
            "restore_account" => Some(Self::RestoreAccount),
            "apply_label" => Some(Self::ApplyLabel),
            "negate_label" => Some(Self::NegateLabel),
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
        }
    }

    /// Whether `OzoneBackend` (the v1.7 backend) implements this
    /// method. Returns `false` for the label methods that
    /// `OzoneBackend` will reject at runtime per A5 (#89). The
    /// resolver uses this to emit a config-load warning when an
    /// action_map entry maps to an unimplemented method.
    pub fn is_implemented_by_ozone_v1_7(self) -> bool {
        match self {
            Self::TakedownAccount | Self::SuspendAccount | Self::RestoreAccount => true,
            Self::ApplyLabel | Self::NegateLabel => false,
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
    /// Construct from a resolved env-var value. Internal to the
    /// resolver — operator code outside this module shouldn't
    /// produce admin passwords.
    pub(crate) fn new(s: String) -> Self {
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
        // staging a v1.8 `[pds_admin.locus]` config behind
        // `enabled = false` should still get told that v1.7 doesn't
        // support locus — but they shouldn't be forced to fill in
        // every action_map entry just to typecheck the toggle off.
        reject_unsupported_backend_subsections(toml)?;

        // [pds_admin.ozone]: per-block validation runs whether or
        // not enabled, so a forward-compat staging config still
        // gets URL/env-var checking. The resolved value only
        // surfaces on the policy when enabled is true.
        let resolved_ozone = toml
            .ozone
            .as_ref()
            .map(|t| validated_ozone_from_toml(t, &read_env))
            .transpose()?;

        if !toml.enabled {
            return Ok(Self {
                enabled: false,
                backend: None,
                action_map: BTreeMap::new(),
            });
        }

        // enabled = true: cross-block rules apply.
        let backend = match resolved_ozone {
            Some(ozone) => PdsAdminBackendConfig::Ozone(ozone),
            None => {
                return Err(Error::Signing(
                    "config: [pds_admin].enabled = true but no backend subsection is present \
                     (v1.7 supports [pds_admin.ozone] only)"
                        .into(),
                ));
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

/// Reject `[pds_admin.locus]` and any other unrecognized backend
/// subsection. Runs even when `enabled = false` so operators
/// catch typos and v1.8-staged configs at v1.7 startup, not at
/// the eventual flip to enabled.
fn reject_unsupported_backend_subsections(toml: &crate::config::PdsAdminConfigToml) -> Result<()> {
    if toml.locus.is_some() {
        return Err(Error::Signing(
            "config: backend not supported in v1.7: locus \
             (Aurora-Locus support is deferred to v1.8; remove [pds_admin.locus] \
             or wait for v1.8)"
                .into(),
        ));
    }
    if let Some(unknown) = toml.other_backends.keys().next() {
        return Err(Error::Signing(format!(
            "config: backend not supported in v1.7: {unknown} \
             (v1.7 supports [pds_admin.ozone] only; check for typos in subsection name)"
        )));
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
            && !method.is_implemented_by_ozone_v1_7()
            && warned_methods.insert((action_type, method))
        {
            tracing::warn!(
                "config: [pds_admin.action_map].{} maps to {}, but OzoneBackend does not \
                 implement label methods in v1.7; this action will not propagate to the PDS \
                 (#89: returns BackendError::Unsupported at runtime)",
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
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let p = from_config_test(&cfg, "secret-value").expect("full config loads");
        assert!(p.enabled);
        let PdsAdminBackendConfig::Ozone(ozone) = p.backend.as_ref().expect("backend present");
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
            locus: None,
            other_backends: BTreeMap::new(),
        });
        let err = from_config_test(&cfg, "secret").expect_err("no backend rejects");
        assert!(format!("{err}").contains("no backend subsection"));
    }

    #[test]
    fn locus_subsection_rejects_with_v1_8_pointer() {
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: false, // even when disabled — typo / staging visibility
            ozone: None,
            action_map: None,
            locus: Some(serde_json::json!({"some_field": "value"})),
            other_backends: BTreeMap::new(),
        });
        let err = PdsAdminPolicy::from_config_with_env_reader(&cfg, env_reader_unset)
            .expect_err("locus rejects");
        let msg = format!("{err}");
        assert!(
            msg.contains("backend not supported in v1.7: locus"),
            "msg={msg}"
        );
        assert!(msg.contains("v1.8"), "msg={msg}");
    }

    #[test]
    fn unknown_backend_subsection_rejects() {
        let mut other = BTreeMap::new();
        other.insert("ozonee".to_string(), serde_json::json!({})); // typo
        let cfg = config_with_pds_admin(PdsAdminConfigToml {
            enabled: false,
            ozone: None,
            action_map: None,
            locus: None,
            other_backends: other,
        });
        let err = PdsAdminPolicy::from_config_with_env_reader(&cfg, env_reader_unset)
            .expect_err("unknown backend rejects");
        let msg = format!("{err}");
        assert!(
            msg.contains("backend not supported in v1.7: ozonee"),
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
}
