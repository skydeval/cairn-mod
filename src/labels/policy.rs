//! Label emission policy (§F21, #58).
//!
//! Operator-config surface that drives v1.5's label emission. The
//! policy is loaded once at config-load time from `[label_emission]`
//! and is read-only thereafter — operators restart `cairn serve` to
//! change the mapping, matching `[moderation_reasons]` (#47) and
//! `[strike_policy]` (#48) posture.
//!
//! # Defaults
//!
//! Public-cairn-mod's baseline:
//!
//! - `enabled = true` — emission is on.
//! - `emit_reason_labels = true` — `reason-<code>` labels emitted
//!   alongside action labels.
//! - `warning_emits_label = false` — warnings are typically
//!   advisory; operators opt in to surface them.
//! - `reason_label_prefix = "reason-"`.
//! - Per-action-type label mapping:
//!
//! | Action type        | Default `val` | Default severity | Notes |
//! |--------------------|---------------|------------------|-------|
//! | `takedown`         | `!takedown`   | `alert`          | ATProto global |
//! | `indef_suspension` | `!hide`       | `alert`          | ATProto global |
//! | `temp_suspension`  | `!hide`       | `alert`          | `exp` set per #63 |
//! | `warning`          | `!warn`       | `inform`         | only when `warning_emits_label = true` |
//! | `note`             | (none)        | (none)           | never emits, no opt-in |
//!
//! # Resolution rules
//!
//! [`LabelEmissionPolicy::resolve_action_label`]:
//!
//! 1. `note` → always `None`. There is no operator opt-in path
//!    for note emission; notes are forensic context, not protocol-
//!    visible moderation.
//! 2. `warning` → `None` unless `warning_emits_label = true`.
//! 3. Otherwise → `Some(spec)` where `spec` comes from:
//!    - `action_label_overrides[action_type]` if the operator
//!      declared a full override; or
//!    - The shipped default for that action type, with
//!      `severity_overrides[action_type]` applied if present.
//!
//! When `action_label_overrides` has an entry, its severity wins —
//! `severity_overrides` is the lighter-weight knob for "tweak
//! severity without changing val."
//!
//! [`LabelEmissionPolicy::resolve_reason_label_value`] always
//! returns the prefix-applied value. Whether to actually emit is
//! the consumer's decision (gated on `emit_reason_labels`).
//!
//! # Customization across deployments
//!
//! The same code path serves Hideaway, Northsky, Eurosky, and the
//! generic public deployment. Per-deployment differences live in
//! `[label_emission]` config values:
//!
//! - Hideaway sets `action_label_overrides.takedown =
//!   { val = "!hideaway-takedown", ... }` to brand its labels.
//! - A deployment that wants visible warnings flips
//!   `warning_emits_label = true`.
//! - A deployment with custom reason vocabulary keeps
//!   `reason_label_prefix = "reason-"` so cairn-mod's default
//!   reason-decoding posture works across the fleet.
//!
//! Cairn-mod's code path is the same for all of them; the
//! deployment-specific behavior emerges from the deployment-
//! specific config.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{BlursToml, LocaleToml, SeverityToml};
use crate::error::{Error, Result};
use crate::moderation::types::ActionType;

/// Resolved label-emission policy. Produced at config-load time by
/// [`Self::from_config`] and held by the writer task + read endpoints
/// that need to surface emission state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelEmissionPolicy {
    /// Master toggle. When `false`, [`Self::resolve_action_label`]
    /// returns `None` for every action type and emission is fully
    /// suppressed.
    pub enabled: bool,
    /// Whether to emit `<prefix><reason_code>` labels alongside the
    /// action label.
    pub emit_reason_labels: bool,
    /// Whether `warning` actions emit a label.
    pub warning_emits_label: bool,
    /// Prefix prepended to each `reason_code` to form the reason
    /// label's `val`. Default `"reason-"`.
    pub reason_label_prefix: String,
    /// Per-action-type label override. Keys are validated
    /// [`ActionType`] values; entries take priority over the
    /// shipped defaults.
    pub action_label_overrides: BTreeMap<ActionType, LabelSpec>,
    /// Per-action-type severity override. Lighter-weight knob than
    /// a full override entry; ignored when
    /// [`Self::action_label_overrides`] has an entry for the same
    /// action type (the explicit override's severity wins).
    pub severity_overrides: BTreeMap<ActionType, SeverityToml>,
}

/// One entry in [`LabelEmissionPolicy::action_label_overrides`]. The
/// runtime equivalent of [`crate::config::LabelSpecToml`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSpec {
    /// The label `val` emitted at action time.
    pub val: String,
    /// Severity hint surfaced to consumer AppViews (#56's trust-
    /// chain disclosure framing applies — operators declare,
    /// observers verify).
    pub severity: SeverityToml,
    /// Optional blur hint. Most graduated-action labels do not
    /// specify blurs since they represent account-level state, not
    /// content-level visual treatment.
    pub blurs: Option<BlursToml>,
    /// Optional localized display strings. Empty by default —
    /// operators that want consumer-friendly labels populate this
    /// in their [`crate::config::LabelSpecToml`].
    pub locales: Vec<LocaleToml>,
}

impl LabelEmissionPolicy {
    /// Build the policy from `cfg.label_emission`. When the field is
    /// `None` (operator declared no `[label_emission]` block),
    /// returns [`Self::defaults`]. When the field is present (even
    /// with only some sub-fields specified), all unspecified
    /// sub-fields take their `serde(default)` values, then the
    /// resolved values are validated together.
    pub fn from_config(cfg: &crate::config::Config) -> Result<Self> {
        let Some(toml) = cfg.label_emission.as_ref() else {
            return Ok(Self::defaults());
        };
        Self::validated_from_toml(toml)
    }

    /// Public-cairn-mod default policy. See module docs for the full
    /// per-action-type table; the runtime defaults here mirror the
    /// shipped baseline for any action_type not present in
    /// `action_label_overrides`.
    pub fn defaults() -> Self {
        Self {
            enabled: true,
            emit_reason_labels: true,
            warning_emits_label: false,
            reason_label_prefix: "reason-".to_string(),
            action_label_overrides: BTreeMap::new(),
            severity_overrides: BTreeMap::new(),
        }
    }

    fn validated_from_toml(toml: &crate::config::LabelEmissionPolicyToml) -> Result<Self> {
        validate_reason_label_prefix(&toml.reason_label_prefix)?;

        // Project action_label_overrides keys: TOML keys are
        // strings; validate each as an ActionType. note is
        // permitted as a key for symmetry with the schema's CHECK
        // values but the resolver will still return None for note
        // (defense-in-depth — see resolve_action_label).
        let mut overrides: BTreeMap<ActionType, LabelSpec> = BTreeMap::new();
        let mut seen_vals: BTreeSet<String> = BTreeSet::new();
        for (key, spec_toml) in &toml.action_label_overrides {
            let action_type = ActionType::from_db_str(key).ok_or_else(|| {
                Error::Signing(format!(
                    "config: [label_emission.action_label_overrides.{key}] is not a valid action_type \
                     (expected one of warning / note / temp_suspension / indef_suspension / takedown)"
                ))
            })?;
            validate_label_val(&spec_toml.val).map_err(|e| {
                Error::Signing(format!(
                    "config: [label_emission.action_label_overrides.{key}].val: {e}"
                ))
            })?;
            if !seen_vals.insert(spec_toml.val.clone()) {
                return Err(Error::Signing(format!(
                    "config: [label_emission.action_label_overrides] declares duplicate val \
                     {:?} across multiple action_type entries — each label val must be \
                     unique to a single action_type so revocation can route negation \
                     unambiguously",
                    spec_toml.val
                )));
            }
            overrides.insert(
                action_type,
                LabelSpec {
                    val: spec_toml.val.clone(),
                    severity: spec_toml.severity,
                    blurs: spec_toml.blurs,
                    locales: spec_toml.locales.clone(),
                },
            );
        }

        // Project severity_overrides keys.
        let mut sev_overrides: BTreeMap<ActionType, SeverityToml> = BTreeMap::new();
        for (key, severity) in &toml.severity_overrides {
            let action_type = ActionType::from_db_str(key).ok_or_else(|| {
                Error::Signing(format!(
                    "config: [label_emission.severity_overrides.{key}] is not a valid action_type"
                ))
            })?;
            sev_overrides.insert(action_type, *severity);
        }

        Ok(Self {
            enabled: toml.enabled,
            emit_reason_labels: toml.emit_reason_labels,
            warning_emits_label: toml.warning_emits_label,
            reason_label_prefix: toml.reason_label_prefix.clone(),
            action_label_overrides: overrides,
            severity_overrides: sev_overrides,
        })
    }

    /// Resolve the action label for an [`ActionType`], honoring all
    /// applicable knobs. See module docs for the full rule table.
    /// Returns `None` when emission is disabled, the action type is
    /// `note`, or the action type is `warning` and
    /// `warning_emits_label = false`.
    pub fn resolve_action_label(&self, action_type: ActionType) -> Option<LabelSpec> {
        if !self.enabled {
            return None;
        }
        if matches!(action_type, ActionType::Note) {
            // Notes never emit, regardless of any operator config.
            // Defense-in-depth: even if a future operator configures
            // an action_label_override for note, this gate still
            // suppresses emission.
            return None;
        }
        if matches!(action_type, ActionType::Warning) && !self.warning_emits_label {
            return None;
        }

        if let Some(spec) = self.action_label_overrides.get(&action_type) {
            // Explicit override — the operator declared the full
            // spec, and severity_overrides does NOT apply on top
            // (the override is the canonical statement).
            return Some(spec.clone());
        }

        // Fall back to the shipped default. severity_overrides
        // applies on top of the default.
        let mut spec = default_spec_for(action_type)?;
        if let Some(sev) = self.severity_overrides.get(&action_type) {
            spec.severity = *sev;
        }
        Some(spec)
    }

    /// Compute the reason label's `val` for a given reason code.
    /// Always returns a value; the consumer (#59 emission core)
    /// decides whether to actually emit based on
    /// [`Self::emit_reason_labels`].
    pub fn resolve_reason_label_value(&self, reason_code: &str) -> String {
        format!("{}{}", self.reason_label_prefix, reason_code)
    }
}

/// Shipped per-action-type default. Returns `None` for `note`
/// (matching the no-emission contract).
fn default_spec_for(action_type: ActionType) -> Option<LabelSpec> {
    match action_type {
        ActionType::Note => None,
        ActionType::Takedown => Some(LabelSpec {
            val: "!takedown".to_string(),
            severity: SeverityToml::Alert,
            blurs: None,
            locales: Vec::new(),
        }),
        ActionType::IndefSuspension => Some(LabelSpec {
            val: "!hide".to_string(),
            severity: SeverityToml::Alert,
            blurs: None,
            locales: Vec::new(),
        }),
        ActionType::TempSuspension => Some(LabelSpec {
            val: "!hide".to_string(),
            severity: SeverityToml::Alert,
            blurs: None,
            locales: Vec::new(),
        }),
        ActionType::Warning => Some(LabelSpec {
            val: "!warn".to_string(),
            severity: SeverityToml::Inform,
            blurs: None,
            locales: Vec::new(),
        }),
    }
}

/// Validate a label `val` per ATProto + cairn-mod conventions.
///
/// Rules:
/// - Length 1..=128 bytes (matches the §6.4 schema CHECK).
/// - First char: ASCII lowercase letter, ASCII digit, or `!`
///   (the latter for ATProto global label values like `!takedown`).
/// - Subsequent chars: ASCII lowercase letter, ASCII digit, or `-`.
fn validate_label_val(val: &str) -> std::result::Result<(), String> {
    if val.is_empty() {
        return Err("label val must be non-empty".into());
    }
    if val.len() > 128 {
        return Err(format!(
            "label val {val:?} exceeds the §6.4 schema CHECK length limit (got {} bytes, max 128)",
            val.len()
        ));
    }
    let mut chars = val.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() && first != '!' {
        return Err(format!(
            "label val {val:?} must start with a lowercase ASCII letter, ASCII digit, or `!` \
             (got {first:?})"
        ));
    }
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            return Err(format!(
                "label val {val:?} contains invalid char {c:?} \
                 (allowed after the first char: a-z, 0-9, hyphen)"
            ));
        }
    }
    Ok(())
}

/// Validate the reason label prefix. Empty is permitted (logged as
/// a startup warning by [`LabelEmissionPolicy::from_config`] —
/// callers pair an empty prefix with intentional reason-code
/// surfacing — though the warning is best-effort and emitted via
/// `tracing`).
fn validate_reason_label_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        // Empty is legal but suspicious. Log a warning so operators
        // see it at startup; don't fail config load.
        tracing::warn!(
            "config: [label_emission].reason_label_prefix is empty — \
             reason labels will use bare reason_codes as their val"
        );
        return Ok(());
    }
    if prefix.len() > 32 {
        return Err(Error::Signing(format!(
            "config: [label_emission].reason_label_prefix {:?} exceeds 32 bytes (got {})",
            prefix,
            prefix.len()
        )));
    }
    let mut chars = prefix.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_lowercase() {
        return Err(Error::Signing(format!(
            "config: [label_emission].reason_label_prefix {:?} must start with a lowercase \
             ASCII letter (got {:?})",
            prefix, first
        )));
    }
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            return Err(Error::Signing(format!(
                "config: [label_emission].reason_label_prefix {:?} contains invalid char {:?} \
                 (allowed: a-z, 0-9, hyphen)",
                prefix, c
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_with_emission(value: serde_json::Value) -> Config {
        let mut v = serde_json::json!({
            "service_did": "did:web:labeler.example",
            "service_endpoint": "https://labeler.example",
            "db_path": "/var/lib/cairn/cairn.db",
            "signing_key_path": "/etc/cairn/signing-key.hex",
        });
        if !value.is_null() {
            v["label_emission"] = value;
        }
        serde_json::from_value(v).expect("config deserializes")
    }

    // ---------- defaults ----------

    #[test]
    fn defaults_match_documented_baseline() {
        let p = LabelEmissionPolicy::defaults();
        assert!(p.enabled);
        assert!(p.emit_reason_labels);
        assert!(!p.warning_emits_label);
        assert_eq!(p.reason_label_prefix, "reason-");
        assert!(p.action_label_overrides.is_empty());
        assert!(p.severity_overrides.is_empty());
    }

    #[test]
    fn absent_block_loads_defaults() {
        let cfg = config_with_emission(serde_json::Value::Null);
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p, LabelEmissionPolicy::defaults());
    }

    #[test]
    fn empty_block_loads_defaults_via_serde_fallbacks() {
        let cfg = config_with_emission(serde_json::json!({}));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p, LabelEmissionPolicy::defaults());
    }

    // ---------- partial declarations ----------

    #[test]
    fn partial_block_uses_serde_defaults_for_other_fields() {
        let cfg = config_with_emission(serde_json::json!({
            "warning_emits_label": true,
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        assert!(p.warning_emits_label);
        assert!(p.enabled);
        assert!(p.emit_reason_labels);
        assert_eq!(p.reason_label_prefix, "reason-");
    }

    #[test]
    fn full_explicit_declaration_reflects_all_values() {
        let cfg = config_with_emission(serde_json::json!({
            "enabled": false,
            "emit_reason_labels": false,
            "warning_emits_label": true,
            "reason_label_prefix": "rsn-",
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        assert!(!p.enabled);
        assert!(!p.emit_reason_labels);
        assert!(p.warning_emits_label);
        assert_eq!(p.reason_label_prefix, "rsn-");
    }

    // ---------- action_label_overrides ----------

    #[test]
    fn action_label_override_replaces_default_for_that_type() {
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": {
                    "val": "!hideaway-takedown",
                    "severity": "alert",
                }
            }
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        let spec = p.resolve_action_label(ActionType::Takedown).unwrap();
        assert_eq!(spec.val, "!hideaway-takedown");
    }

    #[test]
    fn action_label_override_with_unknown_type_rejected() {
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "ban": {
                    "val": "!banned",
                    "severity": "alert",
                }
            }
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not a valid action_type"));
        assert!(msg.contains("ban"));
    }

    #[test]
    fn duplicate_val_across_action_label_overrides_rejected() {
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown":         { "val": "!enforced", "severity": "alert" },
                "indef_suspension": { "val": "!enforced", "severity": "alert" },
            }
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate val"));
    }

    #[test]
    fn action_label_override_with_blurs_and_locales_round_trips() {
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": {
                    "val": "!takedown",
                    "severity": "alert",
                    "blurs": "media",
                    "locales": [
                        { "lang": "en", "name": "Removed", "description": "Account removed by moderation" }
                    ]
                }
            }
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        let spec = p.resolve_action_label(ActionType::Takedown).unwrap();
        assert!(matches!(spec.blurs, Some(BlursToml::Media)));
        assert_eq!(spec.locales.len(), 1);
        assert_eq!(spec.locales[0].lang, "en");
    }

    // ---------- val validation ----------

    #[test]
    fn empty_val_rejected() {
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": "", "severity": "alert" }
            }
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("non-empty"));
    }

    #[test]
    fn uppercase_val_rejected() {
        // "Bad-Val" — first char `B` triggers the start-of-val
        // validator (must start with lowercase letter / digit / `!`).
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": "Bad-Val", "severity": "alert" }
            }
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("lowercase"));
    }

    #[test]
    fn uppercase_in_middle_of_val_rejected() {
        // "good-Val" — first char `g` is fine; later `V` triggers
        // the per-char validator with the `invalid char` message.
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": "good-Val", "severity": "alert" }
            }
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("invalid char"));
    }

    #[test]
    fn val_with_underscore_rejected() {
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": "my_label", "severity": "alert" }
            }
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("invalid char"));
    }

    #[test]
    fn val_starting_with_digit_accepted() {
        // Digits are permitted as the first character.
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": "2025-policy", "severity": "alert" }
            }
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        let spec = p.resolve_action_label(ActionType::Takedown).unwrap();
        assert_eq!(spec.val, "2025-policy");
    }

    #[test]
    fn val_with_bang_prefix_accepted() {
        // ATProto global labels start with `!`.
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": "!hideaway-takedown", "severity": "alert" }
            }
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        let spec = p.resolve_action_label(ActionType::Takedown).unwrap();
        assert_eq!(spec.val, "!hideaway-takedown");
    }

    #[test]
    fn val_too_long_rejected() {
        let long = "a".repeat(129);
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": long, "severity": "alert" }
            }
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("128"));
    }

    // ---------- reason_label_prefix validation ----------

    #[test]
    fn empty_prefix_is_valid_with_warning() {
        // Empty prefix logs a warning but is permitted.
        let cfg = config_with_emission(serde_json::json!({
            "reason_label_prefix": "",
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.reason_label_prefix, "");
        assert_eq!(p.resolve_reason_label_value("hate-speech"), "hate-speech");
    }

    #[test]
    fn uppercase_prefix_rejected() {
        let cfg = config_with_emission(serde_json::json!({
            "reason_label_prefix": "Reason-",
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("lowercase"));
    }

    #[test]
    fn prefix_with_underscore_rejected() {
        let cfg = config_with_emission(serde_json::json!({
            "reason_label_prefix": "rsn_",
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("invalid char"));
    }

    #[test]
    fn prefix_too_long_rejected() {
        let long = "a".repeat(33);
        let cfg = config_with_emission(serde_json::json!({
            "reason_label_prefix": long,
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("32 bytes"));
    }

    // ---------- severity_overrides ----------

    #[test]
    fn severity_override_applies_when_no_full_override() {
        let cfg = config_with_emission(serde_json::json!({
            "warning_emits_label": true,
            "severity_overrides": {
                "warning": "alert",
            }
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        let spec = p.resolve_action_label(ActionType::Warning).unwrap();
        assert!(matches!(spec.severity, SeverityToml::Alert));
        assert_eq!(spec.val, "!warn"); // val from default, severity overridden
    }

    #[test]
    fn severity_override_ignored_when_full_override_present() {
        // When action_label_overrides has the action_type, its
        // severity wins — severity_overrides for the same type is
        // ignored.
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": "!custom", "severity": "inform" }
            },
            "severity_overrides": {
                "takedown": "alert",
            }
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        let spec = p.resolve_action_label(ActionType::Takedown).unwrap();
        assert!(matches!(spec.severity, SeverityToml::Inform));
    }

    #[test]
    fn severity_override_with_unknown_type_rejected() {
        let cfg = config_with_emission(serde_json::json!({
            "severity_overrides": {
                "ban": "alert",
            }
        }));
        let err = LabelEmissionPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("not a valid action_type"));
    }

    // ---------- resolve_action_label semantics ----------

    #[test]
    fn enabled_false_suppresses_all_emission() {
        let cfg = config_with_emission(serde_json::json!({
            "enabled": false,
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        for at in [
            ActionType::Takedown,
            ActionType::IndefSuspension,
            ActionType::TempSuspension,
            ActionType::Warning,
            ActionType::Note,
        ] {
            assert!(
                p.resolve_action_label(at).is_none(),
                "expected None for {at:?}"
            );
        }
    }

    #[test]
    fn note_never_emits_regardless_of_config() {
        // Defense-in-depth: even if a future operator declares an
        // action_label_overrides.note entry, the resolver
        // suppresses it.
        let cfg = config_with_emission(serde_json::json!({
            "action_label_overrides": {
                "note": { "val": "!noted", "severity": "inform" }
            }
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        assert!(p.resolve_action_label(ActionType::Note).is_none());
    }

    #[test]
    fn warning_emits_only_when_flag_true() {
        // Flag false (default) — no emission.
        let p = LabelEmissionPolicy::defaults();
        assert!(p.resolve_action_label(ActionType::Warning).is_none());

        // Flag true — emission with default !warn.
        let cfg = config_with_emission(serde_json::json!({
            "warning_emits_label": true,
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        let spec = p.resolve_action_label(ActionType::Warning).unwrap();
        assert_eq!(spec.val, "!warn");
        assert!(matches!(spec.severity, SeverityToml::Inform));
    }

    #[test]
    fn defaults_resolve_to_atproto_globals() {
        let p = LabelEmissionPolicy::defaults();
        assert_eq!(
            p.resolve_action_label(ActionType::Takedown).unwrap().val,
            "!takedown"
        );
        assert_eq!(
            p.resolve_action_label(ActionType::IndefSuspension)
                .unwrap()
                .val,
            "!hide"
        );
        assert_eq!(
            p.resolve_action_label(ActionType::TempSuspension)
                .unwrap()
                .val,
            "!hide"
        );
    }

    // ---------- resolve_reason_label_value ----------

    #[test]
    fn reason_label_value_uses_default_prefix() {
        let p = LabelEmissionPolicy::defaults();
        assert_eq!(
            p.resolve_reason_label_value("hate-speech"),
            "reason-hate-speech"
        );
        assert_eq!(p.resolve_reason_label_value("spam"), "reason-spam");
    }

    #[test]
    fn reason_label_value_uses_custom_prefix() {
        let cfg = config_with_emission(serde_json::json!({
            "reason_label_prefix": "rsn-",
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        assert_eq!(
            p.resolve_reason_label_value("hate-speech"),
            "rsn-hate-speech"
        );
    }

    #[test]
    fn reason_label_value_returns_value_even_when_emit_reason_labels_false() {
        // The loader doesn't gate on emit_reason_labels — that's
        // the consumer's decision (#59 emission core checks).
        // resolve_reason_label_value always returns the computed
        // val for whoever asks.
        let cfg = config_with_emission(serde_json::json!({
            "emit_reason_labels": false,
        }));
        let p = LabelEmissionPolicy::from_config(&cfg).expect("from_config");
        assert!(!p.emit_reason_labels);
        assert_eq!(p.resolve_reason_label_value("spam"), "reason-spam");
    }
}
