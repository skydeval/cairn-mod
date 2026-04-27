//! Policy automation config loader (§F22, #71).
//!
//! Operator-config surface that drives v1.6's policy-automation
//! engine. The policy is loaded once at config-load time from
//! `[policy_automation]` and is read-only thereafter — operators
//! restart `cairn serve` to change the rule set, matching
//! `[moderation_reasons]` (#47), `[strike_policy]` (#48), and
//! `[label_emission]` (#58) posture.
//!
//! # Defaults
//!
//! Public-cairn-mod's baseline:
//!
//! - `enabled = true` — engine is on, ready to evaluate rules.
//! - `rules = {}` — no rules declared. The engine evaluates each
//!   recordAction and finds nothing to fire; semantically a no-op
//!   in production but distinct from `enabled = false` (which
//!   skips evaluation entirely, even if rules are declared).
//!
//! # Rule shape
//!
//! Each `[policy_automation.rules.<name>]` sub-block declares:
//!
//! - `threshold_strikes` (i64, > 0) — the crossing point. A rule
//!   fires only on the precipitating action *crossing* the
//!   threshold (pre-action count below, post-action count at or
//!   above); see #72's evaluator for the full semantic.
//! - `action_type` — the proposed action
//!   ([`crate::moderation::types::ActionType`] variant from v1.4
//!   #46).
//! - `mode` — `auto` or `flag`. Auto records the action directly;
//!   flag queues a `pending_policy_actions` row for moderator
//!   review (#73 / #74 / #75).
//! - `duration` (ISO-8601) — required iff `action_type ==
//!   temp_suspension`; rejected for other types. Parsed at load
//!   time via the same parser as v1.4 #51's `duration_iso`
//!   surface (`crate::writer::parse_iso8601_duration` —
//!   `pub(crate)` from #51, exposed for cross-module reuse here).
//! - `reason_codes` (optional `Vec<String>`) — reason codes
//!   attached to the produced action. Defaults to
//!   `["policy_threshold"]` when omitted. Each code must appear
//!   in the operator's `[moderation_reasons]` vocabulary;
//!   cross-validation runs at [`crate::config::Config::validate`]
//!   level via [`PolicyAutomationPolicy::validate_reason_codes_against`].
//!
//! # Synthetic actor DID
//!
//! [`SYNTHETIC_POLICY_ACTOR_DID`] is the DID
//! cairn-mod attributes to actions the engine records directly
//! (mode=auto rule firings). Hardcoded as `"did:internal:policy"`
//! in v1.6 — operators don't customize this, so downstream tooling
//! filtering by actor_did + actor_kind has a stable identifier.
//! Pending → confirmed flow (#74) uses the moderator's DID, not
//! this constant; the moderator takes responsibility by
//! confirming, with `triggered_by_policy_rule` preserving the
//! rule name for forensic provenance.
//!
//! # Severity ordering
//!
//! [`PolicyAutomationPolicy::rules_in_severity_order`] is the
//! consumer-facing API #72's evaluator uses. Sort key:
//!
//! 1. `takedown` first (terminal — applying anything else first
//!    would be moot).
//! 2. Among non-takedown rules, intrinsic action_type severity:
//!    `indef_suspension` > `temp_suspension` > `warning` > `note`.
//! 3. Tie within action_type: higher `threshold_strikes` first
//!    (more conservative — "you got further along the curve").
//!
//! Single rule fires per recordAction. The "first matching rule
//! in severity order wins" semantic avoids double jeopardy (one
//! threshold-cross producing multiple auto-actions).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::moderation::reasons::ReasonVocabulary;
use crate::moderation::types::ActionType;

/// DID attributed to actions the policy engine records directly
/// (mode=auto rule firings). Hardcoded; operators don't customize.
/// See module docs for the rationale.
pub const SYNTHETIC_POLICY_ACTOR_DID: &str = "did:internal:policy";

/// Default reason code applied to a rule's produced action when
/// the operator omits `reason_codes` on the rule. Operators using
/// this default must declare a `policy_threshold` reason in their
/// `[moderation_reasons]` vocabulary.
pub const DEFAULT_POLICY_REASON_CODE: &str = "policy_threshold";

/// Whether a rule auto-records the resulting action or queues a
/// pending row for moderator review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    /// Engine inserts a `subject_actions` row directly inside the
    /// triggering recordAction transaction (#73).
    Auto,
    /// Engine inserts a `pending_policy_actions` row (#73);
    /// moderator reviews via `cairn moderator pending` (#78) and
    /// confirms (#74) or dismisses (#75).
    Flag,
}

impl PolicyMode {
    /// Wire-string form (`"auto"` / `"flag"`). Used by the recorder
    /// (#73) when serializing to audit log JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyMode::Auto => "auto",
            PolicyMode::Flag => "flag",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(PolicyMode::Auto),
            "flag" => Some(PolicyMode::Flag),
            _ => None,
        }
    }
}

/// Resolved single rule from `[policy_automation.rules.<name>]`.
/// Produced by [`PolicyAutomationPolicy::from_config`]; consumers
/// (the evaluator #72, the recorder #73) read these fields
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// Rule name — copied from the BTreeMap key for convenience
    /// when handing rules to downstream code (audit log, evaluator
    /// output, pending row's `triggered_by_policy_rule`).
    pub name: String,
    /// Strike count crossing point. Validated `> 0`.
    pub threshold_strikes: i64,
    /// Action type the rule produces. `note` is permitted at parse
    /// time but rules producing notes are operationally degenerate
    /// (notes are forensic-only, never strike-bearing); the
    /// evaluator (#72) and recorder (#73) handle the case
    /// gracefully but operators should think hard about what they
    /// expect to gain.
    pub action_type: ActionType,
    /// Auto or flag.
    pub mode: PolicyMode,
    /// `Some` for `TempSuspension`; `None` for other types.
    /// Pre-parsed; consumers don't re-parse.
    pub duration: Option<Duration>,
    /// Reason codes attached to the produced action. Always
    /// non-empty after construction (defaults to
    /// `[DEFAULT_POLICY_REASON_CODE]` when the operator omits
    /// reason_codes on the rule). Each entry validated against
    /// the operator's `[moderation_reasons]` vocabulary at
    /// [`crate::config::Config::validate`] time.
    pub reason_codes: Vec<String>,
}

/// Resolved policy-automation surface. Produced at config-load
/// time by [`Self::from_config`] and held by the writer task
/// (#79) thereafter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAutomationPolicy {
    /// Master toggle. When `false`, the engine skips evaluation
    /// entirely — declared rules don't fire. Distinct from "no
    /// rules": no rules = engine evaluates and finds nothing;
    /// disabled = engine doesn't evaluate.
    pub enabled: bool,
    /// Resolved rule set, keyed by rule name. Iteration order is
    /// deterministic (BTreeMap = sorted by name); the
    /// severity-aware iteration consumers actually want is
    /// [`Self::rules_in_severity_order`].
    pub rules: BTreeMap<String, PolicyRule>,
}

impl PolicyAutomationPolicy {
    /// Build the policy from `cfg.policy_automation`. When the
    /// field is `None` (operator declared no `[policy_automation]`
    /// block), returns [`Self::defaults`]. When the field is
    /// `Some(_)`, validates each rule per the rules in module
    /// docs and returns the resolved policy.
    ///
    /// **Reason-code cross-validation** against the operator's
    /// `[moderation_reasons]` vocabulary is NOT performed here —
    /// each loader stays focused on its own block. The cross-check
    /// runs at [`crate::config::Config::validate`] time via
    /// [`Self::validate_reason_codes_against`], where both the
    /// vocabulary and the policy have been resolved.
    pub fn from_config(cfg: &crate::config::Config) -> Result<Self> {
        let Some(toml) = cfg.policy_automation.as_ref() else {
            return Ok(Self::defaults());
        };
        Self::validated_from_toml(toml)
    }

    /// Default policy. Engine on; no rules declared.
    pub fn defaults() -> Self {
        Self {
            enabled: true,
            rules: BTreeMap::new(),
        }
    }

    /// Cross-block validation: every rule's `reason_codes` must
    /// exist in the operator's `[moderation_reasons]` vocabulary.
    /// Runs at [`crate::config::Config::validate`] time after both
    /// blocks resolve. Errors include the offending rule name +
    /// reason code so operators can fix the typo without grep.
    ///
    /// Skips validation when the engine is disabled — declared
    /// rules don't fire, so their reason codes don't have to be
    /// real (the operator may be staging a future configuration
    /// behind `enabled = false`). The recorder doesn't consult
    /// rules in disabled mode either; staying lenient here lets
    /// staging configs typecheck without round-tripping reason
    /// declarations.
    pub fn validate_reason_codes_against(&self, vocab: &ReasonVocabulary) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        for rule in self.rules.values() {
            for code in &rule.reason_codes {
                if vocab.lookup(code).is_none() {
                    return Err(Error::Signing(format!(
                        "config: [policy_automation.rules.{}] reason_codes references \
                         '{}' which is not declared in [moderation_reasons]",
                        rule.name, code
                    )));
                }
            }
        }
        Ok(())
    }

    /// Rules sorted by firing priority. See module docs for the
    /// full sort key. Consumer-facing API for #72's evaluator —
    /// returns references in priority order so the evaluator just
    /// iterates and picks the first match.
    pub fn rules_in_severity_order(&self) -> Vec<&PolicyRule> {
        let mut out: Vec<&PolicyRule> = self.rules.values().collect();
        out.sort_by(|a, b| {
            // Higher severity first → reverse() of the natural
            // ordering. severity_rank: takedown=4, indef=3, temp=2,
            // warning=1, note=0.
            let rank_a = severity_rank(a.action_type);
            let rank_b = severity_rank(b.action_type);
            rank_b
                .cmp(&rank_a)
                // Same severity → higher threshold first.
                .then_with(|| b.threshold_strikes.cmp(&a.threshold_strikes))
                // Final tiebreak by name for deterministic order.
                .then_with(|| a.name.cmp(&b.name))
        });
        out
    }

    fn validated_from_toml(toml: &crate::config::PolicyAutomationPolicyToml) -> Result<Self> {
        let mut rules: BTreeMap<String, PolicyRule> = BTreeMap::new();
        // Track (threshold, action_type) pairs to detect collisions
        // across rules. Operator confusion if two rules fire
        // identical actions at identical thresholds.
        let mut seen_pairs: BTreeSet<(i64, ActionType)> = BTreeSet::new();

        for (raw_name, rule_toml) in &toml.rules {
            validate_rule_name(raw_name)?;

            if rule_toml.threshold_strikes <= 0 {
                return Err(Error::Signing(format!(
                    "config: [policy_automation.rules.{}] threshold_strikes must be > 0 (got {})",
                    raw_name, rule_toml.threshold_strikes
                )));
            }

            let action_type = ActionType::from_db_str(&rule_toml.action_type).ok_or_else(|| {
                Error::Signing(format!(
                    "config: [policy_automation.rules.{}] action_type '{}' is not a valid \
                     action_type (expected one of warning / note / temp_suspension / \
                     indef_suspension / takedown)",
                    raw_name, rule_toml.action_type
                ))
            })?;

            let mode = PolicyMode::from_str(&rule_toml.mode).ok_or_else(|| {
                Error::Signing(format!(
                    "config: [policy_automation.rules.{}] mode '{}' is not valid \
                     (expected 'auto' or 'flag')",
                    raw_name, rule_toml.mode
                ))
            })?;

            let duration = match (action_type, rule_toml.duration.as_deref()) {
                (ActionType::TempSuspension, Some(s)) => {
                    let secs = crate::writer::parse_iso8601_duration(s).map_err(|e| {
                        Error::Signing(format!(
                            "config: [policy_automation.rules.{}] duration '{}' is invalid: {}",
                            raw_name, s, e
                        ))
                    })?;
                    Some(Duration::from_secs(secs))
                }
                (ActionType::TempSuspension, None) => {
                    return Err(Error::Signing(format!(
                        "config: [policy_automation.rules.{}] action_type 'temp_suspension' \
                         requires a duration",
                        raw_name
                    )));
                }
                (_, Some(_)) => {
                    return Err(Error::Signing(format!(
                        "config: [policy_automation.rules.{}] duration is only valid for \
                         action_type 'temp_suspension' (got action_type '{}')",
                        raw_name, rule_toml.action_type
                    )));
                }
                (_, None) => None,
            };

            let reason_codes = match &rule_toml.reason_codes {
                Some(codes) if codes.is_empty() => {
                    return Err(Error::Signing(format!(
                        "config: [policy_automation.rules.{}] reason_codes must be non-empty \
                         when specified (omit the key entirely to use the default \
                         [\"{}\"])",
                        raw_name, DEFAULT_POLICY_REASON_CODE
                    )));
                }
                Some(codes) => codes.clone(),
                None => vec![DEFAULT_POLICY_REASON_CODE.to_string()],
            };

            // (threshold, action_type) collision check. Two rules
            // proposing identical action at identical threshold
            // would race the severity-order tiebreak by rule name,
            // which is operator-meaningless surface. Reject early.
            if !seen_pairs.insert((rule_toml.threshold_strikes, action_type)) {
                return Err(Error::Signing(format!(
                    "config: [policy_automation.rules.{}] duplicates the \
                     (threshold_strikes={}, action_type='{}') pair already declared by another \
                     rule — each pair must be unique to a single rule for unambiguous \
                     evaluation",
                    raw_name, rule_toml.threshold_strikes, rule_toml.action_type
                )));
            }

            rules.insert(
                raw_name.clone(),
                PolicyRule {
                    name: raw_name.clone(),
                    threshold_strikes: rule_toml.threshold_strikes,
                    action_type,
                    mode,
                    duration,
                    reason_codes,
                },
            );
        }

        Ok(Self {
            enabled: toml.enabled,
            rules,
        })
    }
}

/// Severity rank for sort. Higher = fires first.
fn severity_rank(t: ActionType) -> u8 {
    match t {
        ActionType::Takedown => 4,
        ActionType::IndefSuspension => 3,
        ActionType::TempSuspension => 2,
        ActionType::Warning => 1,
        ActionType::Note => 0,
    }
}

/// Validate a rule name. Lowercase ASCII letter / digit / underscore;
/// must start with a letter; 1-64 chars. Looser than reason-code
/// validation (#47) only in permitting underscores instead of
/// hyphens — TOML key conventions favor underscores for multi-word
/// rule names like `minor_warning_at_5`.
fn validate_rule_name(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 64 {
        return Err(Error::Signing(format!(
            "config: [policy_automation.rules.{s}] rule name must be 1-64 chars (got {} chars)",
            s.len()
        )));
    }
    let mut chars = s.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_lowercase() {
        return Err(Error::Signing(format!(
            "config: [policy_automation.rules.{s}] rule name must start with a lowercase ASCII \
             letter (got '{first}')"
        )));
    }
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' {
            return Err(Error::Signing(format!(
                "config: [policy_automation.rules.{s}] rule name contains invalid char '{c}' \
                 (allowed: a-z, 0-9, underscore)"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_with_policy(value: serde_json::Value) -> Config {
        let mut v = serde_json::json!({
            "service_did": "did:web:labeler.example",
            "service_endpoint": "https://labeler.example",
            "db_path": "/var/lib/cairn/cairn.db",
            "signing_key_path": "/etc/cairn/signing-key.hex",
        });
        if !value.is_null() {
            v["policy_automation"] = value;
        }
        serde_json::from_value(v).expect("config deserializes")
    }

    fn config_with_policy_and_reasons(
        policy: serde_json::Value,
        reasons: serde_json::Value,
    ) -> Config {
        let mut v = serde_json::json!({
            "service_did": "did:web:labeler.example",
            "service_endpoint": "https://labeler.example",
            "db_path": "/var/lib/cairn/cairn.db",
            "signing_key_path": "/etc/cairn/signing-key.hex",
        });
        if !policy.is_null() {
            v["policy_automation"] = policy;
        }
        if !reasons.is_null() {
            v["moderation_reasons"] = reasons;
        }
        serde_json::from_value(v).expect("config deserializes")
    }

    // ---------- defaults() ----------

    #[test]
    fn defaults_engine_on_no_rules() {
        let p = PolicyAutomationPolicy::defaults();
        assert!(p.enabled);
        assert!(p.rules.is_empty());
    }

    #[test]
    fn from_config_no_block_returns_defaults() {
        let cfg = config_with_policy(serde_json::Value::Null);
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p, PolicyAutomationPolicy::defaults());
    }

    #[test]
    fn synthetic_did_constant_is_did_internal_policy() {
        assert_eq!(SYNTHETIC_POLICY_ACTOR_DID, "did:internal:policy");
    }

    #[test]
    fn default_reason_code_is_policy_threshold() {
        assert_eq!(DEFAULT_POLICY_REASON_CODE, "policy_threshold");
    }

    // ---------- enabled flag ----------

    #[test]
    fn enabled_false_explicit_loads_disabled() {
        let cfg = config_with_policy(serde_json::json!({ "enabled": false }));
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        assert!(!p.enabled);
    }

    #[test]
    fn enabled_defaults_to_true_when_only_rules_specified() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                }
            }
        }));
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        assert!(p.enabled);
    }

    // ---------- single rule, defaults applied ----------

    #[test]
    fn single_warning_rule_loads_with_default_reason_code() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                }
            }
        }));
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let rule = p.rules.get("warn_at_5").expect("rule present");
        assert_eq!(rule.name, "warn_at_5");
        assert_eq!(rule.threshold_strikes, 5);
        assert_eq!(rule.action_type, ActionType::Warning);
        assert_eq!(rule.mode, PolicyMode::Auto);
        assert!(rule.duration.is_none());
        assert_eq!(rule.reason_codes, vec!["policy_threshold".to_string()]);
    }

    #[test]
    fn temp_suspension_rule_with_duration_parses() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "temp_at_10": {
                    "threshold_strikes": 10,
                    "action_type": "temp_suspension",
                    "mode": "auto",
                    "duration": "P3D",
                    "reason_codes": ["policy_threshold", "spam"],
                }
            }
        }));
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let rule = p.rules.get("temp_at_10").expect("rule present");
        assert_eq!(rule.duration, Some(Duration::from_secs(3 * 86_400)));
        assert_eq!(
            rule.reason_codes,
            vec!["policy_threshold".to_string(), "spam".to_string()]
        );
    }

    #[test]
    fn flag_mode_loads() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "indef_at_25": {
                    "threshold_strikes": 25,
                    "action_type": "indef_suspension",
                    "mode": "flag",
                }
            }
        }));
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let rule = p.rules.get("indef_at_25").expect("rule present");
        assert_eq!(rule.mode, PolicyMode::Flag);
    }

    // ---------- rule name validation ----------

    #[test]
    fn rule_name_uppercase_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "Warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("must start with a lowercase"));
    }

    #[test]
    fn rule_name_with_hyphen_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn-at-5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("invalid char"));
    }

    #[test]
    fn rule_name_starts_with_digit_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "5warn": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("must start with a lowercase"));
    }

    #[test]
    fn rule_name_too_long_rejected() {
        let long = "a".repeat(65);
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                long.as_str(): {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("1-64 chars"));
    }

    // ---------- field validation ----------

    #[test]
    fn threshold_zero_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_0": {
                    "threshold_strikes": 0,
                    "action_type": "warning",
                    "mode": "auto",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("threshold_strikes must be > 0"));
    }

    #[test]
    fn threshold_negative_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_neg": {
                    "threshold_strikes": -5,
                    "action_type": "warning",
                    "mode": "auto",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("threshold_strikes must be > 0"));
    }

    #[test]
    fn unknown_action_type_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "bogus_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "exile",
                    "mode": "auto",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("not a valid action_type"));
    }

    #[test]
    fn unknown_mode_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "maybe",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("not valid"));
    }

    #[test]
    fn duration_on_non_temp_suspension_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                    "duration": "P7D",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("only valid for action_type 'temp_suspension'"));
    }

    #[test]
    fn missing_duration_on_temp_suspension_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "temp_at_10": {
                    "threshold_strikes": 10,
                    "action_type": "temp_suspension",
                    "mode": "auto",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("requires a duration"));
    }

    #[test]
    fn duration_year_rejected() {
        // The reused parser from #51 rejects Y/M; pin the
        // error surfaces correctly at the policy boundary.
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "temp_at_10": {
                    "threshold_strikes": 10,
                    "action_type": "temp_suspension",
                    "mode": "auto",
                    "duration": "P1Y",
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duration"), "got: {msg}");
    }

    #[test]
    fn empty_explicit_reason_codes_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                    "reason_codes": [],
                }
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("must be non-empty"));
    }

    #[test]
    fn duplicate_threshold_action_type_pair_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_a": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                },
                "warn_b": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "flag",
                },
            }
        }));
        let err = PolicyAutomationPolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("duplicates the"));
    }

    #[test]
    fn same_threshold_different_action_type_allowed() {
        // Two rules at threshold 5, different action types — fine.
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                },
                "temp_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "temp_suspension",
                    "mode": "auto",
                    "duration": "P1D",
                },
            }
        }));
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.rules.len(), 2);
    }

    // ---------- rules_in_severity_order ----------

    #[test]
    fn severity_order_takedown_first() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                },
                "takedown_at_40": {
                    "threshold_strikes": 40,
                    "action_type": "takedown",
                    "mode": "auto",
                },
                "indef_at_25": {
                    "threshold_strikes": 25,
                    "action_type": "indef_suspension",
                    "mode": "flag",
                },
                "temp_at_10": {
                    "threshold_strikes": 10,
                    "action_type": "temp_suspension",
                    "mode": "auto",
                    "duration": "P3D",
                },
            }
        }));
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let ordered: Vec<&str> = p
            .rules_in_severity_order()
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            ordered,
            vec!["takedown_at_40", "indef_at_25", "temp_at_10", "warn_at_5"]
        );
    }

    #[test]
    fn severity_order_ties_resolve_by_higher_threshold() {
        let cfg = config_with_policy(serde_json::json!({
            "rules": {
                "warn_at_5": {
                    "threshold_strikes": 5,
                    "action_type": "warning",
                    "mode": "auto",
                },
                "warn_at_10": {
                    "threshold_strikes": 10,
                    "action_type": "warning",
                    "mode": "auto",
                },
            }
        }));
        let p = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let ordered: Vec<&str> = p
            .rules_in_severity_order()
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(ordered, vec!["warn_at_10", "warn_at_5"]);
    }

    // ---------- reason-code cross-validation ----------

    #[test]
    fn cross_validation_unknown_reason_code_rejected() {
        let cfg = config_with_policy_and_reasons(
            serde_json::json!({
                "rules": {
                    "warn_at_5": {
                        "threshold_strikes": 5,
                        "action_type": "warning",
                        "mode": "auto",
                        "reason_codes": ["spam", "made_up_code"],
                    }
                }
            }),
            // Operator-declared vocabulary that doesn't include "made_up_code".
            serde_json::json!({
                "spam": { "base_weight": 2, "description": "spam" },
            }),
        );
        let policy = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let vocab = ReasonVocabulary::from_config(&cfg).expect("vocab");
        let err = policy.validate_reason_codes_against(&vocab).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("made_up_code"), "got: {msg}");
        assert!(msg.contains("warn_at_5"), "got: {msg}");
    }

    #[test]
    fn cross_validation_known_reason_codes_pass() {
        let cfg = config_with_policy_and_reasons(
            serde_json::json!({
                "rules": {
                    "warn_at_5": {
                        "threshold_strikes": 5,
                        "action_type": "warning",
                        "mode": "auto",
                        "reason_codes": ["spam", "hate-speech"],
                    }
                }
            }),
            serde_json::json!({
                "spam": { "base_weight": 2, "description": "spam" },
                "hate-speech": { "base_weight": 4, "description": "hate" },
            }),
        );
        let policy = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let vocab = ReasonVocabulary::from_config(&cfg).expect("vocab");
        policy
            .validate_reason_codes_against(&vocab)
            .expect("known codes pass");
    }

    #[test]
    fn cross_validation_default_reason_code_must_be_in_vocabulary() {
        // When operator omits reason_codes on a rule, it defaults
        // to ["policy_threshold"]. If the operator's vocabulary
        // doesn't declare that identifier, cross-validation fails.
        let cfg = config_with_policy_and_reasons(
            serde_json::json!({
                "rules": {
                    "warn_at_5": {
                        "threshold_strikes": 5,
                        "action_type": "warning",
                        "mode": "auto",
                    }
                }
            }),
            serde_json::json!({
                "spam": { "base_weight": 2, "description": "spam" },
            }),
        );
        let policy = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let vocab = ReasonVocabulary::from_config(&cfg).expect("vocab");
        let err = policy.validate_reason_codes_against(&vocab).unwrap_err();
        assert!(format!("{err}").contains("policy_threshold"));
    }

    #[test]
    fn cross_validation_skipped_when_engine_disabled() {
        // Operator may stage a future configuration behind
        // `enabled = false`; reason-code cross-check is lenient
        // in that case so the staging config typechecks.
        let cfg = config_with_policy_and_reasons(
            serde_json::json!({
                "enabled": false,
                "rules": {
                    "warn_at_5": {
                        "threshold_strikes": 5,
                        "action_type": "warning",
                        "mode": "auto",
                        "reason_codes": ["future_reason_not_yet_declared"],
                    }
                }
            }),
            serde_json::json!({
                "spam": { "base_weight": 2, "description": "spam" },
            }),
        );
        let policy = PolicyAutomationPolicy::from_config(&cfg).expect("from_config");
        let vocab = ReasonVocabulary::from_config(&cfg).expect("vocab");
        policy
            .validate_reason_codes_against(&vocab)
            .expect("disabled engine skips cross-check");
    }

    // ---------- PolicyMode::as_str ----------

    #[test]
    fn policy_mode_as_str_round_trip() {
        for m in [PolicyMode::Auto, PolicyMode::Flag] {
            assert_eq!(PolicyMode::from_str(m.as_str()), Some(m));
        }
    }
}
