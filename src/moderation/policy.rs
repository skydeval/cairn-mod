//! Strike policy for the v1.4 graduated-action moderation model
//! (#48, §F20).
//!
//! Drives the dampening curve, decay function, and
//! suspension-freezes-decay behavior. Loaded once at config-load
//! time from `[strike_policy]`; read-only thereafter — operators
//! restart `cairn serve` to change the policy, matching `[labeler]`
//! and `[moderation_reasons]` posture.
//!
//! # Convention: curve length = threshold − 1
//!
//! v1.4 settles on the following dampening interpretation (resolved
//! during #48 — the kickoff issue body and session brief described
//! two slightly different shapes, and the session brief's
//! "Convention B" wins):
//!
//! - `good_standing_threshold` is the strike count at or below which
//!   a subject is considered in good standing. With threshold = 3,
//!   subjects at 0/1/2/3 strikes are still in good standing.
//! - `dampening_curve[N]` is the weight applied to the subject's
//!   `(N+1)`-th in-window offense **while still in good standing**.
//! - The `(threshold)`-th in-window offense (one past the curve's
//!   end) gets the reason's full `base_weight` — no entry in the
//!   curve, no dampening.
//!
//! So for the default (`threshold = 3`, `curve = [1, 2]`):
//!
//! | offense # | applied  | running strikes |
//! |-----------|----------|-----------------|
//! | 1st       | `curve[0]` = 1 | 1           |
//! | 2nd       | `curve[1]` = 2 | 3 (at threshold; still good standing) |
//! | 3rd       | full base    | 3 + base (past threshold; out of good standing) |
//!
//! That makes the curve length always `max(0, threshold − 1)`. With
//! `threshold = 0` (operator opt-out of dampening), the curve must
//! be empty — every offense gets full base weight from the start.
//! With `threshold = 1`, the curve must also be empty — the very
//! first offense pushes the user past the threshold.
//!
//! # decay_window_days lives on the policy, not the variant
//!
//! Both `DecayFunction::Linear` and `DecayFunction::Exponential`
//! consume the same `decay_window_days` field. The exact
//! interpretation per variant is the decay calculator's concern
//! (#50) — for v1.4, linear is "decay from full at action time to
//! zero over the window" and exponential is "half-life such that
//! contribution reaches zero at the window boundary in practice."
//! If a future design needs different windows per variant,
//! restructure then.
//!
//! # Severe reasons bypass the policy entirely
//!
//! When a reason in `[moderation_reasons]` is marked `severe`, the
//! strike calculator (#49) applies its `base_weight` directly with
//! no consultation of the dampening curve, regardless of the
//! subject's standing. The policy's other fields (decay,
//! suspension-freezes-decay) still apply to severe-reason actions
//! — only dampening is skipped.

use serde::Deserialize;

use crate::error::{Error, Result};

/// Resolved strike policy. Use [`StrikePolicy::from_config`] at
/// config-load time and pass the resolved policy into the strike
/// calculator (#49) and decay calculator (#50).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrikePolicy {
    /// Strike count at or below which a subject is in good
    /// standing. New offenses while in good standing get dampened
    /// per [`Self::dampening_curve`]. `0` means no good standing
    /// — every offense gets full weight from the first.
    pub good_standing_threshold: u32,
    /// Per-position dampening weights for in-good-standing
    /// offenses. Length is always `max(0, good_standing_threshold − 1)`
    /// — see the module docs for the rationale.
    pub dampening_curve: Vec<u32>,
    /// How each action's contribution decays over time. The exact
    /// math per variant is the decay calculator's concern (#50);
    /// see the module docs.
    pub decay: DecayFunction,
    /// Window over which `decay` operates, in days. Same value used
    /// by both [`DecayFunction::Linear`] and
    /// [`DecayFunction::Exponential`]; the variant decides how to
    /// interpret it.
    pub decay_window_days: u32,
    /// When `true`, decay halts while the subject has an active
    /// `indef_suspension` action. Revocation is then the only path
    /// back to good standing. Default `true`.
    pub suspension_freezes_decay: bool,
    /// How long the [`subject_strike_state`](
    /// crate::moderation::cache) cache row remains "fresh" before a
    /// reader should recompute via the decay calculator. Used by
    /// the lazy recompute-on-read helper (#55); has no effect on
    /// the v1.4 read endpoints, which always recompute from
    /// source-of-truth regardless. Default 3600 (1 hour).
    pub cache_freshness_window_seconds: u32,
}

/// Decay shape applied to an action's strike contribution as time
/// passes. Per-variant interpretation lives in the decay calculator
/// (#50); the policy just declares which shape is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecayFunction {
    /// Linear ramp from full contribution at the action's effective
    /// time to zero at `effective_time + decay_window_days`. Simple
    /// and predictable; the v1.4 default.
    Linear,
    /// Exponential decay over the same window. The decay calculator
    /// (#50) defines the exact half-life relationship to
    /// `decay_window_days`.
    Exponential,
}

impl StrikePolicy {
    /// Build the policy from `cfg.strike_policy`. When the field is
    /// `None` (operator declared no `[strike_policy]` block),
    /// returns [`Self::defaults`]. When the field is present (even
    /// with only some sub-fields specified), all unspecified
    /// sub-fields take their `serde(default)` values, then the
    /// resolved values are validated together.
    ///
    /// Validation can fire even when only some fields were declared —
    /// e.g., an operator who sets `good_standing_threshold = 5` but
    /// forgets `dampening_curve` will get the default `[1, 2]` curve
    /// and a clear "expected length 4, got 2" error.
    pub fn from_config(cfg: &crate::config::Config) -> Result<Self> {
        let Some(toml) = cfg.strike_policy.as_ref() else {
            return Ok(Self::defaults());
        };
        Self::validated_from_toml(toml)
    }

    /// The shipped default policy: threshold 3, curve [1, 2], linear
    /// decay over 90 days, suspensions freeze decay,
    /// cache_freshness_window 1 hour. Matches the v1.4 design
    /// conversation: "good standing for me would be ≤3 strikes;
    /// 1st offense = 1 strike, 2nd = 2 strikes, 3rd = full base."
    pub fn defaults() -> Self {
        Self {
            good_standing_threshold: 3,
            dampening_curve: vec![1, 2],
            decay: DecayFunction::Linear,
            decay_window_days: 90,
            suspension_freezes_decay: true,
            cache_freshness_window_seconds: 3600,
        }
    }

    fn validated_from_toml(toml: &crate::config::StrikePolicyToml) -> Result<Self> {
        // Curve length convention: max(0, threshold - 1). See the
        // module docs for the worked example.
        let expected_curve_len = toml.good_standing_threshold.saturating_sub(1) as usize;
        if toml.dampening_curve.len() != expected_curve_len {
            return Err(Error::Signing(format!(
                "config: [strike_policy] dampening_curve has length {} but good_standing_threshold = {} requires length {} (curve length = max(0, threshold - 1) — see crate::moderation::policy module docs)",
                toml.dampening_curve.len(),
                toml.good_standing_threshold,
                expected_curve_len,
            )));
        }

        // Each curve entry is positive and the sequence is strictly
        // ascending. Strict (rather than non-strict) because a
        // non-ascending entry contradicts dampening's escalation
        // principle — operators who want flat punishment can declare
        // a constant `base_weight` on the reason side instead.
        let mut prev: Option<u32> = None;
        for (i, &v) in toml.dampening_curve.iter().enumerate() {
            if v < 1 {
                return Err(Error::Signing(format!(
                    "config: [strike_policy] dampening_curve[{i}] = {v} must be >= 1"
                )));
            }
            if let Some(p) = prev
                && v <= p
            {
                return Err(Error::Signing(format!(
                    "config: [strike_policy] dampening_curve[{i}] = {v} must be strictly greater than the previous entry ({p}) — the curve must be strictly ascending"
                )));
            }
            prev = Some(v);
        }

        if toml.decay_window_days < 1 {
            return Err(Error::Signing(format!(
                "config: [strike_policy] decay_window_days = {} must be >= 1",
                toml.decay_window_days
            )));
        }

        if toml.cache_freshness_window_seconds < 1 {
            return Err(Error::Signing(format!(
                "config: [strike_policy] cache_freshness_window_seconds = {} must be >= 1",
                toml.cache_freshness_window_seconds
            )));
        }

        Ok(Self {
            good_standing_threshold: toml.good_standing_threshold,
            dampening_curve: toml.dampening_curve.clone(),
            decay: toml.decay_function,
            decay_window_days: toml.decay_window_days,
            suspension_freezes_decay: toml.suspension_freezes_decay,
            cache_freshness_window_seconds: toml.cache_freshness_window_seconds,
        })
    }
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
            v["strike_policy"] = value;
        }
        serde_json::from_value(v).expect("config deserializes")
    }

    // ---------- defaults ----------

    #[test]
    fn defaults_match_design_conversation() {
        let p = StrikePolicy::defaults();
        assert_eq!(p.good_standing_threshold, 3);
        assert_eq!(p.dampening_curve, vec![1, 2]);
        assert_eq!(p.decay, DecayFunction::Linear);
        assert_eq!(p.decay_window_days, 90);
        assert!(p.suspension_freezes_decay);
        assert_eq!(p.cache_freshness_window_seconds, 3600);
    }

    #[test]
    fn defaults_curve_length_matches_threshold_minus_one() {
        let p = StrikePolicy::defaults();
        let expected = p.good_standing_threshold.saturating_sub(1) as usize;
        assert_eq!(p.dampening_curve.len(), expected);
    }

    // ---------- absent block → defaults ----------

    #[test]
    fn absent_strike_policy_block_loads_defaults() {
        let cfg = config_with_policy(serde_json::Value::Null);
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p, StrikePolicy::defaults());
    }

    // ---------- empty block → defaults via serde fallbacks ----------

    #[test]
    fn empty_strike_policy_block_loads_defaults_via_serde_fallbacks() {
        // Bare `[strike_policy]` header with no sub-fields. Each
        // serde-default fires; the resolved policy is identical to
        // Self::defaults().
        let cfg = config_with_policy(serde_json::json!({}));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p, StrikePolicy::defaults());
    }

    // ---------- explicit declarations ----------

    #[test]
    fn fully_declared_policy_reflects_operator_values() {
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 5,
            "dampening_curve": [1, 2, 3, 4],
            "decay_function": "exponential",
            "decay_window_days": 30,
            "suspension_freezes_decay": false,
        }));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.good_standing_threshold, 5);
        assert_eq!(p.dampening_curve, vec![1, 2, 3, 4]);
        assert_eq!(p.decay, DecayFunction::Exponential);
        assert_eq!(p.decay_window_days, 30);
        assert!(!p.suspension_freezes_decay);
    }

    #[test]
    fn threshold_zero_with_empty_curve_is_valid() {
        // Operator opt-out of dampening: every offense gets full
        // weight immediately. Curve length = max(0, 0 - 1) = 0.
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 0,
            "dampening_curve": [],
        }));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.good_standing_threshold, 0);
        assert!(p.dampening_curve.is_empty());
    }

    #[test]
    fn threshold_one_with_empty_curve_is_valid() {
        // Threshold 1 means even the first offense pushes past good
        // standing, so the curve covers zero in-good-standing
        // offenses. Length = max(0, 1 - 1) = 0.
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 1,
            "dampening_curve": [],
        }));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.good_standing_threshold, 1);
        assert!(p.dampening_curve.is_empty());
    }

    #[test]
    fn partial_declaration_uses_serde_defaults_for_other_fields() {
        // Operator declares only the threshold; serde defaults fill
        // in the curve, decay, and suspension flag. With matching
        // default values, validation passes.
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 3,
        }));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p, StrikePolicy::defaults());
    }

    // ---------- validation: curve length vs threshold ----------

    #[test]
    fn curve_too_long_for_threshold_rejected() {
        // threshold = 3 requires curve length 2; got length 3.
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 3,
            "dampening_curve": [1, 2, 3],
        }));
        let err = StrikePolicy::from_config(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("length 3"));
        assert!(msg.contains("requires length 2"));
    }

    #[test]
    fn curve_too_short_for_threshold_rejected() {
        // threshold = 5 requires curve length 4; got length 2.
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 5,
            "dampening_curve": [1, 2],
        }));
        let err = StrikePolicy::from_config(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("length 2"));
        assert!(msg.contains("requires length 4"));
    }

    #[test]
    fn partial_threshold_with_default_curve_surfaces_clear_mismatch() {
        // Operator sets threshold = 5 but forgets the curve. serde
        // defaults the curve to [1, 2] (length 2), but threshold = 5
        // requires length 4. The validator surfaces this as a clear
        // mismatch error.
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 5,
        }));
        let err = StrikePolicy::from_config(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("requires length 4"));
    }

    // ---------- validation: curve values ----------

    #[test]
    fn non_ascending_curve_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 4,
            "dampening_curve": [1, 2, 1],
        }));
        let err = StrikePolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("strictly ascending"));
    }

    #[test]
    fn flat_curve_rejected_strict_ascending() {
        // [1, 1] is non-strict ascending — rejected because flat
        // dampening contradicts the escalation principle.
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 3,
            "dampening_curve": [1, 1],
        }));
        let err = StrikePolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("strictly ascending"));
    }

    #[test]
    fn zero_curve_entry_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "good_standing_threshold": 3,
            "dampening_curve": [0, 2],
        }));
        let err = StrikePolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains(">= 1"));
    }

    // ---------- validation: decay ----------

    #[test]
    fn unknown_decay_function_rejected_at_deserialize() {
        // serde rejects unknown enum variants at deserialize time;
        // the error surfaces as a config-load failure before
        // validate() runs. Tests that this path errors.
        let cfg_result = serde_json::from_value::<Config>(serde_json::json!({
            "service_did": "did:web:labeler.example",
            "service_endpoint": "https://labeler.example",
            "db_path": "/var/lib/cairn/cairn.db",
            "signing_key_path": "/etc/cairn/signing-key.hex",
            "strike_policy": {
                "decay_function": "logarithmic"
            }
        }));
        assert!(
            cfg_result.is_err(),
            "unknown decay_function variant must fail to deserialize"
        );
    }

    #[test]
    fn zero_decay_window_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "decay_window_days": 0,
        }));
        let err = StrikePolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains(">= 1"));
    }

    #[test]
    fn large_decay_window_accepted() {
        // 365 days is a reasonable operator choice for low-volume
        // labelers; no upper bound enforced.
        let cfg = config_with_policy(serde_json::json!({
            "decay_window_days": 365,
        }));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.decay_window_days, 365);
    }

    // ---------- decay_function string forms ----------

    #[test]
    fn linear_string_deserializes() {
        let cfg = config_with_policy(serde_json::json!({
            "decay_function": "linear",
        }));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.decay, DecayFunction::Linear);
    }

    #[test]
    fn exponential_string_deserializes() {
        let cfg = config_with_policy(serde_json::json!({
            "decay_function": "exponential",
        }));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.decay, DecayFunction::Exponential);
    }

    // ---------- cache freshness window (#55) ----------

    #[test]
    fn cache_freshness_window_operator_override_accepted() {
        let cfg = config_with_policy(serde_json::json!({
            "cache_freshness_window_seconds": 300,
        }));
        let p = StrikePolicy::from_config(&cfg).expect("from_config");
        assert_eq!(p.cache_freshness_window_seconds, 300);
    }

    #[test]
    fn zero_cache_freshness_window_rejected() {
        let cfg = config_with_policy(serde_json::json!({
            "cache_freshness_window_seconds": 0,
        }));
        let err = StrikePolicy::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("cache_freshness_window_seconds"));
    }
}
