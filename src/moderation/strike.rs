//! Strike calculator for the v1.4 graduated-action moderation
//! model (#49, §F20).
//!
//! Pure function: takes the subject's current strike count, the
//! reason being applied, the policy, and the action's 1-indexed
//! position within the current good-standing window — returns the
//! [`StrikeApplication`] to record on the new `subject_actions`
//! row (#46 schema's `strike_value_base` / `strike_value_applied` /
//! `was_dampened` columns).
//!
//! Frozen at action time. The recorder (#51) will compute
//! `position_in_window` from history and call into here; the
//! returned [`StrikeApplication`] then becomes part of the
//! immutable audit trail. Because dampening can change as
//! operators tune `[strike_policy]`, freezing the resolved value
//! at action time means historical actions don't retroactively
//! shift weight when policy is edited.
//!
//! Closest precedent in the codebase is [`crate::audit::hash`]
//! (#39) — same pure-function shape, no I/O, no async, heavy
//! unit-test coverage.
//!
//! # Decision rules
//!
//! 1. **Severe reason** → full `base_weight`, `was_dampened = false`.
//!    Bypasses the dampening curve regardless of standing.
//! 2. **Out of good standing** (`current_strike_count >=
//!    policy.good_standing_threshold`) → full `base_weight`,
//!    `was_dampened = false`.
//! 3. **In good standing**, position covered by the curve →
//!    `applied = min(curve[position - 1], base_weight)`,
//!    `was_dampened = true`. The cap means dampening can lower
//!    a strike value below the curve entry but never *raise* it
//!    above the reason's declared base weight.
//! 4. **In good standing**, position past the curve's end → full
//!    `base_weight`, `was_dampened = false`. With #48's curve-length
//!    convention (`max(0, threshold - 1)`) and a strictly-ascending
//!    curve, this branch is normally unreachable in good standing
//!    because each in-window offense adds at least 1 to the count
//!    and pushes the user past the threshold. It's still handled
//!    defensively for unusual operator policies.
//!
//! # `was_dampened` semantics
//!
//! `was_dampened = true` means "the curve was consulted" (rule 3).
//! This stays `true` even when the cap clamps `applied` back to
//! `base_weight` — e.g. a curve of `[10, 20]` with a reason of
//! `base_weight = 4` resolves to `applied = 4` on first offense,
//! which numerically equals base but conceptually fired the curve
//! path. The recorder uses this flag for forensics ("did dampening
//! affect this action?"), not as a synonym for `applied < base`.
//!
//! # Position determination is the caller's job
//!
//! `position_in_window` is an input, not a computation here. It's
//! the 1-indexed count of this action within the subject's current
//! good-standing window — the caller (the recorder, #51, with help
//! from the decay calculator, #50) walks history to compute it
//! before invoking [`calculate`]. Keeping that out of this module
//! preserves the no-I/O contract.

use crate::error::{Error, Result};
use crate::moderation::policy::StrikePolicy;
use crate::moderation::reasons::{ReasonDef, ReasonVocabulary};

/// Result of one strike calculation. The three fields are stored
/// verbatim on the new `subject_actions` row (#46) and never
/// recomputed — recomputing later would let policy edits rewrite
/// historical action records, which the design explicitly forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrikeApplication {
    /// The strike value to add to the subject's running count.
    /// Always >= 1 because both `base_weight` and curve entries
    /// are validated as >= 1 at config-load time.
    pub applied: u32,
    /// `true` iff the dampening curve was consulted (i.e., severe
    /// = false AND in good standing AND position covered by the
    /// curve). See module docs — this stays `true` even when the
    /// cap clamps `applied` back to `base_weight`.
    pub was_dampened: bool,
    /// Copy of the reason's `base_weight` for convenience. The
    /// recorder writes this to `strike_value_base` so audit
    /// readers don't have to re-look up the reason vocabulary at
    /// read time (and so the value is preserved if the operator
    /// later removes the reason from the vocabulary).
    pub base_weight: u32,
}

/// Compute the strike to apply for a new action. See module docs
/// for the decision rules and `was_dampened` semantics.
///
/// Pure function: no I/O, no DB, no async. Same input always
/// yields the same output.
pub fn calculate(
    current_strike_count: u32,
    reason: &ReasonDef,
    policy: &StrikePolicy,
    position_in_window: u32,
) -> StrikeApplication {
    let base_weight = reason.base_weight;

    if reason.severe {
        return StrikeApplication {
            applied: base_weight,
            was_dampened: false,
            base_weight,
        };
    }

    if current_strike_count >= policy.good_standing_threshold {
        return StrikeApplication {
            applied: base_weight,
            was_dampened: false,
            base_weight,
        };
    }

    // In good standing: consult the curve. position_in_window is
    // 1-indexed; the curve is 0-indexed.
    let curve_index = position_in_window.saturating_sub(1) as usize;
    if curve_index < policy.dampening_curve.len() {
        let curve_value = policy.dampening_curve[curve_index];
        // Cap: the dampening curve must not raise the applied
        // strike above the reason's declared base. See module docs.
        let applied = curve_value.min(base_weight);
        return StrikeApplication {
            applied,
            was_dampened: true,
            base_weight,
        };
    }

    // Position past the curve's end. With #48's convention this is
    // normally unreachable in good standing (each prior offense
    // would have pushed `current_strike_count` past the threshold),
    // but we handle it defensively for unusual operator curves.
    StrikeApplication {
        applied: base_weight,
        was_dampened: false,
        base_weight,
    }
}

/// Resolve a multi-reason action down to a single dominant reason
/// for strike calculation. Per the v1.4 design: severe always wins
/// over non-severe regardless of base_weight; among same-severity
/// reasons, highest base_weight wins; ties on base_weight resolve
/// to the first-listed reason (stable for deterministic recording).
///
/// Errors:
/// - [`Error::ReasonNotFound`] when any identifier in `reason_codes`
///   is not declared in `vocabulary`.
/// - [`Error::Signing`] generic catch-all when `reason_codes` is
///   empty (the recorder pre-validates non-empty; this is
///   defense-in-depth).
///
/// Returns a *cloned* [`ReasonDef`] so the caller doesn't borrow
/// from `vocabulary` for longer than the resolver call. The
/// vocabulary is small (≤ tens of entries) and ReasonDef is cheap
/// to clone.
pub fn resolve_primary_reason(
    reason_codes: &[String],
    vocabulary: &ReasonVocabulary,
) -> Result<ReasonDef> {
    if reason_codes.is_empty() {
        return Err(Error::Signing(
            "recordAction: reason_codes must be non-empty".to_string(),
        ));
    }

    // Resolve each identifier to a ReasonDef. Missing → ReasonNotFound.
    let mut defs: Vec<&ReasonDef> = Vec::with_capacity(reason_codes.len());
    for code in reason_codes {
        let def = vocabulary
            .lookup(code)
            .ok_or_else(|| Error::ReasonNotFound(code.clone()))?;
        defs.push(def);
    }

    // Severe wins: any severe reason promotes the resolution to
    // "highest-base-weight among severe." Ties on base_weight
    // resolve to the first severe reason in the input list.
    if defs.iter().any(|d| d.severe) {
        let pick = defs
            .iter()
            .filter(|d| d.severe)
            .max_by_key(|d| d.base_weight)
            .expect("at least one severe by the any() check");
        return Ok((*pick).clone());
    }

    // No severe: highest base_weight wins; ties → first-listed
    // (max_by_key on iter().enumerate() with reversed index keeps
    // the earliest index on tie because max_by_key picks the LAST
    // maximum equal element — invert with .rev() so first wins).
    let pick = defs
        .iter()
        .enumerate()
        .rev()
        .max_by_key(|(_, d)| d.base_weight)
        .map(|(_, d)| *d)
        .expect("non-empty checked above");
    Ok(pick.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moderation::policy::DecayFunction;

    // ---------- fixture builders ----------

    fn reason(id: &str, weight: u32, severe: bool) -> ReasonDef {
        ReasonDef {
            identifier: id.to_string(),
            base_weight: weight,
            severe,
            description: "test fixture".to_string(),
        }
    }

    fn policy(threshold: u32, curve: Vec<u32>) -> StrikePolicy {
        StrikePolicy {
            good_standing_threshold: threshold,
            dampening_curve: curve,
            decay: DecayFunction::Linear,
            decay_window_days: 90,
            suspension_freezes_decay: true,
        }
    }

    // ---------- severe reason: bypass dampening always ----------

    #[test]
    fn severe_in_good_standing_returns_full_base() {
        let r = reason("threats", 12, true);
        let p = policy(3, vec![1, 2]);
        let out = calculate(0, &r, &p, 1);
        assert_eq!(out.applied, 12);
        assert!(!out.was_dampened);
        assert_eq!(out.base_weight, 12);
    }

    #[test]
    fn severe_out_of_good_standing_returns_full_base() {
        let r = reason("csam", 999, true);
        let p = policy(3, vec![1, 2]);
        let out = calculate(50, &r, &p, 5);
        assert_eq!(out.applied, 999);
        assert!(!out.was_dampened);
        assert_eq!(out.base_weight, 999);
    }

    #[test]
    fn severe_with_threshold_zero_returns_full_base() {
        // threshold=0 means there's no good standing window, but
        // severe reasons bypass that check anyway.
        let r = reason("threats", 8, true);
        let p = policy(0, vec![]);
        let out = calculate(0, &r, &p, 1);
        assert_eq!(out.applied, 8);
        assert!(!out.was_dampened);
    }

    // ---------- non-severe in good standing: dampens ----------

    #[test]
    fn first_offense_in_good_standing_uses_curve_zero() {
        let r = reason("spam", 4, false);
        let p = policy(3, vec![1, 2]);
        let out = calculate(0, &r, &p, 1);
        assert_eq!(out.applied, 1);
        assert!(out.was_dampened);
        assert_eq!(out.base_weight, 4);
    }

    #[test]
    fn second_offense_in_good_standing_uses_curve_one() {
        // current_count=2 (after a prior offense that landed
        // curve[0]+1 plus another small action; in good standing
        // because 2 < threshold=3). position_in_window=2 → curve[1].
        let r = reason("spam", 4, false);
        let p = policy(3, vec![1, 2]);
        let out = calculate(2, &r, &p, 2);
        assert_eq!(out.applied, 2);
        assert!(out.was_dampened);
        assert_eq!(out.base_weight, 4);
    }

    // ---------- non-severe out of good standing: full base ----------

    #[test]
    fn at_threshold_is_out_of_good_standing() {
        // current_count=3, threshold=3 → out of good standing per
        // #48's worked example ("3rd offense ... past threshold").
        let r = reason("spam", 4, false);
        let p = policy(3, vec![1, 2]);
        let out = calculate(3, &r, &p, 3);
        assert_eq!(out.applied, 4);
        assert!(!out.was_dampened);
    }

    #[test]
    fn well_past_threshold_returns_full_base() {
        let r = reason("spam", 4, false);
        let p = policy(3, vec![1, 2]);
        let out = calculate(10, &r, &p, 1);
        assert_eq!(out.applied, 4);
        assert!(!out.was_dampened);
    }

    // ---------- non-severe in good standing, position past curve ----------

    #[test]
    fn position_beyond_curve_in_good_standing_returns_full_base() {
        // Unusual but permissible setup: threshold=3, curve=[1, 2],
        // current_count=2 (in good standing), position_in_window=3
        // (past curve's end). Defensive branch: applied=base,
        // was_dampened=false. Under normal counting this wouldn't
        // happen — position 3 implies two prior in-window offenses
        // that should have pushed current_count to >= threshold —
        // but the calculator handles it cleanly.
        let r = reason("spam", 4, false);
        let p = policy(3, vec![1, 2]);
        let out = calculate(2, &r, &p, 3);
        assert_eq!(out.applied, 4);
        assert!(!out.was_dampened);
    }

    // ---------- the cap: curve > base ----------

    #[test]
    fn curve_value_above_base_caps_at_base() {
        // Operator curve says "20 strikes for 2nd offense", but the
        // reason itself only weighs 4. Apply min(20, 4) = 4. The
        // curve was consulted, so was_dampened = true even though
        // applied numerically equals base.
        let r = reason("spam", 4, false);
        let p = policy(3, vec![10, 20]);
        let out = calculate(0, &r, &p, 2);
        assert_eq!(out.applied, 4);
        assert!(out.was_dampened);
        assert_eq!(out.base_weight, 4);
    }

    #[test]
    fn curve_value_equal_to_base_caps_at_base() {
        // curve[0] = 4, base = 4. min(4, 4) = 4. was_dampened still
        // true: the curve was consulted. The recorder uses this
        // flag to mean "dampening fired", not "applied < base".
        let r = reason("spam", 4, false);
        let p = policy(3, vec![4, 5]);
        let out = calculate(0, &r, &p, 1);
        assert_eq!(out.applied, 4);
        assert!(out.was_dampened);
    }

    // ---------- threshold = 0: no good-standing window ----------

    #[test]
    fn threshold_zero_non_severe_returns_full_base() {
        // Operator opted out of dampening entirely. current_count=0
        // is already >= threshold=0, so out-of-good-standing fires
        // and applied = base_weight. position_in_window is ignored.
        let r = reason("spam", 4, false);
        let p = policy(0, vec![]);
        let out = calculate(0, &r, &p, 1);
        assert_eq!(out.applied, 4);
        assert!(!out.was_dampened);
    }

    #[test]
    fn threshold_zero_with_high_count_returns_full_base() {
        let r = reason("spam", 4, false);
        let p = policy(0, vec![]);
        let out = calculate(100, &r, &p, 50);
        assert_eq!(out.applied, 4);
        assert!(!out.was_dampened);
    }

    // ---------- threshold = 1: empty curve, in-good-standing ----------

    #[test]
    fn threshold_one_first_offense_position_past_empty_curve() {
        // threshold=1 + curve=[] means good standing covers exactly
        // current_count=0, but the curve has no positions. The 1st
        // offense (current_count=0, position=1) hits the
        // "in good standing but position past curve" branch and
        // gets full base, was_dampened=false. Documented edge case
        // from the brief.
        let r = reason("spam", 4, false);
        let p = policy(1, vec![]);
        let out = calculate(0, &r, &p, 1);
        assert_eq!(out.applied, 4);
        assert!(!out.was_dampened);
    }

    // ---------- determinism / output shape ----------

    #[test]
    fn output_is_deterministic_for_same_inputs() {
        let r = reason("spam", 4, false);
        let p = policy(3, vec![1, 2]);
        let a = calculate(1, &r, &p, 2);
        let b = calculate(1, &r, &p, 2);
        assert_eq!(a, b);
    }

    // ---------- multi-reason resolver ----------

    fn vocab_with(entries: &[(&str, u32, bool)]) -> ReasonVocabulary {
        // Build a vocabulary by serializing through the operator
        // path: Config → ReasonVocabulary::from_config. Roundtripping
        // exercises the same parser path the recorder will use.
        let map: serde_json::Map<String, serde_json::Value> = entries
            .iter()
            .map(|(id, w, severe)| {
                (
                    id.to_string(),
                    serde_json::json!({
                        "base_weight": w,
                        "severe": severe,
                        "description": "test fixture",
                    }),
                )
            })
            .collect();
        let v = serde_json::json!({
            "service_did": "did:web:labeler.example",
            "service_endpoint": "https://labeler.example",
            "db_path": "/var/lib/cairn/cairn.db",
            "signing_key_path": "/etc/cairn/signing-key.hex",
            "moderation_reasons": serde_json::Value::Object(map),
        });
        let cfg: crate::config::Config = serde_json::from_value(v).expect("config deserializes");
        ReasonVocabulary::from_config(&cfg).expect("from_config")
    }

    #[test]
    fn resolve_single_non_severe_reason_returns_it() {
        let v = vocab_with(&[("spam", 4, false)]);
        let pick = resolve_primary_reason(&["spam".into()], &v).unwrap();
        assert_eq!(pick.identifier, "spam");
        assert_eq!(pick.base_weight, 4);
    }

    #[test]
    fn resolve_two_non_severe_picks_highest_base_weight() {
        let v = vocab_with(&[("spam", 2, false), ("hate", 4, false)]);
        let pick = resolve_primary_reason(&["spam".into(), "hate".into()], &v).unwrap();
        assert_eq!(pick.identifier, "hate");
    }

    #[test]
    fn resolve_severe_wins_over_higher_weight_non_severe() {
        // Severe rule: severe always wins regardless of base_weight.
        // hate (non-severe, weight 100) vs threats (severe, weight 8)
        // → threats wins.
        let v = vocab_with(&[("hate", 100, false), ("threats", 8, true)]);
        let pick = resolve_primary_reason(&["hate".into(), "threats".into()], &v).unwrap();
        assert_eq!(pick.identifier, "threats");
        assert!(pick.severe);
    }

    #[test]
    fn resolve_two_severe_picks_highest_base_weight_among_severe() {
        let v = vocab_with(&[("threats", 12, true), ("csam", 999, true)]);
        let pick = resolve_primary_reason(&["threats".into(), "csam".into()], &v).unwrap();
        assert_eq!(pick.identifier, "csam");
    }

    #[test]
    fn resolve_tie_on_base_weight_picks_first_listed() {
        // Two non-severe at the same weight. First-listed wins for
        // deterministic recording.
        let v = vocab_with(&[("aaa", 4, false), ("bbb", 4, false)]);
        let pick = resolve_primary_reason(&["aaa".into(), "bbb".into()], &v).unwrap();
        assert_eq!(pick.identifier, "aaa");

        let pick = resolve_primary_reason(&["bbb".into(), "aaa".into()], &v).unwrap();
        assert_eq!(pick.identifier, "bbb");
    }

    #[test]
    fn resolve_unknown_reason_returns_reason_not_found() {
        let v = vocab_with(&[("spam", 2, false)]);
        let err = resolve_primary_reason(&["nope".into()], &v).expect_err("unknown reason");
        match err {
            Error::ReasonNotFound(id) => assert_eq!(id, "nope"),
            other => panic!("expected ReasonNotFound, got {other:?}"),
        }
    }

    #[test]
    fn resolve_empty_codes_errors() {
        let v = vocab_with(&[("spam", 2, false)]);
        let err = resolve_primary_reason(&[], &v).expect_err("empty codes");
        assert!(matches!(err, Error::Signing(_)));
    }

    // ---------- shared helpers ----------

    #[test]
    fn base_weight_is_copied_through_unchanged() {
        // Across all four code paths, `base_weight` on the output
        // should always equal `reason.base_weight` exactly.
        let cases: &[(u32, bool, u32, u32, Vec<u32>)] = &[
            (0, true, 7, 3, vec![1, 2]),  // severe
            (5, false, 4, 3, vec![1, 2]), // out of good standing
            (0, false, 4, 3, vec![1, 2]), // in good standing, in curve
            (0, false, 4, 1, vec![]),     // in good standing, past curve
            (0, false, 4, 0, vec![]),     // threshold zero
        ];
        for (current, severe, base, threshold, curve) in cases {
            let r = reason("x", *base, *severe);
            let p = policy(*threshold, curve.clone());
            let out = calculate(*current, &r, &p, 1);
            assert_eq!(out.base_weight, *base);
        }
    }
}
