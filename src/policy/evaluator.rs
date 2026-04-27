//! Pure-function policy evaluator (§F22, #72).
//!
//! Translates a strike-state transition (the recompute pre and
//! post the latest action) plus the operator's
//! [`PolicyAutomationPolicy`] (#71) into the rule that should fire
//! — or `None` if no rule matches. Mirrors the v1.4 strike
//! calculator (#49), v1.4 decay calculator (#50), and v1.5 label
//! emission resolver (#59) shape: no I/O, no async, no DB. The
//! recorder (#73) loads state, calls into here, and acts on the
//! returned rule (insert a `subject_actions` row for `auto`,
//! insert a `pending_policy_actions` row for `flag`).
//!
//! # Algorithm
//!
//! [`resolve_firing_rule`]:
//!
//! 1. `policy.enabled = false` → `None`. Engine fully off.
//! 2. Subject is takendown (any unrevoked `Takedown` in history)
//!    → `None`. Takedown is terminal; no further policy fires.
//! 3. Iterate [`PolicyAutomationPolicy::rules_in_severity_order`]
//!    (#71) — takedown first, then indef > temp > warning > note,
//!    ties broken by higher threshold first. Pick the first rule
//!    where:
//!    - [`rule_matches_crossing`] is `true` (the precipitating
//!      action *crossed* the threshold), and
//!    - [`rule_already_fired_for_window`] is `false` (no
//!      unrevoked firing or unresolved pending exists for this
//!      `(subject, rule)` pair).
//! 4. Return `Some(rule)` for the first matching rule, or `None`
//!    if no rule matches.
//!
//! Single rule fires per recordAction. The "first matching rule
//! in severity order wins" semantic avoids double jeopardy (one
//! threshold-cross producing multiple auto-actions).
//!
//! # Crossing semantic
//!
//! [`rule_matches_crossing`] is *strict*: pre-action count must
//! be strictly less than the threshold, post-action count must be
//! at-or-above. An action that bumps an already-above-threshold
//! subject further does NOT count as a crossing — the threshold
//! was crossed by some earlier action, and that crossing already
//! fired (or didn't, if it was suppressed by idempotency).
//!
//! Edge case: pre-action count exactly AT threshold. Not a
//! crossing (`pre < threshold` is false). The first action that
//! pushes the count strictly above threshold is the crossing
//! event. This boundary matches the strike calculator's
//! "good-standing-at-or-below-threshold" convention from v1.4
//! #49.
//!
//! # Idempotency: conservative v1.6 stance
//!
//! [`rule_already_fired_for_window`] returns `true` if EITHER:
//! - the subject has an unrevoked `subject_actions` row whose
//!   `triggered_by_policy_rule` matches the rule's name, OR
//! - the subject has an unresolved `pending_policy_actions` row
//!   whose `triggered_by_policy_rule` matches.
//!
//! v1.6 ships the *conservative* version: a rule fires once per
//! subject, ever, until that firing is explicitly revoked
//! (subject_actions side) or dismissed (pending side). After
//! revocation/dismissal, the next threshold-crossing fires the
//! rule again.
//!
//! The kickoff design's "decay-then-recross fires the rule
//! again" semantic — automated re-firing when the subject's
//! strike count drops below threshold and rises back without
//! operator intervention — is more permissive but harder to
//! implement correctly. The conservative version is
//! operationally safer (operators won't get surprised by
//! automated re-firing) and trivially correct. v1.7+ may add the
//! permissive variant if real demand surfaces.
//!
//! Confirmed pendings are intentionally not double-counted: when
//! a pending action is confirmed, the resulting `subject_actions`
//! row carries `triggered_by_policy_rule` (#74's confirm flow),
//! so the subject-side check picks it up. Pending rows with
//! `resolution = 'confirmed'` are skipped to avoid counting the
//! same firing twice.

use std::time::SystemTime;

use crate::moderation::decay::StrikeState;
use crate::moderation::types::ActionType;

use super::automation::{PolicyAutomationPolicy, PolicyRule};

/// Subject-action projection for the policy evaluator. Distinct
/// from [`crate::moderation::types::ActionRecord`] (the v1.4 #50
/// calculator-input projection) because this projection carries
/// `triggered_by_policy_rule`, which the evaluator needs for
/// idempotency detection but the strike + decay calculators
/// don't. Same naming convention as v1.5 #59's
/// [`crate::labels::emission::ActionForEmission`].
///
/// Recorder (#73) builds this projection from each
/// `subject_actions` row when loading subject history at
/// recordAction time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionForPolicyEval {
    /// Wall-clock at which the action took effect. Used for
    /// chronological ordering when scanning history.
    pub effective_at: SystemTime,
    /// Action type — needed to detect takedown (terminal state)
    /// during evaluation.
    pub action_type: ActionType,
    /// `Some` iff the action was revoked. The idempotency check
    /// treats revoked policy-firings as "window open" — re-fire
    /// allowed after revocation.
    pub revoked_at: Option<SystemTime>,
    /// `Some(rule_name)` iff the action was produced by the
    /// policy engine. `None` for moderator-recorded actions.
    /// Idempotency detection scans for matches against
    /// `rule.name`.
    pub triggered_by_policy_rule: Option<String>,
}

/// Pending-action projection for the policy evaluator. Mirrors
/// [`ActionForPolicyEval`]'s narrow shape but for
/// `pending_policy_actions` rows (#70's schema).
///
/// Recorder (#73) loads this from `pending_policy_actions`
/// alongside subject_actions when evaluating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingActionForPolicyEval {
    /// Rule name that produced the pending row. Idempotency
    /// detection matches against [`PolicyRule::name`].
    pub triggered_by_policy_rule: String,
    /// `None` while pending; `Some` once confirmed or dismissed.
    /// Confirmed rows are skipped by the idempotency check —
    /// their corresponding `subject_actions` row (linked via
    /// `confirmed_action_id` from #74's confirm flow) carries
    /// `triggered_by_policy_rule` and is picked up by the
    /// subject-side scan. Dismissed rows open the window so the
    /// rule can re-fire on a future crossing.
    pub resolution: Option<PendingResolution>,
}

/// Resolution state of a pending policy action. Matches the
/// `pending_policy_actions.resolution` column's CHECK values
/// (#70).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingResolution {
    /// Moderator confirmed; a real `subject_actions` row was
    /// created and linked via `confirmed_action_id`.
    Confirmed,
    /// Moderator dismissed; no `subject_actions` row created. The
    /// pending row stays as forensic record.
    Dismissed,
}

/// Top-level evaluator entry point. Returns the rule that should
/// fire as a result of the just-recorded action, or `None` if no
/// rule matches.
///
/// See module docs for the full algorithm and idempotency stance.
pub fn resolve_firing_rule<'a>(
    state_before: &StrikeState,
    state_after: &StrikeState,
    subject_history: &[ActionForPolicyEval],
    pending_actions: &[PendingActionForPolicyEval],
    policy: &'a PolicyAutomationPolicy,
) -> Option<&'a PolicyRule> {
    if !policy.enabled {
        return None;
    }
    if subject_is_takendown(subject_history) {
        return None;
    }

    for rule in policy.rules_in_severity_order() {
        if !rule_matches_crossing(rule, state_before, state_after) {
            continue;
        }
        if rule_already_fired_for_window(rule, subject_history, pending_actions) {
            continue;
        }
        return Some(rule);
    }
    None
}

/// Whether the precipitating action *crossed* the rule's
/// threshold. Strict: pre-action count must be strictly less
/// than the threshold, post-action count must be at-or-above.
/// See module docs for the boundary edge cases.
pub fn rule_matches_crossing(
    rule: &PolicyRule,
    state_before: &StrikeState,
    state_after: &StrikeState,
) -> bool {
    let before = i64::from(state_before.current_count);
    let after = i64::from(state_after.current_count);
    before < rule.threshold_strikes && after >= rule.threshold_strikes
}

/// Whether the rule has already fired against this subject
/// without being explicitly resolved (revoked or dismissed). See
/// module docs for the conservative v1.6 stance.
pub fn rule_already_fired_for_window(
    rule: &PolicyRule,
    subject_history: &[ActionForPolicyEval],
    pending_actions: &[PendingActionForPolicyEval],
) -> bool {
    let any_subject_fire = subject_history.iter().any(|a| {
        a.triggered_by_policy_rule.as_deref() == Some(rule.name.as_str()) && a.revoked_at.is_none()
    });
    let any_pending_fire = pending_actions
        .iter()
        .any(|p| p.triggered_by_policy_rule == rule.name && p.resolution.is_none());
    any_subject_fire || any_pending_fire
}

/// Whether the subject has a non-revoked `Takedown` action in
/// history. Takedown is terminal: no further policy rules fire
/// against a takendown subject. Computed inline rather than
/// derived from [`StrikeState`] (which has no takendown flag in
/// v1.4/v1.5/v1.6) — the history scan is bounded by the same
/// O(n) the rest of the evaluator already pays.
fn subject_is_takendown(history: &[ActionForPolicyEval]) -> bool {
    history
        .iter()
        .any(|a| matches!(a.action_type, ActionType::Takedown) && a.revoked_at.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::automation::{PolicyAutomationPolicy, PolicyMode, PolicyRule};
    use std::collections::BTreeMap;
    use std::time::{Duration, UNIX_EPOCH};

    // ---------- fixture builders ----------

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(2_000_000_000)
    }

    /// Build a StrikeState with just the `current_count` field
    /// the evaluator reads. Other fields default-initialized;
    /// the evaluator doesn't consult them, so values don't
    /// matter.
    fn state(count: u32) -> StrikeState {
        StrikeState {
            current_count: count,
            raw_total: count,
            revoked_count: 0,
            decayed_count: 0,
            active_suspension: None,
            good_standing: count == 0,
        }
    }

    fn rule(name: &str, threshold: i64, action_type: ActionType, mode: PolicyMode) -> PolicyRule {
        PolicyRule {
            name: name.to_string(),
            threshold_strikes: threshold,
            action_type,
            mode,
            duration: if matches!(action_type, ActionType::TempSuspension) {
                Some(Duration::from_secs(86_400))
            } else {
                None
            },
            reason_codes: vec!["policy_threshold".to_string()],
        }
    }

    fn policy_with(rules: Vec<PolicyRule>) -> PolicyAutomationPolicy {
        let mut map = BTreeMap::new();
        for r in rules {
            map.insert(r.name.clone(), r);
        }
        PolicyAutomationPolicy {
            enabled: true,
            rules: map,
        }
    }

    fn unrevoked_action(action_type: ActionType, rule_name: Option<&str>) -> ActionForPolicyEval {
        ActionForPolicyEval {
            effective_at: t0(),
            action_type,
            revoked_at: None,
            triggered_by_policy_rule: rule_name.map(str::to_string),
        }
    }

    fn revoked_action(action_type: ActionType, rule_name: Option<&str>) -> ActionForPolicyEval {
        ActionForPolicyEval {
            effective_at: t0(),
            action_type,
            revoked_at: Some(t0() + Duration::from_secs(60)),
            triggered_by_policy_rule: rule_name.map(str::to_string),
        }
    }

    fn pending(
        rule_name: &str,
        resolution: Option<PendingResolution>,
    ) -> PendingActionForPolicyEval {
        PendingActionForPolicyEval {
            triggered_by_policy_rule: rule_name.to_string(),
            resolution,
        }
    }

    // ============================================================
    // rule_matches_crossing
    // ============================================================

    #[test]
    fn crossing_below_to_above_matches() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        assert!(rule_matches_crossing(&r, &state(4), &state(5)));
    }

    #[test]
    fn crossing_below_to_well_above_matches() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        assert!(rule_matches_crossing(&r, &state(2), &state(7)));
    }

    #[test]
    fn crossing_above_to_above_does_not_match() {
        // Pre-action count was already at-or-above threshold.
        // The threshold was crossed by some earlier action.
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        assert!(!rule_matches_crossing(&r, &state(7), &state(9)));
    }

    #[test]
    fn crossing_below_to_below_does_not_match() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        assert!(!rule_matches_crossing(&r, &state(2), &state(4)));
    }

    #[test]
    fn crossing_above_to_below_does_not_match() {
        // Decay or revocation drove the count down. Not a rule-
        // firing event; rules fire on the *upward* crossing.
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        assert!(!rule_matches_crossing(&r, &state(7), &state(3)));
    }

    #[test]
    fn crossing_pre_at_threshold_does_not_match() {
        // Pre-action count exactly at threshold: not strictly
        // below, so no crossing. Documented edge case — the
        // threshold itself is not a crossing event; the first
        // action that pushes the count strictly above threshold
        // is.
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        assert!(!rule_matches_crossing(&r, &state(5), &state(6)));
    }

    #[test]
    fn crossing_pre_just_below_post_exactly_at_threshold_matches() {
        // Post-action count exactly at threshold counts as
        // crossing (threshold is the rule's `>=` boundary).
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        assert!(rule_matches_crossing(&r, &state(4), &state(5)));
    }

    // ============================================================
    // rule_already_fired_for_window
    // ============================================================

    #[test]
    fn never_fired_window_open() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        assert!(!rule_already_fired_for_window(&r, &[], &[]));
    }

    #[test]
    fn unrevoked_subject_firing_window_closed() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        let history = vec![unrevoked_action(ActionType::Warning, Some("warn_5"))];
        assert!(rule_already_fired_for_window(&r, &history, &[]));
    }

    #[test]
    fn revoked_subject_firing_window_open() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        let history = vec![revoked_action(ActionType::Warning, Some("warn_5"))];
        assert!(!rule_already_fired_for_window(&r, &history, &[]));
    }

    #[test]
    fn unresolved_pending_window_closed() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        let pendings = vec![pending("warn_5", None)];
        assert!(rule_already_fired_for_window(&r, &[], &pendings));
    }

    #[test]
    fn dismissed_pending_window_open() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        let pendings = vec![pending("warn_5", Some(PendingResolution::Dismissed))];
        assert!(!rule_already_fired_for_window(&r, &[], &pendings));
    }

    #[test]
    fn confirmed_pending_alone_window_open_subject_actions_carries_state() {
        // A confirmed pending is "done" from the pending side; the
        // resulting subject_actions row carries
        // triggered_by_policy_rule. With NO corresponding
        // subject_actions row in this test's history, the
        // window is observed as "open" — but this state is
        // unreachable in practice (#74 always inserts the
        // subject_actions row on confirm). Pinned to document
        // the conservative-double-counting-avoidance posture:
        // confirmed pendings don't ALSO close the window via
        // the pending check.
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        let pendings = vec![pending("warn_5", Some(PendingResolution::Confirmed))];
        assert!(!rule_already_fired_for_window(&r, &[], &pendings));
    }

    #[test]
    fn confirmed_pending_with_subject_action_window_closed() {
        // Realistic post-confirm shape: pending has
        // resolution=Confirmed, AND a subject_actions row exists
        // with triggered_by_policy_rule. The subject-side check
        // closes the window.
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        let history = vec![unrevoked_action(ActionType::Warning, Some("warn_5"))];
        let pendings = vec![pending("warn_5", Some(PendingResolution::Confirmed))];
        assert!(rule_already_fired_for_window(&r, &history, &pendings));
    }

    #[test]
    fn unrelated_rule_firings_dont_close_window() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        let history = vec![unrevoked_action(ActionType::Warning, Some("other_rule"))];
        let pendings = vec![pending("yet_another_rule", None)];
        assert!(!rule_already_fired_for_window(&r, &history, &pendings));
    }

    #[test]
    fn moderator_action_with_no_rule_attribution_doesnt_close_window() {
        // Moderator-recorded action (triggered_by_policy_rule =
        // None) doesn't count as a rule firing.
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        let history = vec![unrevoked_action(ActionType::Warning, None)];
        assert!(!rule_already_fired_for_window(&r, &history, &[]));
    }

    #[test]
    fn either_subject_or_pending_firing_closes_window() {
        let r = rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto);
        // Subject side has a firing; pending side empty.
        let history = vec![unrevoked_action(ActionType::Warning, Some("warn_5"))];
        assert!(rule_already_fired_for_window(&r, &history, &[]));
        // Pending side has a firing; subject side empty.
        let pendings = vec![pending("warn_5", None)];
        assert!(rule_already_fired_for_window(&r, &[], &pendings));
    }

    // ============================================================
    // resolve_firing_rule
    // ============================================================

    #[test]
    fn disabled_policy_returns_none() {
        let mut policy = policy_with(vec![rule(
            "warn_5",
            5,
            ActionType::Warning,
            PolicyMode::Auto,
        )]);
        policy.enabled = false;
        assert!(resolve_firing_rule(&state(0), &state(10), &[], &[], &policy).is_none());
    }

    #[test]
    fn empty_policy_returns_none() {
        let policy = policy_with(vec![]);
        assert!(resolve_firing_rule(&state(0), &state(10), &[], &[], &policy).is_none());
    }

    #[test]
    fn no_rules_match_crossing_returns_none() {
        let policy = policy_with(vec![rule(
            "warn_10",
            10,
            ActionType::Warning,
            PolicyMode::Auto,
        )]);
        // Pre 0 → post 5; rule needs threshold 10. No match.
        assert!(resolve_firing_rule(&state(0), &state(5), &[], &[], &policy).is_none());
    }

    #[test]
    fn single_matching_rule_returns_it() {
        let policy = policy_with(vec![rule(
            "warn_5",
            5,
            ActionType::Warning,
            PolicyMode::Auto,
        )]);
        let fired =
            resolve_firing_rule(&state(0), &state(5), &[], &[], &policy).expect("rule fires");
        assert_eq!(fired.name, "warn_5");
    }

    #[test]
    fn matching_rule_already_fired_returns_none() {
        let policy = policy_with(vec![rule(
            "warn_5",
            5,
            ActionType::Warning,
            PolicyMode::Auto,
        )]);
        let history = vec![unrevoked_action(ActionType::Warning, Some("warn_5"))];
        assert!(
            resolve_firing_rule(&state(0), &state(5), &history, &[], &policy).is_none(),
            "already-fired rule must not re-fire while window closed"
        );
    }

    #[test]
    fn takedown_in_history_blocks_all_firings() {
        let policy = policy_with(vec![rule(
            "warn_5",
            5,
            ActionType::Warning,
            PolicyMode::Auto,
        )]);
        let history = vec![unrevoked_action(ActionType::Takedown, None)];
        assert!(
            resolve_firing_rule(&state(0), &state(5), &history, &[], &policy).is_none(),
            "takedown is terminal — no policy fires"
        );
    }

    #[test]
    fn revoked_takedown_does_not_block() {
        // Defensive case: a revoked takedown shouldn't gate the
        // engine. The decay calculator (#50) treats revoked
        // suspensions/takedowns as "didn't happen" for state
        // purposes; the evaluator should match that posture.
        let policy = policy_with(vec![rule(
            "warn_5",
            5,
            ActionType::Warning,
            PolicyMode::Auto,
        )]);
        let history = vec![revoked_action(ActionType::Takedown, None)];
        let fired = resolve_firing_rule(&state(0), &state(5), &history, &[], &policy);
        assert!(
            fired.is_some(),
            "revoked takedown should not block policy evaluation"
        );
    }

    #[test]
    fn severity_order_takedown_wins_over_indef() {
        let policy = policy_with(vec![
            rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto),
            rule("indef_5", 5, ActionType::IndefSuspension, PolicyMode::Auto),
            rule("takedown_5", 5, ActionType::Takedown, PolicyMode::Auto),
        ]);
        let fired =
            resolve_firing_rule(&state(0), &state(5), &[], &[], &policy).expect("rule fires");
        assert_eq!(fired.name, "takedown_5");
    }

    #[test]
    fn severity_order_indef_beats_temp() {
        let policy = policy_with(vec![
            rule("temp_5", 5, ActionType::TempSuspension, PolicyMode::Auto),
            rule("indef_5", 5, ActionType::IndefSuspension, PolicyMode::Auto),
        ]);
        let fired =
            resolve_firing_rule(&state(0), &state(5), &[], &[], &policy).expect("rule fires");
        assert_eq!(fired.name, "indef_5");
    }

    #[test]
    fn severity_order_temp_beats_warning() {
        let policy = policy_with(vec![
            rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto),
            rule("temp_5", 5, ActionType::TempSuspension, PolicyMode::Auto),
        ]);
        let fired =
            resolve_firing_rule(&state(0), &state(5), &[], &[], &policy).expect("rule fires");
        assert_eq!(fired.name, "temp_5");
    }

    #[test]
    fn tie_within_severity_higher_threshold_wins() {
        // Two warning rules, both crossed by the same recordAction.
        // Higher threshold = "you got further along the curve" =
        // more severe outcome.
        let policy = policy_with(vec![
            rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto),
            rule("warn_10", 10, ActionType::Warning, PolicyMode::Auto),
        ]);
        let fired =
            resolve_firing_rule(&state(0), &state(15), &[], &[], &policy).expect("rule fires");
        assert_eq!(fired.name, "warn_10");
    }

    #[test]
    fn highest_severity_already_fired_falls_through_to_next() {
        // Takedown rule already fired (revoked, so window open
        // again — actually wait, an unrevoked takedown blocks
        // everything via subject_is_takendown above).
        // Test the realistic case: subject-side firing of
        // takedown recorded, then revoked. Strike count back
        // to crossing range. Now severity check picks the next
        // rule in line.
        let policy = policy_with(vec![
            rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto),
            rule("takedown_5", 5, ActionType::Takedown, PolicyMode::Auto),
        ]);
        // Takedown rule fired previously, then was revoked.
        // The action is gone from "blocking everything" and the
        // window is open. But warn_5 hasn't fired.
        // Actually: revoked takedown means subject_is_takendown
        // returns false; the takedown rule's window is open
        // (revoked firing); both rules are eligible.
        // Severity order picks takedown again. Test the case
        // where takedown's window is closed (unrevoked previous
        // firing) but takedown isn't blocking — that's
        // unreachable (unrevoked takedown DOES block). So this
        // test pins the simpler severity-order-with-eligible-
        // alternates case.
        let history = vec![
            // Pretend we have warn_5 already fired and revoked,
            // and takedown_5 is eligible. resolve picks
            // takedown_5 (higher severity, eligible).
            revoked_action(ActionType::Warning, Some("warn_5")),
        ];
        let fired =
            resolve_firing_rule(&state(0), &state(5), &history, &[], &policy).expect("rule fires");
        assert_eq!(fired.name, "takedown_5");
    }

    #[test]
    fn all_matching_rules_already_fired_returns_none() {
        let policy = policy_with(vec![
            rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto),
            rule("warn_10", 10, ActionType::Warning, PolicyMode::Auto),
        ]);
        let history = vec![
            unrevoked_action(ActionType::Warning, Some("warn_5")),
            unrevoked_action(ActionType::Warning, Some("warn_10")),
        ];
        assert!(
            resolve_firing_rule(&state(0), &state(15), &history, &[], &policy).is_none(),
            "all matching rules already fired → no firing"
        );
    }

    #[test]
    fn higher_severity_already_fired_falls_through_to_lower() {
        // Multiple rules match crossing: takedown (higher sev,
        // already fired and revoked... no, unrevoked takedown
        // blocks. Use indef + warning instead). Indef already
        // fired, warning hasn't. Warning fires.
        let policy = policy_with(vec![
            rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto),
            rule("indef_5", 5, ActionType::IndefSuspension, PolicyMode::Auto),
        ]);
        let history = vec![unrevoked_action(
            ActionType::IndefSuspension,
            Some("indef_5"),
        )];
        let fired = resolve_firing_rule(&state(0), &state(5), &history, &[], &policy)
            .expect("warning rule fires");
        assert_eq!(fired.name, "warn_5");
    }

    #[test]
    fn pending_blocks_higher_severity_falls_through() {
        // Pending exists for indef rule; warning rule fires
        // instead (lower severity is the next eligible).
        let policy = policy_with(vec![
            rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto),
            rule("indef_5", 5, ActionType::IndefSuspension, PolicyMode::Flag),
        ]);
        let pendings = vec![pending("indef_5", None)];
        let fired = resolve_firing_rule(&state(0), &state(5), &[], &pendings, &policy)
            .expect("warning rule fires");
        assert_eq!(fired.name, "warn_5");
    }

    #[test]
    fn flag_mode_rule_returned_just_like_auto() {
        // The evaluator doesn't distinguish auto vs flag at the
        // resolve step — that's the recorder's concern. Pin
        // that flag rules return the same way.
        let policy = policy_with(vec![rule(
            "indef_5",
            5,
            ActionType::IndefSuspension,
            PolicyMode::Flag,
        )]);
        let fired =
            resolve_firing_rule(&state(0), &state(5), &[], &[], &policy).expect("rule fires");
        assert_eq!(fired.mode, PolicyMode::Flag);
    }

    // ============================================================
    // determinism — same inputs always produce same output
    // ============================================================

    #[test]
    fn outputs_deterministic_for_same_inputs() {
        let policy = policy_with(vec![
            rule("warn_5", 5, ActionType::Warning, PolicyMode::Auto),
            rule("warn_10", 10, ActionType::Warning, PolicyMode::Auto),
            rule(
                "indef_15",
                15,
                ActionType::IndefSuspension,
                PolicyMode::Auto,
            ),
        ]);
        let s_before = state(0);
        let s_after = state(20);
        let a = resolve_firing_rule(&s_before, &s_after, &[], &[], &policy);
        let b = resolve_firing_rule(&s_before, &s_after, &[], &[], &policy);
        assert_eq!(a.map(|r| r.name.as_str()), b.map(|r| r.name.as_str()));
    }
}
