//! Position-in-window calculator for the v1.4 graduated-action
//! moderation model (#51, §F20).
//!
//! Pure function: given a subject's [`ActionRecord`] history, the
//! current [`StrikePolicy`], and a clock value, returns the
//! 1-indexed position the *next* in-good-standing strike-bearing
//! action will occupy in the dampening curve.
//!
//! Used by the recorder (#51) at action time to compute the
//! `position_in_window` input to the strike calculator (#49).
//! Same shape as the rest of the v1.4 calculators — no I/O, no DB,
//! no async.
//!
//! # What "position" means
//!
//! The strike calculator interprets `position_in_window` as the
//! 1-indexed offense count within the user's current good-standing
//! window. With the default policy (threshold 3, curve `[1, 2]`),
//! offense 1 lands at `curve[0] = 1`, offense 2 at `curve[1] = 2`,
//! offense 3 falls past the curve and gets full base weight. The
//! recorder calls this calculator BEFORE inserting the new row, so
//! the returned value is what the new action's position WILL BE if
//! it gets recorded.
//!
//! # In-good-standing predicate
//!
//! "In good standing at action time" is read directly from each
//! prior action's [`ActionRecord::was_dampened`] flag. The strike
//! calculator (#49) sets `was_dampened = true` exactly when the
//! action was applied while the subject was in good standing AND
//! the position was covered by the dampening curve. Treating that
//! flag as the predicate lets this calculator stay independent of
//! strike/decay calculator internals — when policy changes,
//! historical actions keep their original `was_dampened` value
//! frozen on the row, and position counting reflects the standing
//! the subject was actually in at each prior action.
//!
//! # Decay window cutoff
//!
//! Only actions whose `effective_at` falls within
//! `policy.decay_window_days` of `now` count toward the position.
//! Older actions exited the dampening window and are no longer
//! "current" for new-offense counting. This is a simpler cut than
//! the decay calculator's full freeze logic — the position
//! calculator doesn't account for suspension freezes, by design:
//! "how many in-window good-standing offenses has this user had
//! recently" is the question regardless of whether decay was
//! frozen during a suspension.
//!
//! # Severe + revoked filtering
//!
//! - Severe actions are EXCLUDED from position counting. Severe
//!   reasons bypass dampening at action time (their strike value
//!   is full base, not curve-derived); counting them would
//!   over-penalize a non-severe action that follows.
//! - Revoked actions are EXCLUDED. Revocation removes the action
//!   from strike accounting; it must also remove it from position
//!   counting, otherwise revocation would leave a phantom slot.
//! - Non-strike-bearing actions (Warning/Note) are EXCLUDED via
//!   [`crate::moderation::types::ActionType::contributes_strikes`].
//!
//! Severe-but-was-dampened-true is impossible by construction (the
//! strike calculator never sets `was_dampened = true` for severe
//! reasons), but the calculator doesn't need to encode that
//! invariant — `was_dampened` is the only signal it consults.

use std::time::{Duration, SystemTime};

use crate::moderation::policy::StrikePolicy;
use crate::moderation::types::ActionRecord;

/// Compute the 1-indexed position the next in-good-standing action
/// will occupy in the current dampening window.
///
/// Counts prior actions that were:
///
/// 1. strike-bearing ([`ActionRecord::action_type`].`contributes_strikes()`),
/// 2. not revoked (`revoked_at` is `None`),
/// 3. recorded while the subject was in good standing
///    (`was_dampened == true`),
/// 4. within `policy.decay_window_days` of `now`.
///
/// Returns `count + 1` so the value is the position of the NEXT
/// action — what the recorder feeds into the strike calculator.
///
/// Pure function: no I/O, no DB, no async. Same input always
/// produces the same output.
pub fn compute_position_in_window(
    history: &[ActionRecord],
    policy: &StrikePolicy,
    now: SystemTime,
) -> u32 {
    let window = Duration::from_secs(policy.decay_window_days as u64 * 86_400);
    let earliest_in_window = now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH);

    let count = history
        .iter()
        .filter(|a| a.action_type.contributes_strikes())
        .filter(|a| a.revoked_at.is_none())
        .filter(|a| a.was_dampened)
        .filter(|a| a.effective_at >= earliest_in_window && a.effective_at <= now)
        .count();

    // Saturating cast: count is bounded by history length (already u32-safe
    // in practice) but +1 could theoretically overflow. Saturate at u32::MAX.
    let count_u32: u32 = u32::try_from(count).unwrap_or(u32::MAX);
    count_u32.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moderation::policy::DecayFunction;
    use crate::moderation::types::ActionType;

    // ---------- fixture helpers ----------

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
    }

    fn days(n: u64) -> Duration {
        Duration::from_secs(n * 86_400)
    }

    fn action(at: SystemTime, kind: ActionType, was_dampened: bool) -> ActionRecord {
        ActionRecord {
            strike_value_applied: 1,
            effective_at: at,
            revoked_at: None,
            action_type: kind,
            expires_at: None,
            was_dampened,
        }
    }

    fn revoked(at: SystemTime, kind: ActionType, was_dampened: bool) -> ActionRecord {
        ActionRecord {
            strike_value_applied: 1,
            effective_at: at,
            revoked_at: Some(at + Duration::from_secs(60)),
            action_type: kind,
            expires_at: None,
            was_dampened,
        }
    }

    fn policy(threshold: u32, window_days: u32) -> StrikePolicy {
        StrikePolicy {
            good_standing_threshold: threshold,
            dampening_curve: (1..threshold).collect(),
            decay: DecayFunction::Linear,
            decay_window_days: window_days,
            suspension_freezes_decay: true,
            cache_freshness_window_seconds: 3600,
        }
    }

    // ---------- empty / fresh ----------

    #[test]
    fn empty_history_returns_position_one() {
        let p = policy(3, 90);
        assert_eq!(compute_position_in_window(&[], &p, t0()), 1);
    }

    #[test]
    fn single_in_window_dampened_action_returns_position_two() {
        let now = t0();
        let p = policy(3, 90);
        let h = vec![action(now - days(10), ActionType::Takedown, true)];
        assert_eq!(compute_position_in_window(&h, &p, now), 2);
    }

    #[test]
    fn two_in_window_dampened_actions_return_position_three() {
        let now = t0();
        let p = policy(3, 90);
        let h = vec![
            action(now - days(40), ActionType::Takedown, true),
            action(now - days(10), ActionType::Takedown, true),
        ];
        assert_eq!(compute_position_in_window(&h, &p, now), 3);
    }

    // ---------- decay window cutoff ----------

    #[test]
    fn action_just_outside_window_excluded() {
        let now = t0();
        let p = policy(3, 90);
        // 91 days ago is past the 90-day window.
        let h = vec![action(now - days(91), ActionType::Takedown, true)];
        assert_eq!(compute_position_in_window(&h, &p, now), 1);
    }

    #[test]
    fn action_at_exact_window_boundary_included() {
        let now = t0();
        let p = policy(3, 90);
        // Exactly 90 days ago is on the boundary; included via >=.
        let h = vec![action(now - days(90), ActionType::Takedown, true)];
        assert_eq!(compute_position_in_window(&h, &p, now), 2);
    }

    #[test]
    fn mix_of_in_and_out_of_window_actions_only_in_window_counted() {
        let now = t0();
        let p = policy(5, 90);
        let h = vec![
            action(now - days(200), ActionType::Takedown, true),
            action(now - days(100), ActionType::Takedown, true),
            action(now - days(60), ActionType::Takedown, true),
            action(now - days(10), ActionType::Takedown, true),
        ];
        // Only the last two (60 + 10 days ago) are in the window.
        assert_eq!(compute_position_in_window(&h, &p, now), 3);
    }

    // ---------- in-good-standing filter ----------

    #[test]
    fn out_of_good_standing_action_excluded() {
        let now = t0();
        let p = policy(3, 90);
        // was_dampened = false means the action was applied while
        // out of good standing. Doesn't count toward the next
        // action's position.
        let h = vec![action(now - days(10), ActionType::Takedown, false)];
        assert_eq!(compute_position_in_window(&h, &p, now), 1);
    }

    #[test]
    fn mixed_dampened_and_undampened_only_dampened_count() {
        let now = t0();
        let p = policy(5, 90);
        let h = vec![
            action(now - days(60), ActionType::Takedown, true),
            action(now - days(40), ActionType::Takedown, false),
            action(now - days(20), ActionType::Takedown, true),
        ];
        // Two dampened actions count; the undampened one doesn't.
        assert_eq!(compute_position_in_window(&h, &p, now), 3);
    }

    // ---------- revocation filter ----------

    #[test]
    fn revoked_action_excluded() {
        let now = t0();
        let p = policy(3, 90);
        let h = vec![revoked(now - days(10), ActionType::Takedown, true)];
        assert_eq!(compute_position_in_window(&h, &p, now), 1);
    }

    #[test]
    fn revoked_action_does_not_consume_a_position_slot() {
        let now = t0();
        let p = policy(5, 90);
        // First action revoked, second still active. The active
        // action's position is 2, not 3 — revocation removed the
        // first slot.
        let h = vec![
            revoked(now - days(40), ActionType::Takedown, true),
            action(now - days(10), ActionType::Takedown, true),
        ];
        assert_eq!(compute_position_in_window(&h, &p, now), 2);
    }

    // ---------- non-strike-bearing filter ----------

    #[test]
    fn warning_and_note_excluded_even_with_was_dampened_true() {
        let now = t0();
        let p = policy(3, 90);
        // Defense-in-depth: a Warning row with was_dampened = true
        // still doesn't count (warnings don't carry strikes; their
        // dampened flag is meaningless).
        let h = vec![
            action(now - days(20), ActionType::Warning, true),
            action(now - days(10), ActionType::Note, true),
        ];
        assert_eq!(compute_position_in_window(&h, &p, now), 1);
    }

    // ---------- strike-bearing types ----------

    #[test]
    fn temp_suspension_counts_when_dampened_in_window() {
        let now = t0();
        let p = policy(3, 90);
        let h = vec![action(now - days(10), ActionType::TempSuspension, true)];
        assert_eq!(compute_position_in_window(&h, &p, now), 2);
    }

    #[test]
    fn indef_suspension_counts_when_dampened_in_window() {
        let now = t0();
        let p = policy(3, 90);
        let h = vec![action(now - days(10), ActionType::IndefSuspension, true)];
        assert_eq!(compute_position_in_window(&h, &p, now), 2);
    }

    // ---------- determinism ----------

    #[test]
    fn deterministic_for_same_inputs() {
        let now = t0();
        let p = policy(5, 90);
        let h = vec![
            action(now - days(60), ActionType::Takedown, true),
            action(now - days(20), ActionType::Takedown, true),
        ];
        let a = compute_position_in_window(&h, &p, now);
        let b = compute_position_in_window(&h, &p, now);
        assert_eq!(a, b);
    }

    // ---------- combined filters ----------

    #[test]
    fn combined_filters_pruning_correctly() {
        let now = t0();
        let p = policy(5, 90);
        let h = vec![
            action(now - days(200), ActionType::Takedown, true), // out of window
            revoked(now - days(60), ActionType::Takedown, true), // revoked
            action(now - days(40), ActionType::Takedown, false), // not dampened
            action(now - days(30), ActionType::Warning, true),   // warning
            action(now - days(20), ActionType::Takedown, true),  // counts
            action(now - days(10), ActionType::TempSuspension, true), // counts
        ];
        // Only the last two should count → position 3.
        assert_eq!(compute_position_in_window(&h, &p, now), 3);
    }
}
