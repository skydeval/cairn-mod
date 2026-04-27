//! Decay calculator for the v1.4 graduated-action moderation
//! model (#50, §F20).
//!
//! Pure function: given a subject's [`ActionRecord`] history, the
//! current [`StrikePolicy`], and a clock value, returns a
//! [`StrikeState`] summarizing the subject's currently-active
//! strike count and surrounding metadata. Same shape as the strike
//! calculator (#49) — no I/O, no DB, no async, mockable via the
//! `now: SystemTime` parameter.
//!
//! Used at read time by the strikes CLI (#52) and the admin/public
//! XRPC handlers (#53/#54), and at write time by the recorder (#51)
//! to compute the `current_strike_count` input to the strike
//! calculator.
//!
//! # Decay shapes (per [`DecayFunction`], #48)
//!
//! - **Linear**: contribution decays linearly from full at
//!   `effective_at` to zero at `effective_at + decay_window_days`.
//!   Formula: `applied * max(0, 1 - elapsed_days / window_days)`.
//! - **Exponential**: half-life decay tuned so ~1% remains at the
//!   window boundary. Half-life is `window_days / 6.643856` (≈
//!   `ln(0.01) / ln(0.5)` half-lives per window). After
//!   `decay_window_days`, contribution rounds to zero in practice;
//!   accumulated remainders are summed in `f64` and rounded once at
//!   the end so many small actions don't lose precision.
//!
//! # Suspension freezes decay (the simplification)
//!
//! When `policy.suspension_freezes_decay` is `true`, suspensions
//! halt the decay clock. The full design supports a user with
//! arbitrary suspension history; v1.4 ships a deliberate
//! simplification:
//!
//! - **Only the most recent unrevoked suspension affects decay.**
//!   Earlier suspensions in history do not retroactively pause
//!   decay. The first time a user collected a suspension years ago
//!   doesn't continue subtracting from today's elapsed clock once a
//!   newer suspension lands.
//! - **If that suspension is currently active** (effective_at ≤ now
//!   AND (no expiry OR expiry > now)) — decay is paused at the
//!   suspension's effective_at. Actions before the suspension cap
//!   their elapsed clock at `(suspension.effective_at - action.effective_at)`;
//!   actions during the suspension contribute their full
//!   `strike_value_applied` (elapsed = 0).
//! - **If that suspension is expired** (only possible for
//!   `TempSuspension`) — decay resumes from the expiry. Actions
//!   before the suspension lose `(suspension.expires_at - suspension.effective_at)`
//!   from their elapsed clock; actions during the suspension start
//!   their decay clock from the expiry; actions after the suspension
//!   decay normally.
//! - **Revoked suspensions never freeze decay.** A retroactively
//!   revoked suspension is treated as if it never happened — decay
//!   resumes from the original `effective_at` of every other action
//!   (per the issue body's "decay resumes from the original
//!   effective_at, NOT from the revocation moment" rule).
//!
//! Multiple-suspension-history accuracy is a v1.5 refinement.
//!
//! # Field invariants on the result
//!
//! For a successful walk:
//!
//! ```text
//! raw_total = sum_over(strike_value_applied) for non-Note/non-Warning rows
//! revoked_count + decayed_count + current_count = raw_total
//! good_standing = current_count <= policy.good_standing_threshold
//! ```
//!
//! `current_count` is the rounded `f64` sum of post-decay
//! contributions, capped at the unrevoked total to keep
//! `decayed_count` non-negative under rounding.

use std::time::{Duration, SystemTime};

use crate::moderation::policy::{DecayFunction, StrikePolicy};
use crate::moderation::types::{ActionRecord, ActionType};

/// Result of a decay walk over a subject's action history.
///
/// All four counts (`current_count`, `raw_total`, `revoked_count`,
/// `decayed_count`) are u32 strikes; see the module docs for the
/// `revoked + decayed + current = raw` invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrikeState {
    /// Currently-active strike count after decay and revocation
    /// effects. This is the value the recorder feeds into the strike
    /// calculator (#49) as `current_strike_count`, and the value the
    /// CLI/XRPC surfaces display to operators / subjects.
    pub current_count: u32,
    /// Sum of `strike_value_applied` across all strike-bearing
    /// (non-Warning, non-Note) actions, ignoring revocation and
    /// decay. Useful for "lifetime strike count" displays.
    pub raw_total: u32,
    /// Sum of `strike_value_applied` for revoked strike-bearing
    /// actions. These don't contribute to `current_count` but are
    /// surfaced separately so reviewers can distinguish "the user
    /// got these strikes once" from "the user is being penalized
    /// for them now."
    pub revoked_count: u32,
    /// Strikes lost to decay across all unrevoked, strike-bearing
    /// actions. Equal to `(raw_total - revoked_count) - current_count`.
    pub decayed_count: u32,
    /// The active suspension at `now`, if any — the most recent
    /// unrevoked suspension that's currently in force. `None` when
    /// no suspension is active (none in history, or the most recent
    /// has expired or been revoked).
    pub active_suspension: Option<ActiveSuspension>,
    /// Whether the subject is in good standing —
    /// `current_count <= policy.good_standing_threshold`. Mirrors
    /// the boundary semantics from the strike calculator (#49):
    /// "at-or-below threshold = good standing."
    pub good_standing: bool,
}

/// Summary of the subject's currently-active suspension, if any.
/// Surfaced on [`StrikeState::active_suspension`] for CLI/XRPC
/// readers that need to render "this user is suspended until X."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSuspension {
    /// Either [`ActionType::TempSuspension`] or
    /// [`ActionType::IndefSuspension`] — the only variants for
    /// which an active suspension can exist.
    pub action_type: ActionType,
    /// Wall-clock at which the suspension took effect.
    pub effective_at: SystemTime,
    /// Wall-clock at which the suspension ends; `None` for
    /// indefinite suspensions.
    pub expires_at: Option<SystemTime>,
}

/// Walk `actions` (id-ascending; oldest-first) and compute the
/// subject's current strike state at `now`.
///
/// Pure function: no I/O, no DB, no async. Same input always
/// produces the same output. See module docs for decay shapes,
/// suspension-freeze semantics, and field invariants.
pub fn calculate_strike_state(
    actions: &[ActionRecord],
    policy: &StrikePolicy,
    now: SystemTime,
) -> StrikeState {
    // Find the most recent unrevoked suspension. Its state at `now`
    // (active vs. expired) determines how decay applies to every
    // strike-bearing action — see module docs.
    let most_recent_suspension = actions
        .iter()
        .rev()
        .find(|a| a.action_type.is_suspension() && a.revoked_at.is_none());

    let active_suspension = most_recent_suspension.and_then(|s| {
        if is_suspension_active_at(s, now) {
            Some(ActiveSuspension {
                action_type: s.action_type,
                effective_at: s.effective_at,
                expires_at: s.expires_at,
            })
        } else {
            None
        }
    });

    let mut raw_total: u32 = 0;
    let mut revoked_count: u32 = 0;
    let mut active_unrevoked_total: u32 = 0;
    let mut current_count_f: f64 = 0.0;

    for action in actions {
        if !action.action_type.contributes_strikes() {
            continue;
        }
        raw_total = raw_total.saturating_add(action.strike_value_applied);

        if action.revoked_at.is_some() {
            revoked_count = revoked_count.saturating_add(action.strike_value_applied);
            continue;
        }

        active_unrevoked_total = active_unrevoked_total.saturating_add(action.strike_value_applied);

        let elapsed = effective_elapsed_for_decay(
            action.effective_at,
            now,
            most_recent_suspension,
            policy.suspension_freezes_decay,
        );
        current_count_f += apply_decay(action.strike_value_applied, elapsed, policy);
    }

    // Round once at the end. Cap at the unrevoked total so a
    // small rounding-up doesn't push current_count above what's
    // possible (which would underflow `decayed_count` below).
    let current_count = (current_count_f.round() as u32).min(active_unrevoked_total);
    let decayed_count = active_unrevoked_total - current_count;
    let good_standing = current_count <= policy.good_standing_threshold;

    StrikeState {
        current_count,
        raw_total,
        revoked_count,
        decayed_count,
        active_suspension,
        good_standing,
    }
}

/// Whether `action` (which the caller has already established to be
/// a suspension) is currently in force at `now`. "Active" means
/// `effective_at <= now` AND (no expiry OR expiry > now).
fn is_suspension_active_at(action: &ActionRecord, now: SystemTime) -> bool {
    action.effective_at <= now && action.expires_at.is_none_or(|exp| exp > now)
}

/// Compute the elapsed-decay [`Duration`] that should be applied
/// to a single action, accounting for any suspension freeze.
///
/// See the module docs ("Suspension freezes decay") for the four
/// branches: no freeze in policy, no suspension in history, active
/// suspension, expired suspension.
fn effective_elapsed_for_decay(
    action_effective: SystemTime,
    now: SystemTime,
    most_recent_suspension: Option<&ActionRecord>,
    suspension_freezes: bool,
) -> Duration {
    let total = duration_or_zero(now, action_effective);

    if !suspension_freezes {
        return total;
    }
    let Some(susp) = most_recent_suspension else {
        return total;
    };

    if is_suspension_active_at(susp, now) {
        // Decay paused right now. Actions during the suspension
        // contribute their full applied (elapsed = 0). Actions
        // before are capped at the suspension start.
        if action_effective >= susp.effective_at {
            return Duration::ZERO;
        }
        return duration_or_zero(susp.effective_at, action_effective);
    }

    // Suspension exists but isn't currently active. The only
    // case that subtracts from elapsed is an EXPIRED temp
    // suspension (expires_at <= now). Future-dated suspensions
    // (effective_at > now) and indef suspensions that are
    // somehow inactive are treated as no-ops here — defensive
    // but won't happen under the recorder's logic.
    let Some(susp_end) = susp.expires_at.filter(|&exp| exp <= now) else {
        return total;
    };
    let susp_dur = duration_or_zero(susp_end, susp.effective_at);

    if action_effective >= susp_end {
        // Action taken after the suspension ended: pure elapsed.
        total
    } else if action_effective >= susp.effective_at {
        // Action taken during the suspension: decay clock started
        // at suspension end.
        duration_or_zero(now, susp_end)
    } else {
        // Action taken before the suspension: subtract the
        // suspension's frozen interval from total.
        total.checked_sub(susp_dur).unwrap_or(Duration::ZERO)
    }
}

fn duration_or_zero(later: SystemTime, earlier: SystemTime) -> Duration {
    later.duration_since(earlier).unwrap_or(Duration::ZERO)
}

/// Apply [`StrikePolicy::decay`] to a single action's
/// `strike_value_applied`, returning the post-decay contribution as
/// `f64`. Caller sums across all unrevoked actions and rounds once.
fn apply_decay(applied: u32, elapsed: Duration, policy: &StrikePolicy) -> f64 {
    let elapsed_days = duration_to_days(elapsed);
    let window_days = policy.decay_window_days as f64;

    // Defensive: validation in #48 guarantees window_days >= 1, but
    // if some bug constructs a zero window we'd hit div-by-zero.
    // Treat as "no decay" rather than NaN-poisoning the sum.
    if window_days <= 0.0 {
        return applied as f64;
    }

    let applied_f = applied as f64;
    match policy.decay {
        DecayFunction::Linear => {
            let frac = (1.0 - elapsed_days / window_days).max(0.0);
            applied_f * frac
        }
        DecayFunction::Exponential => {
            // Half-life such that ~1% remains at window boundary:
            // 0.5^(window/half_life) = 0.01 → half_life =
            // window / log_2(100) ≈ window / 6.6438.
            const LOG2_100: f64 = 6.643_856_189_774_724;
            let half_life_days = window_days / LOG2_100;
            applied_f * 0.5_f64.powf(elapsed_days / half_life_days)
        }
    }
}

fn duration_to_days(d: Duration) -> f64 {
    d.as_secs_f64() / 86_400.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moderation::policy::DecayFunction;

    // ---------- fixture builders ----------

    fn t0() -> SystemTime {
        // Fixed reference time. Far enough in the future that
        // `now - 6 months` is still well past UNIX_EPOCH.
        SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
    }

    fn days(n: u64) -> Duration {
        Duration::from_secs(n * 86_400)
    }

    fn action(value: u32, kind: ActionType, at: SystemTime) -> ActionRecord {
        ActionRecord {
            strike_value_applied: value,
            effective_at: at,
            revoked_at: None,
            action_type: kind,
            expires_at: None,
            // Decay tests don't exercise the in-good-standing
            // predicate; the field is window-calculator-only (#51).
            was_dampened: false,
        }
    }

    fn revoked_action(
        value: u32,
        kind: ActionType,
        at: SystemTime,
        revoked_at: SystemTime,
    ) -> ActionRecord {
        ActionRecord {
            strike_value_applied: value,
            effective_at: at,
            revoked_at: Some(revoked_at),
            action_type: kind,
            expires_at: None,
            was_dampened: false,
        }
    }

    fn temp_susp(value: u32, at: SystemTime, expires_at: SystemTime) -> ActionRecord {
        ActionRecord {
            strike_value_applied: value,
            effective_at: at,
            revoked_at: None,
            action_type: ActionType::TempSuspension,
            expires_at: Some(expires_at),
            was_dampened: false,
        }
    }

    fn indef_susp(value: u32, at: SystemTime) -> ActionRecord {
        ActionRecord {
            strike_value_applied: value,
            effective_at: at,
            revoked_at: None,
            action_type: ActionType::IndefSuspension,
            expires_at: None,
            was_dampened: false,
        }
    }

    fn linear_policy(threshold: u32, window_days: u32) -> StrikePolicy {
        StrikePolicy {
            good_standing_threshold: threshold,
            dampening_curve: (1..threshold).collect(),
            decay: DecayFunction::Linear,
            decay_window_days: window_days,
            suspension_freezes_decay: true,
            cache_freshness_window_seconds: 3600,
        }
    }

    fn exp_policy(threshold: u32, window_days: u32) -> StrikePolicy {
        let mut p = linear_policy(threshold, window_days);
        p.decay = DecayFunction::Exponential;
        p
    }

    // ---------- empty + trivial ----------

    #[test]
    fn empty_history_yields_all_zeros_in_good_standing() {
        let s = calculate_strike_state(&[], &linear_policy(3, 90), t0());
        assert_eq!(s.current_count, 0);
        assert_eq!(s.raw_total, 0);
        assert_eq!(s.revoked_count, 0);
        assert_eq!(s.decayed_count, 0);
        assert!(s.active_suspension.is_none());
        assert!(s.good_standing);
    }

    #[test]
    fn fresh_action_has_no_decay_loss() {
        let now = t0();
        let actions = vec![action(4, ActionType::Takedown, now)];
        let s = calculate_strike_state(&actions, &linear_policy(3, 90), now);
        assert_eq!(s.current_count, 4);
        assert_eq!(s.raw_total, 4);
        assert_eq!(s.decayed_count, 0);
        assert!(!s.good_standing, "4 > threshold 3");
    }

    // ---------- linear decay ----------

    #[test]
    fn linear_decay_at_half_window_loses_half() {
        let now = t0();
        let actions = vec![action(4, ActionType::Takedown, now - days(45))];
        let s = calculate_strike_state(&actions, &linear_policy(3, 90), now);
        assert_eq!(s.current_count, 2, "4 * 0.5 = 2");
        assert_eq!(s.decayed_count, 2);
        assert_eq!(s.raw_total, 4);
    }

    #[test]
    fn linear_decay_at_window_boundary_is_zero() {
        let now = t0();
        let actions = vec![action(4, ActionType::Takedown, now - days(90))];
        let s = calculate_strike_state(&actions, &linear_policy(3, 90), now);
        assert_eq!(s.current_count, 0);
        assert_eq!(s.decayed_count, 4);
    }

    #[test]
    fn linear_decay_past_window_clamps_to_zero() {
        let now = t0();
        let actions = vec![action(4, ActionType::Takedown, now - days(180))];
        let s = calculate_strike_state(&actions, &linear_policy(3, 90), now);
        assert_eq!(s.current_count, 0);
    }

    #[test]
    fn linear_decay_multiple_actions_sum_correctly() {
        let now = t0();
        // 4 strikes 0 days ago (full), 4 strikes 45 days ago (half),
        // 4 strikes 90 days ago (gone) → 4 + 2 + 0 = 6.
        let actions = vec![
            action(4, ActionType::Takedown, now - days(90)),
            action(4, ActionType::Takedown, now - days(45)),
            action(4, ActionType::Takedown, now),
        ];
        let s = calculate_strike_state(&actions, &linear_policy(10, 90), now);
        assert_eq!(s.current_count, 6);
        assert_eq!(s.raw_total, 12);
        assert_eq!(s.decayed_count, 6);
    }

    // ---------- exponential decay ----------

    #[test]
    fn exponential_at_window_boundary_rounds_to_one_percent() {
        // applied = 100, exp window = 90, elapsed = 90 → ~1.0 (1%).
        let now = t0();
        let actions = vec![action(100, ActionType::Takedown, now - days(90))];
        let s = calculate_strike_state(&actions, &exp_policy(50, 90), now);
        assert_eq!(s.current_count, 1, "100 * 0.01 ≈ 1 after rounding");
    }

    #[test]
    fn exponential_at_six_months_rounds_to_zero() {
        // 6 months >> 90-day window; remaining well under 0.5.
        let now = t0();
        let actions = vec![action(4, ActionType::Takedown, now - days(180))];
        let s = calculate_strike_state(&actions, &exp_policy(50, 90), now);
        assert_eq!(s.current_count, 0);
    }

    #[test]
    fn exponential_at_zero_elapsed_is_full() {
        let now = t0();
        let actions = vec![action(8, ActionType::Takedown, now)];
        let s = calculate_strike_state(&actions, &exp_policy(50, 90), now);
        assert_eq!(s.current_count, 8);
    }

    // ---------- revocation ----------

    #[test]
    fn revoked_action_excluded_from_current_but_in_revoked_total() {
        let now = t0();
        let actions = vec![revoked_action(4, ActionType::Takedown, now, now + days(1))];
        let s = calculate_strike_state(&actions, &linear_policy(3, 90), now);
        assert_eq!(s.current_count, 0);
        assert_eq!(s.revoked_count, 4);
        assert_eq!(s.raw_total, 4);
        assert_eq!(s.decayed_count, 0, "revoked actions don't decay");
    }

    #[test]
    fn retroactively_revoked_suspension_does_not_freeze_decay() {
        // User got a takedown 90 days ago, then a temp_suspension 60
        // days ago that was revoked. With freeze on, the takedown
        // should still fully decay (ignoring the revoked suspension).
        let now = t0();
        let actions = vec![
            action(4, ActionType::Takedown, now - days(90)),
            revoked_action(
                2,
                ActionType::TempSuspension,
                now - days(60),
                now - days(30),
            ),
        ];
        let s = calculate_strike_state(&actions, &linear_policy(10, 90), now);
        assert_eq!(s.current_count, 0, "takedown fully decayed at 90 days");
        assert_eq!(s.revoked_count, 2);
    }

    // ---------- suspension freeze: active ----------

    #[test]
    fn active_temp_suspension_freezes_decay_on_prior_actions() {
        // Takedown 90 days ago (would be fully decayed). Active temp
        // suspension started 30 days ago, expires 30 days from now.
        // With freeze on, the takedown's elapsed decay is capped at
        // (suspension_start - takedown_effective) = 60 days.
        // Linear: 4 * (1 - 60/90) = 4 * 0.333 = 1.33 → rounds to 1.
        let now = t0();
        let actions = vec![
            action(4, ActionType::Takedown, now - days(90)),
            temp_susp(2, now - days(30), now + days(30)),
        ];
        let s = calculate_strike_state(&actions, &linear_policy(10, 90), now);
        // Takedown contributes 4*(1-60/90)=1.333, suspension
        // contributes 2 (in-suspension elapsed=0 → full).
        // Total = 1.333 + 2 = 3.333 → rounds to 3.
        assert_eq!(s.current_count, 3);
        assert!(s.active_suspension.is_some());
        assert_eq!(
            s.active_suspension.as_ref().unwrap().action_type,
            ActionType::TempSuspension
        );
    }

    #[test]
    fn active_indef_suspension_freezes_decay_indefinitely() {
        // Takedown 200 days ago, indef suspension starting 100 days
        // ago. Without freeze, takedown would be 0 (past window).
        // With freeze, elapsed capped at (susp_start - takedown_at)
        // = 100 days, which is also past 90-day window → still 0.
        // Use a longer window so freeze is observably load-bearing.
        let now = t0();
        let actions = vec![
            action(4, ActionType::Takedown, now - days(200)),
            indef_susp(2, now - days(100)),
        ];
        let s = calculate_strike_state(&actions, &linear_policy(10, 365), now);
        // Linear, 365-day window. Takedown: elapsed capped at 100,
        // remaining = 4*(1 - 100/365) ≈ 2.9. Suspension: full 2.
        // Total ≈ 4.9 → rounds to 5.
        assert_eq!(s.current_count, 5);
        let active = s.active_suspension.expect("active_suspension set");
        assert_eq!(active.action_type, ActionType::IndefSuspension);
        assert!(active.expires_at.is_none());
    }

    #[test]
    fn action_during_active_suspension_does_not_decay() {
        // Active suspension started 60 days ago, expires 30 days
        // from now. Takedown taken 30 days ago (during suspension).
        // Elapsed for takedown = 0 → contributes full 4.
        let now = t0();
        let actions = vec![
            temp_susp(1, now - days(60), now + days(30)),
            action(4, ActionType::Takedown, now - days(30)),
        ];
        let s = calculate_strike_state(&actions, &linear_policy(10, 90), now);
        // Suspension contributes 1 (fresh, elapsed=0). Takedown
        // contributes 4 (during active suspension, elapsed=0).
        assert_eq!(s.current_count, 5);
    }

    // ---------- suspension freeze: expired ----------

    #[test]
    fn expired_temp_suspension_resumes_decay_from_expiry() {
        // Takedown 120 days ago. Temp suspension ran from 90 days
        // ago to 30 days ago (60-day suspension). Now is `now`.
        // Without freeze: elapsed=120 → fully decayed.
        // With freeze: elapsed = 120 - 60 (frozen) = 60 days.
        // Linear, 90-day window: 4 * (1 - 60/90) = 1.333 → 1.
        // Suspension contribution: elapsed = 90 days (suspension
        // happened 90 days ago, so it's been 90 days from start).
        // But suspension freeze applies to itself too: the rule says
        // actions BEFORE suspension subtract; actions DURING are
        // considered to start at expiry; the suspension itself was
        // taken AT effective_at == susp.effective_at, so it falls
        // into the "during" branch (action_effective >= susp_start
        // AND action_effective < susp_end). Its decay clock starts
        // at susp_end = 30 days ago, so elapsed = 30 days. Linear:
        // 1 * (1 - 30/90) = 0.667 → contributes 0.667.
        // Total = 1.333 + 0.667 = 2.0 → rounds to 2.
        let now = t0();
        let actions = vec![
            action(4, ActionType::Takedown, now - days(120)),
            temp_susp(1, now - days(90), now - days(30)),
        ];
        let s = calculate_strike_state(&actions, &linear_policy(10, 90), now);
        assert_eq!(s.current_count, 2);
        assert!(
            s.active_suspension.is_none(),
            "expired suspension is not currently active"
        );
    }

    // ---------- suspension freeze flag off ----------

    #[test]
    fn suspension_freezes_decay_false_disables_freeze() {
        let now = t0();
        let mut policy = linear_policy(10, 90);
        policy.suspension_freezes_decay = false;
        let actions = vec![
            action(4, ActionType::Takedown, now - days(90)),
            indef_susp(2, now - days(60)),
        ];
        let s = calculate_strike_state(&actions, &policy, now);
        // Without freeze, takedown fully decays; indef contributes
        // 2 * (1 - 60/90) = 0.667 → contributes that.
        // Total ≈ 0.667 → rounds to 1.
        assert_eq!(s.current_count, 1);
        // active_suspension is independent of the freeze flag.
        assert!(s.active_suspension.is_some());
    }

    // ---------- non-strike-bearing action types ----------

    #[test]
    fn warning_and_note_are_excluded_even_with_nonzero_value() {
        // Defense-in-depth: even if some bug puts a non-zero value
        // on a Warning/Note row, the decay calculator must skip it
        // and not let it bleed into raw_total.
        let now = t0();
        let actions = vec![
            action(99, ActionType::Warning, now),
            action(99, ActionType::Note, now),
            action(2, ActionType::Takedown, now),
        ];
        let s = calculate_strike_state(&actions, &linear_policy(3, 90), now);
        assert_eq!(s.current_count, 2);
        assert_eq!(s.raw_total, 2, "Warning/Note must not bleed into raw_total");
    }

    // ---------- good_standing flag ----------

    #[test]
    fn good_standing_true_when_at_or_below_threshold() {
        let now = t0();
        let actions = vec![action(3, ActionType::Takedown, now)];
        let s = calculate_strike_state(&actions, &linear_policy(3, 90), now);
        assert_eq!(s.current_count, 3);
        assert!(s.good_standing, "3 == threshold is in good standing");
    }

    #[test]
    fn good_standing_false_when_above_threshold() {
        let now = t0();
        let actions = vec![action(4, ActionType::Takedown, now)];
        let s = calculate_strike_state(&actions, &linear_policy(3, 90), now);
        assert_eq!(s.current_count, 4);
        assert!(!s.good_standing);
    }

    // ---------- invariants across cases ----------

    #[test]
    fn invariant_revoked_plus_decayed_plus_current_equals_raw_total() {
        let now = t0();
        let actions = vec![
            action(4, ActionType::Takedown, now - days(45)),
            revoked_action(2, ActionType::Takedown, now - days(10), now - days(5)),
            action(3, ActionType::Takedown, now),
        ];
        let s = calculate_strike_state(&actions, &linear_policy(10, 90), now);
        assert_eq!(
            s.revoked_count + s.decayed_count + s.current_count,
            s.raw_total
        );
    }

    // ---------- determinism ----------

    #[test]
    fn deterministic_for_same_inputs() {
        let now = t0();
        let actions = vec![
            action(4, ActionType::Takedown, now - days(30)),
            temp_susp(1, now - days(10), now + days(20)),
        ];
        let p = linear_policy(5, 90);
        let a = calculate_strike_state(&actions, &p, now);
        let b = calculate_strike_state(&actions, &p, now);
        assert_eq!(a, b);
    }
}
