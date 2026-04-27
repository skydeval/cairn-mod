//! Shared types for the v1.4 graduated-action moderation surface
//! (§F20).
//!
//! [`ActionType`] is the runtime form of the `subject_actions.action_type`
//! TEXT CHECK enum (#46). Variants match the SQL CHECK values
//! one-for-one — `warning`, `note`, `temp_suspension`,
//! `indef_suspension`, `takedown` — and revocation is metadata on the
//! row, NOT a distinct type, so the enum has exactly five variants.
//!
//! [`ActionRecord`] is the read-side projection that the decay
//! calculator (#50) and the strike calculator (#49) consume. It's a
//! deliberate subset of the full `subject_actions` row: the columns
//! needed for strike-state computation, none of the display-only
//! ones (notes, reason_codes, audit_log_id, etc.). Code paths that
//! need richer fields should use a richer struct and project down to
//! `ActionRecord` when handing to the calculators.
//!
//! Both types are also used by:
//! - the recorder (#51) when constructing rows to insert,
//! - the history CLI (#52) and admin/public XRPC (#53/#54) when
//!   surfacing action records to operators or subjects.

use std::time::SystemTime;

/// Operator-facing graduated-action enum (§F20). Variants match the
/// `subject_actions.action_type` SQL CHECK values exactly. New
/// variants here would require a coordinated migration + admin/CLI
/// surface change, so the set is closed for v1.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ActionType {
    /// Operator-issued warning. Does not carry strikes; surfaced to
    /// the subject for awareness. Stored so warnings appear in
    /// history alongside heavier actions.
    Warning,
    /// Internal moderator note. Not visible to the subject; never
    /// carries strikes. Useful for "saw this, didn't act" annotations
    /// that still want to show up in `cairn moderator history` (#52).
    Note,
    /// Time-bounded suspension. `expires_at` is required (set from
    /// `effective_at + duration`); decay halts during the suspension
    /// when `policy.suspension_freezes_decay` is true.
    TempSuspension,
    /// Open-ended suspension. `expires_at` is `None`. Revocation is
    /// the only path back to good standing while this is active.
    IndefSuspension,
    /// Account takedown. Carries strikes; not a suspension (does not
    /// trigger the decay-freeze branch in the decay calculator).
    Takedown,
}

impl ActionType {
    /// Whether this action's `strike_value_applied` should be summed
    /// into the subject's strike total. Returns `true` for
    /// suspensions and takedowns; `false` for warnings and notes.
    ///
    /// This is also a defense-in-depth filter: the decay calculator
    /// uses it before adding a row's contribution, so a stray
    /// non-zero `strike_value_applied` on a Warning/Note row (which
    /// shouldn't happen given the recorder's logic) won't leak into
    /// the count.
    pub fn contributes_strikes(self) -> bool {
        match self {
            ActionType::Note | ActionType::Warning => false,
            ActionType::TempSuspension | ActionType::IndefSuspension | ActionType::Takedown => true,
        }
    }

    /// Whether this action is a suspension (temp or indef). Used by
    /// the decay calculator to find the most recent unrevoked
    /// suspension when applying the freeze rule (§F20 / #48
    /// `suspension_freezes_decay`).
    pub fn is_suspension(self) -> bool {
        matches!(
            self,
            ActionType::TempSuspension | ActionType::IndefSuspension
        )
    }

    /// String form matching the `subject_actions.action_type` SQL
    /// CHECK constraint (#46). Stable wire identifier — used by the
    /// recorder to insert rows, by the lexicon `knownValues` set,
    /// and by CLI flag parsing.
    pub fn as_db_str(self) -> &'static str {
        match self {
            ActionType::Warning => "warning",
            ActionType::Note => "note",
            ActionType::TempSuspension => "temp_suspension",
            ActionType::IndefSuspension => "indef_suspension",
            ActionType::Takedown => "takedown",
        }
    }

    /// Parse the SQL/wire string form. Returns `None` for any value
    /// not in the §F20 enum — the caller surfaces this as
    /// `InvalidActionType` at the request boundary.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "warning" => Some(ActionType::Warning),
            "note" => Some(ActionType::Note),
            "temp_suspension" => Some(ActionType::TempSuspension),
            "indef_suspension" => Some(ActionType::IndefSuspension),
            "takedown" => Some(ActionType::Takedown),
            _ => None,
        }
    }
}

/// Read-side projection of a `subject_actions` row, holding only
/// the columns the strike + decay + window calculators consume.
///
/// Field set is deliberately narrow:
///
/// - `strike_value_applied` — what the strike calculator (#49)
///   resolved at action time, frozen on the row.
/// - `effective_at` — wall-clock at which the action started
///   counting; decay's elapsed-time clock starts here.
/// - `revoked_at` — `Some` iff the action was revoked. Revoked
///   actions don't contribute to `current_count` but still appear
///   in `raw_total` + `revoked_count` for display.
/// - `action_type` — drives the `contributes_strikes` /
///   `is_suspension` branches.
/// - `expires_at` — `Some` for `TempSuspension` (used to detect
///   whether a suspension is currently active vs. expired); `None`
///   for `IndefSuspension` (no end) and for non-suspensions
///   (irrelevant).
/// - `was_dampened` — frozen on the row by the strike calculator
///   (#49) at action time. Read by the window calculator (#51) as
///   the "in-good-standing at action time" predicate; a stable
///   signal that doesn't drift if `[strike_policy]` is later edited.
///
/// Ordering convention: callers pass slices in id-ascending order
/// (matching `SELECT ... ORDER BY id` from `subject_actions`). The
/// calculators iterate in the order given and don't re-sort.
#[derive(Debug, Clone)]
pub struct ActionRecord {
    /// Strike weight applied at action time after dampening, frozen
    /// on the row by the recorder (#51). For Warning/Note rows this
    /// is conventionally `0` and additionally filtered out via
    /// [`ActionType::contributes_strikes`] as defense-in-depth.
    pub strike_value_applied: u32,
    /// Wall-clock at which the action took effect. Decay's elapsed
    /// clock measures from here.
    pub effective_at: SystemTime,
    /// Revocation timestamp, or `None` if the action is still in
    /// force. Revoked actions are excluded from decay accounting
    /// (see [`crate::moderation::decay`] module docs for the
    /// retroactive-revoke semantics).
    pub revoked_at: Option<SystemTime>,
    /// The action's graduated-action category. Drives strike-bearing
    /// and suspension-detection logic.
    pub action_type: ActionType,
    /// Expiration wall-clock for `TempSuspension`; `None` for
    /// `IndefSuspension` (open-ended) and for non-suspensions.
    pub expires_at: Option<SystemTime>,
    /// `true` iff the strike calculator's dampening curve was
    /// consulted at action time — i.e., the subject was in good
    /// standing AND the position was covered by the curve (#49).
    /// Used by the window calculator (#51) as the "in-good-standing
    /// at action time" predicate. Frozen on the row, so historical
    /// position counting reflects the standing the subject was
    /// actually in when each prior action fired.
    pub was_dampened: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contributes_strikes_matches_design() {
        assert!(!ActionType::Warning.contributes_strikes());
        assert!(!ActionType::Note.contributes_strikes());
        assert!(ActionType::TempSuspension.contributes_strikes());
        assert!(ActionType::IndefSuspension.contributes_strikes());
        assert!(ActionType::Takedown.contributes_strikes());
    }

    #[test]
    fn is_suspension_only_for_temp_and_indef() {
        assert!(!ActionType::Warning.is_suspension());
        assert!(!ActionType::Note.is_suspension());
        assert!(ActionType::TempSuspension.is_suspension());
        assert!(ActionType::IndefSuspension.is_suspension());
        assert!(
            !ActionType::Takedown.is_suspension(),
            "Takedown carries strikes but is not a suspension — it does not trigger decay freeze"
        );
    }

    #[test]
    fn db_str_round_trip_for_every_variant() {
        for v in [
            ActionType::Warning,
            ActionType::Note,
            ActionType::TempSuspension,
            ActionType::IndefSuspension,
            ActionType::Takedown,
        ] {
            assert_eq!(ActionType::from_db_str(v.as_db_str()), Some(v));
        }
    }

    #[test]
    fn db_str_unknown_value_yields_none() {
        assert!(ActionType::from_db_str("WARNING").is_none()); // case-sensitive
        assert!(ActionType::from_db_str("ban").is_none());
        assert!(ActionType::from_db_str("").is_none());
    }
}
