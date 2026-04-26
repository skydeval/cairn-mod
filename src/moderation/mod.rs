//! Account moderation state model (§F20, v1.4).
//!
//! Submodules land incrementally:
//!
//! - [`reasons`] — operator-configurable reason vocabulary
//!   (`[moderation_reasons]` config block). Used by the action
//!   recorder to validate incoming reason codes and by the strike
//!   calculator to look up base weights. (#47)
//! - [`policy`] — strike policy (dampening curve, decay function,
//!   suspension-freezes-decay flag, `[strike_policy]` config block).
//!   Used by the strike calculator and decay calculator. (#48)
//! - [`strike`] — pure strike calculator. Takes
//!   `(current_count, reason, policy, position_in_window)` and
//!   returns the resolved [`StrikeApplication`](strike::StrikeApplication)
//!   to record on the new `subject_actions` row. (#49)
//!
//! Future submodules:
//! - `decay` — pure decay calculator. (#50)

pub mod policy;
pub mod reasons;
pub mod strike;
