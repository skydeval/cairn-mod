//! Account moderation state model (§F20, v1.4).
//!
//! Submodules land incrementally:
//!
//! - [`reasons`] — operator-configurable reason vocabulary
//!   (`[moderation_reasons]` config block). Used by the action
//!   recorder to validate incoming reason codes and by the strike
//!   calculator to look up base weights. (#47)
//!
//! Future submodules:
//! - `policy` — strike policy (dampening curve, decay function,
//!   suspension-freezes-decay flag). (#48)
//! - `strike` — pure strike calculator. (#49)
//! - `decay` — pure decay calculator. (#50)

pub mod reasons;
