//! Label emission for the v1.5 graduated-action moderation model
//! (§F21).
//!
//! Submodules land incrementally:
//!
//! - [`policy`] — operator-configurable label-emission policy
//!   (`[label_emission]` config block, action-type → label
//!   mapping, reason-label prefix, severity overrides). Used by
//!   the emission core and the recorder integration. (#58)
//! - [`emission`] — pure functions translating an
//!   [`emission::ActionForEmission`] (purpose-specific projection
//!   of a `subject_actions` row) into [`emission::LabelDraft`]s
//!   the recorder signs and persists. (#59)

pub mod emission;
pub mod policy;
