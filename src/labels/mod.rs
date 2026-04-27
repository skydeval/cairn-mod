//! Label emission for the v1.5 graduated-action moderation model
//! (§F21).
//!
//! Submodules land incrementally:
//!
//! - [`policy`] — operator-configurable label-emission policy
//!   (`[label_emission]` config block, action-type → label
//!   mapping, reason-label prefix, severity overrides). Used by
//!   the emission core and the recorder integration. (#58)
//!
//! Future submodules:
//! - `emission` — pure functions translating
//!   [`crate::moderation::types::ActionRecord`] into
//!   `LabelDraft`s the recorder signs and persists. (#59)

pub mod policy;
