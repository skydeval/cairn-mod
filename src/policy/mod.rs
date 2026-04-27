//! Policy automation surface (§F22, v1.6).
//!
//! v1.4 records moderation actions; v1.5 makes them protocol-visible
//! via labels; v1.6 adds an engine that evaluates operator-declared
//! rules against subject strike state on every recordAction and
//! either auto-records consequent actions or queues them as pending
//! for moderator review. This module hosts the v1.6 contribution:
//!
//! - [`automation`] — operator-config surface
//!   ([`automation::PolicyAutomationPolicy`],
//!   [`automation::PolicyRule`], [`automation::PolicyMode`]).
//!   TOML projection lives in [`crate::config`]; runtime resolution
//!   + validation is here. (#71)
//!
//! Pure-function evaluator and recorder integration land
//! incrementally — see #72-#82.

pub mod automation;
