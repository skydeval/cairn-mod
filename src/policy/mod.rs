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
//! - [`evaluator`] — pure-function policy evaluator
//!   ([`evaluator::resolve_firing_rule`] and helpers). Translates
//!   a strike-state transition (pre/post the latest action) plus
//!   the resolved policy into the rule that should fire (or
//!   `None`). Same shape as the v1.4 calculators (#49 strike,
//!   #50 decay, #51 window) and v1.5 #59 emission core. (#72)
//!
//! Recorder integration and downstream surfaces land
//! incrementally — see #73-#82.

pub mod automation;
pub mod evaluator;
