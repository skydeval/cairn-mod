//! Pure-function projections from cairn-mod's internal data
//! model into Ozone's read-side wire shapes (#97/#98, v1.7).
//!
//! Each child module owns the mapping for one Ozone read endpoint:
//!
//! - [`subject_status`] — `subject_actions` + `labels` + `reports`
//!   → `tools.ozone.moderation.defs#subjectStatusView` (#97).
//! - [`audit_event`] — `audit_log` joined with `subject_actions`
//!   → `tools.ozone.moderation.defs#modEventView` (#98).
//!
//! The projection functions are kept **synchronous** and operate
//! on already-loaded rows — the SQL layer in the parent handler
//! does the IO; the projection does the shape translation. This
//! keeps the design-heavy translation logic unit-testable without
//! a database, and surfaces the per-field decisions in one place
//! per endpoint (so an operator reading the response can find
//! "why is `appealed` always false?" by looking at one file).

pub mod audit_event;
pub mod subject_status;
