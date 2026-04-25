//! Command-line surface for `cairn` (§F9 + §5.3).
//!
//! Sub-modules land incrementally:
//! - [`session`] — on-disk session file (§5.3 storage format + 0600 +
//!   owner checks + atomic write-rename).
//!
//! Future sessions add:
//! - `pds` — client for `com.atproto.server.{createSession,
//!   refreshSession, deleteSession, getServiceAuth}`.
//! - `login` / `logout` — session lifecycle.
//! - `report` — `cairn report create`.
//! - `output` — human vs `--json` formatting.

pub mod error;
pub mod login;
pub mod logout;
pub mod moderator;
pub mod operator_login;
pub mod operator_session;
pub mod pds;
pub mod publish_service_record;
pub mod report;
pub mod session;
