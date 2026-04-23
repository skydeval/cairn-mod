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

pub mod session;
