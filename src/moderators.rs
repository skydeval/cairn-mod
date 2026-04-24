//! Moderator identity + role-based authorization primitives shared
//! between the HTTP admin surface and the `cairn moderator` CLI
//! (#24).
//!
//! Lives outside `server::admin` so the CLI can depend on it
//! without reaching into a server-internal module.
//!
//! At present this file owns only the [`Role`] enum. Commit 2 of
//! #24 adds the [`Moderator`] record struct and the DB helpers
//! that `cairn moderator {add, remove, list}` and
//! `server::admin::common`'s auth check call into.

/// Role values persisted in `moderators.role`. The schema CHECK
/// constrains the column to exactly these two strings, so any
/// other value in a read means corrupt data, not an unknown role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Mod,
    Admin,
}
