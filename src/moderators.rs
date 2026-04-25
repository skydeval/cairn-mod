//! Moderator identity + role-based authorization primitives shared
//! between the HTTP admin surface and the `cairn moderator` CLI
//! (#24).
//!
//! Lives outside `server::admin` so the CLI can depend on it
//! without reaching into a server-internal module. Owns:
//!
//! - [`Role`] — enum mirroring the `moderators.role` column's
//!   CHECK constraint (`'mod' | 'admin'`).
//! - `Moderator` — record struct mapping one row.
//! - `Error` — thiserror-wrapped DB + corruption variants.
//! - `add`, `remove`, `list`, `count_admins` — the DB helpers
//!   `cairn moderator` invokes (pub(crate); links omitted because
//!   the public-API docs would treat them as broken).

use sqlx::{Pool, Sqlite};

use crate::writer::epoch_ms_now;

/// Role values persisted in `moderators.role`. The schema CHECK
/// constrains the column to exactly these two strings, so any
/// other value in a read means corrupt data, not an unknown role.
///
/// Public so the `cairn moderator` CLI in the binary crate can
/// construct values for the helpers below; helpers themselves stay
/// `pub(crate)` — moderator-table mutation is not part of the
/// library's external API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Standard moderator role: can apply, negate, and resolve.
    Mod,
    /// Elevated role: everything `Mod` can do, plus
    /// `tools.cairn.admin.listAuditLog` (§F12).
    Admin,
}

impl Role {
    /// DB-side string representation. Must match the CHECK
    /// constraint in migrations and the values read at
    /// `server::admin::common` auth time.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Role::Mod => "mod",
            Role::Admin => "admin",
        }
    }

    /// Parse the string stored in `moderators.role`. Returns
    /// `None` if the value doesn't match the CHECK constraint —
    /// which should be unreachable in practice and is surfaced
    /// as [`Error::CorruptRole`] by the helpers below.
    pub(crate) fn from_db_str(s: &str) -> Option<Role> {
        match s {
            "mod" => Some(Role::Mod),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of the `moderators` table, decoded into strongly-typed
/// fields. `added_by` is nullable: populated for HTTP-admin
/// insertions via the JWT `iss`, and left NULL for CLI-initiated
/// inserts (#24 decision C — no attested caller identity at the
/// CLI boundary).
#[derive(Debug, Clone)]
pub(crate) struct Moderator {
    pub did: String,
    pub role: Role,
    pub added_by: Option<String>,
    /// Unix epoch milliseconds.
    pub added_at: i64,
}

/// Error shape for the helpers in this module. DB errors bubble
/// through unchanged; [`CorruptRole`](Self::CorruptRole) covers
/// the CHECK-violating-row case that's nominally unreachable.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// Any sqlx-side failure: connection closed, serialization,
    /// constraint violation other than the CHECK.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// A `moderators.role` read returned a value outside the
    /// CHECK-constrained set. Shouldn't happen with an uncorrupted
    /// DB; surfaced so callers don't silently drop rows.
    #[error("corrupt moderator row: role value {0:?} violates CHECK constraint on moderators.role")]
    CorruptRole(String),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Outcome of [`add`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AddOutcome {
    /// No prior row for this DID; new row inserted.
    Inserted,
    /// DID already existed with a different role and
    /// `allow_role_update` was `true`; role was updated.
    RoleUpdated {
        /// Role the row held before this call.
        previous: Role,
    },
    /// DID already existed with the requested role; no change
    /// made. Returned whether or not `allow_role_update` was set.
    Unchanged,
    /// DID already existed with a different role and
    /// `allow_role_update` was `false`; the caller chose not to
    /// permit role changes via this invocation. No DB write
    /// occurred.
    DuplicateBlocked {
        /// Current role of the existing row.
        current_role: Role,
    },
}

/// Insert or (optionally) update a moderator row.
///
/// `added_by` is the caller-DID for attribution, `None` for
/// CLI-initiated inserts (per #24 decision C). `allow_role_update`
/// gates whether an existing DID's role can be rewritten by this
/// call: the `cairn moderator add` CLI path exposes this as the
/// `--update-role` flag. Same-role re-invocation is always
/// [`AddOutcome::Unchanged`] — never an error.
pub(crate) async fn add(
    pool: &Pool<Sqlite>,
    did: &str,
    role: Role,
    added_by: Option<&str>,
    allow_role_update: bool,
) -> Result<AddOutcome> {
    let existing_role: Option<Role> =
        sqlx::query_scalar!("SELECT role FROM moderators WHERE did = ?1", did)
            .fetch_optional(pool)
            .await?
            .map(|s| Role::from_db_str(&s).ok_or(Error::CorruptRole(s)))
            .transpose()?;

    match existing_role {
        Some(current) if current == role => Ok(AddOutcome::Unchanged),
        Some(current) if !allow_role_update => Ok(AddOutcome::DuplicateBlocked {
            current_role: current,
        }),
        Some(current) => {
            let role_str = role.as_str();
            sqlx::query!(
                "UPDATE moderators SET role = ?1 WHERE did = ?2",
                role_str,
                did
            )
            .execute(pool)
            .await?;
            Ok(AddOutcome::RoleUpdated { previous: current })
        }
        None => {
            // CLI inserts have no attested caller identity; added_by
            // is set only for HTTP-admin attribution via JWT iss.
            let now = epoch_ms_now();
            let role_str = role.as_str();
            sqlx::query!(
                "INSERT INTO moderators (did, role, added_by, added_at) VALUES (?1, ?2, ?3, ?4)",
                did,
                role_str,
                added_by,
                now,
            )
            .execute(pool)
            .await?;
            Ok(AddOutcome::Inserted)
        }
    }
}

/// Outcome of [`remove`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RemoveOutcome {
    /// Row existed and was deleted.
    Removed,
    /// No row for the given DID — nothing to remove.
    NotFound,
}

/// Delete a moderator row. See [`RemoveOutcome`] for the
/// not-found-vs-removed distinction; `cairn moderator remove`
/// maps `NotFound` to a usage-exit-code error, not a silent
/// success.
pub(crate) async fn remove(pool: &Pool<Sqlite>, did: &str) -> Result<RemoveOutcome> {
    let res = sqlx::query!("DELETE FROM moderators WHERE did = ?1", did)
        .execute(pool)
        .await?;
    if res.rows_affected() == 0 {
        Ok(RemoveOutcome::NotFound)
    } else {
        Ok(RemoveOutcome::Removed)
    }
}

/// List all moderators, optionally filtered to a single role.
/// Ordered by `added_at ASC, did ASC` for deterministic output in
/// tests and in the CLI's tabular rendering.
pub(crate) async fn list(pool: &Pool<Sqlite>, role_filter: Option<Role>) -> Result<Vec<Moderator>> {
    // The two queries share a projection but differ in the WHERE
    // clause; kept as two explicit call sites rather than a runtime
    // SQL-concat because `sqlx::query!` checks each string against
    // the compile-time cache.
    let rows = match role_filter {
        Some(r) => {
            let role_str = r.as_str();
            sqlx::query!(
                "SELECT did, role, added_by, added_at FROM moderators
                 WHERE role = ?1 ORDER BY added_at ASC, did ASC",
                role_str
            )
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|r| (r.did, r.role, r.added_by, r.added_at))
            .collect::<Vec<_>>()
        }
        None => sqlx::query!(
            "SELECT did, role, added_by, added_at FROM moderators
             ORDER BY added_at ASC, did ASC"
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| (r.did, r.role, r.added_by, r.added_at))
        .collect::<Vec<_>>(),
    };

    rows.into_iter()
        .map(|(did, role, added_by, added_at)| {
            let role = Role::from_db_str(&role).ok_or(Error::CorruptRole(role))?;
            Ok(Moderator {
                did,
                role,
                added_by,
                added_at,
            })
        })
        .collect()
}

/// Count admin-role rows. Used by `cairn moderator remove` to
/// block removing the last admin (unless `--force` is set) — see
/// #24 decision 5.
pub(crate) async fn count_admins(pool: &Pool<Sqlite>) -> Result<i64> {
    let n = sqlx::query_scalar!("SELECT COUNT(*) FROM moderators WHERE role = 'admin'")
        .fetch_one(pool)
        .await?;
    Ok(n)
}
