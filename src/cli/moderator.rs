//! `cairn moderator {add, remove, list}` — orchestrators (#24).
//!
//! Thin wrapper over `crate::moderators`: translates CLI input
//! shapes into helper calls, maps helper outcomes to typed
//! results + [`CliError`], and exposes pure `format_*` functions
//! that turn results into stdout strings (human or JSON).
//!
//! Pattern matches `cli/report.rs`: orchestrator returns a typed
//! value; formatters are pure functions of that value; the
//! `main.rs` dispatcher composes the two and prints. Tests can
//! assert on the typed outcome (logic) and on `format_*` strings
//! (output contract) independently, without capturing stdout.
//!
//! Input validation is intentionally minimal: DID format is a
//! prefix check matching the rest of the codebase
//! (see `crate::server::create_report` and peers). Further
//! DID-shape validation lives at the DB CHECK + real-use layer.

use serde::Serialize;
use sqlx::{Pool, Sqlite};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::moderators::{self, AddOutcome, Moderator, RemoveOutcome, Role};

use super::error::CliError;

// =================== Inputs ===================

/// Input shape for `cairn moderator add`.
pub struct AddInput {
    /// DID of the moderator to add (or update via
    /// `update_role=true`).
    pub did: String,
    /// Role to assign.
    pub role: Role,
    /// If `true`, an existing DID's role is overwritten when it
    /// differs. If `false`, an existing-DID-with-different-role
    /// returns a USAGE-coded [`CliError`].
    pub update_role: bool,
}

/// Input shape for `cairn moderator remove`.
pub struct RemoveInput {
    /// DID of the moderator to remove.
    pub did: String,
    /// Skip the last-admin guard. Without this flag, removing the
    /// only remaining admin returns a USAGE error.
    pub force: bool,
}

/// Input shape for `cairn moderator list`.
pub struct ListInput {
    /// Optional role filter; `None` lists all moderators.
    pub role: Option<Role>,
}

// =================== Outcomes ===================

/// Successful outcome of `cairn moderator add`. Failure cases
/// (`DuplicateBlocked`, DB errors) flow through [`CliError`] and
/// don't appear here.
#[derive(Debug, PartialEq, Eq)]
pub enum AddResult {
    /// New row created.
    Inserted {
        /// DID that was added.
        did: String,
        /// Role assigned.
        role: Role,
    },
    /// Existing DID's role was changed via `--update-role`.
    RoleUpdated {
        /// DID whose row was updated.
        did: String,
        /// Role the row held before this call.
        previous: Role,
        /// New role.
        role: Role,
    },
    /// DID already had the requested role; nothing to do.
    Unchanged {
        /// DID inspected.
        did: String,
        /// Role on the row (matches the requested role).
        role: Role,
    },
}

/// Successful outcome of `cairn moderator remove`. The
/// not-found / last-admin / DB-error cases flow through
/// [`CliError`].
#[derive(Debug, PartialEq, Eq)]
pub struct RemoveResult {
    /// DID that was removed.
    pub did: String,
}

// =================== Orchestrators ===================

/// `cairn moderator add` — insert a moderator row, or update an
/// existing role when `input.update_role` is set. Same-role
/// re-invocation is [`AddResult::Unchanged`], never an error.
/// `DuplicateBlocked` from the underlying helper returns a
/// USAGE-coded [`CliError`].
pub async fn add(pool: &Pool<Sqlite>, input: AddInput) -> Result<AddResult, CliError> {
    validate_did(&input.did)?;

    // CLI inserts have no attested caller identity; added_by is
    // set only for HTTP-admin attribution via JWT iss (#24
    // decision C).
    let outcome = moderators::add(pool, &input.did, input.role, None, input.update_role)
        .await
        .map_err(map_db_error)?;

    match outcome {
        AddOutcome::Inserted => Ok(AddResult::Inserted {
            did: input.did,
            role: input.role,
        }),
        AddOutcome::RoleUpdated { previous } => Ok(AddResult::RoleUpdated {
            did: input.did,
            previous,
            role: input.role,
        }),
        AddOutcome::Unchanged => Ok(AddResult::Unchanged {
            did: input.did,
            role: input.role,
        }),
        AddOutcome::DuplicateBlocked { current_role } => Err(CliError::Config(format!(
            "{} is already a moderator (role {current_role}); pass --update-role to change role",
            input.did
        ))),
    }
}

/// `cairn moderator remove` — delete a moderator row. Errors with
/// USAGE exit code if the DID isn't a moderator. Refuses to remove
/// the last admin unless `input.force` is set.
pub async fn remove(pool: &Pool<Sqlite>, input: RemoveInput) -> Result<RemoveResult, CliError> {
    validate_did(&input.did)?;

    // Last-admin guard: block if the target is the only remaining
    // admin and --force wasn't passed. The check races between
    // SELECT and DELETE in theory, but the CLI is a one-shot
    // operator tool — the window isn't exploitable in practice and
    // a transactional guard would be overkill for v1.1.
    let existing_role: Option<Role> =
        sqlx::query_scalar!("SELECT role FROM moderators WHERE did = ?1", input.did)
            .fetch_optional(pool)
            .await
            .map_err(|e| CliError::Startup(format!("moderator lookup: {e}")))?
            .and_then(|s| Role::from_db_str(&s));

    if existing_role == Some(Role::Admin) && !input.force {
        let admin_count = moderators::count_admins(pool).await.map_err(map_db_error)?;
        if admin_count <= 1 {
            return Err(CliError::Config(format!(
                "{} is the last admin; pass --force to remove anyway",
                input.did
            )));
        }
    }

    match moderators::remove(pool, &input.did)
        .await
        .map_err(map_db_error)?
    {
        RemoveOutcome::Removed => Ok(RemoveResult { did: input.did }),
        RemoveOutcome::NotFound => Err(CliError::Config(format!(
            "{} is not a moderator",
            input.did
        ))),
    }
}

/// `cairn moderator list` — return all moderators (optionally
/// filtered by role). Caller chooses [`format_list_human`] or
/// [`format_list_json`] for stdout; the orchestrator does no
/// printing of its own.
pub async fn list(pool: &Pool<Sqlite>, input: ListInput) -> Result<Vec<Moderator>, CliError> {
    moderators::list(pool, input.role)
        .await
        .map_err(map_db_error)
}

// =================== Formatters: human ===================

/// Human-one-liner for the `add` outcome. UTF-8 arrow used in
/// `RoleUpdated` matches the pattern in `cli/report.rs`.
pub fn format_add_human(result: &AddResult) -> String {
    match result {
        AddResult::Inserted { did, role } => format!("added {did} as {role}"),
        AddResult::RoleUpdated {
            did,
            previous,
            role,
        } => format!("updated {did}: {previous} → {role}"),
        AddResult::Unchanged { did, role } => {
            format!("{did} already has role {role}; no change")
        }
    }
}

/// Human one-liner for the `remove` outcome.
pub fn format_remove_human(result: &RemoveResult) -> String {
    format!("removed moderator {}", result.did)
}

/// Human-readable table for `list`. Column widths sized to
/// content for `DID` and `ADDED_BY`; `ROLE` and `ADDED_AT` are
/// fixed (5 chars and the RFC-3339-Z width respectively).
/// Returns `(no moderators)` for an empty list rather than an
/// empty string so the caller's `println!` produces visible
/// output.
pub fn format_list_human(mods: &[Moderator]) -> String {
    use std::fmt::Write;

    if mods.is_empty() {
        return "(no moderators)".to_string();
    }
    let did_w = mods.iter().map(|m| m.did.len()).max().unwrap_or(3).max(3);
    let added_by_w = mods
        .iter()
        .map(|m| m.added_by.as_deref().unwrap_or("-").len())
        .max()
        .unwrap_or(8)
        .max(8);

    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<did_w$}  {:<5}  {:<20}  {:<added_by_w$}",
        "DID",
        "ROLE",
        "ADDED_AT",
        "ADDED_BY",
        did_w = did_w,
        added_by_w = added_by_w
    );
    for m in mods {
        let added_at = format_rfc3339(m.added_at);
        let added_by = m.added_by.as_deref().unwrap_or("-");
        let _ = writeln!(
            s,
            "{:<did_w$}  {:<5}  {:<20}  {:<added_by_w$}",
            m.did,
            m.role.as_str(),
            added_at,
            added_by,
            did_w = did_w,
            added_by_w = added_by_w
        );
    }
    // Trim the trailing newline; the caller appends its own via println!.
    if s.ends_with('\n') {
        s.pop();
    }
    s
}

// =================== Formatters: JSON ===================

#[derive(Serialize)]
struct AddJson<'a> {
    action: &'a str,
    did: &'a str,
    role: &'a str,
    result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_role: Option<&'a str>,
}

/// JSON one-line for the `add` outcome. Stable field names
/// (`action`, `did`, `role`, `result`, optional `previous_role`).
pub fn format_add_json(result: &AddResult) -> String {
    let body = match result {
        AddResult::Inserted { did, role } => AddJson {
            action: "add",
            did,
            role: role.as_str(),
            result: "inserted",
            previous_role: None,
        },
        AddResult::RoleUpdated {
            did,
            previous,
            role,
        } => AddJson {
            action: "add",
            did,
            role: role.as_str(),
            result: "role_updated",
            previous_role: Some(previous.as_str()),
        },
        AddResult::Unchanged { did, role } => AddJson {
            action: "add",
            did,
            role: role.as_str(),
            result: "unchanged",
            previous_role: None,
        },
    };
    serde_json::to_string(&body).expect("AddJson serializes")
}

#[derive(Serialize)]
struct RemoveJson<'a> {
    action: &'a str,
    did: &'a str,
    result: &'a str,
}

/// JSON one-line for the `remove` outcome.
pub fn format_remove_json(result: &RemoveResult) -> String {
    let body = RemoveJson {
        action: "remove",
        did: &result.did,
        result: "removed",
    };
    serde_json::to_string(&body).expect("RemoveJson serializes")
}

#[derive(Serialize)]
struct ListEntryJson<'a> {
    did: &'a str,
    role: &'a str,
    added_by: Option<&'a str>,
    added_at: String,
}

/// JSON array for `list`. Each element carries `did`, `role`,
/// nullable `added_by`, and an RFC-3339 UTC `added_at`.
pub fn format_list_json(mods: &[Moderator]) -> String {
    let entries: Vec<ListEntryJson> = mods
        .iter()
        .map(|m| ListEntryJson {
            did: &m.did,
            role: m.role.as_str(),
            added_by: m.added_by.as_deref(),
            added_at: format_rfc3339(m.added_at),
        })
        .collect();
    serde_json::to_string(&entries).expect("ListEntryJson serializes")
}

// =================== shared helpers ===================

fn validate_did(did: &str) -> Result<(), CliError> {
    if !did.starts_with("did:") || did.len() <= "did:".len() {
        return Err(CliError::Config(format!(
            "DID must start with 'did:' and include an identifier; got {did:?}"
        )));
    }
    Ok(())
}

/// Convert `moderators::Error` to the CLI's taxonomy. DB errors
/// map to [`CliError::Startup`] (INTERNAL exit code) matching the
/// pattern used in `publish_service_record`; `CorruptRole`
/// likewise — it signals a schema-level corruption that the
/// operator needs to diagnose manually.
fn map_db_error(e: moderators::Error) -> CliError {
    CliError::Startup(e.to_string())
}

/// Format an epoch-ms value as RFC 3339 UTC
/// (e.g. `2026-04-24T12:34:56Z`). Falls back to
/// `"ms=<raw>"` on out-of-range inputs; the fallback keeps tabular
/// output aligned without introducing a second error path.
fn format_rfc3339(epoch_ms: i64) -> String {
    let seconds = epoch_ms / 1000;
    let nanos = ((epoch_ms % 1000).unsigned_abs() * 1_000_000) as u32;
    let Ok(dt) = OffsetDateTime::from_unix_timestamp(seconds) else {
        return format!("ms={epoch_ms}");
    };
    let dt = dt.replace_nanosecond(nanos).unwrap_or(dt);
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| format!("ms={epoch_ms}"))
}
