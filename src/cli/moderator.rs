//! `cairn moderator {add, remove, list}` — orchestrators (#24).
//!
//! Thin wrapper over `crate::moderators`: translates CLI input
//! shapes into helper calls, maps helper outcomes to
//! [`CliError`] + stdout/stderr, and handles `--json` vs
//! human-readable output. No new DB queries beyond an inline
//! scalar lookup that shares its sqlx cache entry with
//! `crate::moderators::add`'s existing-row probe.
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

/// Input shape for `cairn moderator add`.
pub struct AddInput {
    /// DID of the moderator to add (or update via
    /// `update_role=true`).
    pub did: String,
    /// Role to assign.
    pub role: Role,
    /// If `true`, an existing DID's role is overwritten when it
    /// differs. If `false`, an existing-DID-with-different-role
    /// is reported as `DuplicateBlocked` and the call exits with
    /// a USAGE error.
    pub update_role: bool,
    /// Emit JSON instead of human one-liner.
    pub json: bool,
}

/// Input shape for `cairn moderator remove`.
pub struct RemoveInput {
    /// DID of the moderator to remove.
    pub did: String,
    /// Skip the last-admin guard. Without this flag, removing the
    /// only remaining admin returns a USAGE error.
    pub force: bool,
    /// Emit JSON instead of human one-liner.
    pub json: bool,
}

/// Input shape for `cairn moderator list`.
pub struct ListInput {
    /// Optional role filter; `None` lists all moderators.
    pub role: Option<Role>,
    /// Emit JSON array instead of the human-readable table.
    pub json: bool,
}

// ============ add ============

/// JSON shape for `cairn moderator add --json`. Kept close to the
/// emit site so drift between the typed shape and the emitted bytes
/// is one diff to review.
#[derive(Serialize)]
struct AddJson<'a> {
    action: &'a str,
    did: &'a str,
    role: &'a str,
    result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_role: Option<&'a str>,
}

/// `cairn moderator add` — insert a moderator row, or update an
/// existing role when `input.update_role` is set. Same-role
/// re-invocation is `Unchanged` (printed as such), never an error.
/// `DuplicateBlocked` returns a USAGE-coded [`CliError`].
pub async fn add(pool: &Pool<Sqlite>, input: AddInput) -> Result<(), CliError> {
    validate_did(&input.did)?;

    let outcome = moderators::add(pool, &input.did, input.role, None, input.update_role)
        .await
        .map_err(map_db_error)?;

    let (result_key, previous_role) = match &outcome {
        AddOutcome::Inserted => ("inserted", None),
        AddOutcome::RoleUpdated { previous } => ("role_updated", Some(*previous)),
        AddOutcome::Unchanged => ("unchanged", None),
        AddOutcome::DuplicateBlocked { current_role } => ("duplicate_blocked", Some(*current_role)),
    };

    if input.json {
        let j = AddJson {
            action: "add",
            did: &input.did,
            role: input.role.as_str(),
            result: result_key,
            previous_role: previous_role.map(|r| r.as_str()),
        };
        println!("{}", serde_json::to_string(&j).expect("AddJson serializes"));
    } else {
        match &outcome {
            AddOutcome::Inserted => {
                println!("added {} as {}", input.did, input.role);
            }
            AddOutcome::RoleUpdated { previous } => {
                println!("updated {}: {} → {}", input.did, previous, input.role);
            }
            AddOutcome::Unchanged => {
                println!("{} already has role {}; no change", input.did, input.role);
            }
            AddOutcome::DuplicateBlocked { current_role } => {
                eprintln!(
                    "error: {} is already a moderator (role {}); pass --update-role to change role",
                    input.did, current_role
                );
            }
        }
    }

    if matches!(outcome, AddOutcome::DuplicateBlocked { .. }) {
        return Err(CliError::Config(format!(
            "{} is already a moderator",
            input.did
        )));
    }
    Ok(())
}

// ============ remove ============

/// JSON shape for `cairn moderator remove --json`.
#[derive(Serialize)]
struct RemoveJson<'a> {
    action: &'a str,
    did: &'a str,
    result: &'a str,
}

/// `cairn moderator remove` — delete a moderator row. Errors with
/// USAGE exit code if the DID isn't a moderator. Refuses to remove
/// the last admin unless `input.force` is set.
pub async fn remove(pool: &Pool<Sqlite>, input: RemoveInput) -> Result<(), CliError> {
    validate_did(&input.did)?;

    // Last-admin guard: block if the target is the only remaining admin
    // and --force wasn't passed. The check races between SELECT and
    // DELETE in theory, but the CLI is a one-shot operator tool — the
    // window isn't exploitable in practice and a transactional guard
    // would be overkill for v1.1.
    let existing_role: Option<Role> =
        sqlx::query_scalar!("SELECT role FROM moderators WHERE did = ?1", input.did)
            .fetch_optional(pool)
            .await
            .map_err(|e| CliError::Startup(format!("moderator lookup: {e}")))?
            .and_then(|s| Role::from_db_str(&s));

    if existing_role == Some(Role::Admin) && !input.force {
        let admin_count = moderators::count_admins(pool).await.map_err(map_db_error)?;
        if admin_count <= 1 {
            if input.json {
                let j = RemoveJson {
                    action: "remove",
                    did: &input.did,
                    result: "blocked_last_admin",
                };
                println!(
                    "{}",
                    serde_json::to_string(&j).expect("RemoveJson serializes")
                );
            } else {
                eprintln!(
                    "error: {} is the last admin; pass --force to remove anyway",
                    input.did
                );
            }
            return Err(CliError::Config(format!("{} is the last admin", input.did)));
        }
    }

    match moderators::remove(pool, &input.did)
        .await
        .map_err(map_db_error)?
    {
        RemoveOutcome::Removed => {
            if input.json {
                let j = RemoveJson {
                    action: "remove",
                    did: &input.did,
                    result: "removed",
                };
                println!(
                    "{}",
                    serde_json::to_string(&j).expect("RemoveJson serializes")
                );
            } else {
                println!("removed moderator {}", input.did);
            }
            Ok(())
        }
        RemoveOutcome::NotFound => {
            if input.json {
                let j = RemoveJson {
                    action: "remove",
                    did: &input.did,
                    result: "not_found",
                };
                println!(
                    "{}",
                    serde_json::to_string(&j).expect("RemoveJson serializes")
                );
            } else {
                eprintln!("error: {} is not a moderator", input.did);
            }
            Err(CliError::Config(format!(
                "{} is not a moderator",
                input.did
            )))
        }
    }
}

// ============ list ============

/// JSON shape for one row emitted by `cairn moderator list --json`.
#[derive(Serialize)]
struct ListEntryJson<'a> {
    did: &'a str,
    role: &'a str,
    added_by: Option<&'a str>,
    /// RFC-3339 UTC. Operators paste these into graphs + audit
    /// narratives; epoch ms is offered only as a fallback if the
    /// row's `added_at` is outside the representable range.
    added_at: String,
}

/// `cairn moderator list` — print all moderators (optionally
/// filtered by role) as either a human-readable table or a JSON
/// array. Order is `added_at ASC, did ASC` for stable output.
pub async fn list(pool: &Pool<Sqlite>, input: ListInput) -> Result<(), CliError> {
    let mods = moderators::list(pool, input.role)
        .await
        .map_err(map_db_error)?;

    if input.json {
        let entries: Vec<ListEntryJson> = mods
            .iter()
            .map(|m| ListEntryJson {
                did: &m.did,
                role: m.role.as_str(),
                added_by: m.added_by.as_deref(),
                added_at: format_rfc3339(m.added_at),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&entries).expect("ListEntryJson serializes")
        );
    } else {
        print_list_table(&mods);
    }
    Ok(())
}

fn print_list_table(mods: &[Moderator]) {
    if mods.is_empty() {
        println!("(no moderators)");
        return;
    }
    // Columns sized to content: DID and ADDED_BY vary; ROLE is at
    // most 5 chars ("admin"); ADDED_AT is the RFC-3339-Z fixed
    // width.
    let did_w = mods.iter().map(|m| m.did.len()).max().unwrap_or(3).max(3);
    let added_by_w = mods
        .iter()
        .map(|m| m.added_by.as_deref().unwrap_or("-").len())
        .max()
        .unwrap_or(8)
        .max(8);
    println!(
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
        println!(
            "{:<did_w$}  {:<5}  {:<20}  {:<added_by_w$}",
            m.did,
            m.role.as_str(),
            added_at,
            added_by,
            did_w = did_w,
            added_by_w = added_by_w
        );
    }
}

// ============ shared helpers ============

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
/// pattern used in `publish_service_record`; [`moderators::Error::CorruptRole`]
/// likewise — it signals a schema-level corruption that the operator
/// needs to diagnose manually.
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
