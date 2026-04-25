//! Integration tests for `cairn moderator` (#24).
//!
//! Covers the full test matrix from the #24 acceptance criteria:
//!
//! - `add` succeeds for a new DID (Inserted outcome, NULL `added_by`)
//! - `add` errors on a duplicate without `--update-role`
//!   (DuplicateBlocked → USAGE-coded CliError; no DB mutation)
//! - `add --update-role` changes role on an existing DID
//!   (RoleUpdated; carries previous role)
//! - `remove` succeeds for an existing DID
//! - `remove` errors on a nonexistent DID
//! - `list` returns all moderators in deterministic order
//! - `list --role admin` filters correctly
//! - `--json` output is valid JSON for all three subcommands
//!   (parse via serde_json into a generic Value, then assert key
//!   presence + variant values)
//! - Invalid DID format is rejected by `validate_did` before any
//!   DB call
//! - Last-admin remove blocks without `--force` and proceeds with
//!   it
//! - `add` from the CLI leaves `moderators.added_by` NULL — the
//!   #24 decision-C invariant
//!
//! Not covered here:
//!
//! - Invalid `--role` values: clap's ValueEnum rejects these
//!   before our code runs. The clap library tests cover that
//!   layer; this file would need a subprocess invocation to
//!   exercise it, which buys nothing over trusting clap's
//!   correctness.

use cairn_mod::cli::error::CliError;
use cairn_mod::cli::moderator::{self, AddInput, AddResult, ListInput, RemoveInput, RemoveResult};
use cairn_mod::moderators::Role;
use cairn_mod::storage;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

const ALICE: &str = "did:plc:alice00000000000000000000000";
const BOB: &str = "did:plc:bob0000000000000000000000000";
const CAROL: &str = "did:plc:carol00000000000000000000000";

async fn fresh_pool() -> (TempDir, Pool<Sqlite>) {
    let dir = tempfile::tempdir().unwrap();
    let pool = storage::open(&dir.path().join("cairn.db")).await.unwrap();
    (dir, pool)
}

async fn seed(pool: &Pool<Sqlite>, did: &str, role: Role) {
    moderator::add(
        pool,
        AddInput {
            did: did.to_string(),
            role,
            update_role: false,
        },
    )
    .await
    .expect("seed add");
}

/// Test-only helper. Bypasses `moderator::add()`'s `epoch_ms_now()`
/// so ordering tests can specify deterministic, well-separated
/// timestamps. Without this, fast CI runners (test-msrv on GitHub
/// Actions ubuntu-latest) can land sequential inserts in the same
/// millisecond, making the production `ORDER BY added_at ASC, did
/// ASC` tie-break to the alphabetical `did` and breaking insert-
/// order assertions. Same nondeterminism class as #21's cache TTL
/// flake — determinism via explicit values, not timing margins.
async fn seed_at(pool: &Pool<Sqlite>, did: &str, role: Role, added_at_ms: i64) {
    let role_str = role.to_string();
    sqlx::query!(
        "INSERT INTO moderators (did, role, added_at) VALUES (?1, ?2, ?3)",
        did,
        role_str,
        added_at_ms,
    )
    .execute(pool)
    .await
    .expect("seed_at insert");
}

// ============ add ============

#[tokio::test]
async fn add_succeeds_for_new_did() {
    let (_dir, pool) = fresh_pool().await;

    let result = moderator::add(
        &pool,
        AddInput {
            did: ALICE.to_string(),
            role: Role::Mod,
            update_role: false,
        },
    )
    .await
    .expect("add");

    match result {
        AddResult::Inserted { did, role } => {
            assert_eq!(did, ALICE);
            assert_eq!(role, Role::Mod);
        }
        other => panic!("expected Inserted, got {other:?}"),
    }

    let row = sqlx::query!(
        "SELECT role, added_at FROM moderators WHERE did = ?1",
        ALICE
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.role, "mod");
    assert!(row.added_at > 0, "added_at should be a real timestamp");
}

#[tokio::test]
async fn add_errors_on_duplicate_without_update_flag() {
    let (_dir, pool) = fresh_pool().await;
    seed(&pool, ALICE, Role::Mod).await;

    let err = moderator::add(
        &pool,
        AddInput {
            did: ALICE.to_string(),
            role: Role::Admin,
            update_role: false,
        },
    )
    .await
    .expect_err("must error on duplicate without --update-role");

    match err {
        CliError::Config(msg) => {
            assert!(msg.contains(ALICE), "msg should name the DID: {msg}");
            assert!(
                msg.contains("--update-role"),
                "msg should hint at --update-role: {msg}"
            );
        }
        other => panic!("expected CliError::Config, got {other:?}"),
    }

    // No DB mutation: role stays Mod.
    let role: String = sqlx::query_scalar!("SELECT role FROM moderators WHERE did = ?1", ALICE)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "mod");
}

#[tokio::test]
async fn add_with_update_role_changes_role_on_existing_did() {
    let (_dir, pool) = fresh_pool().await;
    seed(&pool, ALICE, Role::Mod).await;

    let result = moderator::add(
        &pool,
        AddInput {
            did: ALICE.to_string(),
            role: Role::Admin,
            update_role: true,
        },
    )
    .await
    .expect("update_role allows the change");

    match result {
        AddResult::RoleUpdated {
            did,
            previous,
            role,
        } => {
            assert_eq!(did, ALICE);
            assert_eq!(previous, Role::Mod);
            assert_eq!(role, Role::Admin);
        }
        other => panic!("expected RoleUpdated, got {other:?}"),
    }

    let role: String = sqlx::query_scalar!("SELECT role FROM moderators WHERE did = ?1", ALICE)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "admin");
}

#[tokio::test]
async fn add_same_role_is_unchanged_not_error() {
    let (_dir, pool) = fresh_pool().await;
    seed(&pool, ALICE, Role::Admin).await;

    let result = moderator::add(
        &pool,
        AddInput {
            did: ALICE.to_string(),
            role: Role::Admin,
            update_role: false,
        },
    )
    .await
    .expect("same-role re-add is Unchanged, not an error");

    assert!(matches!(result, AddResult::Unchanged { .. }));
}

#[tokio::test]
async fn add_emits_null_added_by_from_cli() {
    // #24 decision C invariant: CLI inserts have no attested
    // caller identity, so added_by must be NULL. Future
    // ergonomics PRs that introduce a default --added-by sentinel
    // would silently break this contract; the test catches it.
    let (_dir, pool) = fresh_pool().await;
    moderator::add(
        &pool,
        AddInput {
            did: ALICE.to_string(),
            role: Role::Mod,
            update_role: false,
        },
    )
    .await
    .unwrap();

    let added_by: Option<String> =
        sqlx::query_scalar!("SELECT added_by FROM moderators WHERE did = ?1", ALICE)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        added_by.is_none(),
        "CLI inserts must leave added_by NULL; got Some({added_by:?})"
    );
}

// ============ remove ============

#[tokio::test]
async fn remove_succeeds_for_existing_did() {
    let (_dir, pool) = fresh_pool().await;
    seed(&pool, ALICE, Role::Mod).await;
    seed(&pool, BOB, Role::Admin).await; // keep at least one admin around

    let result = moderator::remove(
        &pool,
        RemoveInput {
            did: ALICE.to_string(),
            force: false,
        },
    )
    .await
    .expect("remove");
    assert_eq!(result, RemoveResult { did: ALICE.into() });

    let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM moderators WHERE did = ?1", ALICE)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn remove_errors_on_nonexistent_did() {
    let (_dir, pool) = fresh_pool().await;

    let err = moderator::remove(
        &pool,
        RemoveInput {
            did: ALICE.to_string(),
            force: false,
        },
    )
    .await
    .expect_err("remove must error when DID is not a moderator");

    match err {
        CliError::Config(msg) => assert!(msg.contains(ALICE)),
        other => panic!("expected CliError::Config, got {other:?}"),
    }
}

#[tokio::test]
async fn last_admin_remove_blocks_without_force() {
    let (_dir, pool) = fresh_pool().await;
    seed(&pool, ALICE, Role::Admin).await;
    seed(&pool, BOB, Role::Mod).await; // mod doesn't count as admin

    let err = moderator::remove(
        &pool,
        RemoveInput {
            did: ALICE.to_string(),
            force: false,
        },
    )
    .await
    .expect_err("must block last-admin removal without --force");

    match err {
        CliError::Config(msg) => {
            assert!(msg.contains("last admin"), "msg: {msg}");
            assert!(msg.contains("--force"), "msg should hint at --force: {msg}");
        }
        other => panic!("expected CliError::Config, got {other:?}"),
    }

    // Row still exists.
    let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM moderators WHERE did = ?1", ALICE)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn last_admin_remove_proceeds_with_force() {
    let (_dir, pool) = fresh_pool().await;
    seed(&pool, ALICE, Role::Admin).await;

    let result = moderator::remove(
        &pool,
        RemoveInput {
            did: ALICE.to_string(),
            force: true,
        },
    )
    .await
    .expect("--force bypasses last-admin guard");
    assert_eq!(result.did, ALICE);
}

// ============ list ============

#[tokio::test]
async fn list_returns_all_sorted_deterministically() {
    let (_dir, pool) = fresh_pool().await;
    // Explicit, well-separated timestamps so the production
    // `ORDER BY added_at ASC, did ASC` lands on the primary key
    // unambiguously. The earlier version used the seed-add path
    // and relied on `epoch_ms_now()` advancing between calls;
    // that worked locally but flaked on test-msrv CI runners where
    // sequential inserts can share a millisecond, kicking the
    // tie-break to `did ASC` and breaking the BOB/ALICE/CAROL
    // assertion (alphabetical: alice < bob < carol).
    seed_at(&pool, BOB, Role::Mod, 1_000_000_000_000).await;
    seed_at(&pool, ALICE, Role::Admin, 2_000_000_000_000).await;
    seed_at(&pool, CAROL, Role::Mod, 3_000_000_000_000).await;

    let mods = moderator::list(&pool, ListInput { role: None })
        .await
        .expect("list");

    assert_eq!(mods.len(), 3);
    // added_at ASC order matches the seed sequence — insertion
    // order, not alphabetical.
    assert_eq!(mods[0].did, BOB);
    assert_eq!(mods[1].did, ALICE);
    assert_eq!(mods[2].did, CAROL);
}

#[tokio::test]
async fn list_role_filter_returns_matching_only() {
    let (_dir, pool) = fresh_pool().await;
    seed(&pool, ALICE, Role::Admin).await;
    seed(&pool, BOB, Role::Mod).await;
    seed(&pool, CAROL, Role::Mod).await;

    let admins = moderator::list(
        &pool,
        ListInput {
            role: Some(Role::Admin),
        },
    )
    .await
    .expect("list admins");
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].did, ALICE);

    let mods = moderator::list(
        &pool,
        ListInput {
            role: Some(Role::Mod),
        },
    )
    .await
    .expect("list mods");
    assert_eq!(mods.len(), 2);
    assert!(mods.iter().any(|m| m.did == BOB));
    assert!(mods.iter().any(|m| m.did == CAROL));
}

// ============ JSON output ============

#[tokio::test]
async fn add_json_inserted_parses_with_expected_shape() {
    let result = AddResult::Inserted {
        did: ALICE.to_string(),
        role: Role::Mod,
    };
    let json = moderator::format_add_json(&result);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(v["action"], "add");
    assert_eq!(v["did"], ALICE);
    assert_eq!(v["role"], "mod");
    assert_eq!(v["result"], "inserted");
    assert!(
        v.get("previous_role").is_none(),
        "no previous_role on Inserted"
    );
}

#[tokio::test]
async fn add_json_role_updated_includes_previous_role() {
    let result = AddResult::RoleUpdated {
        did: ALICE.to_string(),
        previous: Role::Mod,
        role: Role::Admin,
    };
    let v: serde_json::Value = serde_json::from_str(&moderator::format_add_json(&result)).unwrap();
    assert_eq!(v["result"], "role_updated");
    assert_eq!(v["role"], "admin");
    assert_eq!(v["previous_role"], "mod");
}

#[tokio::test]
async fn add_json_unchanged_omits_previous_role() {
    let result = AddResult::Unchanged {
        did: ALICE.to_string(),
        role: Role::Mod,
    };
    let v: serde_json::Value = serde_json::from_str(&moderator::format_add_json(&result)).unwrap();
    assert_eq!(v["result"], "unchanged");
    assert!(v.get("previous_role").is_none());
}

#[tokio::test]
async fn remove_json_parses_with_expected_shape() {
    let result = RemoveResult { did: ALICE.into() };
    let v: serde_json::Value =
        serde_json::from_str(&moderator::format_remove_json(&result)).unwrap();
    assert_eq!(v["action"], "remove");
    assert_eq!(v["did"], ALICE);
    assert_eq!(v["result"], "removed");
}

#[tokio::test]
async fn list_json_is_array_with_per_row_shape() {
    let (_dir, pool) = fresh_pool().await;
    seed(&pool, ALICE, Role::Mod).await;

    let mods = moderator::list(&pool, ListInput { role: None })
        .await
        .unwrap();
    let json = moderator::format_list_json(&mods);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let arr = v.as_array().expect("list JSON is an array");
    assert_eq!(arr.len(), 1);
    let row = &arr[0];
    assert_eq!(row["did"], ALICE);
    assert_eq!(row["role"], "mod");
    assert!(row["added_by"].is_null(), "CLI insert leaves added_by NULL");
    let added_at = row["added_at"]
        .as_str()
        .expect("added_at is a string (RFC 3339)");
    assert!(
        added_at.contains('T') && added_at.ends_with('Z'),
        "expected RFC 3339 UTC, got {added_at:?}"
    );
}

// ============ DID validation ============

#[tokio::test]
async fn invalid_did_is_rejected_with_clear_error() {
    let (_dir, pool) = fresh_pool().await;
    for bad in ["", "foo", "did:", "DID:plc:upper"] {
        let err = moderator::add(
            &pool,
            AddInput {
                did: bad.to_string(),
                role: Role::Mod,
                update_role: false,
            },
        )
        .await
        .expect_err("must reject {bad:?}");
        match err {
            CliError::Config(msg) => assert!(
                msg.contains("DID must start with 'did:'"),
                "expected DID-format error, got: {msg}"
            ),
            other => panic!("expected CliError::Config for {bad:?}, got {other:?}"),
        }
    }
}
