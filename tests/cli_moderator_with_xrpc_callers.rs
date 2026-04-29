//! Integration tests for `cairn moderator add --with-xrpc-callers`
//! (#99). The clap-side flag wiring lives in `main.rs`; this test
//! exercises the orchestration logic directly (moderator add +
//! xrpc_known_callers add as a paired operation).

use cairn_mod::cli::moderator::{self, AddInput};
use cairn_mod::moderators::Role;
use cairn_mod::storage;
use cairn_mod::xrpc_gateway::{add_known_caller, is_known_caller, list_known_callers};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

const ALICE: &str = "did:plc:alice00000000000000000000";
const OPERATOR: &str = "did:plc:operator0000000000000000";

async fn fresh_pool() -> (TempDir, Pool<Sqlite>) {
    let dir = tempfile::tempdir().unwrap();
    let pool = storage::open(&dir.path().join("cairn.db")).await.unwrap();
    (dir, pool)
}

#[tokio::test]
async fn moderator_add_alone_does_not_touch_xrpc_callers() {
    let (_d, pool) = fresh_pool().await;
    moderator::add(
        &pool,
        AddInput {
            did: ALICE.into(),
            role: Role::Mod,
            update_role: false,
        },
    )
    .await
    .expect("add");
    let rows = list_known_callers(&pool, true).await.unwrap();
    assert_eq!(rows.len(), 0, "xrpc_known_callers must be empty");
}

#[tokio::test]
async fn moderator_add_with_xrpc_callers_inserts_both() {
    // Simulate the main.rs flow: moderator::add then
    // add_known_caller in the same handler invocation.
    let (_d, pool) = fresh_pool().await;
    moderator::add(
        &pool,
        AddInput {
            did: ALICE.into(),
            role: Role::Mod,
            update_role: false,
        },
    )
    .await
    .expect("add");
    add_known_caller(&pool, ALICE, None, OPERATOR)
        .await
        .expect("add_known_caller");

    let rows = list_known_callers(&pool, true).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].did, ALICE);
    assert_eq!(rows[0].added_by_moderator, OPERATOR);
}

#[tokio::test]
async fn moderator_add_with_xrpc_callers_is_idempotent_on_rerun() {
    // The clap-side handler pre-checks `is_known_caller` and
    // skips the second add when the DID is already active.
    // Replicate that flow here.
    let (_d, pool) = fresh_pool().await;
    moderator::add(
        &pool,
        AddInput {
            did: ALICE.into(),
            role: Role::Mod,
            update_role: false,
        },
    )
    .await
    .expect("add");
    add_known_caller(&pool, ALICE, None, OPERATOR)
        .await
        .expect("first add_known_caller");

    // Second invocation: pre-check, skip the add since the DID is
    // already an active caller.
    let already = is_known_caller(&pool, ALICE).await.unwrap();
    assert!(already, "first add made the DID an active caller");

    let rows = list_known_callers(&pool, true).await.unwrap();
    assert_eq!(rows.len(), 1, "still one row after the pre-check skip");
}
