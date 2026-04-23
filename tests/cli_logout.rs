//! Integration tests for `cairn_mod::cli::logout`.
//!
//! Covered:
//! - Happy path: deleteSession called + local file removed →
//!   `RevokedAndRemoved`.
//! - No session on disk → `NotLoggedIn`, no HTTP call.
//! - PDS reachable but rejects token (stale refresh) → local file
//!   still removed, outcome is `RemovedLocalOnlyPdsFailed` (Q3).
//! - PDS unreachable (network error) → same — local file removed,
//!   outcome reports PDS failure.

mod support;

use std::sync::atomic::Ordering;

use cairn_mod::cli::login::login;
use cairn_mod::cli::logout::{LogoutOutcome, logout};
use support::mock_pds::{self, MOCK_APP_PASSWORD, MOCK_HANDLE};

const MODERATOR_DID: &str = "did:plc:mockmoderator0000000000000";
const CAIRN_SERVICE_DID: &str = "did:web:labeler.test";

async fn seed_session(session_path: &std::path::Path) -> mock_pds::MockPds {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    login(
        "https://labeler.example",
        &pds.base_url(),
        MOCK_HANDLE,
        MOCK_APP_PASSWORD,
        Some(CAIRN_SERVICE_DID),
        session_path,
    )
    .await
    .expect("login seeds session");
    pds
}

#[tokio::test]
async fn logout_happy_path_revokes_and_removes() {
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");
    let pds = seed_session(&session_path).await;
    assert!(session_path.exists());

    let outcome = logout(&session_path).await.expect("logout");
    assert_eq!(outcome, LogoutOutcome::RevokedAndRemoved);
    assert!(!session_path.exists(), "local session file must be removed");
    assert_eq!(
        pds.state.delete_session_calls.load(Ordering::SeqCst),
        1,
        "PDS deleteSession must be called exactly once"
    );
}

#[tokio::test]
async fn logout_without_session_reports_not_logged_in() {
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");
    assert!(!session_path.exists());

    let outcome = logout(&session_path).await.expect("logout on empty");
    assert_eq!(outcome, LogoutOutcome::NotLoggedIn);
}

#[tokio::test]
async fn logout_with_stale_token_removes_local_anyway() {
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");
    let pds = seed_session(&session_path).await;

    // Rotate tokens at the PDS so the session file's refresh token
    // is now stale — the mock will return 401 on deleteSession.
    // (Uses the real refresh_session endpoint to do the rotation.)
    let pds_client = cairn_mod::cli::pds::PdsClient::new(&pds.base_url()).unwrap();
    let initial_session = cairn_mod::cli::session::SessionFile::load(&session_path)
        .unwrap()
        .unwrap();
    let _ = pds_client
        .refresh_session(&initial_session.refresh_jwt)
        .await
        .expect("rotate once");

    // session on disk still holds the OLD refresh_jwt → PDS will 401.
    let outcome = logout(&session_path).await.expect("logout cleans anyway");
    assert_eq!(outcome, LogoutOutcome::RemovedLocalOnlyPdsFailed);
    assert!(
        !session_path.exists(),
        "local session file removed on PDS 401"
    );
}

#[tokio::test]
async fn logout_with_unreachable_pds_removes_local_anyway() {
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");

    // Hand-build a session pointing at a dead host — login() can't
    // help us here because it needs a reachable PDS.
    let session = cairn_mod::cli::session::SessionFile {
        version: cairn_mod::cli::session::SESSION_VERSION,
        cairn_server_url: "https://labeler.example".into(),
        cairn_service_did: CAIRN_SERVICE_DID.into(),
        pds_url: "http://127.0.0.1:1".into(),
        moderator_did: MODERATOR_DID.into(),
        moderator_handle: MOCK_HANDLE.into(),
        access_jwt: "a".into(),
        refresh_jwt: "r".into(),
    };
    session.save(&session_path).unwrap();

    let outcome = logout(&session_path).await.expect("logout cleans anyway");
    assert_eq!(outcome, LogoutOutcome::RemovedLocalOnlyPdsFailed);
    assert!(!session_path.exists());
}
