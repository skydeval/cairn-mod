//! Integration tests for `cairn_mod::cli::login` (§5.3 login flow).
//!
//! Covered:
//! - Login with `--cairn-did` override writes a valid session
//!   file (no `.well-known` dependency).
//! - Authoritative DID: session.moderator_did comes from the PDS
//!   response, not the user-supplied handle.
//! - Wrong app password surfaces `PdsError::Unauthorized` on
//!   `createSession` context.
//! - Login against a live mock did.json server resolves the Cairn
//!   service DID from `<cairn_server>/.well-known/did.json`.
//! - post_login_warning output contains the §5.3 warning wording
//!   verbatim (pins the security message so a future wording tweak
//!   has a test to update).

mod support;

use std::net::SocketAddr;

use axum::Router;
use axum::response::Json;
use axum::routing::get;
use cairn_mod::cli::error::CliError;
use cairn_mod::cli::login::{login, post_login_warning};
use cairn_mod::cli::pds::PdsError;
use cairn_mod::cli::session::SessionFile;
use serde_json::json;
use support::mock_pds::{self, MOCK_APP_PASSWORD, MOCK_HANDLE};
use tokio::net::TcpListener;

const MODERATOR_DID: &str = "did:plc:mockmoderator0000000000000";
const CAIRN_SERVICE_DID: &str = "did:web:labeler.test";

async fn spawn_wellknown(service_did: &str) -> SocketAddr {
    let did = service_did.to_string();
    let router = Router::new().route(
        "/.well-known/did.json",
        get(move || {
            let did = did.clone();
            async move { Json(json!({ "id": did })) }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    addr
}

#[tokio::test]
async fn login_with_did_override_writes_valid_session() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");

    let session = login(
        "https://labeler.example",
        &pds.base_url(),
        MOCK_HANDLE,
        MOCK_APP_PASSWORD,
        Some(CAIRN_SERVICE_DID),
        &session_path,
    )
    .await
    .expect("login");

    assert_eq!(session.cairn_server_url, "https://labeler.example");
    assert_eq!(session.cairn_service_did, CAIRN_SERVICE_DID);
    assert_eq!(session.moderator_did, MODERATOR_DID);
    assert_eq!(session.moderator_handle, MOCK_HANDLE);
    assert!(!session.access_jwt.is_empty());
    assert!(!session.refresh_jwt.is_empty());

    // File on disk matches.
    let loaded = SessionFile::load(&session_path).unwrap().unwrap();
    assert_eq!(loaded, session);
}

#[tokio::test]
async fn login_authoritative_did_comes_from_pds_response() {
    // User passes handle — the session stores the DID the PDS
    // authenticated, not whatever the user typed.
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");

    let session = login(
        "https://labeler.example",
        &pds.base_url(),
        "alice.bsky.social", // a handle, not a DID
        MOCK_APP_PASSWORD,
        Some(CAIRN_SERVICE_DID),
        &session_path,
    )
    .await
    .unwrap();

    assert_eq!(session.moderator_did, MODERATOR_DID);
}

#[tokio::test]
async fn login_with_wrong_password_returns_pds_unauthorized() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");

    let err = login(
        "https://labeler.example",
        &pds.base_url(),
        MOCK_HANDLE,
        "wrong-password",
        Some(CAIRN_SERVICE_DID),
        &session_path,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            CliError::Pds(PdsError::Unauthorized {
                context: "createSession",
                ..
            })
        ),
        "got {err:?}"
    );
    assert!(!session_path.exists(), "no session file on auth failure");
}

#[tokio::test]
async fn login_resolves_cairn_did_from_well_known() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let wellknown_addr = spawn_wellknown(CAIRN_SERVICE_DID).await;
    let cairn_server = format!("http://{}", wellknown_addr);
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");

    let session = login(
        &cairn_server,
        &pds.base_url(),
        MOCK_HANDLE,
        MOCK_APP_PASSWORD,
        None, // <-- resolve via .well-known
        &session_path,
    )
    .await
    .expect("login with well-known");

    assert_eq!(session.cairn_service_did, CAIRN_SERVICE_DID);
}

#[tokio::test]
async fn login_surfaces_unreachable_well_known_as_http_error() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session.json");

    // Port 1 is the "nope" port for network tests here (same as
    // pds_client.rs). No cairn-did override → .well-known is
    // attempted and fails.
    let err = login(
        "http://127.0.0.1:1",
        &pds.base_url(),
        MOCK_HANDLE,
        MOCK_APP_PASSWORD,
        None,
        &session_path,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, CliError::Http { .. }), "got {err:?}");
    assert!(!session_path.exists());
}

#[tokio::test]
async fn post_login_warning_contains_security_notice() {
    let session = SessionFile {
        version: cairn_mod::cli::session::SESSION_VERSION,
        cairn_server_url: "https://labeler.example".into(),
        cairn_service_did: CAIRN_SERVICE_DID.into(),
        pds_url: "https://bsky.social".into(),
        moderator_did: MODERATOR_DID.into(),
        moderator_handle: MOCK_HANDLE.into(),
        access_jwt: "a".into(),
        refresh_jwt: "r".into(),
    };
    let msg = post_login_warning(&session, std::path::Path::new("/tmp/s.json"));
    // The precise §5.3 security warning must stay intact.
    assert!(msg.contains("WARNING"), "missing WARNING header:\n{msg}");
    assert!(
        msg.contains("equivalent\nto your PDS app password"),
        "missing PDS-equivalent clause:\n{msg}"
    );
    assert!(
        msg.contains("`cairn logout`"),
        "missing logout hint:\n{msg}"
    );
    assert!(msg.contains(MODERATOR_DID), "DID not surfaced:\n{msg}");
}
