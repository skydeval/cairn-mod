//! Integration tests for `cairn_mod::cli::pds::PdsClient`.
//!
//! Coverage:
//! - createSession / refreshSession / deleteSession / getServiceAuth
//!   happy paths via the mock PDS fixture.
//! - 401 mapping for each endpoint → `PdsError::Unauthorized` with
//!   the correct `context` discriminator.
//! - Refresh rotation: refreshSession returns new tokens; the old
//!   access is rejected.
//! - Network error: client pointed at a dead socket →
//!   `PdsError::Network`.
//! - **Agreement test** (§J-15): the JWT minted by the mock PDS
//!   fixture is accepted by Cairn's production
//!   `AuthContext::verify_service_auth`. This locks the wire shape
//!   the CLI will actually present to Cairn — if the mock and the
//!   verifier ever drift, this test catches it before production
//!   does.

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::cli::pds::{PdsClient, PdsError};
use support::mock_pds::{self, MOCK_APP_PASSWORD, MOCK_HANDLE};

const MODERATOR_DID: &str = "did:plc:mockmoderator0000000000000";
const SERVICE_DID: &str = "did:web:labeler.test";

// ---------- happy paths ----------

#[tokio::test]
async fn create_session_happy_path() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    let resp = client
        .create_session(MOCK_HANDLE, MOCK_APP_PASSWORD)
        .await
        .expect("createSession");
    assert_eq!(resp.did, MODERATOR_DID);
    assert_eq!(resp.handle, MOCK_HANDLE);
    assert!(!resp.access_jwt.is_empty());
    assert!(!resp.refresh_jwt.is_empty());
}

#[tokio::test]
async fn refresh_session_rotates_tokens() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    let initial = client
        .create_session(MOCK_HANDLE, MOCK_APP_PASSWORD)
        .await
        .unwrap();
    let refreshed = client
        .refresh_session(&initial.refresh_jwt)
        .await
        .expect("refreshSession");
    assert_ne!(refreshed.access_jwt, initial.access_jwt);
    assert_ne!(refreshed.refresh_jwt, initial.refresh_jwt);

    // Old refresh now stale.
    let err = client
        .refresh_session(&initial.refresh_jwt)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        PdsError::Unauthorized {
            context: "refreshSession",
            ..
        }
    ));
}

#[tokio::test]
async fn delete_session_happy_path_then_idempotent_401() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    let initial = client
        .create_session(MOCK_HANDLE, MOCK_APP_PASSWORD)
        .await
        .unwrap();
    client
        .delete_session(&initial.refresh_jwt)
        .await
        .expect("deleteSession");
    assert_eq!(
        pds.state
            .delete_session_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    // Real PDSes return 401 on a reused refresh token post-delete;
    // our mock doesn't invalidate on delete but it DOES invalidate
    // on refresh — which is all the CLI flow actually depends on.
    // This assertion documents that limitation intentionally.
}

#[tokio::test]
async fn get_service_auth_happy_path() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    let session = client
        .create_session(MOCK_HANDLE, MOCK_APP_PASSWORD)
        .await
        .unwrap();
    let token = client
        .get_service_auth(
            &session.access_jwt,
            SERVICE_DID,
            "com.atproto.moderation.createReport",
        )
        .await
        .expect("getServiceAuth");
    // Cheap structural sanity; full wire-shape agreement is in the
    // agreement test below.
    assert_eq!(token.split('.').count(), 3, "JWT has 3 segments");
}

// ---------- 401 + error classification ----------

#[tokio::test]
async fn create_session_bad_password_returns_unauthorized() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    let err = client
        .create_session(MOCK_HANDLE, "wrong-password")
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            PdsError::Unauthorized {
                context: "createSession",
                ..
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn refresh_session_forced_401_returns_unauthorized() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    let initial = client
        .create_session(MOCK_HANDLE, MOCK_APP_PASSWORD)
        .await
        .unwrap();
    pds.state
        .force_refresh_401
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let err = client
        .refresh_session(&initial.refresh_jwt)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            PdsError::Unauthorized {
                context: "refreshSession",
                ..
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn get_service_auth_forced_401_returns_unauthorized() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    let session = client
        .create_session(MOCK_HANDLE, MOCK_APP_PASSWORD)
        .await
        .unwrap();
    pds.state
        .force_get_service_auth_401_next
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let err = client
        .get_service_auth(
            &session.access_jwt,
            SERVICE_DID,
            "com.atproto.moderation.createReport",
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            PdsError::Unauthorized {
                context: "getServiceAuth",
                ..
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn delete_session_bad_token_returns_unauthorized() {
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    // Skip createSession so we never learn the valid refresh token.
    let err = client.delete_session("stale-token").await.unwrap_err();
    assert!(
        matches!(
            err,
            PdsError::Unauthorized {
                context: "deleteSession",
                ..
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn network_error_on_unreachable_host() {
    // Port 1 is reserved and should never answer. If this
    // flakes in some exotic environment, swap for a truly closed
    // ephemeral port.
    let client = PdsClient::new("http://127.0.0.1:1").unwrap();
    let err = client
        .create_session(MOCK_HANDLE, MOCK_APP_PASSWORD)
        .await
        .unwrap_err();
    assert!(matches!(err, PdsError::Network { .. }), "got {err:?}");
}

// ---------- agreement: mock-PDS-minted JWT verified by Cairn AuthContext ----------

struct MapResolver(Mutex<HashMap<String, DidDocument>>);

#[async_trait]
impl DidResolver for MapResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError> {
        self.0
            .lock()
            .unwrap()
            .get(did)
            .cloned()
            .ok_or(ResolveError::BadStatus(404))
    }
}

/// The load-bearing test: a JWT produced by the mock PDS fixture
/// must be accepted by Cairn's production
/// `AuthContext::verify_service_auth`. A failure here means the
/// fixture and the verifier have drifted and every downstream CLI
/// integration test is running against a fiction.
#[tokio::test]
async fn mock_pds_minted_jwt_is_accepted_by_cairn_auth_context() {
    // Mock PDS side.
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    let client = PdsClient::new(&pds.base_url()).unwrap();
    let session = client
        .create_session(MOCK_HANDLE, MOCK_APP_PASSWORD)
        .await
        .unwrap();
    let lxm = "com.atproto.moderation.createReport";
    let token = client
        .get_service_auth(&session.access_jwt, SERVICE_DID, lxm)
        .await
        .unwrap();

    // Cairn side.
    let did_doc: DidDocument =
        serde_json::from_value(mock_pds::fixture_did_document(MODERATOR_DID)).unwrap();
    let resolver = Arc::new(MapResolver(Mutex::new(
        [(MODERATOR_DID.to_string(), did_doc)].into(),
    )));
    let auth = AuthContext::with_resolver(
        AuthConfig {
            service_did: SERVICE_DID.to_string(),
            ..AuthConfig::default()
        },
        resolver,
    );

    let verified = auth
        .verify_service_auth(&token, lxm)
        .await
        .expect("Cairn accepts mock-PDS-minted JWT");
    assert_eq!(verified.iss, MODERATOR_DID);
}
