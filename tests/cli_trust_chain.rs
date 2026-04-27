//! Integration tests for `cairn trust-chain show` (#37).
//!
//! Same fixture pattern as tests/cli_audit.rs (which see for the
//! design notes on mock_pds + admin_router + MapResolver
//! composition). Test surface:
//!
//! - happy path: admin role returns the envelope; required fields
//!   come through and provenance/serviceRecord branches deserialize
//! - admin-only auth contract: a moderator-role session receives
//!   `CliError::CairnStatus { status: 403, .. }` (the load-bearing
//!   reason this section of the README spells out the role
//!   requirement)
//!
//! Pure format_human / format_show_json / deserialization-shape
//! tests live next to the implementation in src/cli/trust_chain.rs's
//! #[cfg(test)] block — those don't need a fixture and stay there.

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::cli::error::CliError;
use cairn_mod::cli::session::SessionFile;
use cairn_mod::cli::trust_chain::{self, TrustChainShowInput};
use cairn_mod::{AdminConfig, admin_router, spawn_writer, storage};
use sqlx::{Pool, Sqlite};
use support::mock_pds::{self, MOCK_APP_PASSWORD, MOCK_HANDLE};
use tempfile::TempDir;
use tokio::net::TcpListener;

const MODERATOR_DID: &str = "did:plc:mockmoderator0000000000000";
const CAIRN_SERVICE_DID: &str = "did:plc:cairntest00000000000000000";
const CAIRN_SERVICE_ENDPOINT: &str = "https://labeler.example";

// ---------- harness ----------

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

struct CairnHarness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    addr: SocketAddr,
}

async fn spawn_cairn_with_config(admin_cfg: AdminConfig) -> CairnHarness {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cairn.db");
    let pool = storage::open(&db_path).await.unwrap();

    let did_doc: DidDocument =
        serde_json::from_value(mock_pds::fixture_did_document(MODERATOR_DID)).unwrap();
    let resolver = Arc::new(MapResolver(Mutex::new(
        [(MODERATOR_DID.to_string(), did_doc)].into(),
    )));
    let auth = Arc::new(AuthContext::with_resolver(
        AuthConfig {
            service_did: CAIRN_SERVICE_DID.to_string(),
            ..AuthConfig::default()
        },
        resolver,
    ));

    let writer = spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(
            hex::decode(mock_pds::MOCK_MODERATOR_PRIV_HEX)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        CAIRN_SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();
    let router = admin_router(
        pool.clone(),
        writer,
        auth,
        admin_cfg,
        cairn_mod::StrikePolicy::defaults(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    CairnHarness {
        _dir: dir,
        pool,
        addr,
    }
}

/// Default-shaped harness for trust-chain tests: AdminConfig with the
/// service identity populated (so the envelope returns those fields)
/// but no declared_label_values — endpoint reports
/// `serviceRecord: null` in this state.
async fn spawn_cairn() -> CairnHarness {
    spawn_cairn_with_config(AdminConfig {
        service_did: CAIRN_SERVICE_DID.to_string(),
        service_endpoint: CAIRN_SERVICE_ENDPOINT.to_string(),
        ..Default::default()
    })
    .await
}

async fn seed_moderator(pool: &Pool<Sqlite>, did: &str, role: &str) {
    sqlx::query!(
        "INSERT INTO moderators (did, role, added_at)
         VALUES (?1, ?2, strftime('%s', 'now') * 1000)",
        did,
        role
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn seeded_session(
    cairn_addr: SocketAddr,
    pds_base: &str,
    session_path: &std::path::Path,
) -> SessionFile {
    cairn_mod::cli::login::login(
        &format!("http://{cairn_addr}"),
        pds_base,
        MOCK_HANDLE,
        MOCK_APP_PASSWORD,
        Some(CAIRN_SERVICE_DID),
        session_path,
    )
    .await
    .expect("login seeds session")
}

// ============ tests ============

#[tokio::test]
async fn show_admin_role_returns_envelope() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "admin").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = trust_chain::show(&mut session, &path, TrustChainShowInput::default())
        .await
        .expect("show");

    assert_eq!(resp.service_did, CAIRN_SERVICE_DID);

    // Writer-bootstrapped signing-keys row shows up.
    assert_eq!(resp.signing_keys.len(), 1);
    assert!(resp.signing_keys[0].is_active);
    assert!(resp.signing_keys[0].valid_to.is_none());

    // Maintainer roster includes the seeded admin row (NULL added_by).
    let maintainer = resp
        .maintainers
        .iter()
        .find(|m| m.did == MODERATOR_DID)
        .expect("seeded moderator present");
    assert_eq!(maintainer.role, "admin");
    assert!(!maintainer.provenance_attested);
    assert!(maintainer.added_by.is_none());

    // Default config: declared_label_values is None, so the endpoint
    // omits serviceRecord — CLI deserializes that as None.
    assert!(resp.service_record.is_none());

    // Instance metadata reflects AdminConfig + build version.
    assert_eq!(resp.instance.service_endpoint, CAIRN_SERVICE_ENDPOINT);
    assert!(
        resp.instance
            .version
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false),
        "version starts with a digit (CARGO_PKG_VERSION semver shape)"
    );
}

#[tokio::test]
async fn show_with_service_record_populated_round_trips() {
    // Positive case for the serviceRecord branch — config has a
    // declared taxonomy AND a published content hash, so the
    // server emits the summary and the CLI deserializes it.
    let cairn = spawn_cairn_with_config(AdminConfig {
        service_did: CAIRN_SERVICE_DID.to_string(),
        service_endpoint: CAIRN_SERVICE_ENDPOINT.to_string(),
        declared_label_values: Some(vec!["spam".into(), "abuse".into()]),
        ..Default::default()
    })
    .await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "admin").await;
    sqlx::query!(
        "INSERT INTO labeler_config (key, value, updated_at)
         VALUES ('service_record_content_hash', ?1, ?2)",
        "abc123def456",
        0_i64,
    )
    .execute(&cairn.pool)
    .await
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let resp = trust_chain::show(&mut session, &path, TrustChainShowInput::default())
        .await
        .expect("show");
    let sr = resp
        .service_record
        .expect("populated when both halves present");
    assert_eq!(sr.content_hash, "abc123def456");
    assert_eq!(
        sr.label_values,
        vec!["spam".to_string(), "abuse".to_string()]
    );
}

#[tokio::test]
async fn show_mod_role_returns_403_as_clear_error() {
    let cairn = spawn_cairn().await;
    let pds = mock_pds::spawn(MODERATOR_DID).await;
    seed_moderator(&cairn.pool, MODERATOR_DID, "mod").await;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("session.json");
    let mut session = seeded_session(cairn.addr, &pds.base_url(), &path).await;

    let err = trust_chain::show(&mut session, &path, TrustChainShowInput::default())
        .await
        .expect_err("mod role must surface 403");
    match err {
        CliError::CairnStatus { status, .. } => {
            assert_eq!(status, 403, "admin-only endpoint, mod gets 403");
        }
        other => panic!("expected CairnStatus 403, got: {other:?}"),
    }
}
