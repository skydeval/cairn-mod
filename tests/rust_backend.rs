//! v1.8.1 RustBackend integration tests (per-release doc §8).
//!
//! - Mock-Aurora `describeCapabilities` end-to-end: full
//!   `RustBackend::probe` flow against an in-process axum server
//!   speaking Aurora's wire shape (recon §1b), including
//!   verification that the minted service-auth JWT is a
//!   well-formed ES256K token whose DER signature verifies.
//! - `backend = "rust"` boot path: the three v1.8.1 boot gates
//!   (`validated_rust_from_toml` via `PdsAdminPolicy::from_config`,
//!   `validate_audit_divergence_acknowledgment`,
//!   `RustBackend::new`) plus inspector-only dispatch behavior.
//! - Startup-failure paths produce clear operator-facing errors.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use k256::ecdsa::signature::Verifier as _;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::json;
use tokio::net::TcpListener;

use cairn_mod::pds_admin::backend::BackendError;
use cairn_mod::pds_admin::rust::RustBackend;
use cairn_mod::pds_admin::{
    PdsAdminBackend, PdsAdminBackendConfig, PdsAdminPolicy, RustBackendConfig,
    validate_audit_divergence_acknowledgment,
};

/// 64 hex chars — a valid non-zero secp256k1 scalar.
const TEST_KEY_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";

fn test_signing_key() -> SigningKey {
    SigningKey::from_slice(hex::decode(TEST_KEY_HEX).unwrap().as_slice()).unwrap()
}

/// What the mock Aurora returns from `describeCapabilities`.
#[derive(Clone)]
struct MockAuroraBehavior {
    status: StatusCode,
    body: String,
}

struct MockAuroraState {
    behavior: MockAuroraBehavior,
    /// Last `Authorization` header value seen, for JWT assertions.
    last_authorization: Mutex<Option<String>>,
}

/// Canonical successful response body — Aurora's wire shape per
/// recon §1b, advertising real capability strings from the
/// 19-string list (the ones v1.8.2 will consume, plus one the
/// registry doesn't know so the unknown-family path is exercised).
fn canonical_body() -> String {
    json!({
        "families": {
            "tools.aurora.admin": ["emitEvent"],
            "tools.aurora.moderator": ["queryEvents", "queryStatuses"]
        },
        "extensions": [
            {"name": "mod-events-emit-v1"},
            {"name": "audit-trail-v1"},
            {"name": "queue-stats-v1", "value": {"note": "placeholder"}}
        ],
        "implementation": "aurora-locus",
        "version": "0.10.0"
    })
    .to_string()
}

async fn describe_capabilities(
    State(state): State<Arc<MockAuroraState>>,
    headers: HeaderMap,
) -> Response {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    *state.last_authorization.lock().unwrap() = auth;
    (
        state.behavior.status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        state.behavior.body.clone(),
    )
        .into_response()
}

/// Spawn a mock Aurora exposing only the probe endpoint. Returns
/// once the listener is bound.
async fn spawn_mock_aurora(behavior: MockAuroraBehavior) -> (SocketAddr, Arc<MockAuroraState>) {
    let state = Arc::new(MockAuroraState {
        behavior,
        last_authorization: Mutex::new(None),
    });
    let router = Router::new()
        .route(
            "/xrpc/tools.aurora.describeCapabilities",
            get(describe_capabilities),
        )
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    (addr, state)
}

fn backend_config(addr: SocketAddr, required: Vec<String>) -> RustBackendConfig {
    RustBackendConfig {
        pds_url: url::Url::parse(&format!("http://{addr}")).unwrap(),
        service_did: "did:web:cairn-mod.example.test".into(),
        service_signing_key_env: "CAIRN_TEST_RUST_SERVICE_SIGNING_KEY".into(),
        service_did_document_url: None,
        target_service_did: "did:web:aurora-locus.example.test".into(),
        request_timeout: Duration::from_secs(5),
        capability_refresh_interval: Duration::from_secs(3600),
        required_capabilities: required,
        pinned_versions: BTreeMap::new(),
        verification_persist: true,
        acknowledge_v1_8_1_audit_divergence: true,
    }
}

fn backend_against(addr: SocketAddr, required: Vec<String>) -> RustBackend {
    RustBackend::new_with_key_source(&backend_config(addr, required), &|_| {
        Ok(TEST_KEY_HEX.to_string())
    })
    .unwrap()
}

// =========================================================================
// Mock-Aurora describeCapabilities end-to-end (§8 integration)
// =========================================================================

#[tokio::test]
async fn probe_end_to_end_against_canonical_mock_aurora() {
    let (addr, state) = spawn_mock_aurora(MockAuroraBehavior {
        status: StatusCode::OK,
        body: canonical_body(),
    })
    .await;

    let backend = backend_against(addr, vec!["mod-events-emit-v1".into()]);
    let report = backend.probe().await.expect("probe succeeds");

    // ProbeReport shape (§4.3 step 7).
    assert_eq!(report.backend_name, "rust");
    assert_eq!(report.detected_version.as_deref(), Some("0.10.0"));
    assert_eq!(
        report.capabilities,
        vec![
            "mod-events-emit-v1".to_string(),
            "audit-trail-v1".to_string(),
            "queue-stats-v1".to_string(),
        ]
    );

    // The request carried a well-formed ES256K service-auth JWT:
    // Bearer scheme, three parts, ES256K header, expected claims,
    // DER signature verifying against cairn-mod's public key over
    // the transmitted signing input (Aurora's verification path).
    let auth = state
        .last_authorization
        .lock()
        .unwrap()
        .clone()
        .expect("mock saw an Authorization header");
    let jwt = auth.strip_prefix("Bearer ").expect("Bearer scheme");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);

    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "ES256K");
    assert_eq!(header["typ"], "JWT");

    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], "did:web:cairn-mod.example.test");
    assert_eq!(claims["aud"], "did:web:aurora-locus.example.test");
    assert_eq!(claims["lxm"], "tools.aurora.describeCapabilities");
    // exp - iat = 3600 (the lxm-present cap Aurora enforces).
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        3600
    );

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature =
        Signature::from_der(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).expect("DER signature");
    VerifyingKey::from(&test_signing_key())
        .verify(signing_input.as_bytes(), &signature)
        .expect("signature verifies against cairn-mod's public key");
}

#[tokio::test]
async fn probe_maps_401_to_auth_error() {
    let (addr, _state) = spawn_mock_aurora(MockAuroraBehavior {
        status: StatusCode::UNAUTHORIZED,
        body: json!({"error": "AuthenticationRequired", "message": "bad token"}).to_string(),
    })
    .await;
    let backend = backend_against(addr, Vec::new());
    let err = backend.probe().await.unwrap_err();
    assert!(matches!(err, BackendError::Auth(_)), "{err:?}");
}

#[tokio::test]
async fn probe_maps_500_to_transient_error() {
    let (addr, _state) = spawn_mock_aurora(MockAuroraBehavior {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: String::new(),
    })
    .await;
    let backend = backend_against(addr, Vec::new());
    let err = backend.probe().await.unwrap_err();
    assert!(matches!(err, BackendError::Transient(_)), "{err:?}");
}

#[tokio::test]
async fn probe_malformed_body_errors_clearly() {
    let (addr, _state) = spawn_mock_aurora(MockAuroraBehavior {
        status: StatusCode::OK,
        body: "not json at all".into(),
    })
    .await;
    let backend = backend_against(addr, Vec::new());
    let err = backend.probe().await.unwrap_err();
    assert!(matches!(err, BackendError::Terminal(_)), "{err:?}");
    assert!(
        err.to_string().contains("describeCapabilities"),
        "operator-facing message names the endpoint: {err}"
    );
}

#[tokio::test]
async fn probe_required_capability_present_passes() {
    let (addr, _state) = spawn_mock_aurora(MockAuroraBehavior {
        status: StatusCode::OK,
        body: canonical_body(),
    })
    .await;
    let backend = backend_against(
        addr,
        vec!["mod-events-emit-v1".into(), "audit-trail-v1".into()],
    );
    assert!(backend.probe().await.is_ok());
}

#[tokio::test]
async fn probe_required_capability_absent_returns_capability_not_advertised() {
    let (addr, _state) = spawn_mock_aurora(MockAuroraBehavior {
        status: StatusCode::OK,
        body: canonical_body(),
    })
    .await;
    let backend = backend_against(addr, vec!["runtime-settings-v1".into()]);
    let err = backend.probe().await.unwrap_err();
    match err {
        BackendError::CapabilityNotAdvertised(s) => assert_eq!(s, "runtime-settings-v1"),
        other => panic!("expected CapabilityNotAdvertised, got {other:?}"),
    }
}

// =========================================================================
// backend = "rust" boot path (§13 three-gate pass) + dispatch
// =========================================================================

fn config_from_json(v: serde_json::Value) -> cairn_mod::config::Config {
    serde_json::from_value(v).expect("config deserializes")
}

fn rust_backend_config_json(key_env: &str, service_did: &str) -> serde_json::Value {
    json!({
        "service_did": "did:web:cairn.example.com",
        "service_endpoint": "https://cairn.example.com",
        "db_path": "/tmp/cairn.db",
        "signing_key_path": "/tmp/key.hex",
        "pds_admin": {
            "enabled": true,
            "backend": "rust",
            "rust": {
                "url": "https://aurora.example.com",
                "service_did": service_did,
                "service_signing_key_env": key_env,
                "target_service_did": "did:web:aurora.example.com",
                "acknowledge_v1_8_1_audit_divergence": true,
            },
            "action_map": {
                "warning": "skip",
                "note": "skip",
                "temp_suspension": "suspend_account",
                "indef_suspension": "suspend_account",
                "takedown": "takedown_account",
            },
        },
    })
}

#[tokio::test]
async fn rust_backend_toml_boots_and_dispatches_inspector_only() {
    // Gate 1 input: the env var the config references must be set
    // and non-empty at config load. SAFETY: process-global, but the
    // var name is unique to this test.
    unsafe {
        std::env::set_var("CAIRN_TEST_RUST_BOOT_KEY", TEST_KEY_HEX);
    }
    let cfg = config_from_json(rust_backend_config_json(
        "CAIRN_TEST_RUST_BOOT_KEY",
        "did:web:cairn.example.com",
    ));

    // Gate 1: config parses + resolves (validated_rust_from_toml).
    let policy = PdsAdminPolicy::from_config(&cfg).expect("gate 1: config resolves");
    let Some(PdsAdminBackendConfig::Rust(rust_cfg)) = policy.backend.as_ref() else {
        panic!("expected resolved Rust backend config");
    };
    assert_eq!(rust_cfg.request_timeout, Duration::from_secs(30));

    // Gate 2: audit-divergence inspector passes (ack flag true, no
    // auto-mode rules, no xrpc_gateway).
    validate_audit_divergence_acknowledgment(&policy, None, None)
        .expect("gate 2: inspector passes");

    // Gate 3: backend constructs (key load + DID checks).
    let backend = RustBackend::new(rust_cfg).expect("gate 3: RustBackend::new succeeds");

    // Inspector-only dispatch: every non-probe, non-label method
    // returns CapabilityNotAdvertised (§4.9 first producer).
    let err = backend
        .takedown_account("did:plc:subject", "spam", None, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::CapabilityNotAdvertised(_)));
}

#[test]
fn boot_fails_clearly_on_missing_signing_key_env() {
    // Env var deliberately never set.
    let cfg = config_from_json(rust_backend_config_json(
        "CAIRN_TEST_RUST_BOOT_KEY_UNSET",
        "did:web:cairn.example.com",
    ));
    let err = PdsAdminPolicy::from_config(&cfg).expect_err("missing env var fails gate 1");
    assert!(
        err.to_string().contains("CAIRN_TEST_RUST_BOOT_KEY_UNSET"),
        "operator-facing error names the env var: {err}"
    );
}

#[test]
fn boot_fails_clearly_on_malformed_service_did() {
    unsafe {
        std::env::set_var("CAIRN_TEST_RUST_BOOT_KEY_BADDID", TEST_KEY_HEX);
    }
    let cfg = config_from_json(rust_backend_config_json(
        "CAIRN_TEST_RUST_BOOT_KEY_BADDID",
        "not-a-did",
    ));
    let err = PdsAdminPolicy::from_config(&cfg).expect_err("malformed DID fails gate 1");
    assert!(
        err.to_string().contains("service_did"),
        "operator-facing error names the field: {err}"
    );
}

#[test]
fn boot_fails_clearly_on_removed_oauth_keys() {
    unsafe {
        std::env::set_var("CAIRN_TEST_RUST_BOOT_KEY_OAUTH", TEST_KEY_HEX);
    }
    let mut v = rust_backend_config_json(
        "CAIRN_TEST_RUST_BOOT_KEY_OAUTH",
        "did:web:cairn.example.com",
    );
    v["pds_admin"]["rust"]["scopes"] = json!(["atproto:admin.moderation"]);
    let cfg = config_from_json(v);
    let err = PdsAdminPolicy::from_config(&cfg).expect_err("removed key fails gate 1");
    let msg = err.to_string();
    assert!(
        msg.contains("scopes") && msg.contains("removed in v1.8.1"),
        "migration error names the removed key: {msg}"
    );
}
