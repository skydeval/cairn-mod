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

// =========================================================================
// v1.8.2 — emitEvent dispatch end-to-end (per-release doc §8)
// =========================================================================

use cairn_mod::pds_admin::BackendActionId;

struct MockEmitAurora {
    emit_status: StatusCode,
    emit_body: String,
    /// Captured emitEvent request bodies, in arrival order.
    emit_requests: Mutex<Vec<serde_json::Value>>,
    /// Captured Retry-After to send on error responses.
    retry_after: Option<u32>,
}

async fn emit_event_handler(State(state): State<Arc<MockEmitAurora>>, body: String) -> Response {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    state.emit_requests.lock().unwrap().push(parsed);
    let mut resp = (
        state.emit_status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        state.emit_body.clone(),
    )
        .into_response();
    if let Some(secs) = state.retry_after {
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_str(&secs.to_string()).unwrap(),
        );
    }
    resp
}

/// Mock Aurora serving BOTH describeCapabilities (canonical,
/// advertising `mod-events-emit-v1`) and emitEvent (configurable).
async fn spawn_emit_mock(
    emit_status: StatusCode,
    emit_body: String,
    retry_after: Option<u32>,
) -> (SocketAddr, Arc<MockEmitAurora>) {
    let emit_state = Arc::new(MockEmitAurora {
        emit_status,
        emit_body,
        emit_requests: Mutex::new(Vec::new()),
        retry_after,
    });
    let desc_state = Arc::new(MockAuroraState {
        behavior: MockAuroraBehavior {
            status: StatusCode::OK,
            body: canonical_body(),
        },
        last_authorization: Mutex::new(None),
    });
    let router = Router::new()
        .route(
            "/xrpc/tools.aurora.describeCapabilities",
            get(describe_capabilities).with_state(desc_state),
        )
        .route(
            "/xrpc/tools.aurora.admin.emitEvent",
            axum::routing::post(emit_event_handler).with_state(emit_state.clone()),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    (addr, emit_state)
}

fn emit_success_body(event_id: &str) -> String {
    serde_json::json!({
        "eventId": event_id,
        "auditEntryId": "chain-1",
        "snapshots": [],
        "cascadingActions": []
    })
    .to_string()
}

/// Probe first (populates the capability set from the mock's
/// canonical advertisement), then return the backend ready for
/// emitEvent dispatch.
async fn probed_backend(addr: SocketAddr) -> RustBackend {
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe succeeds");
    backend
}

#[tokio::test]
async fn takedown_account_dispatches_kind_tagged_body_and_returns_event_id() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-100"), None).await;
    let backend = probed_backend(addr).await;

    let id = backend
        .takedown_account("did:plc:subject", "spam", Some("mod notes"), 42)
        .await
        .expect("dispatch succeeds");
    assert_eq!(id, BackendActionId::PerEvent("evt-100".to_string()));

    let requests = state.emit_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let body = &requests[0];
    // Aurora's actual wire contract: kind discriminator, action
    // field, canonical subjects array, no notes on the wire.
    assert_eq!(
        body["action"],
        serde_json::json!({"kind": "TakedownAccount"})
    );
    assert_eq!(
        body["subjects"],
        serde_json::json!([{"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:subject"}])
    );
    assert_eq!(body["rationale"], "spam");
    assert!(body.get("notes").is_none(), "notes never transmitted");
    assert!(
        body.get("event").is_none(),
        "field is `action`, not `event`"
    );
    assert!(
        body.get("subject").is_none(),
        "canonical plural, not legacy"
    );
}

#[tokio::test]
async fn suspend_account_duration_rides_top_level_metadata() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-101"), None).await;
    let backend = probed_backend(addr).await;

    backend
        .suspend_account("did:plc:subject", "spam", Some(7), None, 43)
        .await
        .expect("dispatch succeeds");
    // Indefinite suspension second: no metadata at all.
    backend
        .suspend_account("did:plc:subject", "spam", None, None, 44)
        .await
        .expect("dispatch succeeds");

    let requests = state.emit_requests.lock().unwrap();
    assert_eq!(
        requests[0]["action"],
        serde_json::json!({"kind": "SuspendAccount"})
    );
    assert_eq!(
        requests[0]["metadata"],
        serde_json::json!({"durationDays": 7})
    );
    assert!(requests[1].get("metadata").is_none());
}

#[tokio::test]
async fn restore_account_dispatches_and_discards_event_id() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-102"), None).await;
    let backend = probed_backend(addr).await;

    backend
        .restore_account(
            "did:plc:subject",
            &BackendActionId::new("prior-1"),
            "resolved",
        )
        .await
        .expect("dispatch succeeds");

    let requests = state.emit_requests.lock().unwrap();
    let body = &requests[0];
    assert_eq!(
        body["action"],
        serde_json::json!({"kind": "RestoreAccount"})
    );
    // prior_action_id documented non-transmission (§4.5).
    assert!(!body.to_string().contains("prior-1"));
}

#[tokio::test]
async fn takedown_record_dispatches_strong_ref_subject() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-103"), None).await;
    let backend = probed_backend(addr).await;

    let subject = cairn_mod::pds_admin::Subject::record(
        "did:plc:subject",
        "at://did:plc:subject/app.bsky.feed.post/rkey",
        Some("bafyrecord".to_string()),
    );
    let id = backend
        .takedown_record(&subject, "csam", None, 45)
        .await
        .expect("dispatch succeeds");
    assert_eq!(id, BackendActionId::PerEvent("evt-103".to_string()));

    let requests = state.emit_requests.lock().unwrap();
    let body = &requests[0];
    assert_eq!(
        body["action"],
        serde_json::json!({"kind": "TakedownRecord"})
    );
    assert_eq!(
        body["subjects"],
        serde_json::json!([{
            "$type": "com.atproto.repo.strongRef",
            "uri": "at://did:plc:subject/app.bsky.feed.post/rkey",
            "cid": "bafyrecord"
        }])
    );
}

#[tokio::test]
async fn emit_event_http_errors_map_to_backend_errors() {
    // 400 → Validation
    let (addr, _s) = spawn_emit_mock(
        StatusCode::BAD_REQUEST,
        serde_json::json!({"error": "InvalidEvent", "message": "bad"}).to_string(),
        None,
    )
    .await;
    let backend = probed_backend(addr).await;
    let err = backend
        .takedown_account("did:plc:x", "r", None, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Validation(_)), "{err:?}");

    // 401 → Auth
    let (addr, _s) = spawn_emit_mock(StatusCode::UNAUTHORIZED, String::new(), None).await;
    let backend = probed_backend(addr).await;
    let err = backend
        .takedown_account("did:plc:x", "r", None, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Auth(_)), "{err:?}");

    // 429 with Retry-After → Transient carrying the hint
    let (addr, _s) = spawn_emit_mock(StatusCode::TOO_MANY_REQUESTS, String::new(), Some(45)).await;
    let backend = probed_backend(addr).await;
    let err = backend
        .takedown_account("did:plc:x", "r", None, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Transient(_)), "{err:?}");
    assert_eq!(err.retry_after_seconds(), Some(45));

    // 500 → Transient
    let (addr, _s) = spawn_emit_mock(StatusCode::INTERNAL_SERVER_ERROR, String::new(), None).await;
    let backend = probed_backend(addr).await;
    let err = backend
        .takedown_account("did:plc:x", "r", None, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Transient(_)), "{err:?}");
}

#[tokio::test]
async fn unprobed_backend_still_gates_on_capability() {
    // Without a probe, the capability set is empty — every
    // dispatch returns CapabilityNotAdvertised (and would fire
    // the should_warn path at the dispatch layer).
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-x"), None).await;
    let backend = backend_against(addr, Vec::new());
    let err = backend
        .takedown_account("did:plc:x", "r", None, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::CapabilityNotAdvertised(_)));
    assert!(
        state.emit_requests.lock().unwrap().is_empty(),
        "no HTTP call made"
    );
}
