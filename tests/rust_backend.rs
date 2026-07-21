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
                            "delete_account": "delete_account",
                "quarantine_blob": "quarantine_blob",
                "restore_blob": "restore_blob",
                "delete_blob": "delete_blob",
                "resolve_report": "resolve_report",
                "dismiss_report": "dismiss_report",
                "resolve_appeal": "resolve_appeal",
                "escalate_appeal": "escalate_appeal",
                "send_email": "send_email",
                "update_subject_status": "update_subject_status",
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

// =========================================================================
// v1.8.3 — moderator-read dispatch end-to-end (per-release doc §8)
// =========================================================================

use cairn_mod::pds_admin::rust::read_types::{
    EventWithContext, PaginatedResponse, QueryEventsFilter, QueryStatusesFilter, ReadSubject,
    StatusWithContext,
};

struct MockReadAurora {
    events_status: StatusCode,
    events_body: String,
    statuses_body: String,
    /// Full query strings seen, in arrival order.
    seen_queries: Mutex<Vec<String>>,
}

async fn read_events_handler(
    State(state): State<Arc<MockReadAurora>>,
    uri: axum::http::Uri,
) -> Response {
    state
        .seen_queries
        .lock()
        .unwrap()
        .push(uri.query().unwrap_or("").to_string());
    (
        state.events_status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        state.events_body.clone(),
    )
        .into_response()
}

async fn read_statuses_handler(
    State(state): State<Arc<MockReadAurora>>,
    uri: axum::http::Uri,
) -> Response {
    state
        .seen_queries
        .lock()
        .unwrap()
        .push(uri.query().unwrap_or("").to_string());
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        state.statuses_body.clone(),
    )
        .into_response()
}

/// Mock Aurora with describeCapabilities (canonical, advertising
/// `moderator-activity-v1`) + both GET read endpoints.
async fn spawn_read_mock(
    events_status: StatusCode,
    events_body: String,
    statuses_body: String,
) -> (SocketAddr, Arc<MockReadAurora>) {
    let read_state = Arc::new(MockReadAurora {
        events_status,
        events_body,
        statuses_body,
        seen_queries: Mutex::new(Vec::new()),
    });
    let desc_state = Arc::new(MockAuroraState {
        behavior: MockAuroraBehavior {
            status: StatusCode::OK,
            body: json!({
                "families": {"tools.aurora.moderator": ["queryEvents", "queryStatuses"]},
                "extensions": [
                    {"name": "mod-events-emit-v1"},
                    {"name": "moderator-activity-v1"}
                ],
                "implementation": "aurora-locus",
                "version": "0.10.0"
            })
            .to_string(),
        },
        last_authorization: Mutex::new(None),
    });
    let router = Router::new()
        .route(
            "/xrpc/tools.aurora.describeCapabilities",
            get(describe_capabilities).with_state(desc_state),
        )
        .route(
            "/xrpc/tools.aurora.moderator.queryEvents",
            get(read_events_handler).with_state(read_state.clone()),
        )
        .route(
            "/xrpc/tools.aurora.moderator.queryStatuses",
            get(read_statuses_handler).with_state(read_state.clone()),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    (addr, read_state)
}

fn canonical_events_body() -> String {
    json!({
        "items": [
            {
                "id": 42,
                "eventType": "account_takedown",
                "actorDid": "did:web:cairn-mod.example.test",
                "actorHandle": null,
                "subject": {"$type": "com.atproto.repo.strongRef",
                            "uri": "at://did:plc:x/app.bsky.feed.post/r",
                            "cid": "bafyr"},
                "subjectHandle": null,
                "details": {"rationale": "spam"},
                "createdAt": "2026-07-20T12:00:00Z"
            }
        ],
        "cursor": "next-page"
    })
    .to_string()
}

fn canonical_statuses_body() -> String {
    json!({
        "items": [
            {
                "id": 7,
                "did": "did:plc:x",
                "handle": null,
                "action": "takedown",
                "reason": "spam",
                "moderatedBy": "did:plc:mod",
                "moderatedByHandle": null,
                "moderatedAt": "2026-07-20T12:00:00Z",
                "expiresAt": null,
                "reversed": false,
                "reversedAt": null,
                "reportId": null
            }
        ],
        "cursor": null
    })
    .to_string()
}

#[tokio::test]
async fn query_events_end_to_end_with_camel_case_params() {
    let (addr, state) = spawn_read_mock(
        StatusCode::OK,
        canonical_events_body(),
        canonical_statuses_body(),
    )
    .await;
    let backend = backend_against(addr, Vec::new());
    backend
        .probe()
        .await
        .expect("probe populates capability set");

    let filter = QueryEventsFilter {
        event_type: Some("account_takedown".to_string()),
        subject_did: Some("did:plc:x".to_string()),
        ..Default::default()
    };
    let page: PaginatedResponse<EventWithContext> = backend
        .query_events(filter, Some("cur0"), Some(25))
        .await
        .expect("query succeeds");

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].event_type, "account_takedown");
    assert!(matches!(
        page.items[0].subject,
        Some(ReadSubject::Record { ref cid, .. }) if cid == "bafyr"
    ));
    assert_eq!(page.cursor.as_deref(), Some("next-page"));

    // Wire query string: camelCase param names, snake_case
    // event-type VALUE, pagination appended, no fabricated params.
    let qs = state.seen_queries.lock().unwrap()[0].clone();
    assert!(qs.contains("eventType=account_takedown"), "{qs}");
    assert!(qs.contains("subjectDid=did%3Aplc%3Ax"), "{qs}");
    assert!(qs.contains("cursor=cur0"), "{qs}");
    assert!(qs.contains("limit=25"), "{qs}");
    assert!(!qs.contains("sortOrder"), "{qs}");
}

#[tokio::test]
async fn query_statuses_end_to_end() {
    let (addr, state) = spawn_read_mock(
        StatusCode::OK,
        canonical_events_body(),
        canonical_statuses_body(),
    )
    .await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let filter = QueryStatusesFilter {
        did: Some("did:plc:x".to_string()),
        subject_type: Some("account".to_string()),
        include_reversed: Some(true),
        ..Default::default()
    };
    let page: PaginatedResponse<StatusWithContext> = backend
        .query_statuses(filter, None, None)
        .await
        .expect("query succeeds");

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].action, "takedown");
    assert!(page.cursor.is_none());

    let qs = state.seen_queries.lock().unwrap()[0].clone();
    assert!(qs.contains("subjectType=account"), "{qs}");
    assert!(qs.contains("includeReversed=true"), "{qs}");
}

#[tokio::test]
async fn query_events_outdated_cursor_maps_to_validation_with_error_code() {
    // OutdatedCursor is HTTP 400 with error field "OutdatedCursor"
    // (aurora defs.rs:342-350) → Validation with the RemoteError
    // marker carrying the code (detectable via error_code()).
    let (addr, _state) = spawn_read_mock(
        StatusCode::BAD_REQUEST,
        json!({"error": "OutdatedCursor"}).to_string(),
        canonical_statuses_body(),
    )
    .await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let err = backend
        .query_events(QueryEventsFilter::default(), Some("stale"), None)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Validation(_)), "{err:?}");
    assert_eq!(err.error_code(), Some("OutdatedCursor"));
}

#[tokio::test]
async fn query_events_5xx_and_429_map_like_v1_8_2() {
    let (addr, _state) = spawn_read_mock(
        StatusCode::INTERNAL_SERVER_ERROR,
        String::new(),
        canonical_statuses_body(),
    )
    .await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");
    let err = backend
        .query_events(QueryEventsFilter::default(), None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Transient(_)), "{err:?}");
}

#[tokio::test]
async fn unprobed_backend_gates_reads_on_moderator_activity() {
    let (addr, state) = spawn_read_mock(
        StatusCode::OK,
        canonical_events_body(),
        canonical_statuses_body(),
    )
    .await;
    let backend = backend_against(addr, Vec::new());
    // No probe → empty capability set → CapabilityNotAdvertised,
    // and no read HTTP call is made.
    let err = backend
        .query_events(QueryEventsFilter::default(), None, None)
        .await
        .unwrap_err();
    match &err {
        BackendError::CapabilityNotAdvertised(s) => assert_eq!(s, "moderator-activity-v1"),
        other => panic!("expected CapabilityNotAdvertised, got {other:?}"),
    }
    assert!(state.seen_queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ozone_backend_reads_return_unsupported() {
    let cfg = cairn_mod::pds_admin::OzoneBackendConfig {
        pds_url: url::Url::parse("https://bsky.example.test").unwrap(),
        admin_password: cairn_mod::pds_admin::AdminPassword::new("pw".into()),
        request_timeout: Duration::from_secs(5),
    };
    let ozone = cairn_mod::pds_admin::OzoneBackend::new(&cfg).unwrap();
    let ev = ozone
        .query_events(QueryEventsFilter::default(), None, None)
        .await;
    assert!(matches!(ev, Err(BackendError::Unsupported)));
    let st = ozone
        .query_statuses(QueryStatusesFilter::default(), None, None)
        .await;
    assert!(matches!(st, Err(BackendError::Unsupported)));
}

// =========================================================================
// v1.8.4 — moderator single-fetch / subject / appeal reads (§8)
// =========================================================================

use cairn_mod::pds_admin::rust::read_types::{
    AppealDetail, AppealView, ListAppealsFilter, SubjectContextResponse, SubjectHistoryFilter,
};

struct MockModeratorReads {
    /// Applied to every read endpoint (describeCapabilities is
    /// always 200).
    status: StatusCode,
    get_event_body: String,
    subject_context_body: String,
    subject_history_body: String,
    list_appeals_body: String,
    get_appeal_body: String,
    /// (path, query) pairs seen, in arrival order.
    seen: Mutex<Vec<(String, String)>>,
}

async fn v184_read_handler(
    State(state): State<Arc<MockModeratorReads>>,
    uri: axum::http::Uri,
) -> Response {
    let path = uri.path().to_string();
    state
        .seen
        .lock()
        .unwrap()
        .push((path.clone(), uri.query().unwrap_or("").to_string()));
    let body = match path.rsplit('/').next().unwrap_or("") {
        "tools.aurora.moderator.getEvent" => state.get_event_body.clone(),
        "tools.aurora.moderator.getSubjectContext" => state.subject_context_body.clone(),
        "tools.aurora.moderator.getSubjectHistory" => state.subject_history_body.clone(),
        "tools.aurora.moderator.listAppeals" => state.list_appeals_body.clone(),
        "tools.aurora.moderator.getAppeal" => state.get_appeal_body.clone(),
        other => panic!("unexpected mock path {other}"),
    };
    (
        state.status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Mock Aurora advertising `advertised` capability strings, serving
/// all five v1.8.4 moderator-read endpoints from one state.
async fn spawn_v184_mock(
    advertised: &[&str],
    status: StatusCode,
) -> (SocketAddr, Arc<MockModeratorReads>) {
    let read_state = Arc::new(MockModeratorReads {
        status,
        get_event_body: canonical_event_detail_body(),
        subject_context_body: canonical_subject_context_body(),
        subject_history_body: canonical_statuses_body(),
        list_appeals_body: canonical_appeals_page_body(),
        get_appeal_body: canonical_appeal_detail_body(),
        seen: Mutex::new(Vec::new()),
    });
    let desc_state = Arc::new(MockAuroraState {
        behavior: MockAuroraBehavior {
            status: StatusCode::OK,
            body: json!({
                "families": {"tools.aurora.moderator": [
                    "queryEvents", "queryStatuses", "getEvent",
                    "getSubjectContext", "getSubjectHistory",
                    "listAppeals", "getAppeal"
                ]},
                "extensions": advertised
                    .iter()
                    .map(|name| json!({"name": name}))
                    .collect::<Vec<_>>(),
                "implementation": "aurora-locus",
                "version": "0.11.0"
            })
            .to_string(),
        },
        last_authorization: Mutex::new(None),
    });
    let mut router = Router::new().route(
        "/xrpc/tools.aurora.describeCapabilities",
        get(describe_capabilities).with_state(desc_state),
    );
    for nsid in [
        "tools.aurora.moderator.getEvent",
        "tools.aurora.moderator.getSubjectContext",
        "tools.aurora.moderator.getSubjectHistory",
        "tools.aurora.moderator.listAppeals",
        "tools.aurora.moderator.getAppeal",
    ] {
        router = router.route(
            &format!("/xrpc/{nsid}"),
            get(v184_read_handler).with_state(read_state.clone()),
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    (addr, read_state)
}

const ALL_V184_CAPS: &[&str] = &[
    "mod-events-emit-v1",
    "moderator-activity-v1",
    "subject-context-v1",
    "subject-history-v1",
    "appeals-v1",
];

fn canonical_event_detail_body() -> String {
    // getEvent returns a bare EventWithContext (aurora_moderator.rs
    // :419-423) — same item shape as queryEvents, no page wrapper.
    json!({
        "id": 42,
        "eventType": "account_takedown",
        "actorDid": "did:web:cairn-mod.example.test",
        "actorHandle": null,
        "subject": {"$type": "com.atproto.repo.strongRef",
                    "uri": "at://did:plc:x/app.bsky.feed.post/r",
                    "cid": "bafyr"},
        "subjectHandle": null,
        "details": {"rationale": "spam"},
        "createdAt": "2026-07-20T12:00:00Z"
    })
    .to_string()
}

fn canonical_subject_context_body() -> String {
    json!({
        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"},
        "primaryDid": "did:plc:x",
        "handle": "user.example.com",
        "currentStatus": {
            "takedownRef": "TAKEDOWN-9",
            "deactivatedAt": null,
            "activeAction": "takedown"
        },
        "recentActions": [],
        "relatedReports": [],
        "relatedAppeals": [{
            "id": 5,
            "appellantDid": "did:plc:x",
            "appellantHandle": null,
            "status": "pending",
            "submittedAt": "2026-07-20T13:00:00Z"
        }]
    })
    .to_string()
}

fn canonical_appeals_page_body() -> String {
    json!({
        "items": [{
            "id": 5,
            "status": "pending",
            "submitterDid": "did:plc:x",
            "submitterHandle": null,
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"},
            "reason": "wrongful takedown",
            "details": null,
            "submittedAt": "2026-07-20T13:00:00Z",
            "originalActionSummary": {"kind": "moderation", "id": 7, "summary": "takedown: spam"},
            "resolution": null
        }],
        "cursor": "appeal-page-2"
    })
    .to_string()
}

fn canonical_appeal_detail_body() -> String {
    json!({
        "id": 5,
        "status": "approved",
        "submitterDid": "did:plc:x",
        "submitterHandle": null,
        "subject": null,
        "reason": "wrongful takedown",
        "details": null,
        "submittedAt": "2026-07-20T13:00:00Z",
        "originalActionSummary": null,
        "resolution": {
            "reviewedBy": "did:plc:mod",
            "reviewedByHandle": null,
            "reviewedAt": "2026-07-21T09:00:00Z",
            "decision": "overturned",
            "notes": null
        },
        "timeline": [
            {"kind": "submitted", "at": "2026-07-20T13:00:00Z",
             "byDid": "did:plc:x", "byHandle": null, "note": null},
            {"kind": "reviewed", "at": "2026-07-21T09:00:00Z",
             "byDid": "did:plc:mod", "byHandle": null, "note": null}
        ]
    })
    .to_string()
}

#[tokio::test]
async fn get_event_end_to_end() {
    let (addr, state) = spawn_v184_mock(ALL_V184_CAPS, StatusCode::OK).await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let event: EventWithContext = backend.get_event(42).await.expect("get_event succeeds");
    assert_eq!(event.id, 42);
    assert_eq!(event.event_type, "account_takedown");
    assert!(matches!(
        event.subject,
        Some(ReadSubject::Record { ref cid, .. }) if cid == "bafyr"
    ));

    let (path, qs) = state.seen.lock().unwrap()[0].clone();
    assert!(path.ends_with("tools.aurora.moderator.getEvent"), "{path}");
    assert_eq!(qs, "id=42", "single-fetch: id only, no pagination");
}

#[tokio::test]
async fn get_subject_context_end_to_end() {
    let (addr, state) = spawn_v184_mock(ALL_V184_CAPS, StatusCode::OK).await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let ctx: SubjectContextResponse = backend
        .get_subject_context("did:plc:x")
        .await
        .expect("get_subject_context succeeds");
    assert_eq!(ctx.primary_did.as_deref(), Some("did:plc:x"));
    assert_eq!(
        ctx.current_status.unwrap().active_action.as_deref(),
        Some("takedown")
    );
    assert_eq!(ctx.related_appeals[0].id, 5);

    let (path, qs) = state.seen.lock().unwrap()[0].clone();
    assert!(
        path.ends_with("tools.aurora.moderator.getSubjectContext"),
        "{path}"
    );
    assert_eq!(qs, "did=did%3Aplc%3Ax", "plain-DID param, no pagination");
}

#[tokio::test]
async fn get_subject_history_end_to_end_with_filters() {
    let (addr, state) = spawn_v184_mock(ALL_V184_CAPS, StatusCode::OK).await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let filter = SubjectHistoryFilter {
        action: Some("takedown".to_string()),
        direction: Some("asc".to_string()),
    };
    let page: PaginatedResponse<StatusWithContext> = backend
        .get_subject_history("did:plc:x", filter, Some("cur0"), Some(10))
        .await
        .expect("get_subject_history succeeds");

    // History rows are action rows — the v1.8.3 StatusWithContext
    // shape, not events.
    assert_eq!(page.items[0].action, "takedown");

    let (path, qs) = state.seen.lock().unwrap()[0].clone();
    assert!(
        path.ends_with("tools.aurora.moderator.getSubjectHistory"),
        "{path}"
    );
    assert!(qs.contains("did=did%3Aplc%3Ax"), "{qs}");
    assert!(qs.contains("action=takedown"), "{qs}");
    assert!(qs.contains("direction=asc"), "{qs}");
    assert!(qs.contains("cursor=cur0"), "{qs}");
    assert!(qs.contains("limit=10"), "{qs}");
}

#[tokio::test]
async fn list_appeals_end_to_end_with_filters() {
    let (addr, state) = spawn_v184_mock(ALL_V184_CAPS, StatusCode::OK).await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let filter = ListAppealsFilter {
        status: Some("pending".to_string()),
        appellant: Some("did:plc:x".to_string()),
        submitted_after: Some("2026-07-01T00:00:00Z".to_string()),
        ..Default::default()
    };
    let page: PaginatedResponse<AppealView> = backend
        .list_appeals(filter, None, Some(25))
        .await
        .expect("list_appeals succeeds");

    assert_eq!(page.items[0].status, "pending");
    assert_eq!(page.items[0].submitter_did, "did:plc:x");
    assert_eq!(page.cursor.as_deref(), Some("appeal-page-2"));

    let (path, qs) = state.seen.lock().unwrap()[0].clone();
    assert!(
        path.ends_with("tools.aurora.moderator.listAppeals"),
        "{path}"
    );
    assert!(qs.contains("status=pending"), "{qs}");
    assert!(qs.contains("appellant=did%3Aplc%3Ax"), "{qs}");
    assert!(qs.contains("submittedAfter="), "camelCase bound: {qs}");
    assert!(!qs.contains("reviewer"), "None omitted: {qs}");
    assert!(qs.contains("limit=25"), "{qs}");
}

#[tokio::test]
async fn get_appeal_end_to_end_flattened_detail() {
    let (addr, state) = spawn_v184_mock(ALL_V184_CAPS, StatusCode::OK).await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let detail: AppealDetail = backend.get_appeal(5).await.expect("get_appeal succeeds");
    assert_eq!(detail.view.id, 5);
    assert_eq!(detail.view.status, "approved");
    assert_eq!(
        detail.view.resolution.as_ref().unwrap().decision.as_deref(),
        Some("overturned")
    );
    assert_eq!(detail.timeline.len(), 2);
    assert_eq!(detail.timeline[0].kind, "submitted");

    let (path, qs) = state.seen.lock().unwrap()[0].clone();
    assert!(path.ends_with("tools.aurora.moderator.getAppeal"), "{path}");
    assert_eq!(qs, "id=5");
}

#[tokio::test]
async fn single_fetch_404_maps_to_terminal() {
    // Unknown-id getEvent/getAppeal → upstream 404 → Terminal
    // (exit 18 at the CLI) per map_rust_backend_http_error.
    let (addr, _state) = spawn_v184_mock(ALL_V184_CAPS, StatusCode::NOT_FOUND).await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let ev = backend.get_event(999_999).await.unwrap_err();
    assert!(matches!(ev, BackendError::Terminal(_)), "{ev:?}");
    let ap = backend.get_appeal(999_999).await.unwrap_err();
    assert!(matches!(ap, BackendError::Terminal(_)), "{ap:?}");
}

#[tokio::test]
async fn v184_reads_5xx_map_to_transient() {
    let (addr, _state) = spawn_v184_mock(ALL_V184_CAPS, StatusCode::INTERNAL_SERVER_ERROR).await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    let err = backend
        .list_appeals(ListAppealsFilter::default(), None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Transient(_)), "{err:?}");
}

#[tokio::test]
async fn capability_families_gate_independently() {
    // Aurora advertises only the v1.8.3 families: getEvent (which
    // shares moderator-activity) dispatches; the three new
    // families gate their endpoints with the family-specific wire
    // string, and no HTTP call is made for gated reads.
    let (addr, state) = spawn_v184_mock(
        &["mod-events-emit-v1", "moderator-activity-v1"],
        StatusCode::OK,
    )
    .await;
    let backend = backend_against(addr, Vec::new());
    backend.probe().await.expect("probe");

    backend
        .get_event(42)
        .await
        .expect("getEvent shares moderator-activity");

    let cases: [(BackendError, &str); 4] = [
        (
            backend.get_subject_context("did:plc:x").await.unwrap_err(),
            "subject-context-v1",
        ),
        (
            backend
                .get_subject_history("did:plc:x", SubjectHistoryFilter::default(), None, None)
                .await
                .unwrap_err(),
            "subject-history-v1",
        ),
        (
            backend
                .list_appeals(ListAppealsFilter::default(), None, None)
                .await
                .unwrap_err(),
            "appeals-v1",
        ),
        (backend.get_appeal(5).await.unwrap_err(), "appeals-v1"),
    ];
    for (err, expected_wire) in cases {
        match &err {
            BackendError::CapabilityNotAdvertised(s) => assert_eq!(s, expected_wire),
            other => panic!("expected CapabilityNotAdvertised({expected_wire}), got {other:?}"),
        }
    }
    // Only the successful getEvent reached the wire.
    let seen = state.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].0.ends_with("getEvent"), "{seen:?}");
}

#[tokio::test]
async fn ozone_backend_v1_8_4_reads_return_unsupported() {
    let cfg = cairn_mod::pds_admin::OzoneBackendConfig {
        pds_url: url::Url::parse("https://bsky.example.test").unwrap(),
        admin_password: cairn_mod::pds_admin::AdminPassword::new("pw".into()),
        request_timeout: Duration::from_secs(5),
    };
    let ozone = cairn_mod::pds_admin::OzoneBackend::new(&cfg).unwrap();
    assert!(matches!(
        ozone.get_event(1).await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone.get_subject_context("did:plc:x").await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone
            .get_subject_history("did:plc:x", SubjectHistoryFilter::default(), None, None)
            .await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone
            .list_appeals(ListAppealsFilter::default(), None, None)
            .await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone.get_appeal(1).await,
        Err(BackendError::Unsupported)
    ));
}

// =========================================================================
// v1.8.5 — action-surface enrichment: 10 new emitEvent dispatches (§8)
// =========================================================================

use cairn_mod::pds_admin::Subject;
use cairn_mod::pds_admin::rust::action_types::{
    ActionResponse, AppealDecision, BlobSubject, ReportResolution, SubjectStatus,
};

fn emit_success_with_cascade(event_id: &str, cascades: &[&str]) -> String {
    serde_json::json!({
        "eventId": event_id,
        "auditEntryId": "chain-9",
        "snapshots": [
            {"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:subject"},
             "snapshotId": "snap-1"}
        ],
        "cascadingActions": cascades
    })
    .to_string()
}

#[tokio::test]
async fn delete_account_wire_shape_and_full_response() {
    let (addr, state) = spawn_emit_mock(
        StatusCode::OK,
        emit_success_with_cascade("evt-del", &[]),
        None,
    )
    .await;
    let backend = probed_backend(addr).await;

    let resp: ActionResponse = backend
        .delete_account("did:plc:subject", "tos-violation", 42)
        .await
        .expect("delete_account succeeds");
    assert_eq!(resp.event_id, "evt-del");
    assert_eq!(resp.audit_entry_id, "chain-9");
    assert_eq!(resp.snapshots.len(), 1);
    assert!(resp.cascading_actions.is_empty());

    let body = state.emit_requests.lock().unwrap()[0].clone();
    // PascalCase kind discriminator (R3 NEW-R3-1), canonical
    // subjects array, rationale field, no notes.
    assert_eq!(body["action"], serde_json::json!({"kind": "DeleteAccount"}));
    assert_eq!(
        body["subjects"],
        serde_json::json!([{"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:subject"}])
    );
    assert_eq!(body["rationale"], "tos-violation");
    assert!(body.get("notes").is_none());
    assert!(body.get("subject").is_none(), "legacy shape never sent");
}

#[tokio::test]
async fn blob_actions_dispatch_repo_blob_ref() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-blob"), None).await;
    let backend = probed_backend(addr).await;

    let with_uri = BlobSubject {
        did: "did:plc:subject".to_string(),
        cid: "bafyblob".to_string(),
        record_uri: Some("at://did:plc:subject/app.bsky.feed.post/r".to_string()),
    };
    backend
        .quarantine_blob(&with_uri, "malware", 1)
        .await
        .expect("quarantine succeeds");

    let bare = BlobSubject {
        did: "did:plc:subject".to_string(),
        cid: "bafyblob".to_string(),
        record_uri: None,
    };
    backend
        .delete_blob(&bare, "csam-hash-match", 2)
        .await
        .expect("delete succeeds");

    let bodies = state.emit_requests.lock().unwrap().clone();
    assert_eq!(
        bodies[0]["action"],
        serde_json::json!({"kind": "QuarantineBlob"})
    );
    assert_eq!(
        bodies[0]["subjects"],
        serde_json::json!([{
            "$type": "com.atproto.admin.defs#repoBlobRef",
            "did": "did:plc:subject",
            "cid": "bafyblob",
            "record_uri": "at://did:plc:subject/app.bsky.feed.post/r"
        }])
    );
    assert_eq!(
        bodies[1]["action"],
        serde_json::json!({"kind": "DeleteBlob"})
    );
    assert!(
        bodies[1]["subjects"][0].get("record_uri").is_none(),
        "record_uri omitted when absent"
    );
}

#[tokio::test]
async fn restore_blob_returns_unit_and_sends_unit_variant() {
    let (addr, state) =
        spawn_emit_mock(StatusCode::OK, emit_success_body("evt-restore"), None).await;
    let backend = probed_backend(addr).await;

    let blob = BlobSubject {
        did: "did:plc:subject".to_string(),
        cid: "bafyblob".to_string(),
        record_uri: None,
    };
    let prior = BackendActionId::PerEvent("evt-quarantine".to_string());
    backend
        .restore_blob(&blob, &prior, "appeal upheld")
        .await
        .expect("restore succeeds");

    let body = state.emit_requests.lock().unwrap()[0].clone();
    // Unit variant on the wire; the prior action id never rides it.
    assert_eq!(body["action"], serde_json::json!({"kind": "RestoreBlob"}));
    assert!(!body.to_string().contains("evt-quarantine"));
}

#[tokio::test]
async fn resolve_report_embedded_id_wire_shape() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-rr"), None).await;
    let backend = probed_backend(addr).await;

    // Record-targeted report: crate Subject with uri+cid maps to a
    // strongRef wire subject per Aurora's from_columns precedence.
    let subject = Subject::record(
        "did:plc:subject",
        "at://did:plc:subject/app.bsky.feed.post/r",
        Some("bafyrec".to_string()),
    );
    backend
        .resolve_report(&subject, 7, ReportResolution::Acknowledged, "reviewed", 3)
        .await
        .expect("resolve_report succeeds");

    let body = state.emit_requests.lock().unwrap()[0].clone();
    assert_eq!(
        body["action"],
        serde_json::json!({"kind": "ResolveReport", "reportId": 7, "resolution": "acknowledged"})
    );
    assert_eq!(body["subjects"][0]["$type"], "com.atproto.repo.strongRef");
    assert_eq!(body["subjects"][0]["cid"], "bafyrec");
}

#[tokio::test]
async fn dismiss_report_blob_subject_via_from_columns_precedence() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-dr"), None).await;
    let backend = probed_backend(addr).await;

    // cid without uri → Blob wire subject (Aurora's from_columns
    // precedence, mirrored by wire_subject_from).
    let subject = Subject {
        did: "did:plc:subject".to_string(),
        at_uri: None,
        cid: Some("bafyblob".to_string()),
    };
    backend
        .dismiss_report(&subject, 8, "duplicate", 4)
        .await
        .expect("dismiss_report succeeds");

    let body = state.emit_requests.lock().unwrap()[0].clone();
    assert_eq!(
        body["action"],
        serde_json::json!({"kind": "DismissReport", "reportId": 8})
    );
    assert_eq!(
        body["subjects"][0]["$type"],
        "com.atproto.admin.defs#repoBlobRef"
    );
}

#[tokio::test]
async fn resolve_appeal_approve_surfaces_cascade() {
    let (addr, state) = spawn_emit_mock(
        StatusCode::OK,
        emit_success_with_cascade("evt-appeal", &["evt-reversal"]),
        None,
    )
    .await;
    let backend = probed_backend(addr).await;

    let subject = Subject::account("did:plc:subject");
    let resp = backend
        .resolve_appeal(&subject, 9, AppealDecision::Approve, "appeal upheld", 5)
        .await
        .expect("resolve_appeal succeeds");
    assert_eq!(resp.cascading_actions, vec!["evt-reversal".to_string()]);

    let body = state.emit_requests.lock().unwrap()[0].clone();
    // Wire field carrying the decision is `resolution`, snake_case
    // value; kind stays PascalCase.
    assert_eq!(
        body["action"],
        serde_json::json!({"kind": "ResolveAppeal", "appealId": 9, "resolution": "approve"})
    );
}

#[tokio::test]
async fn escalate_appeal_and_update_subject_status_wire_shapes() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-x"), None).await;
    let backend = probed_backend(addr).await;

    backend
        .escalate_appeal(&Subject::account("did:plc:subject"), 11, "needs senior", 6)
        .await
        .expect("escalate succeeds");
    backend
        .update_subject_status("did:plc:subject", SubjectStatus::Deactivated, "cooldown", 7)
        .await
        .expect("update status succeeds");

    let bodies = state.emit_requests.lock().unwrap().clone();
    assert_eq!(
        bodies[0]["action"],
        serde_json::json!({"kind": "EscalateAppeal", "appealId": 11})
    );
    assert_eq!(
        bodies[1]["action"],
        serde_json::json!({"kind": "UpdateSubjectStatus", "status": "deactivated"})
    );
}

#[tokio::test]
async fn send_email_wire_shape_omits_absent_template() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-mail"), None).await;
    let backend = probed_backend(addr).await;

    backend
        .send_email(
            "did:plc:subject",
            None,
            "Account notice",
            "Your account was flagged.",
            "notify-owner",
            8,
        )
        .await
        .expect("send_email succeeds");

    let body = state.emit_requests.lock().unwrap()[0].clone();
    // Wire field is `subject` (the email subject line), template
    // omitted when None; rationale required and separate.
    assert_eq!(
        body["action"],
        serde_json::json!({
            "kind": "SendEmail",
            "subject": "Account notice",
            "body": "Your account was flagged."
        })
    );
    assert_eq!(body["rationale"], "notify-owner");
}

#[tokio::test]
async fn admin_gated_methods_map_403_to_auth() {
    // Aurora's check_role gates DeleteAccount | SendEmail at Admin+
    // (R1 LB-B); an under-privileged service DID sees 403 → Auth.
    let forbidden_body = serde_json::json!({
        "error": "PermissionDenied",
        "message": "action requires Admin+ role; caller has Moderator"
    })
    .to_string();
    let (addr, _state) = spawn_emit_mock(StatusCode::FORBIDDEN, forbidden_body, None).await;
    let backend = probed_backend(addr).await;

    let del = backend
        .delete_account("did:plc:subject", "tos", 1)
        .await
        .unwrap_err();
    assert!(matches!(del, BackendError::Auth(_)), "{del:?}");
    let mail = backend
        .send_email("did:plc:subject", None, "s", "b", "r", 2)
        .await
        .unwrap_err();
    assert!(matches!(mail, BackendError::Auth(_)), "{mail:?}");
}

#[tokio::test]
async fn record_shaped_subject_without_cid_rejects_before_dispatch() {
    let (addr, state) = spawn_emit_mock(StatusCode::OK, emit_success_body("evt-nope"), None).await;
    let backend = probed_backend(addr).await;

    let partial = Subject {
        did: "did:plc:subject".to_string(),
        at_uri: Some("at://did:plc:subject/app.bsky.feed.post/r".to_string()),
        cid: None,
    };
    let err = backend
        .resolve_report(&partial, 7, ReportResolution::Resolved, "r", 1)
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Validation(_)), "{err:?}");
    assert!(state.emit_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ozone_backend_v1_8_5_actions_return_unsupported() {
    let cfg = cairn_mod::pds_admin::OzoneBackendConfig {
        pds_url: url::Url::parse("https://bsky.example.test").unwrap(),
        admin_password: cairn_mod::pds_admin::AdminPassword::new("pw".into()),
        request_timeout: Duration::from_secs(5),
    };
    let ozone = cairn_mod::pds_admin::OzoneBackend::new(&cfg).unwrap();
    let blob = BlobSubject {
        did: "did:plc:x".to_string(),
        cid: "bafyblob".to_string(),
        record_uri: None,
    };
    let subject = Subject::account("did:plc:x");
    let prior = BackendActionId::PerEvent("evt-1".to_string());

    assert!(matches!(
        ozone.delete_account("did:plc:x", "r", 1).await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone.quarantine_blob(&blob, "r", 1).await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone.restore_blob(&blob, &prior, "r").await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone.delete_blob(&blob, "r", 1).await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone
            .resolve_report(&subject, 1, ReportResolution::Resolved, "r", 1)
            .await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone.dismiss_report(&subject, 1, "r", 1).await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone
            .resolve_appeal(&subject, 1, AppealDecision::Deny, "r", 1)
            .await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone.escalate_appeal(&subject, 1, "r", 1).await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone.send_email("did:plc:x", None, "s", "b", "r", 1).await,
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        ozone
            .update_subject_status("did:plc:x", SubjectStatus::Active, "r", 1)
            .await,
        Err(BackendError::Unsupported)
    ));
}

// =========================================================================
// v1.8.6 — audit-trail reads + cross-verify (§8)
// =========================================================================

use cairn_mod::cli::audit_cross_verify::{self, CrossVerifyOutcome};
use cairn_mod::pds_admin::record_pds_admin_call;
use cairn_mod::pds_admin::rust::action_types::ActionResponse as UpstreamActionResponse;
use cairn_mod::pds_admin::rust::audit_types::{AuditEntryLookup, AuditTrailFilter};
use cairn_mod::pds_admin::rust::upstream_verify::{CanonicalFields, build_canonical_v09};

fn sha256_hex_of(s: &str) -> String {
    hex::encode(proto_blue_crypto_shim(s))
}

fn proto_blue_crypto_shim(s: &str) -> [u8; 32] {
    // The test crate doesn't depend on proto-blue directly; SHA-256
    // via k256's re-exported sha2 keeps the fixture self-contained.
    use k256::sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

/// A hash-valid upstream entry (genesis, repoRef subject) as the
/// wire JSON Aurora's serde would emit, plus its stored-form hash.
fn upstream_entry_json(
    sequence: i64,
    event_id: Option<i64>,
    prev_hash: Option<&str>,
    rationale: &str,
) -> (serde_json::Value, String) {
    let cascade =
        r#"[{"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:subject"}]"#.to_string();
    let fields = CanonicalFields {
        sequence,
        timestamp: "2026-05-09T00:00:00+00:00".to_string(),
        actor_did: "did:web:cairn-mod.example.test".to_string(),
        action: "TakedownAccount".to_string(),
        subject_did: Some("did:plc:subject".to_string()),
        subject_uri: None,
        subject_cid: None,
        rationale: rationale.to_string(),
        snapshot_id: None,
        event_id,
        previous_hash: prev_hash.map(String::from),
        cascade_subjects: Some(cascade),
        cascade_snapshot_ids: None,
        source: "manual".to_string(),
        payload: None,
    };
    let hash = sha256_hex_of(&build_canonical_v09(&fields));
    let wire = serde_json::json!({
        "id": sequence.to_string(),
        "sequence": sequence,
        "timestamp": "2026-05-09T00:00:00Z",
        "actorDid": "did:web:cairn-mod.example.test",
        "action": "TakedownAccount",
        "subjectRef": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:subject"},
        "rationale": rationale,
        "snapshotId": null,
        "eventId": event_id.map(|e| e.to_string()),
        "currentHash": hash.clone(),
        "previousHash": prev_hash,
        "verified": true,
        "cascadeSubjects": [{"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:subject"}],
        "cascadeSnapshotIds": [],
        "source": "manual"
    });
    (wire, hash)
}

struct MockAuditAurora {
    trail_body: String,
    entry_bodies: Mutex<std::collections::HashMap<String, String>>,
    seen: Mutex<Vec<(String, String)>>,
}

async fn audit_trail_handler(
    State(state): State<Arc<MockAuditAurora>>,
    uri: axum::http::Uri,
) -> Response {
    state
        .seen
        .lock()
        .unwrap()
        .push(("trail".to_string(), uri.query().unwrap_or("").to_string()));
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        state.trail_body.clone(),
    )
        .into_response()
}

async fn audit_entry_handler(
    State(state): State<Arc<MockAuditAurora>>,
    uri: axum::http::Uri,
) -> Response {
    let q = uri.query().unwrap_or("").to_string();
    state
        .seen
        .lock()
        .unwrap()
        .push(("entry".to_string(), q.clone()));
    let id = q
        .split('&')
        .find_map(|kv| kv.strip_prefix("id="))
        .unwrap_or("")
        .to_string();
    match state.entry_bodies.lock().unwrap().get(&id) {
        Some(body) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body.clone(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            serde_json::json!({"error": "AuditEntryNotFound",
                "message": "no audit entry matches the given id or hash"})
            .to_string(),
        )
            .into_response(),
    }
}

async fn spawn_audit_mock(
    trail_body: String,
    entries: Vec<(String, String)>,
) -> (SocketAddr, Arc<MockAuditAurora>) {
    let state = Arc::new(MockAuditAurora {
        trail_body,
        entry_bodies: Mutex::new(entries.into_iter().collect()),
        seen: Mutex::new(Vec::new()),
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
            "/xrpc/tools.aurora.admin.getAuditTrail",
            get(audit_trail_handler).with_state(state.clone()),
        )
        .route(
            "/xrpc/tools.aurora.admin.getAuditEntry",
            get(audit_entry_handler).with_state(state.clone()),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    (addr, state)
}

#[tokio::test]
async fn get_audit_trail_end_to_end_and_gate() {
    let (e1, _h1) = upstream_entry_json(1, Some(42), None, "genesis row");
    let trail = serde_json::json!({
        "items": [e1],
        "chainVerified": true,
        "chainVerifiedThrough": 1,
        "chainLegacyCount": 0
    })
    .to_string();
    let (addr, state) = spawn_audit_mock(trail, Vec::new()).await;
    let backend = probed_backend(addr).await;

    let page = backend
        .get_audit_trail(
            AuditTrailFilter {
                source: Some("manual".to_string()),
                ..Default::default()
            },
            None,
            Some(50),
        )
        .await
        .expect("trail fetch succeeds");
    assert!(page.chain_verified);
    assert_eq!(page.chain_verified_through, 1);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].event_id.as_deref(), Some("42"));

    let seen = state.seen.lock().unwrap().clone();
    assert!(seen[0].1.contains("source=manual"), "{seen:?}");
    assert!(seen[0].1.contains("limit=50"), "{seen:?}");

    // Capability gate: unprobed backend → no advertisement → gate
    // fires with the family wire string, zero HTTP calls.
    let ungated = backend_against(addr, Vec::new());
    let err = ungated
        .get_audit_trail(AuditTrailFilter::default(), None, None)
        .await
        .unwrap_err();
    match &err {
        BackendError::CapabilityNotAdvertised(s) => assert_eq!(s, "audit-trail-v1"),
        other => panic!("expected CapabilityNotAdvertised, got {other:?}"),
    }
}

#[tokio::test]
async fn get_audit_entry_by_id_hash_and_404() {
    let (e1, h1) = upstream_entry_json(1, None, None, "solo");
    let (addr, state) =
        spawn_audit_mock("{}".to_string(), vec![("1".to_string(), e1.to_string())]).await;
    let backend = probed_backend(addr).await;

    let entry = backend
        .get_audit_entry(&AuditEntryLookup::Id(1))
        .await
        .expect("entry by id");
    assert_eq!(entry.current_hash, h1);

    let missing = backend
        .get_audit_entry(&AuditEntryLookup::Id(999))
        .await
        .unwrap_err();
    assert!(matches!(missing, BackendError::Terminal(_)), "{missing:?}");

    // Hash lookups serialize the hash param (mock only resolves by
    // id; the wire shape is what we pin here).
    let _ = backend
        .get_audit_entry(&AuditEntryLookup::Hash("cafe".to_string()))
        .await
        .unwrap_err();
    let seen = state.seen.lock().unwrap().clone();
    assert_eq!(seen[0].1, "id=1");
    assert_eq!(seen[1].1, "id=999");
    assert_eq!(seen[2].1, "hash=cafe");
}

async fn cross_verify_pool() -> sqlx::Pool<sqlx::Sqlite> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cross-verify.db");
    let pool = cairn_mod::storage::open(&path).await.unwrap();
    Box::leak(Box::new(dir));
    pool
}

async fn fixture_action_row(pool: &sqlx::Pool<sqlx::Sqlite>) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO subject_actions (
            subject_did, actor_did, action_type, reason_codes,
            effective_at, strike_value_base, strike_value_applied,
            strikes_at_time_of_action, created_at
         ) VALUES ('did:plc:subject', 'did:plc:mod', 'takedown', '[\"spam\"]',
                   1000, 0, 0, 0, 1000)
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn cross_verify_end_to_end_verified_and_persisted() {
    let pool = cross_verify_pool().await;
    let action_id = fixture_action_row(&pool).await;

    // Local dispatch row with join keys, hash-stamped through the
    // production audit-append path (12-field preimage).
    record_pds_admin_call(
        &pool,
        action_id,
        cairn_mod::pds_admin::BackendMethod::DeleteAccount,
        Ok(Some(BackendActionId::PerEvent("42".to_string()))),
        Some(cairn_mod::pds_admin::UpstreamResponse::Action(
            &UpstreamActionResponse {
                event_id: "42".to_string(),
                audit_entry_id: "1".to_string(),
                snapshots: Vec::new(),
                cascading_actions: Vec::new(),
            },
        )),
        1_000,
        1_500,
    )
    .await
    .expect("audit row lands");

    // Upstream chain: one genesis entry whose event_id matches the
    // local backend_action_id and whose chain-entry id matches the
    // stored upstream_audit_entry_id.
    let (e1, _h1) = upstream_entry_json(1, Some(42), None, "genesis row");
    let trail = serde_json::json!({
        "items": [e1],
        "chainVerified": true,
        "chainVerifiedThrough": 1,
        "chainLegacyCount": 0
    })
    .to_string();
    let (addr, _state) = spawn_audit_mock(trail, Vec::new()).await;
    let backend = probed_backend(addr).await;

    let report = audit_cross_verify::run(&pool, &backend, true, (None, None))
        .await
        .expect("cross-verify runs");
    assert_eq!(report.outcome, CrossVerifyOutcome::Verified, "{report:?}");
    assert!(report.local_verified && report.upstream_verified && report.cross_verified);
    assert!(report.persisted);

    let history = audit_cross_verify::history(&pool, 10).await.unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].cross_verified);
}

#[tokio::test]
async fn cross_verify_join_mismatch_and_persist_gate() {
    let pool = cross_verify_pool().await;
    let action_id = fixture_action_row(&pool).await;
    record_pds_admin_call(
        &pool,
        action_id,
        cairn_mod::pds_admin::BackendMethod::DeleteAccount,
        Ok(Some(BackendActionId::PerEvent("42".to_string()))),
        Some(cairn_mod::pds_admin::UpstreamResponse::Action(
            &UpstreamActionResponse {
                event_id: "42".to_string(),
                audit_entry_id: "1".to_string(),
                snapshots: Vec::new(),
                cascading_actions: Vec::new(),
            },
        )),
        1_000,
        1_500,
    )
    .await
    .unwrap();

    // Upstream entry exists but carries a DIFFERENT event id →
    // divergence-join-mismatch; verification_persist=false writes
    // no outcome row.
    let (e1, _h1) = upstream_entry_json(1, Some(777), None, "genesis row");
    let trail = serde_json::json!({
        "items": [e1],
        "chainVerified": true,
        "chainVerifiedThrough": 1,
        "chainLegacyCount": 0
    })
    .to_string();
    let (addr, _state) = spawn_audit_mock(trail, Vec::new()).await;
    let backend = probed_backend(addr).await;

    let report = audit_cross_verify::run(&pool, &backend, false, (None, None))
        .await
        .expect("cross-verify runs");
    assert_eq!(report.outcome, CrossVerifyOutcome::DivergenceJoinMismatch);
    assert!(!report.persisted);
    assert!(
        audit_cross_verify::history(&pool, 10)
            .await
            .unwrap()
            .is_empty(),
        "verification_persist=false must not write an outcome row"
    );
}

#[tokio::test]
async fn cross_verify_detects_upstream_tamper() {
    let pool = cross_verify_pool().await;

    // Tampered upstream row: rationale rewritten after sealing.
    let (mut e1, _h1) = upstream_entry_json(1, None, None, "original rationale");
    e1["rationale"] = serde_json::json!("rewritten by attacker");
    let trail = serde_json::json!({
        "items": [e1],
        "chainVerified": true,   // Aurora (mock) claims clean...
        "chainVerifiedThrough": 1,
        "chainLegacyCount": 0
    })
    .to_string();
    let (addr, _state) = spawn_audit_mock(trail, Vec::new()).await;
    let backend = probed_backend(addr).await;

    // ...but cairn-mod's independent Path A walk catches the
    // per-row mismatch → divergence-cross.
    let report = audit_cross_verify::run(&pool, &backend, true, (None, None))
        .await
        .expect("cross-verify runs");
    assert_eq!(
        report.outcome,
        CrossVerifyOutcome::DivergenceCross,
        "{report:?}"
    );
    assert!(
        report.notes["auroraDisagreesWithIndependentWalk"]
            .as_bool()
            .unwrap()
    );
}
