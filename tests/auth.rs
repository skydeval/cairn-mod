//! Integration tests for `cairn_mod::auth` (§5.2, §5.4).
//!
//! Two harness layers:
//!
//! 1. **MockResolver**: returns canned [`DidDocument`]s without any HTTP,
//!    used for JWT-verification-pipeline tests (alg, claims, signature,
//!    replay). This keeps the fast tests fast and lets us drive every
//!    branch of the pipeline without a wiremock lifecycle.
//! 2. **Wiremock**: exercises the real `HttpDidResolver` against a
//!    loopback server. Tests that need to pin the `did:plc` and
//!    `did:web` URL shapes, 404 handling, and the positive/negative
//!    cache hit counts live here. SSRF protection is bypassed in this
//!    stack via a pass-through DNS resolver; the SafeDnsResolver is
//!    covered by its own unit tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{
    DidDocument, DidResolver, HttpDidResolver, ResolveError, VerificationMethod,
};
use cairn_mod::auth::{AuthConfig, AuthContext, AuthError};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ========== Test key + signing helpers ==========

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";

fn test_keypair() -> K256Keypair {
    let bytes = hex::decode(TEST_PRIV_HEX).expect("hex");
    K256Keypair::from_private_key(&bytes).expect("keypair")
}

fn moderator_multibase() -> String {
    let kp = test_keypair();
    format_multikey("ES256K", &kp.public_key_compressed())
}

fn build_jwt(claims: &serde_json::Value, alg: &str) -> String {
    let header = serde_json::json!({"alg": alg, "typ": "JWT"});
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h_b64 = engine.encode(header.to_string());
    let p_b64 = engine.encode(claims.to_string());
    let signing_input = format!("{h_b64}.{p_b64}");
    let kp = test_keypair();
    let sig = kp.sign(signing_input.as_bytes()).expect("sign");
    let s_b64 = engine.encode(sig);
    format!("{h_b64}.{p_b64}.{s_b64}")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn valid_claims(lxm: &str) -> serde_json::Value {
    let now = now_unix();
    serde_json::json!({
        "iss": MODERATOR_DID,
        "aud": SERVICE_DID,
        "exp": now + 60,
        "iat": now,
        "jti": format!("jti-{}", uuid::Uuid::new_v4()),
        "lxm": lxm,
    })
}

fn moderator_did_doc() -> DidDocument {
    DidDocument {
        id: MODERATOR_DID.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{MODERATOR_DID}#atproto"),
            r#type: "Multikey".to_string(),
            public_key_multibase: moderator_multibase(),
        }],
    }
}

// ========== Mock resolver ==========

struct MockResolver {
    docs: Mutex<HashMap<String, DidDocument>>,
    call_count: Mutex<HashMap<String, usize>>,
}

impl MockResolver {
    fn new() -> Self {
        Self {
            docs: Mutex::new(HashMap::new()),
            call_count: Mutex::new(HashMap::new()),
        }
    }

    fn with_doc(self, did: &str, doc: DidDocument) -> Self {
        self.docs.lock().unwrap().insert(did.to_string(), doc);
        self
    }

    fn calls(&self, did: &str) -> usize {
        *self.call_count.lock().unwrap().get(did).unwrap_or(&0)
    }
}

#[async_trait]
impl DidResolver for MockResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError> {
        *self
            .call_count
            .lock()
            .unwrap()
            .entry(did.to_string())
            .or_insert(0) += 1;

        match self.docs.lock().unwrap().get(did).cloned() {
            Some(doc) => Ok(doc),
            None => Err(ResolveError::BadStatus(404)),
        }
    }
}

/// DNS resolver used ONLY in the wiremock tests below, where the target
/// is 127.0.0.1 and the prod SafeDnsResolver would (correctly) refuse.
/// Delegates to the system resolver with no filtering.
#[derive(Debug)]
struct PassthroughDns;

impl reqwest::dns::Resolve for PassthroughDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = tokio::net::lookup_host(format!("{host}:0"))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            Ok(Box::new(addrs) as reqwest::dns::Addrs)
        })
    }
}

fn auth_with_mock(resolver: Arc<MockResolver>) -> AuthContext {
    let config = AuthConfig {
        service_did: SERVICE_DID.to_string(),
        ..AuthConfig::default()
    };
    AuthContext::with_resolver(config, resolver)
}

// ========== JWT pipeline tests (MockResolver) ==========

#[tokio::test]
async fn valid_jwt_verifies_and_returns_caller() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver);
    let token = build_jwt(&valid_claims("tools.cairn.admin.applyLabel"), "ES256K");

    let caller = ctx
        .verify_service_auth(&token, "tools.cairn.admin.applyLabel")
        .await
        .expect("verify");
    assert_eq!(caller.iss, MODERATOR_DID);
    assert_eq!(caller.key_id, format!("{MODERATOR_DID}#atproto"));
}

#[tokio::test]
async fn expired_jwt_rejects() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver);
    let mut claims = valid_claims("x");
    claims["exp"] = serde_json::json!(now_unix() - 120); // well past skew window
    let token = build_jwt(&claims, "ES256K");

    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(
        matches!(err, AuthError::ClaimMismatch("exp")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn future_iat_rejects() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver);
    let mut claims = valid_claims("x");
    claims["iat"] = serde_json::json!(now_unix() + 120); // beyond max_iat_future
    let token = build_jwt(&claims, "ES256K");

    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(
        matches!(err, AuthError::ClaimMismatch("iat")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn alg_mismatch_rejects_none_and_non_es256k() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver);

    for bad_alg in ["none", "HS256", "RS256", "ES256", "EdDSA"] {
        let token = build_jwt(&valid_claims("x"), bad_alg);
        let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
        assert!(
            matches!(err, AuthError::AlgRejected(_)),
            "alg={bad_alg}: {err:?}"
        );
    }
}

#[tokio::test]
async fn missing_claims_reject() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver);

    // Build a payload missing `lxm` — every other field present.
    let bad = serde_json::json!({
        "iss": MODERATOR_DID,
        "aud": SERVICE_DID,
        "exp": now_unix() + 60,
        "iat": now_unix(),
        "jti": "j",
    });
    let token = build_jwt(&bad, "ES256K");
    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(matches!(err, AuthError::Structural(_)), "got {err:?}");
}

#[tokio::test]
async fn wrong_aud_rejects() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver);
    let mut claims = valid_claims("x");
    claims["aud"] = serde_json::json!("did:plc:someoneelse");
    let token = build_jwt(&claims, "ES256K");

    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(
        matches!(err, AuthError::ClaimMismatch("aud")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn wrong_lxm_rejects() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver);
    let token = build_jwt(&valid_claims("tools.cairn.admin.applyLabel"), "ES256K");

    let err = ctx
        .verify_service_auth(&token, "tools.cairn.admin.negateLabel")
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::ClaimMismatch("lxm")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn signature_mismatch_rejects() {
    // Doc has a DIFFERENT key than the one that signed the JWT.
    let wrong_kp = K256Keypair::from_private_key(&[0x11; 32]).unwrap();
    let wrong_multibase = format_multikey("ES256K", &wrong_kp.public_key_compressed());
    let wrong_doc = DidDocument {
        id: MODERATOR_DID.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{MODERATOR_DID}#atproto"),
            r#type: "Multikey".to_string(),
            public_key_multibase: wrong_multibase,
        }],
    };
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, wrong_doc));
    let ctx = auth_with_mock(resolver);
    let token = build_jwt(&valid_claims("x"), "ES256K");

    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(matches!(err, AuthError::SignatureInvalid), "got {err:?}");
}

#[tokio::test]
async fn replay_rejects_second_use_of_same_iss_jti() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver);
    let token = build_jwt(&valid_claims("x"), "ES256K");

    ctx.verify_service_auth(&token, "x")
        .await
        .expect("first ok");
    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(
        matches!(err, AuthError::Replay { .. }),
        "second use must be replay: {err:?}"
    );
}

#[tokio::test]
async fn did_missing_atproto_verification_method_rejects() {
    let no_vm_doc = DidDocument {
        id: MODERATOR_DID.to_string(),
        verification_method: vec![VerificationMethod {
            // Wrong fragment — #atproto_label is the labeler's key, not
            // the moderator's repo key.
            id: format!("{MODERATOR_DID}#atproto_label"),
            r#type: "Multikey".to_string(),
            public_key_multibase: moderator_multibase(),
        }],
    };
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, no_vm_doc));
    let ctx = auth_with_mock(resolver);
    let token = build_jwt(&valid_claims("x"), "ES256K");

    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(
        matches!(err, AuthError::NoVerificationMethod),
        "got {err:?}"
    );
}

#[tokio::test]
async fn did_wrong_key_algorithm_rejects() {
    // P-256 (ES256) Multikey instead of ES256K.
    let p256 = proto_blue_crypto::P256Keypair::generate();
    let p256_mb = format_multikey("ES256", &p256.public_key_compressed());
    let doc = DidDocument {
        id: MODERATOR_DID.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{MODERATOR_DID}#atproto"),
            r#type: "Multikey".to_string(),
            public_key_multibase: p256_mb,
        }],
    };
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, doc));
    let ctx = auth_with_mock(resolver);
    let token = build_jwt(&valid_claims("x"), "ES256K");

    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(matches!(err, AuthError::WrongKeyType), "got {err:?}");
}

// ========== HTTP resolver tests (wiremock) ==========

fn doc_json() -> serde_json::Value {
    serde_json::json!({
        "id": MODERATOR_DID,
        "verificationMethod": [{
            "id": format!("{MODERATOR_DID}#atproto"),
            "type": "Multikey",
            "controller": MODERATOR_DID,
            "publicKeyMultibase": moderator_multibase(),
        }]
    })
}

async fn spawn_auth_with_wiremock(server: &MockServer) -> AuthContext {
    let resolver = Arc::new(HttpDidResolver::with_dns_resolver(
        server.uri(),
        Duration::from_secs(5),
        Arc::new(PassthroughDns),
    ));
    let config = AuthConfig {
        service_did: SERVICE_DID.to_string(),
        plc_directory_url: server.uri(),
        // Keep caches small + short for cache-behavior tests.
        positive_cache_ttl: Duration::from_millis(200),
        negative_cache_ttl: Duration::from_millis(100),
        ..AuthConfig::default()
    };
    AuthContext::with_resolver(config, resolver)
}

#[tokio::test]
async fn did_plc_http_happy_path() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{MODERATOR_DID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc_json()))
        .expect(1)
        .mount(&server)
        .await;

    let ctx = spawn_auth_with_wiremock(&server).await;
    let token = build_jwt(&valid_claims("x"), "ES256K");
    ctx.verify_service_auth(&token, "x")
        .await
        .expect("verify via wiremock");
}

// did:web HTTP integration against wiremock would need HTTPS (§5.4
// mandates HTTPS for resolution), which wiremock doesn't serve
// without TLS-cert setup. Coverage is split across layers:
//   - URL shape (path-component form, .well-known form, malformed):
//     unit tests in `src/auth/did.rs::tests::did_web_*`.
//   - HTTP plumbing (GET + status + JSON parse): covered below by
//     `did_plc_http_happy_path` and `did_not_found_rejects`.
// A TLS end-to-end did:web test would add substantial harness
// complexity for coverage already present at the unit layer.

#[tokio::test]
async fn did_not_found_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{MODERATOR_DID}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let ctx = spawn_auth_with_wiremock(&server).await;
    let token = build_jwt(&valid_claims("x"), "ES256K");
    let err = ctx.verify_service_auth(&token, "x").await.unwrap_err();
    assert!(matches!(
        err,
        AuthError::Resolve(ResolveError::BadStatus(404))
    ));
}

#[tokio::test]
async fn doc_cache_hit_prevents_second_http() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{MODERATOR_DID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc_json()))
        .expect(1) // wiremock enforces: exactly one hit
        .mount(&server)
        .await;

    let ctx = spawn_auth_with_wiremock(&server).await;

    // Two different JWTs (different jtis, so no replay) but same iss —
    // second call should hit the cache.
    let t1 = build_jwt(&valid_claims("x"), "ES256K");
    let t2 = build_jwt(&valid_claims("x"), "ES256K");
    assert_ne!(t1, t2, "jtis should differ");

    ctx.verify_service_auth(&t1, "x").await.expect("first ok");
    ctx.verify_service_auth(&t2, "x")
        .await
        .expect("second ok via cache");
    // Drop forces wiremock's .expect(1) to run its assertion.
}

#[tokio::test]
async fn doc_cache_miss_after_ttl_reresolves() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{MODERATOR_DID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc_json()))
        .expect(2) // 2 hits: once, TTL, once more
        .mount(&server)
        .await;

    let ctx = spawn_auth_with_wiremock(&server).await;

    let t1 = build_jwt(&valid_claims("x"), "ES256K");
    ctx.verify_service_auth(&t1, "x").await.expect("first");

    // Positive TTL is 200ms in spawn_auth_with_wiremock.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let t2 = build_jwt(&valid_claims("x"), "ES256K");
    ctx.verify_service_auth(&t2, "x").await.expect("second");
}

#[tokio::test]
async fn failure_cache_suppresses_reresolve() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{MODERATOR_DID}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1) // exactly one upstream hit — second attempt uses neg cache
        .mount(&server)
        .await;

    let ctx = spawn_auth_with_wiremock(&server).await;
    let t1 = build_jwt(&valid_claims("x"), "ES256K");
    let t2 = build_jwt(&valid_claims("x"), "ES256K");

    let _ = ctx.verify_service_auth(&t1, "x").await;
    let _ = ctx.verify_service_auth(&t2, "x").await;
    // Under 100ms negative-cache TTL, second call short-circuits.
}

// ========== MockResolver-based cache test (no wiremock dep) ==========

#[tokio::test]
async fn mock_resolver_caches_positive_results() {
    let resolver = Arc::new(MockResolver::new().with_doc(MODERATOR_DID, moderator_did_doc()));
    let ctx = auth_with_mock(resolver.clone());

    ctx.verify_service_auth(&build_jwt(&valid_claims("x"), "ES256K"), "x")
        .await
        .expect("ok");
    ctx.verify_service_auth(&build_jwt(&valid_claims("x"), "ES256K"), "x")
        .await
        .expect("ok");

    assert_eq!(
        resolver.calls(MODERATOR_DID),
        1,
        "second verify should hit cache, not re-resolve"
    );
}
