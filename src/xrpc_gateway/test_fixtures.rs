//! Shared test fixtures for the xrpc_gateway tests (#93+).
//!
//! Contains JWT-construction helpers, a synthetic ES256K keypair,
//! a mock [`DidResolver`], and an [`XrpcAuthService`] builder
//! with a deterministic clock. Used by both
//! [`crate::xrpc_gateway::auth::tests`] (unit-level) and
//! [`crate::xrpc_gateway::router::tests`] (integration-level
//! through-the-middleware tests). Centralizing them here keeps
//! the two test surfaces consistent — a JWT that auth's tests
//! consider valid is the same JWT that the router's tests will
//! see fall through to handlers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};

use crate::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use crate::xrpc_gateway::auth::XrpcAuthService;
use crate::xrpc_gateway::config::XrpcGatewayConfig;

/// Fixed test private key in hex. Matches the key used elsewhere
/// in cairn-mod's test suite (e.g. tests/auth.rs) so a developer
/// inspecting test JWTs can correlate signers across surfaces.
pub const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

/// Audience DID used by the gateway tests. Operators in
/// production set this from `[xrpc_gateway].service_did`.
pub const SERVICE_DID: &str = "did:web:cairn.example.com";

/// Issuer DID for test JWTs.
pub const ISSUER_DID: &str = "did:plc:issuer0000000000000000000";

/// Fixed Unix-seconds value the tests use as "now". Choosing a
/// realistic non-zero value rather than 0 so any timestamp-relative
/// arithmetic (`exp - now`, `iat + skew`, etc.) exercises the same
/// arithmetic paths as production.
pub const FIXED_NOW: i64 = 1_700_000_000;

/// Construct the test ES256K keypair from [`TEST_PRIV_HEX`].
pub fn test_keypair() -> K256Keypair {
    K256Keypair::from_private_key(&hex::decode(TEST_PRIV_HEX).unwrap()).unwrap()
}

/// Synthetic DID document with a single `#atproto` verification
/// method whose pubkey matches [`test_keypair`].
pub fn test_did_doc(did: &str) -> DidDocument {
    DidDocument {
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#atproto"),
            r#type: "Multikey".into(),
            public_key_multibase: format_multikey(
                "ES256K",
                &test_keypair().public_key_compressed(),
            ),
        }],
    }
}

/// In-memory mock [`DidResolver`]. Snapshot under the lock then
/// drop the guard before any await
/// (`clippy::await_holding_lock` discipline from #89/#92).
pub struct MockResolver(Mutex<HashMap<String, DidDocument>>);

impl MockResolver {
    pub fn with_doc(did: &str, doc: DidDocument) -> Arc<Self> {
        let mut m = HashMap::new();
        m.insert(did.to_string(), doc);
        Arc::new(Self(Mutex::new(m)))
    }
}

#[async_trait]
impl DidResolver for MockResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError> {
        let snapshot = self.0.lock().unwrap().get(did).cloned();
        snapshot.ok_or(ResolveError::BadStatus(404))
    }
}

/// Build a JWT signed by [`test_keypair`].
pub fn build_jwt(claims: &serde_json::Value, alg_header: &str) -> String {
    let header = serde_json::json!({"alg": alg_header, "typ": "JWT"});
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h = engine.encode(header.to_string());
    let p = engine.encode(claims.to_string());
    let signing_input = format!("{h}.{p}");
    let sig = test_keypair().sign(signing_input.as_bytes()).unwrap();
    format!("{h}.{p}.{}", engine.encode(sig))
}

/// Default valid claims fixture. Tests override individual fields
/// via `serde_json::Value::as_object_mut`.
pub fn valid_claims(lxm: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER_DID,
        "aud": SERVICE_DID,
        "exp": FIXED_NOW + 60,
        "iat": FIXED_NOW - 5,
        "jti": "jti-fixture-1",
        "lxm": lxm,
    })
}

/// Wall-clock-replacement closure returning [`FIXED_NOW`]. Inject
/// via [`XrpcAuthService::with_clock`] so test verifications run
/// against deterministic time without relying on
/// `SystemTime::now`.
pub fn fixed_clock() -> Arc<dyn Fn() -> i64 + Send + Sync> {
    Arc::new(|| FIXED_NOW)
}

/// Default gateway config fixture matching the JWT fixtures.
pub fn fixture_config() -> XrpcGatewayConfig {
    XrpcGatewayConfig {
        enabled: true,
        service_did: SERVICE_DID.into(),
        clock_skew_tolerance: Duration::from_secs(30),
        replay_cache_ttl: Duration::from_secs(90),
    }
}

/// Build an [`XrpcAuthService`] with the [`MockResolver`] preloaded
/// for [`ISSUER_DID`] and the fixed-time clock.
pub fn build_service() -> Arc<XrpcAuthService> {
    let resolver = MockResolver::with_doc(ISSUER_DID, test_did_doc(ISSUER_DID));
    Arc::new(XrpcAuthService::with_clock(
        fixture_config(),
        resolver,
        fixed_clock(),
    ))
}
