//! Integration tests for `tools.cairn.admin.getTrustChain` (#36).
//!
//! Auth + role: 401 for no auth, 403 for mod role (admin-only).
//!
//! Response shape: covers the four shared-typed fields the lexicon
//! declares (signingKeys, maintainers, serviceRecord, instance) plus
//! the top-level serviceDid wrapper.
//!
//! `provenanceAttested` semantics: NULL `added_by` ⇒ false, non-NULL
//! `added_by` ⇒ true. The CLI/HTTP-attribution distinction this surfaces
//! is the read-side of the writer-side documentation in the README's
//! Moderator-management `added_by` semantics block.
//!
//! `serviceRecord` nullability: returned only when BOTH the deployment
//! has a `[labeler]` config block (i.e., AdminConfig::declared_label_values
//! is `Some`) AND a publish has happened (labeler_config row exists for
//! `service_record_content_hash`). All other states ⇒ field absent.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::{AdminConfig, admin_router, spawn_writer, storage};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const SERVICE_ENDPOINT: &str = "https://labeler.example";
const ADMIN_DID: &str = "did:plc:admin00000000000000000000";
const MOD_DID: &str = "did:plc:moderator0000000000000000";

// ---------- JWT + resolver helpers (same shape as admin_audit.rs) ----------

fn test_keypair() -> K256Keypair {
    K256Keypair::from_private_key(&hex::decode(TEST_PRIV_HEX).unwrap()).unwrap()
}

fn did_doc(did: &str) -> DidDocument {
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

fn build_jwt(iss: &str, lxm: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": iss,
        "aud": SERVICE_DID,
        "exp": now + 60,
        "iat": now,
        "jti": format!("jti-{}", uuid::Uuid::new_v4()),
        "lxm": lxm,
    });
    let header = serde_json::json!({"alg": "ES256K", "typ": "JWT"});
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h = engine.encode(header.to_string());
    let p = engine.encode(claims.to_string());
    let input = format!("{h}.{p}");
    let sig = test_keypair().sign(input.as_bytes()).unwrap();
    format!("{h}.{p}.{}", engine.encode(sig))
}

struct MockResolver(Mutex<HashMap<String, DidDocument>>);

#[async_trait]
impl DidResolver for MockResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError> {
        self.0
            .lock()
            .unwrap()
            .get(did)
            .cloned()
            .ok_or(ResolveError::BadStatus(404))
    }
}

fn auth_ctx() -> Arc<AuthContext> {
    let resolver = Arc::new(MockResolver(Mutex::new(
        [
            (ADMIN_DID.to_string(), did_doc(ADMIN_DID)),
            (MOD_DID.to_string(), did_doc(MOD_DID)),
        ]
        .into(),
    )));
    Arc::new(AuthContext::with_resolver(
        AuthConfig {
            service_did: SERVICE_DID.to_string(),
            ..AuthConfig::default()
        },
        resolver,
    ))
}

// ---------- Harness ----------

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    writer: cairn_mod::WriterHandle,
    addr: SocketAddr,
}

async fn spawn_with_config(admin_cfg: AdminConfig) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();
    let writer = spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
        cairn_mod::PolicyAutomationPolicy::defaults(),
    )
    .await
    .unwrap();
    let router = admin_router(
        pool.clone(),
        writer.clone(),
        auth_ctx(),
        admin_cfg,
        cairn_mod::StrikePolicy::defaults(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    Harness {
        _dir: dir,
        pool,
        writer,
        addr,
    }
}

/// Default-shaped harness: AdminConfig populated only with the
/// service identity (so envelope assertions can verify those fields)
/// and no declared label values. Trust-chain endpoint reports
/// serviceRecord: absent in this state.
async fn spawn() -> Harness {
    spawn_with_config(AdminConfig {
        service_did: SERVICE_DID.to_string(),
        service_endpoint: SERVICE_ENDPOINT.to_string(),
        ..Default::default()
    })
    .await
}

async fn add_moderator(pool: &Pool<Sqlite>, did: &str, role: &str, added_by: Option<&str>) {
    sqlx::query!(
        "INSERT INTO moderators (did, role, added_by, added_at) VALUES (?1, ?2, ?3, ?4)",
        did,
        role,
        added_by,
        0_i64,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn put_labeler_config(pool: &Pool<Sqlite>, key: &str, value: &str) {
    sqlx::query!(
        "INSERT INTO labeler_config (key, value, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        key,
        value,
        0_i64,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn get_query(addr: SocketAddr, auth: Option<&str>) -> (u16, Value) {
    use http_body_util::{BodyExt as _, Empty};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
    let (mut send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut req = hyper::Request::builder()
        .method("GET")
        .uri("/xrpc/tools.cairn.admin.getTrustChain")
        .header("host", "127.0.0.1");
    if let Some(t) = auth {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = req.body(Empty::<Bytes>::new()).unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), send.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, json)
}

// ============ tests ============

#[tokio::test]
async fn unauthenticated_returns_401() {
    let h = spawn().await;
    let (status, body) = get_query(h.addr, None).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "AuthenticationRequired");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn mod_role_rejected_403() {
    let h = spawn().await;
    add_moderator(&h.pool, MOD_DID, "mod", None).await;
    let jwt = build_jwt(MOD_DID, "tools.cairn.admin.getTrustChain");
    let (status, body) = get_query(h.addr, Some(&jwt)).await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "Forbidden");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn admin_returns_envelope_with_default_admin_config() {
    let h = spawn().await;
    add_moderator(&h.pool, ADMIN_DID, "admin", None).await;
    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.getTrustChain");
    let (status, body) = get_query(h.addr, Some(&jwt)).await;
    assert_eq!(status, 200, "body: {body}");

    // Top-level shape — required fields per the lexicon.
    assert_eq!(body["serviceDid"], SERVICE_DID);
    assert!(body["signingKeys"].is_array());
    assert!(body["maintainers"].is_array());
    assert!(body["instance"].is_object());

    // Writer-bootstrap row shows up: spawn_writer inserts one
    // signing_keys row via ensure_signing_key_row.
    let keys = body["signingKeys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "writer bootstraps exactly one row");
    let key = &keys[0];
    assert!(key["publicKeyMultibase"].as_str().unwrap().starts_with('z'));
    assert!(key["validFrom"].is_string());
    assert!(key["createdAt"].is_string());
    assert_eq!(key["isActive"], true, "live key has no validTo");
    // validTo absent ⇒ field omitted (skip_serializing_if = "Option::is_none")
    assert!(
        key.get("validTo").is_none(),
        "validTo absent for active key, body: {body}"
    );

    // Maintainers includes the admin we seeded with NULL added_by;
    // provenanceAttested must be false.
    let maintainers = body["maintainers"].as_array().unwrap();
    assert_eq!(maintainers.len(), 1);
    assert_eq!(maintainers[0]["did"], ADMIN_DID);
    assert_eq!(maintainers[0]["role"], "admin");
    assert_eq!(maintainers[0]["provenanceAttested"], false);
    assert!(maintainers[0].get("addedBy").is_none());

    // Instance fields populated from AdminConfig.
    assert_eq!(body["instance"]["serviceEndpoint"], SERVICE_ENDPOINT);
    assert!(
        body["instance"]["version"]
            .as_str()
            .unwrap()
            .starts_with(char::is_numeric),
        "version should be a semver string (CARGO_PKG_VERSION)"
    );

    // serviceRecord absent: declared_label_values is None on the
    // default harness, so the field is omitted entirely.
    assert!(
        body.get("serviceRecord").is_none(),
        "serviceRecord must be field-absent when [labeler] is not configured, body: {body}"
    );

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn maintainers_provenance_attested_reflects_added_by() {
    // Two moderators: one with NULL added_by (CLI-inserted), one with
    // a verified caller DID (HTTP-attested). Only the latter has
    // provenanceAttested: true.
    let h = spawn().await;
    add_moderator(&h.pool, ADMIN_DID, "admin", None).await;
    add_moderator(
        &h.pool,
        "did:plc:byhttp00000000000000000000",
        "mod",
        Some(ADMIN_DID),
    )
    .await;
    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.getTrustChain");
    let (status, body) = get_query(h.addr, Some(&jwt)).await;
    assert_eq!(status, 200, "body: {body}");

    let mut by_did: std::collections::HashMap<String, &Value> = std::collections::HashMap::new();
    for m in body["maintainers"].as_array().unwrap() {
        by_did.insert(m["did"].as_str().unwrap().to_string(), m);
    }
    assert_eq!(by_did.len(), 2);

    let cli_inserted = by_did.get(ADMIN_DID).unwrap();
    assert_eq!(cli_inserted["provenanceAttested"], false);
    assert!(cli_inserted.get("addedBy").is_none());

    let http_inserted = by_did.get("did:plc:byhttp00000000000000000000").unwrap();
    assert_eq!(http_inserted["provenanceAttested"], true);
    assert_eq!(http_inserted["addedBy"], ADMIN_DID);

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn service_record_present_when_labeler_declared_and_hash_published() {
    let h = spawn_with_config(AdminConfig {
        service_did: SERVICE_DID.to_string(),
        service_endpoint: SERVICE_ENDPOINT.to_string(),
        declared_label_values: Some(vec!["spam".into(), "abuse".into()]),
        ..Default::default()
    })
    .await;
    add_moderator(&h.pool, ADMIN_DID, "admin", None).await;
    put_labeler_config(
        &h.pool,
        "service_record_content_hash",
        "abc123def456deadbeef",
    )
    .await;

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.getTrustChain");
    let (status, body) = get_query(h.addr, Some(&jwt)).await;
    assert_eq!(status, 200, "body: {body}");

    let sr = body
        .get("serviceRecord")
        .expect("serviceRecord present when both halves available");
    assert_eq!(sr["contentHash"], "abc123def456deadbeef");
    let label_values = sr["labelValues"].as_array().unwrap();
    assert_eq!(label_values.len(), 2);
    assert_eq!(label_values[0], "spam");
    assert_eq!(label_values[1], "abuse");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn service_record_absent_when_labeler_declared_but_hash_unpublished() {
    // Half-state: [labeler] is declared (declared_label_values =
    // Some) but no publish has happened (no labeler_config row).
    // Per the handler's conservative read, serviceRecord is omitted
    // — the contentHash is the load-bearing half and reporting
    // labelValues alone would surface a half-truth.
    let h = spawn_with_config(AdminConfig {
        service_did: SERVICE_DID.to_string(),
        service_endpoint: SERVICE_ENDPOINT.to_string(),
        declared_label_values: Some(vec!["spam".into()]),
        ..Default::default()
    })
    .await;
    add_moderator(&h.pool, ADMIN_DID, "admin", None).await;

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.getTrustChain");
    let (status, body) = get_query(h.addr, Some(&jwt)).await;
    assert_eq!(status, 200, "body: {body}");
    assert!(
        body.get("serviceRecord").is_none(),
        "serviceRecord must be absent when no publish has happened, body: {body}"
    );

    h.writer.shutdown().await.unwrap();
}
