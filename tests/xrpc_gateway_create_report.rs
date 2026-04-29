//! Integration tests for `com.atproto.moderation.createReport`
//! handler (#96). Mirrors the harness from
//! `tests/xrpc_gateway_emit_event.rs`, adapted for the
//! PDS-signed flow per §A10.
//!
//! Coverage:
//! - trusted PDS happy paths (account-level + record-level subjects)
//! - row insertion side-effects (subject_type / subject_did /
//!   subject_uri / subject_cid populated correctly)
//! - untrusted PDS short-circuits at membership middleware (403)
//! - cross-table isolation: a known-callers DID can't call createReport
//! - reasonType allowlist enforcement
//! - reportedBy DID-syntax validation
//! - missing / malformed request body
//! - missing auth → 401

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::xrpc_gateway::{
    XrpcAuthService, XrpcGatewayConfig, XrpcGatewayState, XrpcReplayCache, add_known_caller,
    add_trusted_pds,
};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::{Value, json};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:web:cairn.example.com";
const PDS_DID: &str = "did:web:pds.example.com";
const REPORTER_DID: &str = "did:plc:reporter000000000000000000";
const TARGET_DID: &str = "did:plc:target000000000000000000";
const MODERATOR_OWNER_DID: &str = "did:plc:m000000000000000000000000";

// ---------- JWT + resolver helpers ----------

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
    let claims = json!({
        "iss": iss,
        "aud": SERVICE_DID,
        "exp": now + 60,
        "iat": now,
        "jti": format!("jti-{}", uuid::Uuid::new_v4()),
        "lxm": lxm,
    });
    let header = json!({"alg": "ES256K", "typ": "JWT"});
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

// ---------- Vocabulary + writer ----------

fn build_vocab() -> cairn_mod::ReasonVocabulary {
    cairn_mod::ReasonVocabulary::defaults()
}

// ---------- Harness ----------

/// Membership-table seeding strategy for the gateway under test.
#[derive(Clone, Copy)]
enum SeedAs {
    /// Caller is in `xrpc_trusted_pdses`.
    TrustedPds,
    /// Caller is in `xrpc_known_callers` (NOT `xrpc_trusted_pdses`).
    /// Used for the cross-table-isolation negative case.
    KnownCaller,
    /// Caller is in neither table.
    Neither,
}

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    addr: SocketAddr,
}

async fn spawn(seed: SeedAs) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = cairn_mod::storage::open(&path).await.unwrap();

    let writer = cairn_mod::spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        build_vocab(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
        cairn_mod::PolicyAutomationPolicy::defaults(),
    )
    .await
    .unwrap();

    match seed {
        SeedAs::TrustedPds => {
            add_trusted_pds(&pool, PDS_DID, Some("test"), MODERATOR_OWNER_DID)
                .await
                .unwrap();
        }
        SeedAs::KnownCaller => {
            add_known_caller(&pool, PDS_DID, Some("test"), MODERATOR_OWNER_DID)
                .await
                .unwrap();
        }
        SeedAs::Neither => {}
    }

    let resolver = Arc::new(MockResolver(Mutex::new(
        [(PDS_DID.to_string(), did_doc(PDS_DID))].into(),
    )));
    let gateway_cfg = XrpcGatewayConfig {
        enabled: true,
        service_did: SERVICE_DID.into(),
        clock_skew_tolerance: Duration::from_secs(30),
        replay_cache_ttl: Duration::from_secs(90),
    };
    let auth = Arc::new(XrpcAuthService::new(gateway_cfg.clone(), resolver));
    let cache = Arc::new(XrpcReplayCache::new(gateway_cfg.replay_cache_ttl));
    let state = XrpcGatewayState {
        writer,
        pool: pool.clone(),
        service_did: SERVICE_DID.to_string(),
    };

    let router =
        cairn_mod::xrpc_gateway::build_router(gateway_cfg, auth, pool.clone(), cache, state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });

    Harness {
        _dir: dir,
        pool,
        addr,
    }
}

async fn post_create_report(addr: SocketAddr, jwt: &str, body: &Value) -> (u16, Value) {
    let url = format!("http://{addr}/xrpc/com.atproto.moderation.createReport");
    let res = reqwest::Client::new()
        .post(&url)
        .bearer_auth(jwt)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    let body = res.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

fn repo_ref(did: &str) -> Value {
    json!({
        "$type": "com.atproto.admin.defs#repoRef",
        "did": did,
    })
}

fn strong_ref(uri: &str, cid: &str) -> Value {
    json!({
        "$type": "com.atproto.repo.strongRef",
        "uri": uri,
        "cid": cid,
    })
}

// ---------- Tests ----------

#[tokio::test]
async fn trusted_pds_account_level_report_inserts_row() {
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "reason": "looks like spam",
        "subject": repo_ref(TARGET_DID),
        "reportedBy": REPORTER_DID,
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");

    // Echoed fields
    assert_eq!(
        view["reasonType"].as_str(),
        Some("com.atproto.moderation.defs#reasonSpam")
    );
    assert_eq!(view["reason"].as_str(), Some("looks like spam"));
    assert_eq!(view["reportedBy"].as_str(), Some(REPORTER_DID));
    assert_eq!(view["subject"], body["subject"]);
    let id = view["id"].as_i64().unwrap();
    assert!(id > 0, "id should be positive: {id}");

    // Side effect: row in reports
    let row = sqlx::query!(
        r#"SELECT
             reported_by, reason_type, reason, subject_type, subject_did,
             subject_uri, subject_cid, status
           FROM reports WHERE id = ?1"#,
        id,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(row.reported_by, REPORTER_DID);
    assert_eq!(row.reason_type, "com.atproto.moderation.defs#reasonSpam");
    assert_eq!(row.reason.as_deref(), Some("looks like spam"));
    assert_eq!(row.subject_type, "account");
    assert_eq!(row.subject_did, TARGET_DID);
    assert!(row.subject_uri.is_none());
    assert!(row.subject_cid.is_none());
    assert_eq!(row.status, "pending");
}

#[tokio::test]
async fn trusted_pds_record_level_report_inserts_row_with_uri_cid() {
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    let target_uri = format!("at://{TARGET_DID}/app.bsky.feed.post/abc");
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonViolation",
        "subject": strong_ref(&target_uri, "bafy123"),
        "reportedBy": REPORTER_DID,
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");
    let id = view["id"].as_i64().unwrap();

    let row = sqlx::query!(
        r#"SELECT subject_type, subject_did, subject_uri, subject_cid
           FROM reports WHERE id = ?1"#,
        id,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(row.subject_type, "record");
    assert_eq!(row.subject_did, TARGET_DID);
    assert_eq!(row.subject_uri.as_deref(), Some(target_uri.as_str()));
    assert_eq!(row.subject_cid.as_deref(), Some("bafy123"));
}

#[tokio::test]
async fn untrusted_pds_create_report_returns_403() {
    // PDS in NEITHER table → membership middleware short-circuits.
    // Distinct from the row-insertion path: we never reach the
    // handler, so no row should appear in `reports` regardless of
    // body shape.
    let h = spawn(SeedAs::Neither).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": repo_ref(TARGET_DID),
        "reportedBy": REPORTER_DID,
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 403, "{view}");
    assert_eq!(view["error"].as_str(), Some("AccountTakedown"));

    // No row inserted.
    let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM reports")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn known_caller_only_did_cannot_call_create_report() {
    // Cross-table isolation per #94's design: a DID in
    // xrpc_known_callers is NOT trusted as a PDS for forwarded
    // reports. Membership middleware routes createReport to
    // is_trusted_pds, which returns false → 403.
    let h = spawn(SeedAs::KnownCaller).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": repo_ref(TARGET_DID),
        "reportedBy": REPORTER_DID,
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 403, "{view}");
}

#[tokio::test]
async fn unknown_reason_type_returns_400() {
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonNotInAllowlist",
        "subject": repo_ref(TARGET_DID),
        "reportedBy": REPORTER_DID,
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    assert_eq!(view["error"].as_str(), Some("InvalidRequest"));
    let msg = view["message"].as_str().unwrap();
    assert!(msg.contains("reasonType"), "{msg}");
}

#[tokio::test]
async fn malformed_reported_by_returns_400() {
    // Defense-in-depth: even though the PDS is trusted, a
    // malformed reportedBy (not DID-shaped) must not poison the
    // table.
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": repo_ref(TARGET_DID),
        "reportedBy": "not-a-did",
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    let msg = view["message"].as_str().unwrap();
    assert!(msg.contains("reportedBy"), "{msg}");
}

#[tokio::test]
async fn malformed_request_body_returns_400() {
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    // Missing required `subject` and `reportedBy` fields.
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    assert_eq!(view["error"].as_str(), Some("InvalidRequest"));
}

#[tokio::test]
async fn missing_authorization_returns_401() {
    let h = spawn(SeedAs::TrustedPds).await;
    let url = format!("http://{}/xrpc/com.atproto.moderation.createReport", h.addr);
    let res = reqwest::Client::new()
        .post(&url)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
    let view: Value = res.json().await.unwrap();
    assert_eq!(view["error"].as_str(), Some("AuthRequired"));
}

#[tokio::test]
async fn record_level_report_with_malformed_uri_returns_400() {
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": strong_ref("https://not-an-at-uri.com/post", "bafy"),
        "reportedBy": REPORTER_DID,
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    let msg = view["message"].as_str().unwrap();
    assert!(msg.contains("AT-URI"), "{msg}");
}

#[tokio::test]
async fn reported_by_field_is_taken_verbatim_from_body_not_jwt_iss() {
    // §A10 trust model: the PDS asserts the user's identity via
    // reportedBy. Verify cairn-mod takes that field verbatim and
    // does NOT substitute claims.iss (which would be the PDS's
    // DID, not the user's).
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID, "com.atproto.moderation.createReport");
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonOther",
        "subject": repo_ref(TARGET_DID),
        "reportedBy": REPORTER_DID,
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");
    let id = view["id"].as_i64().unwrap();
    let row = sqlx::query!("SELECT reported_by FROM reports WHERE id = ?1", id,)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    // Reporter, not PDS.
    assert_eq!(row.reported_by, REPORTER_DID);
    assert_ne!(row.reported_by, PDS_DID);
}
