//! Integration tests for `tools.ozone.moderation.emitEvent`
//! handler (#95). Mirrors the harness pattern from
//! `tests/admin_labels.rs` (real DB + writer + axum::serve +
//! reqwest), adapted for the inbound xrpc_gateway surface.
//!
//! Coverage:
//! - happy paths for all four ModEvent variants
//! - response wire shape (echoed event/subject; created_by from
//!   claims; id is the cairn-mod action_id)
//! - createdBy ↔ claims.iss enforcement
//! - subject discriminator validation (repoRef accepted; strongRef
//!   rejected)
//! - modEventLabel rejects negateLabelVals
//! - modEventReverseTakedown lookup: success path + no-active-takedown
//!   failure path
//! - Unsupported $type returns 400 InvalidRequest

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::xrpc_gateway::{
    XRPC_GATEWAY_DEFAULT_REASON_CODE, XrpcAuthService, XrpcGatewayConfig, XrpcGatewayState,
    XrpcReplayCache, add_known_caller,
};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::{Value, json};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:web:cairn.example.com";
const ISSUER_DID: &str = "did:plc:moderator0000000000000000";
const TARGET_DID: &str = "did:plc:target0000000000000000000";
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

// ---------- Config + vocabulary ----------

/// Build a Config-shaped JSON Value with `[moderation_reasons]`
/// entries for the codes the integration tests need: the reserved
/// `xrpc-gateway-default` (used by Takedown / Comment events) plus
/// "spam" / "harassment" (mapped 1:1 from createLabelVals).
fn test_config_value() -> serde_json::Map<String, Value> {
    let mut reasons = serde_json::Map::new();
    for id in &[XRPC_GATEWAY_DEFAULT_REASON_CODE, "spam", "harassment"] {
        reasons.insert(
            (*id).to_string(),
            json!({
                "base_weight": 1,
                "severe": false,
                "description": "test fixture",
            }),
        );
    }
    let mut cfg = serde_json::Map::new();
    cfg.insert("service_did".into(), json!(SERVICE_DID));
    cfg.insert("service_endpoint".into(), json!("https://labeler.example"));
    cfg.insert("db_path".into(), json!("/var/lib/cairn/cairn.db"));
    cfg.insert(
        "signing_key_path".into(),
        json!("/etc/cairn/signing-key.hex"),
    );
    cfg.insert("moderation_reasons".into(), Value::Object(reasons));
    cfg
}

fn build_vocab() -> cairn_mod::ReasonVocabulary {
    let cfg: cairn_mod::Config =
        serde_json::from_value(Value::Object(test_config_value())).unwrap();
    cairn_mod::ReasonVocabulary::from_config(&cfg).unwrap()
}

// ---------- Harness ----------

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    addr: SocketAddr,
}

impl Harness {
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn spawn() -> Harness {
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

    // Seed xrpc_known_callers so the membership middleware lets
    // ISSUER_DID through. The handle to `MODERATOR_OWNER_DID` is
    // arbitrary — it's the cairn-mod operator's own DID for audit
    // attribution on the membership row.
    add_known_caller(&pool, ISSUER_DID, Some("test"), MODERATOR_OWNER_DID)
        .await
        .unwrap();

    let resolver = Arc::new(MockResolver(Mutex::new(
        [(ISSUER_DID.to_string(), did_doc(ISSUER_DID))].into(),
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

async fn post_emit_event(addr: SocketAddr, jwt: &str, body: &Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/xrpc/tools.ozone.moderation.emitEvent");
    let res = client
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

// ---------- Tests ----------

#[tokio::test]
async fn label_event_records_warning_action_and_returns_view() {
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventLabel",
            "createLabelVals": ["spam"],
            "comment": "looks like spam to me",
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(
        view.get("createdBy").and_then(|v| v.as_str()),
        Some(ISSUER_DID)
    );
    // event/subject echoed verbatim
    assert_eq!(view["event"], body["event"]);
    assert_eq!(view["subject"], body["subject"]);
    // id is a positive integer (the action_id)
    let id = view.get("id").and_then(|v| v.as_i64()).unwrap();
    assert!(id > 0, "id should be positive: {id}");

    // Side effect: subject_actions row was inserted with the
    // mapped action_type=warning.
    let row = sqlx::query!(
        "SELECT action_type, actor_did FROM subject_actions WHERE id = ?1",
        id,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(row.action_type, "warning");
    assert_eq!(row.actor_did, ISSUER_DID);
}

#[tokio::test]
async fn takedown_event_without_duration_records_takedown() {
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventTakedown",
            "comment": "spam farm",
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");
    let id = view["id"].as_i64().unwrap();
    let row = sqlx::query!(
        "SELECT action_type, duration FROM subject_actions WHERE id = ?1",
        id,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(row.action_type, "takedown");
    assert_eq!(row.duration, None);
}

#[tokio::test]
async fn takedown_event_with_duration_records_temp_suspension() {
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventTakedown",
            "comment": "7-day cooldown",
            "durationInHours": 168,
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");
    let id = view["id"].as_i64().unwrap();
    let row = sqlx::query!(
        "SELECT action_type, duration FROM subject_actions WHERE id = ?1",
        id,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(row.action_type, "temp_suspension");
    assert_eq!(row.duration.as_deref(), Some("PT168H"));
}

#[tokio::test]
async fn comment_event_records_note_action() {
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventComment",
            "comment": "needs second review",
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");
    let id = view["id"].as_i64().unwrap();
    let row = sqlx::query!(
        "SELECT action_type, notes FROM subject_actions WHERE id = ?1",
        id,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(row.action_type, "note");
    assert_eq!(row.notes.as_deref(), Some("needs second review"));
}

#[tokio::test]
async fn reverse_takedown_revokes_most_recent_unrevoked_takedown() {
    let h = spawn().await;
    let jwt_takedown = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");

    // Step 1: lay down a takedown via emitEvent.
    let takedown_body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventTakedown",
            "comment": "initial takedown",
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt_takedown, &takedown_body).await;
    assert_eq!(status, 200, "{view}");
    let takedown_id = view["id"].as_i64().unwrap();

    // Step 2: reverse it. Fresh JWT (different jti) so replay
    // cache doesn't reject.
    let jwt_reverse = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let reverse_body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventReverseTakedown",
            "comment": "appeal granted",
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt_reverse, &reverse_body).await;
    assert_eq!(status, 200, "{view}");
    // Response id is the action_id of the action being revoked.
    assert_eq!(view["id"].as_i64(), Some(takedown_id));

    // Side effect: revoked_at / revoked_by / revoked_reason set.
    let row = sqlx::query!(
        "SELECT revoked_at, revoked_by_did, revoked_reason FROM subject_actions WHERE id = ?1",
        takedown_id,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(row.revoked_at.is_some());
    assert_eq!(row.revoked_by_did.as_deref(), Some(ISSUER_DID));
    assert_eq!(row.revoked_reason.as_deref(), Some("appeal granted"));
}

#[tokio::test]
async fn reverse_takedown_with_no_active_takedown_returns_400() {
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventReverseTakedown",
            "comment": "no takedown to reverse",
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    assert_eq!(
        view.get("error").and_then(|v| v.as_str()),
        Some("InvalidRequest")
    );
    let msg = view["message"].as_str().unwrap();
    assert!(msg.contains("no active takedown"), "{msg}");
}

#[tokio::test]
async fn created_by_spoofing_is_rejected() {
    // JWT iss = ISSUER_DID; createdBy claims a different DID.
    // §A8.1 defense-in-depth: must equal the authenticated issuer.
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let other_did = "did:plc:imposter000000000000000000";
    let body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventComment",
            "comment": "spoofed",
        },
        "createdBy": other_did,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    assert_eq!(view["error"].as_str(), Some("InvalidRequest"));
    let msg = view["message"].as_str().unwrap();
    assert!(msg.contains("createdBy"), "{msg}");
    assert!(msg.contains(other_did), "{msg}");
}

#[tokio::test]
async fn unsupported_event_type_returns_400() {
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventMute",
            "durationInHours": 24,
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    assert_eq!(view["error"].as_str(), Some("InvalidRequest"));
    let msg = view["message"].as_str().unwrap();
    assert!(msg.contains("modEventMute"), "{msg}");
}

#[tokio::test]
async fn label_event_with_negate_label_vals_is_rejected() {
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let body = json!({
        "subject": repo_ref(TARGET_DID),
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventLabel",
            "createLabelVals": ["spam"],
            "negateLabelVals": ["harassment"],
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    let msg = view["message"].as_str().unwrap();
    assert!(msg.contains("negateLabelVals"), "{msg}");
}

#[tokio::test]
async fn strong_ref_subject_is_rejected() {
    let h = spawn().await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.emitEvent");
    let body = json!({
        "subject": {
            "$type": "com.atproto.repo.strongRef",
            "uri": format!("at://{TARGET_DID}/app.bsky.feed.post/abc"),
            "cid": "bafyreigh2akiscaildc5xpwafpnq",
        },
        "event": {
            "$type": "tools.ozone.moderation.defs#modEventComment",
            "comment": "x",
        },
        "createdBy": ISSUER_DID,
    });
    let (status, view) = post_emit_event(h.addr, &jwt, &body).await;
    assert_eq!(status, 400, "{view}");
    let msg = view["message"].as_str().unwrap();
    assert!(
        msg.contains("repoRef") || msg.contains("strongRef"),
        "{msg}"
    );
}

#[tokio::test]
async fn missing_authorization_returns_401() {
    let h = spawn().await;
    let url = format!("{}/xrpc/tools.ozone.moderation.emitEvent", h.url());
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
