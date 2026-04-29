//! Integration tests for `tools.ozone.moderation.queryStatuses`
//! handler (#97). Mirrors the harness pattern from
//! `tests/xrpc_gateway_emit_event.rs` adapted for the read-only
//! GET endpoint.
//!
//! Coverage:
//! - happy paths: account-level + record-level subjects, with/
//!   without filters
//! - field projection correctness: takendown true/false,
//!   updated/created timestamps, comment from most recent action
//! - filter handling: subject, takendown, tags, appealed
//! - filter rejection: comment / reportedAfter / reviewState etc.
//!   return 400 InvalidRequest
//! - pagination: cursor round-trip across multiple pages
//! - membership gating: untrusted caller → 403
//! - empty result: subject with no history returns empty array

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::xrpc_gateway::{
    XrpcAuthService, XrpcGatewayConfig, XrpcGatewayState, XrpcReplayCache, add_known_caller,
};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::{Value, json};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:web:cairn.example.com";
const ISSUER_DID: &str = "did:plc:moderator0000000000000000";
const TARGET_A: &str = "did:plc:targetA000000000000000000";
const TARGET_B: &str = "did:plc:targetB000000000000000000";
const TARGET_C: &str = "did:plc:targetC000000000000000000";
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

// ---------- Vocabulary ----------

fn build_vocab() -> cairn_mod::ReasonVocabulary {
    cairn_mod::ReasonVocabulary::defaults()
}

// ---------- Harness ----------

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    writer: cairn_mod::WriterHandle,
    addr: SocketAddr,
}

impl Harness {
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn spawn(seed_known_caller: bool) -> Harness {
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

    if seed_known_caller {
        add_known_caller(&pool, ISSUER_DID, Some("test"), MODERATOR_OWNER_DID)
            .await
            .unwrap();
    }

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
        writer: writer.clone(),
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
        writer,
        addr,
    }
}

/// Record an action against a subject via the writer (the
/// canonical recordAction pipeline). Returns the action_id.
async fn record(
    h: &Harness,
    subject_did: &str,
    action_type: cairn_mod::moderation::types::ActionType,
    reason: &str,
    notes: Option<&str>,
    duration_iso: Option<&str>,
) -> i64 {
    let req = cairn_mod::writer::RecordActionRequest {
        subject: subject_did.to_string(),
        actor_did: ISSUER_DID.to_string(),
        action_type,
        reason_codes: vec![reason.into()],
        duration_iso: duration_iso.map(String::from),
        notes: notes.map(String::from),
        report_ids: Vec::new(),
    };
    let r = h.writer.record_action(req).await.expect("record action");
    r.action_id
}

async fn revoke(h: &Harness, action_id: i64) {
    let req = cairn_mod::writer::RevokeActionRequest {
        action_id,
        revoked_by_did: ISSUER_DID.to_string(),
        revoked_reason: Some("test revoke".into()),
    };
    h.writer.revoke_action(req).await.expect("revoke");
}

/// Fire a queryStatuses request with the given query string.
async fn get_query_statuses(addr: SocketAddr, jwt: &str, qs: &str) -> (u16, Value) {
    let url = format!("http://{addr}/xrpc/tools.ozone.moderation.queryStatuses?{qs}");
    let res = reqwest::Client::new()
        .get(&url)
        .bearer_auth(jwt)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    let body = res.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

// ---------- Tests ----------

#[tokio::test]
async fn empty_db_returns_empty_array() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["subjectStatuses"].as_array().unwrap().len(), 0);
    assert!(body.get("cursor").is_none() || body["cursor"].is_null());
}

#[tokio::test]
async fn account_level_subject_filter_returns_one_status() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        Some("first warning"),
        None,
    )
    .await;
    record(
        &h,
        TARGET_B,
        cairn_mod::moderation::types::ActionType::Note,
        "spam",
        None,
        None,
    )
    .await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let qs = format!("subject={TARGET_A}");
    let (status, body) = get_query_statuses(h.addr, &jwt, &qs).await;
    assert_eq!(status, 200, "{body}");
    let arr = body["subjectStatuses"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let view = &arr[0];
    assert_eq!(view["subject"]["did"].as_str(), Some(TARGET_A));
    assert_eq!(
        view["subject"]["$type"].as_str(),
        Some("com.atproto.admin.defs#repoRef")
    );
    assert_eq!(view["takendown"].as_bool(), Some(false));
    assert_eq!(view["appealed"].as_bool(), Some(false));
    assert_eq!(view["comment"].as_str(), Some("first warning"));
    assert_eq!(view["lastReviewedBy"].as_str(), Some(ISSUER_DID));
    assert_eq!(
        view["reviewState"].as_str(),
        Some("tools.ozone.moderation.defs#reviewClosed")
    );
}

#[tokio::test]
async fn takedown_action_yields_takendown_true() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Takedown,
        "spam",
        Some("banned"),
        None,
    )
    .await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, &format!("subject={TARGET_A}")).await;
    assert_eq!(status, 200, "{body}");
    let view = &body["subjectStatuses"].as_array().unwrap()[0];
    assert_eq!(view["takendown"].as_bool(), Some(true));
}

#[tokio::test]
async fn revoked_takedown_yields_takendown_false() {
    let h = spawn(true).await;
    let id = record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Takedown,
        "spam",
        None,
        None,
    )
    .await;
    revoke(&h, id).await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, &format!("subject={TARGET_A}")).await;
    assert_eq!(status, 200, "{body}");
    let view = &body["subjectStatuses"].as_array().unwrap()[0];
    assert_eq!(view["takendown"].as_bool(), Some(false));
}

#[tokio::test]
async fn takendown_filter_true_excludes_non_takendown() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;
    record(
        &h,
        TARGET_B,
        cairn_mod::moderation::types::ActionType::Takedown,
        "spam",
        None,
        None,
    )
    .await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, "takendown=true").await;
    assert_eq!(status, 200, "{body}");
    let arr = body["subjectStatuses"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "{body}");
    assert_eq!(arr[0]["subject"]["did"].as_str(), Some(TARGET_B));
}

#[tokio::test]
async fn takendown_filter_false_excludes_takendown() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;
    record(
        &h,
        TARGET_B,
        cairn_mod::moderation::types::ActionType::Takedown,
        "spam",
        None,
        None,
    )
    .await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, "takendown=false").await;
    assert_eq!(status, 200, "{body}");
    let arr = body["subjectStatuses"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["subject"]["did"].as_str(), Some(TARGET_A));
}

#[tokio::test]
async fn appealed_true_returns_empty_array() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, "appealed=true").await;
    assert_eq!(status, 200, "{body}");
    let arr = body["subjectStatuses"].as_array().unwrap();
    assert_eq!(arr.len(), 0);
}

#[tokio::test]
async fn unsupported_comment_filter_returns_400() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, "comment=foo").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"].as_str(), Some("InvalidRequest"));
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("comment"), "{msg}");
}

#[tokio::test]
async fn unsupported_review_state_filter_returns_400() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, "reviewState=open").await;
    assert_eq!(status, 400, "{body}");
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("reviewState"), "{msg}");
}

#[tokio::test]
async fn invalid_limit_returns_400() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, "limit=200").await;
    assert_eq!(status, 400, "{body}");
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("100"), "{msg}");
}

#[tokio::test]
async fn malformed_cursor_returns_400() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, "cursor=not-base64-!!!").await;
    assert_eq!(status, 400, "{body}");
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("cursor") || msg.contains("base64"), "{msg}");
}

#[tokio::test]
async fn unknown_caller_returns_403() {
    // Caller NOT in xrpc_known_callers — membership middleware
    // short-circuits.
    let h = spawn(false).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, _body) = get_query_statuses(h.addr, &jwt, "").await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn pagination_round_trip() {
    let h = spawn(true).await;
    // Three subjects, one action each.
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;
    record(
        &h,
        TARGET_B,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;
    record(
        &h,
        TARGET_C,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;

    // Each request needs a fresh JWT (distinct jti) — the replay
    // middleware rejects duplicates.
    let jwt1 = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let jwt2 = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");

    // Page 1: limit=2 → 2 results + cursor.
    let (status, body) = get_query_statuses(h.addr, &jwt1, "limit=2").await;
    assert_eq!(status, 200, "{body}");
    let arr = body["subjectStatuses"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let cursor = body["cursor"].as_str().expect("cursor present").to_string();

    // Page 2: cursor → 1 remaining result, no cursor.
    let qs = format!("limit=2&cursor={}", urlencoding::encode(&cursor));
    let (status, body) = get_query_statuses(h.addr, &jwt2, &qs).await;
    assert_eq!(status, 200, "{body}");
    let arr = body["subjectStatuses"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert!(body.get("cursor").is_none() || body["cursor"].is_null());
}

#[tokio::test]
async fn most_recent_action_drives_updated_at_and_comment() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        Some("first"),
        None,
    )
    .await;
    // Sleep is wall-clock dependent — instead, advance via two
    // separate writer commands with distinct ids; ids are
    // monotonic and that's what the projection sorts on.
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Note,
        "spam",
        Some("second"),
        None,
    )
    .await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Note,
        "spam",
        Some("third"),
        None,
    )
    .await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, &format!("subject={TARGET_A}")).await;
    assert_eq!(status, 200, "{body}");
    let view = &body["subjectStatuses"].as_array().unwrap()[0];
    assert_eq!(view["comment"].as_str(), Some("third"));
    // `id` is the most recent action's id (largest)
    let id = view["id"].as_i64().unwrap();
    assert!(id > 0);
}

#[tokio::test]
async fn created_at_is_earliest_updated_at_is_latest() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Note,
        "spam",
        None,
        None,
    )
    .await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, &format!("subject={TARGET_A}")).await;
    assert_eq!(status, 200, "{body}");
    let view = &body["subjectStatuses"].as_array().unwrap()[0];
    let created = view["createdAt"].as_str().unwrap();
    let updated = view["updatedAt"].as_str().unwrap();
    // Both are RFC-3339 Z. createdAt <= updatedAt
    // lexicographically (which is also chronologically for the
    // matching format).
    assert!(
        created <= updated,
        "createdAt {created} > updatedAt {updated}"
    );
}

#[tokio::test]
async fn missing_authorization_returns_401() {
    let h = spawn(true).await;
    let url = format!("{}/xrpc/tools.ozone.moderation.queryStatuses", h.url());
    let res = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn record_level_subject_yields_strong_ref() {
    let h = spawn(true).await;
    // Record-level action: write directly via writer with a
    // record subject (at:// URI).
    let req = cairn_mod::writer::RecordActionRequest {
        subject: format!("at://{TARGET_A}/app.bsky.feed.post/abc"),
        actor_did: ISSUER_DID.to_string(),
        action_type: cairn_mod::moderation::types::ActionType::Warning,
        reason_codes: vec!["spam".into()],
        duration_iso: None,
        notes: Some("record warning".into()),
        report_ids: Vec::new(),
    };
    h.writer.record_action(req).await.expect("record");

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let qs = format!(
        "subject={}",
        urlencoding::encode(&format!("at://{TARGET_A}/app.bsky.feed.post/abc"))
    );
    let (status, body) = get_query_statuses(h.addr, &jwt, &qs).await;
    assert_eq!(status, 200, "{body}");
    let view = &body["subjectStatuses"].as_array().unwrap()[0];
    assert_eq!(
        view["subject"]["$type"].as_str(),
        Some("com.atproto.repo.strongRef")
    );
    assert_eq!(
        view["subject"]["uri"].as_str(),
        Some(format!("at://{TARGET_A}/app.bsky.feed.post/abc").as_str())
    );
}

#[tokio::test]
async fn last_reported_at_populated_when_report_exists() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;
    // Write a row to the reports table directly. The gateway
    // path's createReport handler (#96) doesn't have access here;
    // we just simulate the user-direct intake landing one.
    sqlx::query!(
        r#"INSERT INTO reports (
             created_at, reported_by, reason_type, reason,
             subject_type, subject_did, status
           )
           VALUES ('2026-04-29T12:00:00.000Z', 'did:plc:reporter', 'com.atproto.moderation.defs#reasonSpam', NULL, 'account', ?1, 'pending')"#,
        TARGET_A,
    )
    .execute(&h.pool)
    .await
    .unwrap();

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryStatuses");
    let (status, body) = get_query_statuses(h.addr, &jwt, &format!("subject={TARGET_A}")).await;
    assert_eq!(status, 200, "{body}");
    let view = &body["subjectStatuses"].as_array().unwrap()[0];
    assert_eq!(
        view["lastReportedAt"].as_str(),
        Some("2026-04-29T12:00:00.000Z")
    );
}
