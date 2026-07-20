//! Integration tests for `tools.ozone.moderation.queryEvents`
//! handler (#98). Mirrors the harness pattern from
//! `tests/xrpc_gateway_query_statuses.rs` adapted for the
//! audit_log → modEventView projection.
//!
//! Coverage:
//! - happy path: events from subject_action_recorded surface
//!   with the right $type per action_type
//! - filter-out policy: cairn-mod-internal audit rows
//!   (pending_*, report_resolved, etc.) do NOT surface here
//! - revoked-takedown surfaces as modEventReverseTakedown
//! - revoked-warning is filtered out (no Ozone analog)
//! - filters: subject, types, createdBy, date-range
//! - pagination cursor round-trip
//! - membership gating: untrusted caller → 403
//! - unsupported filters → 400 InvalidRequest

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
        subject_cid: None,
        detail: None,
    };
    h.writer.record_action(req).await.expect("record").action_id
}

async fn revoke(h: &Harness, action_id: i64, revoke_reason: Option<&str>) {
    let req = cairn_mod::writer::RevokeActionRequest {
        action_id,
        revoked_by_did: ISSUER_DID.to_string(),
        revoked_reason: revoke_reason.map(String::from),
    };
    h.writer.revoke_action(req).await.expect("revoke");
}

async fn get_query_events(addr: SocketAddr, jwt: &str, qs: &str) -> (u16, Value) {
    let url = format!("http://{addr}/xrpc/tools.ozone.moderation.queryEvents?{qs}");
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
async fn empty_audit_log_returns_empty_events() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn warning_action_surfaces_as_label_event() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        Some("warning rationale"),
        None,
    )
    .await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(
        ev["event"]["$type"].as_str(),
        Some("tools.ozone.moderation.defs#modEventLabel")
    );
    assert_eq!(ev["event"]["createLabelVals"], json!(["spam"]));
    assert_eq!(ev["event"]["comment"].as_str(), Some("warning rationale"));
    assert_eq!(ev["createdBy"].as_str(), Some(ISSUER_DID));
    assert_eq!(ev["subject"]["did"].as_str(), Some(TARGET_A));
}

#[tokio::test]
async fn note_action_surfaces_as_comment_event() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Note,
        "spam",
        Some("just logging"),
        None,
    )
    .await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    let ev = &body["events"].as_array().unwrap()[0];
    assert_eq!(
        ev["event"]["$type"].as_str(),
        Some("tools.ozone.moderation.defs#modEventComment")
    );
    assert_eq!(ev["event"]["comment"].as_str(), Some("just logging"));
}

#[tokio::test]
async fn takedown_action_surfaces_as_takedown_event() {
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
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    let ev = &body["events"].as_array().unwrap()[0];
    assert_eq!(
        ev["event"]["$type"].as_str(),
        Some("tools.ozone.moderation.defs#modEventTakedown")
    );
    assert_eq!(ev["event"]["comment"].as_str(), Some("banned"));
    assert!(ev["event"].get("durationInHours").is_none());
}

#[tokio::test]
async fn temp_suspension_surfaces_as_takedown_with_duration() {
    let h = spawn(true).await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::TempSuspension,
        "spam",
        None,
        Some("PT72H"),
    )
    .await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    let ev = &body["events"].as_array().unwrap()[0];
    assert_eq!(
        ev["event"]["$type"].as_str(),
        Some("tools.ozone.moderation.defs#modEventTakedown")
    );
    assert_eq!(ev["event"]["durationInHours"].as_i64(), Some(72));
}

#[tokio::test]
async fn revoked_takedown_surfaces_both_recorded_and_reverse_takedown() {
    let h = spawn(true).await;
    let action_id = record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Takedown,
        "spam",
        Some("banned"),
        None,
    )
    .await;
    revoke(&h, action_id, Some("appeal granted")).await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "{body}");
    // sort_direction=desc default → most recent first =
    // the revocation.
    let types: Vec<&str> = events
        .iter()
        .map(|e| e["event"]["$type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        vec![
            "tools.ozone.moderation.defs#modEventReverseTakedown",
            "tools.ozone.moderation.defs#modEventTakedown",
        ]
    );
    assert_eq!(
        events[0]["event"]["comment"].as_str(),
        Some("appeal granted")
    );
}

#[tokio::test]
async fn revoked_warning_is_filtered_out() {
    let h = spawn(true).await;
    let action_id = record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;
    revoke(&h, action_id, Some("mistake")).await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    // Only the original recorded event surfaces; the revocation
    // is filtered out (Ozone has no "reverse label" event type).
    assert_eq!(events.len(), 1, "{body}");
    assert_eq!(
        events[0]["event"]["$type"].as_str(),
        Some("tools.ozone.moderation.defs#modEventLabel")
    );
}

#[tokio::test]
async fn cairn_internal_audit_rows_are_filtered_out() {
    // Insert audit_log rows with cairn-mod-internal action
    // values. The handler's SQL filter limits to the Ozone-
    // eligible set; these rows should NOT appear in queryEvents
    // output. Use direct SQL insertion since these aren't
    // produced by the writer's public API in the integration
    // test scope.
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

    // Insert noisy cairn-mod-internal rows that should be
    // filtered out.
    for action in &[
        "report_resolved",
        "reporter_flagged",
        "retention_sweep",
        "service_record_published",
        "label_applied",
    ] {
        sqlx::query!(
            r#"INSERT INTO audit_log (created_at, action, actor_did, outcome)
               VALUES (?1, ?2, ?3, 'success')"#,
            1_000_000i64,
            action,
            ISSUER_DID,
        )
        .execute(&h.pool)
        .await
        .unwrap();
    }

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    // Only the warning event surfaces; the five cairn-mod-
    // internal rows are filtered.
    assert_eq!(events.len(), 1, "{body}");
    assert_eq!(
        events[0]["event"]["$type"].as_str(),
        Some("tools.ozone.moderation.defs#modEventLabel")
    );
}

#[tokio::test]
async fn subject_filter_narrows_to_one_target() {
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
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, &format!("subject={TARGET_A}")).await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["subject"]["did"].as_str(), Some(TARGET_A));
}

#[tokio::test]
async fn types_filter_narrows_to_takedown() {
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

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let qs = "types=tools.ozone.moderation.defs%23modEventTakedown";
    let (status, body) = get_query_events(h.addr, &jwt, qs).await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]["event"]["$type"].as_str(),
        Some("tools.ozone.moderation.defs#modEventTakedown")
    );
}

#[tokio::test]
async fn created_by_filter_narrows_to_one_moderator() {
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
    // Insert an audit_log + subject_actions for a different
    // moderator directly (the writer's record_action sets
    // actor_did from the request, but it's identical to
    // ISSUER_DID across our `record()` calls).
    let other_mod = "did:plc:othermod00000000000000000";
    let req = cairn_mod::writer::RecordActionRequest {
        subject: TARGET_B.to_string(),
        actor_did: other_mod.to_string(),
        action_type: cairn_mod::moderation::types::ActionType::Note,
        reason_codes: vec!["spam".into()],
        duration_iso: None,
        notes: None,
        report_ids: Vec::new(),
        subject_cid: None,
        detail: None,
    };
    h.writer.record_action(req).await.expect("record");

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, &format!("createdBy={other_mod}")).await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["createdBy"].as_str(), Some(other_mod));
}

#[tokio::test]
async fn pagination_round_trip() {
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
        cairn_mod::moderation::types::ActionType::Note,
        "spam",
        None,
        None,
    )
    .await;
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Takedown,
        "spam",
        None,
        None,
    )
    .await;

    let jwt1 = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let jwt2 = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");

    // Page 1: limit=2 → 2 events + cursor.
    let (status, body) = get_query_events(h.addr, &jwt1, "limit=2").await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    let cursor = body["cursor"].as_str().expect("cursor present").to_string();

    // Page 2: cursor → 1 remaining event, no cursor.
    let qs = format!("limit=2&cursor={}", urlencoding::encode(&cursor));
    let (status, body) = get_query_events(h.addr, &jwt2, &qs).await;
    assert_eq!(status, 200, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert!(body.get("cursor").is_none() || body["cursor"].is_null());
}

#[tokio::test]
async fn unknown_caller_returns_403() {
    let h = spawn(false).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, _body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn unsupported_added_labels_filter_returns_400() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "addedLabels=spam").await;
    assert_eq!(status, 400, "{body}");
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("addedLabels"), "{msg}");
}

#[tokio::test]
async fn unsupported_has_comment_filter_returns_400() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "hasComment=true").await;
    assert_eq!(status, 400, "{body}");
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("hasComment"), "{msg}");
}

#[tokio::test]
async fn malformed_cursor_returns_400() {
    let h = spawn(true).await;
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "cursor=not-base64-!!!").await;
    assert_eq!(status, 400, "{body}");
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("cursor") || msg.contains("base64"), "{msg}");
}

#[tokio::test]
async fn date_range_filter_narrows_results() {
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
        cairn_mod::moderation::types::ActionType::Note,
        "spam",
        None,
        None,
    )
    .await;

    // Far-future lower bound → no events match.
    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "createdAfter=2099-01-01T00:00:00Z").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn missing_authorization_returns_401() {
    let h = spawn(true).await;
    let url = format!("http://{}/xrpc/tools.ozone.moderation.queryEvents", h.addr);
    let res = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn record_level_subject_yields_strong_ref_in_event_view() {
    let h = spawn(true).await;
    let req = cairn_mod::writer::RecordActionRequest {
        subject: format!("at://{TARGET_A}/app.bsky.feed.post/abc"),
        actor_did: ISSUER_DID.to_string(),
        action_type: cairn_mod::moderation::types::ActionType::Warning,
        reason_codes: vec!["spam".into()],
        duration_iso: None,
        notes: None,
        report_ids: Vec::new(),
        subject_cid: None,
        detail: None,
    };
    h.writer.record_action(req).await.expect("record");

    let jwt = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let (status, body) = get_query_events(h.addr, &jwt, "").await;
    assert_eq!(status, 200, "{body}");
    let ev = &body["events"].as_array().unwrap()[0];
    assert_eq!(
        ev["subject"]["$type"].as_str(),
        Some("com.atproto.repo.strongRef")
    );
    assert_eq!(
        ev["subject"]["uri"].as_str(),
        Some(format!("at://{TARGET_A}/app.bsky.feed.post/abc").as_str())
    );
}

#[tokio::test]
async fn include_all_user_records_expands_subject_filter() {
    let h = spawn(true).await;
    // Account-level action on TARGET_A.
    record(
        &h,
        TARGET_A,
        cairn_mod::moderation::types::ActionType::Warning,
        "spam",
        None,
        None,
    )
    .await;
    // Record-level action under TARGET_A.
    let req = cairn_mod::writer::RecordActionRequest {
        subject: format!("at://{TARGET_A}/app.bsky.feed.post/abc"),
        actor_did: ISSUER_DID.to_string(),
        action_type: cairn_mod::moderation::types::ActionType::Note,
        reason_codes: vec!["spam".into()],
        duration_iso: None,
        notes: None,
        report_ids: Vec::new(),
        subject_cid: None,
        detail: None,
    };
    h.writer.record_action(req).await.expect("record");

    let jwt1 = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");
    let jwt2 = build_jwt(ISSUER_DID, "tools.ozone.moderation.queryEvents");

    // Without includeAllUserRecords: only account-level event.
    let (status, body) = get_query_events(h.addr, &jwt1, &format!("subject={TARGET_A}")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events"].as_array().unwrap().len(), 1);

    // With includeAllUserRecords=true: both events.
    let (status, body) = get_query_events(
        h.addr,
        &jwt2,
        &format!("subject={TARGET_A}&includeAllUserRecords=true"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events"].as_array().unwrap().len(), 2);
}
