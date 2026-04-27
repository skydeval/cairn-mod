//! Integration tests for `tools.cairn.public.getMyStrikeState`
//! (#54).
//!
//! Coverage:
//! - 401 when no Authorization header.
//! - 401 when the Bearer token fails service-auth verification.
//! - 200 when the caller's iss DID has history → returns the
//!   strike-state envelope shaped per
//!   `tools.cairn.admin.defs#subjectStrikeState`.
//! - 404 when the caller's iss DID has no history.
//! - Field-omission: `decayWindowRemainingDays` is omitted when
//!   `currentStrikeCount == 0` (the only path to 0 with non-empty
//!   history is a fully-revoked record, which we exercise here).
//! - Cross-endpoint consistency: the public response for the
//!   caller matches what `tools.cairn.admin.getSubjectStrikes`
//!   returns for the same DID — the two endpoints share the same
//!   projection by design (`crate::server::strike_state`), so this
//!   guards against accidental drift.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::{AdminConfig, admin_router, public_router, spawn_writer, storage};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const ADMIN_DID: &str = "did:plc:admin00000000000000000000";
const SUBJECT_DID: &str = "did:plc:subject000000000000000000";

// ---------- JWT + resolver helpers (mirror tests/admin_*.rs) ----------

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
            (SUBJECT_DID.to_string(), did_doc(SUBJECT_DID)),
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

// ---------- Harness: mounts both admin + public routers so the
// cross-endpoint consistency test can exercise both. ----------

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    addr: SocketAddr,
}

async fn spawn() -> Harness {
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
    )
    .await
    .unwrap();

    let auth = auth_ctx();
    let admin = admin_router(
        pool.clone(),
        writer.clone(),
        auth.clone(),
        AdminConfig::default(),
        cairn_mod::StrikePolicy::defaults(),
    );
    let public = public_router(
        pool.clone(),
        auth.clone(),
        cairn_mod::StrikePolicy::defaults(),
    );
    let router = admin.merge(public);

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

async fn grant_role(pool: &Pool<Sqlite>, did: &str, role: &str) {
    sqlx::query!(
        "INSERT INTO moderators (did, role, added_at) VALUES (?1, ?2, ?3)",
        did,
        role,
        0_i64,
    )
    .execute(pool)
    .await
    .unwrap();
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

const PUBLIC_LXM: &str = "tools.cairn.public.getMyStrikeState";
const RECORD_LXM: &str = "tools.cairn.admin.recordAction";
const REVOKE_LXM: &str = "tools.cairn.admin.revokeAction";
const ADMIN_STRIKES_LXM: &str = "tools.cairn.admin.getSubjectStrikes";

/// Record a takedown against SUBJECT_DID via the admin write path.
/// Returns the inserted action id.
async fn record_takedown_against_subject(h: &Harness) -> i64 {
    let r = http()
        .post(format!("http://{}/xrpc/{RECORD_LXM}", h.addr))
        .bearer_auth(build_jwt(ADMIN_DID, RECORD_LXM))
        .json(&serde_json::json!({
            "subject": SUBJECT_DID,
            "type": "takedown",
            "reasons": ["hate-speech"],
        }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "record status={}", r.status());
    r.json::<Value>().await.unwrap()["actionId"]
        .as_i64()
        .unwrap()
}

// =================== tests ===================

#[tokio::test]
async fn no_auth_returns_401() {
    let h = spawn().await;
    let resp = http()
        .get(format!("http://{}/xrpc/{PUBLIC_LXM}", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn malformed_bearer_returns_401() {
    let h = spawn().await;
    let resp = http()
        .get(format!("http://{}/xrpc/{PUBLIC_LXM}", h.addr))
        .bearer_auth("not-a-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn caller_with_no_history_returns_404() {
    let h = spawn().await;
    // No actions recorded against SUBJECT_DID; SUBJECT_DID calls
    // the public endpoint about themselves.
    let resp = http()
        .get(format!("http://{}/xrpc/{PUBLIC_LXM}", h.addr))
        .bearer_auth(build_jwt(SUBJECT_DID, PUBLIC_LXM))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "SubjectNotFound");
}

#[tokio::test]
async fn caller_with_history_returns_strike_state() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    record_takedown_against_subject(&h).await;

    let resp = http()
        .get(format!("http://{}/xrpc/{PUBLIC_LXM}", h.addr))
        .bearer_auth(build_jwt(SUBJECT_DID, PUBLIC_LXM))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status={}", resp.status());
    let body: Value = resp.json().await.unwrap();
    // Default policy: first offense in good standing → curve[0] = 1.
    // hate-speech base_weight = 4.
    assert_eq!(body["currentStrikeCount"], 1);
    assert_eq!(body["rawTotal"], 1);
    assert_eq!(body["decayedCount"], 0);
    assert_eq!(body["revokedCount"], 0);
    assert_eq!(body["goodStanding"], true);
    // current > 0 → decayWindowRemainingDays present.
    assert!(body["decayWindowRemainingDays"].as_u64().is_some());
}

#[tokio::test]
async fn fully_revoked_history_omits_decay_window_remaining_days() {
    // Edge case: a subject has a strike-bearing action that was
    // revoked. currentStrikeCount = 0, but rawTotal > 0 (history
    // exists). The decayWindowRemainingDays field should be
    // omitted because there's nothing left to decay.
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let action_id = record_takedown_against_subject(&h).await;
    // Revoke it.
    let r = http()
        .post(format!("http://{}/xrpc/{REVOKE_LXM}", h.addr))
        .bearer_auth(build_jwt(ADMIN_DID, REVOKE_LXM))
        .json(&serde_json::json!({"actionId": action_id}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());

    let resp = http()
        .get(format!("http://{}/xrpc/{PUBLIC_LXM}", h.addr))
        .bearer_auth(build_jwt(SUBJECT_DID, PUBLIC_LXM))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["currentStrikeCount"], 0);
    assert_eq!(body["rawTotal"], 1);
    assert_eq!(body["revokedCount"], 1);
    // Field omission contract.
    assert!(
        body.get("decayWindowRemainingDays").is_none()
            || body["decayWindowRemainingDays"].is_null(),
        "decayWindowRemainingDays must be omitted when currentStrikeCount == 0"
    );
}

#[tokio::test]
async fn public_response_matches_admin_response_for_same_subject() {
    // Cross-endpoint consistency: same projection used by both.
    // If they ever drift on field shape, this catches it.
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    record_takedown_against_subject(&h).await;

    let public_resp: Value = http()
        .get(format!("http://{}/xrpc/{PUBLIC_LXM}", h.addr))
        .bearer_auth(build_jwt(SUBJECT_DID, PUBLIC_LXM))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let admin_resp: Value = http()
        .get(format!(
            "http://{}/xrpc/{ADMIN_STRIKES_LXM}?subject={SUBJECT_DID}",
            h.addr
        ))
        .bearer_auth(build_jwt(ADMIN_DID, ADMIN_STRIKES_LXM))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Compare the load-bearing numeric fields directly. The two
    // responses share the same wire shape via the shared
    // `crate::server::strike_state` projection; the only fields
    // that legitimately can differ are timestamps (lastActionAt,
    // decayWindowRemainingDays) if SystemTime::now() is sampled at
    // distinct moments by the two handlers — those can differ by a
    // ms or two. Numeric counts must match exactly.
    for field in [
        "currentStrikeCount",
        "rawTotal",
        "decayedCount",
        "revokedCount",
        "goodStanding",
    ] {
        assert_eq!(
            public_resp[field], admin_resp[field],
            "{field} differs: public={} vs admin={}",
            public_resp[field], admin_resp[field]
        );
    }
}
