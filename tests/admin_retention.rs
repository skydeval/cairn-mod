//! Integration tests for `tools.cairn.admin.retentionSweep` (#12).
//!
//! Coverage:
//! - mod role rejected (403, admin-only endpoint).
//! - no auth rejected (401).
//! - origin-bearing request rejected (403, server-to-server only).
//! - admin role succeeds; returns SweepResult JSON; writes audit_log
//!   row with action=retention_sweep + actor_did=JWT iss.
//! - retention_days=None path returns rowsDeleted=0 and the optional
//!   `retentionDaysApplied` field is omitted (Option::is_none skip).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::{AdminConfig, ApplyLabelRequest, admin_router, spawn_writer, storage};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const ADMIN_DID: &str = "did:plc:admin00000000000000000000";
const MOD_DID: &str = "did:plc:moderator0000000000000000";
const MODERATOR_DID_FOR_LABELS: &str = "did:plc:moderator0000000000000000";
const LXM: &str = "tools.cairn.admin.retentionSweep";

// ---------- JWT + resolver helpers (same pattern as admin_audit.rs) ----------

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

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    writer: cairn_mod::WriterHandle,
    addr: SocketAddr,
}

async fn spawn_with_retention(retention_days: Option<u32>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();
    let writer = spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
        retention_days,
        cairn_mod::RetentionConfig {
            sweep_enabled: false, // manual-only path; this endpoint IS the manual trigger
            sweep_run_at_utc_hour: 4,
            sweep_batch_size: 1000,
        },
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();

    let router = admin_router(
        pool.clone(),
        writer.clone(),
        auth_ctx(),
        AdminConfig::default(),
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

async fn post_json(
    addr: SocketAddr,
    path: &str,
    auth: Option<&str>,
    origin: Option<&str>,
) -> (u16, Value) {
    use http_body_util::{BodyExt as _, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
    let (mut send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut req = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "127.0.0.1")
        .header("content-type", "application/json");
    if let Some(t) = auth {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    if let Some(o) = origin {
        req = req.header("origin", o);
    }
    let req = req.body(Full::<Bytes>::new(Bytes::from("{}"))).unwrap();
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
async fn no_auth_returns_401() {
    let h = spawn_with_retention(Some(30)).await;
    let (status, body) =
        post_json(h.addr, "/xrpc/tools.cairn.admin.retentionSweep", None, None).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "AuthenticationRequired");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn origin_bearing_request_returns_403() {
    let h = spawn_with_retention(Some(30)).await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let jwt = build_jwt(ADMIN_DID, LXM);
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.retentionSweep",
        Some(&jwt),
        Some("https://evil.example"),
    )
    .await;
    assert_eq!(status, 403, "admin endpoints reject browser-style origins");
    assert_eq!(body["error"], "Forbidden");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn mod_role_rejected_403() {
    let h = spawn_with_retention(Some(30)).await;
    grant_role(&h.pool, MOD_DID, "mod").await;
    let jwt = build_jwt(MOD_DID, LXM);
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.retentionSweep",
        Some(&jwt),
        None,
    )
    .await;
    assert_eq!(status, 403, "retentionSweep is admin-only");
    assert_eq!(body["error"], "Forbidden");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn admin_succeeds_writes_audit_row_and_returns_result_json() {
    let h = spawn_with_retention(Some(30)).await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;

    // Seed two labels and backdate them so the sweep has work to do.
    let label = ApplyLabelRequest {
        actor_did: MODERATOR_DID_FOR_LABELS.to_string(),
        uri: "at://did:plc:test000000000000000000000/app.bsky.feed.post/aaa".to_string(),
        cid: None,
        val: "spam".to_string(),
        exp: None,
        moderator_reason: Some("seed".to_string()),
    };
    h.writer.apply_label(label.clone()).await.unwrap();
    let mut label2 = label.clone();
    label2.uri = "at://did:plc:test111111111111111111111/app.bsky.feed.post/bbb".to_string();
    h.writer.apply_label(label2).await.unwrap();

    let cutoff_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        - 30 * 86_400_000;
    let too_old = cutoff_ms - 3_600_000;
    sqlx::query!("UPDATE labels SET created_at = ?1", too_old)
        .execute(&h.pool)
        .await
        .unwrap();

    let jwt = build_jwt(ADMIN_DID, LXM);
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.retentionSweep",
        Some(&jwt),
        None,
    )
    .await;
    assert_eq!(status, 200, "got body: {body}");
    assert_eq!(body["rowsDeleted"], 2);
    assert!(body["batches"].as_i64().unwrap() >= 1);
    assert!(body["durationMs"].is_number());
    assert_eq!(body["retentionDaysApplied"], 30);

    // Audit row written: exactly one with action=retention_sweep
    // and actor_did matching the JWT iss.
    let count = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n: i64" FROM audit_log
           WHERE action = 'retention_sweep' AND actor_did = ?1"#,
        ADMIN_DID,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "operator-initiated sweep MUST write an audit row");

    // Reason JSON carries the sweep result (per AUDIT_REASON_RETENTION_SWEEP).
    let reason: Option<String> = sqlx::query_scalar!(
        "SELECT reason FROM audit_log
         WHERE action = 'retention_sweep' AND actor_did = ?1",
        ADMIN_DID,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    let reason_json: Value = serde_json::from_str(&reason.unwrap()).unwrap();
    assert_eq!(reason_json["rows_deleted"], 2);
    assert_eq!(reason_json["retention_days_applied"], 30);
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn admin_succeeds_when_retention_disabled_with_zero_rows() {
    // retention_days=None at writer spawn time → sweep is a no-op.
    // Endpoint still returns 200 + the all-zero result.
    let h = spawn_with_retention(None).await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let jwt = build_jwt(ADMIN_DID, LXM);
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.retentionSweep",
        Some(&jwt),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["rowsDeleted"], 0);
    assert!(
        body.get("retentionDaysApplied").is_none(),
        "no cutoff configured → field omitted"
    );
    h.writer.shutdown().await.unwrap();
}
