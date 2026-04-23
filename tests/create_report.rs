//! Integration tests for `com.atproto.moderation.createReport` (§F11).
//!
//! Each test spins up a real axum server on an ephemeral port against a
//! fresh tempfile-backed SQLite DB, with a [`MockResolver`]-backed
//! [`AuthContext`] for verifying canned JWTs. The HTTP client is a
//! minimal hyper setup rather than reqwest — same pattern as
//! [`tests/query.rs`] — so tests can inspect raw headers and status
//! codes without reqwest's helpful-but-opaque error wrapping.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::{CreateReportConfig, create_report_router, storage};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";
const LXM: &str = "com.atproto.moderation.createReport";

// ========== JWT + resolver helpers (mirrors tests/auth.rs patterns) ==========

fn test_keypair() -> K256Keypair {
    let bytes = hex::decode(TEST_PRIV_HEX).expect("hex");
    K256Keypair::from_private_key(&bytes).expect("keypair")
}

fn multibase() -> String {
    format_multikey("ES256K", &test_keypair().public_key_compressed())
}

fn did_doc() -> DidDocument {
    DidDocument {
        id: MODERATOR_DID.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{MODERATOR_DID}#atproto"),
            r#type: "Multikey".to_string(),
            public_key_multibase: multibase(),
        }],
    }
}

fn build_jwt(claims: &Value) -> String {
    let header = serde_json::json!({"alg": "ES256K", "typ": "JWT"});
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h = engine.encode(header.to_string());
    let p = engine.encode(claims.to_string());
    let input = format!("{h}.{p}");
    let sig = test_keypair().sign(input.as_bytes()).expect("sign");
    let s = engine.encode(sig);
    format!("{h}.{p}.{s}")
}

fn valid_jwt() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    build_jwt(&serde_json::json!({
        "iss": MODERATOR_DID,
        "aud": SERVICE_DID,
        "exp": now + 60,
        "iat": now,
        "jti": format!("jti-{}", uuid::Uuid::new_v4()),
        "lxm": LXM,
    }))
}

struct MockResolver(Mutex<HashMap<String, DidDocument>>);

#[async_trait]
impl DidResolver for MockResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError> {
        match self.0.lock().unwrap().get(did).cloned() {
            Some(doc) => Ok(doc),
            None => Err(ResolveError::BadStatus(404)),
        }
    }
}

fn mock_auth() -> Arc<AuthContext> {
    let resolver = Arc::new(MockResolver(Mutex::new(
        [(MODERATOR_DID.to_string(), did_doc())].into(),
    )));
    let cfg = AuthConfig {
        service_did: SERVICE_DID.to_string(),
        ..AuthConfig::default()
    };
    Arc::new(AuthContext::with_resolver(cfg, resolver))
}

// ========== Harness ==========

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    addr: SocketAddr,
}

async fn spawn(config: CreateReportConfig) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.expect("open pool");

    // db_path must point at the file the pool opened so disk-guard has
    // something to stat. Each test's config is default unless it passed
    // its own; patch db_path here regardless.
    let mut config = config;
    config.db_path = path;

    let router = create_report_router(pool.clone(), mock_auth(), config);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    Harness {
        _dir: dir,
        pool,
        addr,
    }
}

// ========== HTTP client ==========

async fn post_json(
    addr: SocketAddr,
    auth: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &Value,
) -> (u16, Value, hyper::HeaderMap) {
    use http_body_util::{BodyExt as _, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(addr).await.expect("connect");
    let io = TokioIo::new(stream);
    let (mut send, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let body_bytes = serde_json::to_vec(body).unwrap();
    let mut req = hyper::Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.moderation.createReport")
        .header("host", "127.0.0.1")
        .header("content-type", "application/json")
        .header("content-length", body_bytes.len().to_string());
    if let Some(token) = auth {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Full::new(Bytes::from(body_bytes))).unwrap();

    let resp = send.send_request(req).await.expect("send");
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("parse json")
    };
    (status, json, headers)
}

async fn options_request(
    addr: SocketAddr,
    extra_headers: &[(&str, &str)],
) -> (u16, hyper::HeaderMap) {
    use http_body_util::{BodyExt as _, Empty};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(addr).await.expect("connect");
    let io = TokioIo::new(stream);
    let (mut send, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut req = hyper::Request::builder()
        .method("OPTIONS")
        .uri("/xrpc/com.atproto.moderation.createReport")
        .header("host", "127.0.0.1");
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Empty::<Bytes>::new()).unwrap();
    let resp = send.send_request(req).await.expect("send");
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let _ = resp.into_body().collect().await;
    (status, headers)
}

fn repo_subject(did: &str) -> Value {
    serde_json::json!({"$type": "com.atproto.admin.defs#repoRef", "did": did})
}

fn strong_subject(uri: &str, cid: &str) -> Value {
    serde_json::json!({
        "$type": "com.atproto.repo.strongRef",
        "uri": uri,
        "cid": cid,
    })
}

fn valid_body() -> Value {
    serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": repo_subject("did:plc:target000000000000000000"),
        "reason": "looks like spam",
    })
}

// ========== Tests ==========

#[tokio::test]
async fn valid_jwt_plus_valid_report_returns_200_with_row() {
    let h = spawn(CreateReportConfig::default()).await;
    let (status, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
    assert_eq!(status, 200);
    assert!(body["id"].as_i64().is_some());
    assert_eq!(body["reportedBy"], MODERATOR_DID);
    assert_eq!(body["reasonType"], "com.atproto.moderation.defs#reasonSpam");

    let row_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM reports")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(row_count, 1);
}

#[tokio::test]
async fn invalid_jwt_returns_401() {
    let h = spawn(CreateReportConfig::default()).await;
    let (status, body, _) = post_json(h.addr, Some("not.a.jwt"), &[], &valid_body()).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn missing_authorization_returns_401() {
    let h = spawn(CreateReportConfig::default()).await;
    let (status, body, _) = post_json(h.addr, None, &[], &valid_body()).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn malformed_body_returns_400() {
    let h = spawn(CreateReportConfig::default()).await;
    let (status, body, _) = post_json(
        h.addr,
        Some(&valid_jwt()),
        &[],
        &serde_json::json!({"garbage": true}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn unknown_reason_type_returns_400() {
    let h = spawn(CreateReportConfig::default()).await;
    // Ozone-derived reason NOT in Cairn's §F11 literal allowlist.
    let payload = serde_json::json!({
        "reasonType": "tools.ozone.report.defs#reasonSpamContent",
        "subject": repo_subject("did:plc:target000000000000000000"),
    });
    let (status, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &payload).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn reason_over_2kb_returns_400_without_leaking_limit() {
    let h = spawn(CreateReportConfig::default()).await;
    // Body large enough to exceed the 2KB reason cap but well under
    // max_body_bytes (32KB default), so we hit the reason check, not
    // the body-size check.
    let oversized = "a".repeat(4096);
    let mut payload = valid_body();
    payload["reason"] = Value::String(oversized);
    let (status, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &payload).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");
    // §F11: message must NOT quote the exact threshold.
    let msg = body["message"].as_str().unwrap_or("");
    assert!(
        !msg.contains("2048") && !msg.contains("2KB") && !msg.contains("2048"),
        "message leaked limit: {msg:?}"
    );
}

#[tokio::test]
async fn mod_tool_field_is_accepted_and_ignored() {
    let h = spawn(CreateReportConfig::default()).await;
    let mut payload = valid_body();
    payload["modTool"] = serde_json::json!({"name": "test-client/1.0"});
    let (status, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &payload).await;
    assert_eq!(status, 200);
    // Response shape doesn't echo modTool.
    assert!(body.get("modTool").is_none());
}

#[tokio::test]
async fn per_did_rate_limit_kicks_on_eleventh() {
    let cfg = CreateReportConfig {
        per_did_limit: 10,
        per_did_window: Duration::from_secs(3600),
        ..CreateReportConfig::default()
    };
    let h = spawn(cfg).await;
    for i in 0..10 {
        let (status, _, _) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
        assert_eq!(status, 200, "request {i} unexpectedly failed");
    }
    let (status, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
    assert_eq!(status, 429);
    assert_eq!(body["error"], "RateLimitExceeded");
}

#[tokio::test]
async fn global_pending_cap_kicks_on_third_when_cap_is_2() {
    let cfg = CreateReportConfig {
        global_pending_cap: 2,
        ..CreateReportConfig::default()
    };
    let h = spawn(cfg).await;
    let (s1, _, _) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
    let (s2, _, _) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
    assert_eq!(s1, 200);
    assert_eq!(s2, 200);
    let (s3, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
    assert_eq!(s3, 429);
    assert_eq!(body["error"], "RateLimitExceeded");
}

#[tokio::test]
async fn suppressed_reporter_gets_same_429_as_rate_limit() {
    let h = spawn(CreateReportConfig::default()).await;
    // Pre-insert a suppression row for the moderator DID.
    sqlx::query!(
        "INSERT INTO suppressed_reporters (did, suppressed_by, suppressed_at)
         VALUES (?1, 'did:plc:admin0000000000000000000000', 0)",
        MODERATOR_DID
    )
    .execute(&h.pool)
    .await
    .unwrap();

    let (status, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
    assert_eq!(status, 429);
    // §12 non-enumeration: response must be indistinguishable from a
    // genuine rate limit. Error name and message both identical.
    assert_eq!(body["error"], "RateLimitExceeded");
    assert_eq!(body["message"], "rate limit exceeded");
}

#[tokio::test]
async fn disk_guard_returns_generic_error_when_file_exceeds_limit() {
    // Default DB is tiny but we set limit to 1 byte so any non-empty
    // file trips the guard. Generic 500, no hint about the cause.
    let cfg = CreateReportConfig {
        disk_size_limit_bytes: 1,
        ..CreateReportConfig::default()
    };
    let h = spawn(cfg).await;
    let (status, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
    assert_eq!(status, 500);
    assert_eq!(body["error"], "InternalServerError");
}

#[tokio::test]
async fn no_origin_header_proceeds_normally() {
    let h = spawn(CreateReportConfig::default()).await;
    let (status, _, headers) = post_json(h.addr, Some(&valid_jwt()), &[], &valid_body()).await;
    assert_eq!(status, 200);
    assert!(
        headers.get("access-control-allow-origin").is_none(),
        "ACAO should not appear when request had no Origin"
    );
}

#[tokio::test]
async fn origin_in_allowlist_is_accepted_with_acao() {
    let cfg = CreateReportConfig {
        cors_allowed_origins: vec!["https://good.example.com".to_string()],
        ..CreateReportConfig::default()
    };
    let h = spawn(cfg).await;
    let (status, _, headers) = post_json(
        h.addr,
        Some(&valid_jwt()),
        &[("origin", "https://good.example.com")],
        &valid_body(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://good.example.com")
    );
    assert!(
        headers.get("access-control-allow-credentials").is_none(),
        "credentials must never be echoed"
    );
}

#[tokio::test]
async fn origin_not_in_allowlist_returns_403() {
    let cfg = CreateReportConfig {
        cors_allowed_origins: vec!["https://allowed.example.com".to_string()],
        ..CreateReportConfig::default()
    };
    let h = spawn(cfg).await;
    let (status, _, _) = post_json(
        h.addr,
        Some(&valid_jwt()),
        &[("origin", "https://evil.example.com")],
        &valid_body(),
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn preflight_options_with_allowed_origin_returns_204() {
    let cfg = CreateReportConfig {
        cors_allowed_origins: vec!["https://tool.example.com".to_string()],
        ..CreateReportConfig::default()
    };
    let h = spawn(cfg).await;
    let (status, headers) =
        options_request(h.addr, &[("origin", "https://tool.example.com")]).await;
    assert_eq!(status, 204);
    assert_eq!(
        headers
            .get("access-control-allow-methods")
            .and_then(|v| v.to_str().ok()),
        Some("POST")
    );
}

#[tokio::test]
async fn preflight_options_with_disallowed_origin_returns_403() {
    let cfg = CreateReportConfig {
        cors_allowed_origins: vec!["https://tool.example.com".to_string()],
        ..CreateReportConfig::default()
    };
    let h = spawn(cfg).await;
    let (status, _) = options_request(h.addr, &[("origin", "https://evil.example.com")]).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn strong_ref_subject_extracts_did_and_stores_record() {
    let h = spawn(CreateReportConfig::default()).await;
    let payload = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonViolation",
        "subject": strong_subject(
            "at://did:plc:target000000000000000000/app.bsky.feed.post/xyz",
            "bafy123"
        ),
    });
    let (status, _, _) = post_json(h.addr, Some(&valid_jwt()), &[], &payload).await;
    assert_eq!(status, 200);

    let row =
        sqlx::query!("SELECT subject_type, subject_did, subject_uri, subject_cid FROM reports")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(row.subject_type, "record");
    assert_eq!(row.subject_did, "did:plc:target000000000000000000");
    assert_eq!(
        row.subject_uri.as_deref(),
        Some("at://did:plc:target000000000000000000/app.bsky.feed.post/xyz")
    );
    assert_eq!(row.subject_cid.as_deref(), Some("bafy123"));
}

#[tokio::test]
async fn strong_ref_with_non_at_uri_rejects() {
    let h = spawn(CreateReportConfig::default()).await;
    let payload = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": strong_subject("https://example.com/not-an-at-uri", "bafy"),
    });
    let (status, body, _) = post_json(h.addr, Some(&valid_jwt()), &[], &payload).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn subject_existence_is_not_verified() {
    // §F11 Ozone parity: any well-formed AT-URI is accepted even for
    // subjects that don't exist in any PDS.
    let h = spawn(CreateReportConfig::default()).await;
    let payload = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": strong_subject(
            "at://did:plc:definitelyDoesNotExist00000/app.bsky.feed.post/x",
            "bafy000"
        ),
    });
    let (status, _, _) = post_json(h.addr, Some(&valid_jwt()), &[], &payload).await;
    assert_eq!(status, 200);
}
