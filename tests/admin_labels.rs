//! Integration tests for `tools.cairn.admin.{applyLabel, negateLabel,
//! listLabels}` (#13). Tests share the JWT + MockResolver pattern
//! from `tests/auth.rs` / `tests/create_report.rs` plus a small helper
//! for populating `moderators` roles.

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
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";
const ADMIN_DID: &str = "did:plc:admin00000000000000000000000";

// ---------- JWT + resolver helpers ----------

fn test_keypair() -> K256Keypair {
    K256Keypair::from_private_key(&hex::decode(TEST_PRIV_HEX).unwrap()).unwrap()
}

fn multibase() -> String {
    format_multikey("ES256K", &test_keypair().public_key_compressed())
}

fn did_doc(did: &str) -> DidDocument {
    DidDocument {
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#atproto"),
            r#type: "Multikey".into(),
            public_key_multibase: multibase(),
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
            (MODERATOR_DID.to_string(), did_doc(MODERATOR_DID)),
            (ADMIN_DID.to_string(), did_doc(ADMIN_DID)),
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

async fn spawn(config: AdminConfig) -> Harness {
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

    let router = admin_router(pool.clone(), writer.clone(), auth_ctx(), config);
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

// ---------- HTTP client ----------

async fn post_json(
    addr: SocketAddr,
    path: &str,
    auth: Option<&str>,
    extra: &[(&str, &str)],
    body: &Value,
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
    let bytes = serde_json::to_vec(body).unwrap();
    let mut req = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "127.0.0.1")
        .header("content-type", "application/json")
        .header("content-length", bytes.len().to_string());
    if let Some(t) = auth {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let req = req.body(Full::new(Bytes::from(bytes))).unwrap();
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

async fn get_query(addr: SocketAddr, path_with_query: &str, auth: Option<&str>) -> (u16, Value) {
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
        .uri(path_with_query)
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

// ========== applyLabel tests ==========

#[tokio::test]
async fn apply_label_happy_path_mod() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt),
        &[],
        &serde_json::json!({
            "uri": "at://did:plc:target000000000000000000/col/rkey",
            "val": "spam",
            "reason": "test",
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["seq"], 1);
    assert!(body["cts"].is_string());

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn apply_label_admin_role_also_permitted() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.applyLabel");
    let (status, _) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt),
        &[],
        &serde_json::json!({
            "uri": "at://did:plc:target000000000000000000/col/rkey",
            "val": "spam",
        }),
    )
    .await;
    assert_eq!(status, 200);
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn apply_label_without_role_returns_403() {
    // Auth succeeds (DID doc mocked) but the DID has no moderators row.
    let h = spawn(AdminConfig::default()).await;
    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt),
        &[],
        &serde_json::json!({
            "uri": "at://did:plc:x/col/rkey",
            "val": "spam",
        }),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "Forbidden");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn apply_label_invalid_jwt_returns_401() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some("not.a.valid.jwt"),
        &[],
        &serde_json::json!({"uri": "at://did:plc:x/c/r", "val": "spam"}),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "AuthenticationRequired");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn apply_label_invalid_label_value_when_allowlist_configured() {
    let cfg = AdminConfig {
        label_values: Some(vec!["spam".into(), "nudity".into()]),
        ..Default::default()
    };
    let h = spawn(cfg).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;
    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt),
        &[],
        &serde_json::json!({
            "uri": "at://did:plc:x/c/r",
            "val": "harassment",
        }),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidLabelValue");
    // Anti-leak: message must NOT enumerate the allowed set.
    let msg = body["message"].as_str().unwrap_or("");
    assert!(!msg.contains("spam"), "leaked allowed value: {msg:?}");
    assert!(!msg.contains("nudity"), "leaked allowed value: {msg:?}");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn apply_label_any_origin_header_returns_403() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;
    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt),
        &[("origin", "https://whatever.example.com")],
        &serde_json::json!({"uri": "at://did:plc:x/c/r", "val": "spam"}),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "Forbidden");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn apply_label_malformed_body_returns_400() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;
    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt),
        &[],
        &serde_json::json!({"nope": "nope"}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");
    h.writer.shutdown().await.unwrap();
}

// ========== negateLabel tests ==========

#[tokio::test]
async fn negate_label_happy_path_after_apply() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let uri = "at://did:plc:target000000000000000000/col/rkey";
    let jwt1 = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    let (s1, _) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt1),
        &[],
        &serde_json::json!({"uri": uri, "val": "spam"}),
    )
    .await;
    assert_eq!(s1, 200);

    let jwt2 = build_jwt(MODERATOR_DID, "tools.cairn.admin.negateLabel");
    let (s2, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.negateLabel",
        Some(&jwt2),
        &[],
        &serde_json::json!({"uri": uri, "val": "spam"}),
    )
    .await;
    assert_eq!(s2, 200);
    assert_eq!(body["seq"], 2);
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn negate_label_no_prior_apply_returns_label_not_found() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;
    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.negateLabel");
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.negateLabel",
        Some(&jwt),
        &[],
        &serde_json::json!({"uri": "at://did:plc:x/c/r", "val": "spam"}),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(body["error"], "LabelNotFound");
    h.writer.shutdown().await.unwrap();
}

// ========== listLabels tests ==========

#[tokio::test]
async fn list_labels_happy_path_returns_applied_only_by_default() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let uri = "at://did:plc:target000000000000000000/col/rkey";

    // Apply then negate: by default listLabels hides this tuple.
    let a_jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    let (_, _) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&a_jwt),
        &[],
        &serde_json::json!({"uri": uri, "val": "spam"}),
    )
    .await;
    let n_jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.negateLabel");
    let (_, _) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.negateLabel",
        Some(&n_jwt),
        &[],
        &serde_json::json!({"uri": uri, "val": "spam"}),
    )
    .await;

    let l_jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listLabels");
    let (status, body) =
        get_query(h.addr, "/xrpc/tools.cairn.admin.listLabels", Some(&l_jwt)).await;
    assert_eq!(status, 200);
    let labels = body["labels"].as_array().unwrap();
    assert_eq!(
        labels.len(),
        0,
        "default list hides apply events that have been negated"
    );
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_labels_include_negated_returns_all_rows() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let uri = "at://did:plc:target000000000000000000/col/rkey";
    let a_jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&a_jwt),
        &[],
        &serde_json::json!({"uri": uri, "val": "spam"}),
    )
    .await;
    let n_jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.negateLabel");
    post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.negateLabel",
        Some(&n_jwt),
        &[],
        &serde_json::json!({"uri": uri, "val": "spam"}),
    )
    .await;

    let l_jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listLabels");
    let (status, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listLabels?includeNegated=true",
        Some(&l_jwt),
    )
    .await;
    assert_eq!(status, 200);
    let labels = body["labels"].as_array().unwrap();
    assert_eq!(labels.len(), 2, "apply + negate both visible");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_labels_filters_by_uri_and_val() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    // Each apply needs a fresh JWT — the auth layer's jti replay cache
    // rejects reuse even across different target rows.
    for (uri, val) in [
        ("at://did:plc:a/c/1", "spam"),
        ("at://did:plc:a/c/2", "spam"),
        ("at://did:plc:b/c/1", "spam"),
        ("at://did:plc:a/c/1", "nudity"),
    ] {
        let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
        post_json(
            h.addr,
            "/xrpc/tools.cairn.admin.applyLabel",
            Some(&jwt),
            &[],
            &serde_json::json!({"uri": uri, "val": val}),
        )
        .await;
    }

    let l_jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listLabels");
    let (_, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listLabels?uri=at://did:plc:a/c/1",
        Some(&l_jwt),
    )
    .await;
    let labels = body["labels"].as_array().unwrap();
    assert_eq!(labels.len(), 2, "two labels on at://did:plc:a/c/1");

    let l_jwt2 = build_jwt(MODERATOR_DID, "tools.cairn.admin.listLabels");
    let (_, body2) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listLabels?val=nudity",
        Some(&l_jwt2),
    )
    .await;
    let labels2 = body2["labels"].as_array().unwrap();
    assert_eq!(labels2.len(), 1, "one nudity-valued label");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_labels_filters_by_actor_using_audit_join() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;

    let jwt_m = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
    post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt_m),
        &[],
        &serde_json::json!({"uri": "at://did:plc:a/c/1", "val": "spam"}),
    )
    .await;
    let jwt_a = build_jwt(ADMIN_DID, "tools.cairn.admin.applyLabel");
    post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.applyLabel",
        Some(&jwt_a),
        &[],
        &serde_json::json!({"uri": "at://did:plc:a/c/2", "val": "spam"}),
    )
    .await;

    let l_jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listLabels");
    let (_, body) = get_query(
        h.addr,
        &format!(
            "/xrpc/tools.cairn.admin.listLabels?actor={}",
            urlencoding::encode(MODERATOR_DID)
        ),
        Some(&l_jwt),
    )
    .await;
    let labels = body["labels"].as_array().unwrap();
    assert_eq!(labels.len(), 1, "actor filter returns only mod's apply");
    assert_eq!(labels[0]["uri"], "at://did:plc:a/c/1");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_labels_pagination_no_gaps_no_dupes() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    for i in 0..60 {
        // Fresh JWT per apply — otherwise jti replay rejects after the
        // first call.
        let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.applyLabel");
        post_json(
            h.addr,
            "/xrpc/tools.cairn.admin.applyLabel",
            Some(&jwt),
            &[],
            &serde_json::json!({
                "uri": format!("at://did:plc:target/col/{i:03}"),
                "val": "spam",
            }),
        )
        .await;
    }

    let mut seen: Vec<i64> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let l_jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listLabels");
        let mut url = "/xrpc/tools.cairn.admin.listLabels?limit=25".to_string();
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={}", urlencoding::encode(c)));
        }
        let (_, body) = get_query(h.addr, &url, Some(&l_jwt)).await;
        let labels = body["labels"].as_array().unwrap();
        for l in labels {
            seen.push(l["seq"].as_i64().unwrap());
        }
        cursor = body
            .get("cursor")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        if cursor.is_none() {
            break;
        }
    }
    let mut uniq = seen.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(seen.len(), 60, "60 applied labels visible across pages");
    assert_eq!(uniq.len(), 60, "no duplicates across pages");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_labels_limit_out_of_range_rejects() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;
    for bad in ["0", "-1", "251", "abc"] {
        // Fresh JWT per iteration — jti replay cache rejects reuse.
        let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listLabels");
        let (status, body) = get_query(
            h.addr,
            &format!("/xrpc/tools.cairn.admin.listLabels?limit={bad}"),
            Some(&jwt),
        )
        .await;
        assert_eq!(status, 400, "limit={bad} must be rejected");
        assert_eq!(body["error"], "InvalidRequest");
    }
    h.writer.shutdown().await.unwrap();
}
