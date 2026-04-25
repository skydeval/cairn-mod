//! Integration tests for `tools.cairn.admin.listAuditLog` (#17).
//!
//! Admin-role-only endpoint. Tests cover role gating, all filters
//! (actor, action, outcome, since, until), bound-swap 400, unknown
//! action/outcome 400, DESC pagination across 60 rows, no-auth 401,
//! CORS reject-any-origin 403, reason-passthrough of writer-produced
//! rows, and the `labels.created_at == audit_log.created_at` join
//! invariant for actor filtering used by list_labels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::{
    AdminConfig, ApplyLabelRequest, admin_router, spawn_writer, storage,
    writer::{AUDIT_ACTION_VALUES, AUDIT_OUTCOME_VALUES},
};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const ADMIN_DID: &str = "did:plc:admin00000000000000000000";
const MOD_DID: &str = "did:plc:moderator0000000000000000";

// ---------- JWT + resolver helpers (same pattern as admin_reports.rs) ----------

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
    )
    .await
    .unwrap();

    let router = admin_router(
        pool.clone(),
        writer.clone(),
        auth_ctx(),
        AdminConfig::default(),
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

/// Seed a raw audit_log row. Uses direct SQL so tests can pin
/// filter/pagination behavior without running through the writer.
/// Returns (id, created_at_ms) — the id is needed for pagination
/// assertions; created_at lets tests compute since/until bounds.
async fn seed_audit(
    pool: &Pool<Sqlite>,
    created_at_ms: i64,
    action: &str,
    actor_did: &str,
    target: Option<&str>,
    outcome: &str,
    reason: Option<&str>,
) -> i64 {
    sqlx::query_scalar!(
        "INSERT INTO audit_log
             (created_at, action, actor_did, target, target_cid, outcome, reason)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)
         RETURNING id",
        created_at_ms,
        action,
        actor_did,
        target,
        outcome,
        reason,
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

// ---------- HTTP helper ----------

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

async fn get_with_origin(
    addr: SocketAddr,
    path_with_query: &str,
    auth: Option<&str>,
    origin: &str,
) -> u16 {
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
        .header("host", "127.0.0.1")
        .header("origin", origin);
    if let Some(t) = auth {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = req.body(Empty::<Bytes>::new()).unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), send.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await.unwrap();
    status
}

// ========== auth + role ==========

#[tokio::test]
async fn no_auth_returns_401() {
    let h = spawn().await;
    let (status, body) = get_query(h.addr, "/xrpc/tools.cairn.admin.listAuditLog", None).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "AuthenticationRequired");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn mod_role_rejected_403() {
    let h = spawn().await;
    grant_role(&h.pool, MOD_DID, "mod").await;
    let jwt = build_jwt(MOD_DID, "tools.cairn.admin.listAuditLog");
    let (status, body) =
        get_query(h.addr, "/xrpc/tools.cairn.admin.listAuditLog", Some(&jwt)).await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "Forbidden");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn admin_role_accepted() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (status, _) = get_query(h.addr, "/xrpc/tools.cairn.admin.listAuditLog", Some(&jwt)).await;
    assert_eq!(status, 200);
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn cors_any_origin_rejected_403() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let status = get_with_origin(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog",
        Some(&jwt),
        "https://evil.example",
    )
    .await;
    assert_eq!(status, 403);
    h.writer.shutdown().await.unwrap();
}

// ========== basic listing ==========

#[tokio::test]
async fn no_filters_returns_desc_by_id() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    // Three rows in insertion order — SQLite AUTOINCREMENT assigns
    // ascending ids.
    let a = seed_audit(
        &h.pool,
        1_777_104_000_000,
        "label_applied",
        MOD_DID,
        Some("at://did:plc:t/col/r"),
        "success",
        None,
    )
    .await;
    let b = seed_audit(
        &h.pool,
        1_777_104_001_000,
        "label_negated",
        MOD_DID,
        Some("at://did:plc:t/col/r"),
        "success",
        None,
    )
    .await;
    let c = seed_audit(
        &h.pool,
        1_777_104_002_000,
        "report_resolved",
        ADMIN_DID,
        Some("42"),
        "success",
        None,
    )
    .await;

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (status, body) =
        get_query(h.addr, "/xrpc/tools.cairn.admin.listAuditLog", Some(&jwt)).await;
    assert_eq!(status, 200);
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    // DESC: newest first (c, b, a).
    assert_eq!(entries[0]["id"].as_i64().unwrap(), c);
    assert_eq!(entries[1]["id"].as_i64().unwrap(), b);
    assert_eq!(entries[2]["id"].as_i64().unwrap(), a);
    // Required fields present per lexicon.
    for e in entries {
        for k in ["id", "createdAt", "action", "actorDid", "outcome"] {
            assert!(e.get(k).is_some(), "required field {k} missing: {e}");
        }
    }
    h.writer.shutdown().await.unwrap();
}

// ========== filters ==========

#[tokio::test]
async fn actor_filter_narrows() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    seed_audit(
        &h.pool,
        1_777_104_000_000,
        "label_applied",
        MOD_DID,
        None,
        "success",
        None,
    )
    .await;
    seed_audit(
        &h.pool,
        1_777_104_001_000,
        "label_applied",
        ADMIN_DID,
        None,
        "success",
        None,
    )
    .await;

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (_, body) = get_query(
        h.addr,
        &format!("/xrpc/tools.cairn.admin.listAuditLog?actor={MOD_DID}"),
        Some(&jwt),
    )
    .await;
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["actorDid"], MOD_DID);
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn action_filter_narrows_known_value() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    seed_audit(
        &h.pool,
        1_777_104_000_000,
        "label_applied",
        MOD_DID,
        None,
        "success",
        None,
    )
    .await;
    seed_audit(
        &h.pool,
        1_777_104_001_000,
        "label_negated",
        MOD_DID,
        None,
        "success",
        None,
    )
    .await;

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (_, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog?action=label_negated",
        Some(&jwt),
    )
    .await;
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["action"], "label_negated");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn unknown_action_rejected_400() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (status, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog?action=banana",
        Some(&jwt),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");
    // Anti-leak: message must NOT enumerate the allowed values.
    let msg = body["message"].as_str().unwrap();
    for v in AUDIT_ACTION_VALUES {
        assert!(
            !msg.contains(v),
            "error message leaks allowed value {v}: {msg}"
        );
    }
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn outcome_filter_narrows() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    seed_audit(
        &h.pool,
        1_777_104_000_000,
        "label_applied",
        MOD_DID,
        None,
        "success",
        None,
    )
    .await;
    seed_audit(
        &h.pool,
        1_777_104_001_000,
        "label_applied",
        MOD_DID,
        None,
        "failure",
        None,
    )
    .await;

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (_, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog?outcome=failure",
        Some(&jwt),
    )
    .await;
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["outcome"], "failure");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_outcome_rejected_400() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (status, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog?outcome=maybe",
        Some(&jwt),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");
    let msg = body["message"].as_str().unwrap();
    for v in AUDIT_OUTCOME_VALUES {
        assert!(
            !msg.contains(v),
            "error message leaks allowed outcome {v}: {msg}"
        );
    }
    h.writer.shutdown().await.unwrap();
}

// ========== since / until bounds ==========

#[tokio::test]
async fn since_until_bounds_applied() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    // Base = 2026-04-23T00:00:00.000Z.
    const BASE_MS: i64 = 1_776_902_400_000;
    // t1 at 00:00, t2 at 00:10, t3 at 00:30 — window (00:05, 00:20) brackets only t2.
    let t1 = BASE_MS;
    let t2 = BASE_MS + 10 * 60 * 1000;
    let t3 = BASE_MS + 30 * 60 * 1000;
    seed_audit(&h.pool, t1, "label_applied", MOD_DID, None, "success", None).await;
    let inside = seed_audit(&h.pool, t2, "label_applied", MOD_DID, None, "success", None).await;
    seed_audit(&h.pool, t3, "label_applied", MOD_DID, None, "success", None).await;

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (_, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog\
         ?since=2026-04-23T00:05:00.000Z\
         &until=2026-04-23T00:20:00.000Z",
        Some(&jwt),
    )
    .await;
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"].as_i64().unwrap(), inside);
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn since_greater_than_until_rejected_400() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (status, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog\
         ?since=2026-04-24T00:00:00.000Z\
         &until=2026-04-23T00:00:00.000Z",
        Some(&jwt),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");
    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_since_rejected_400() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (status, _) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog?since=yesterday",
        Some(&jwt),
    )
    .await;
    assert_eq!(status, 400);
    h.writer.shutdown().await.unwrap();
}

// ========== pagination ==========

#[tokio::test]
async fn pagination_desc_no_gaps_no_dupes() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;
    for i in 0..60 {
        seed_audit(
            &h.pool,
            1_777_104_000_000 + i,
            "label_applied",
            MOD_DID,
            None,
            "success",
            None,
        )
        .await;
    }

    let mut seen_ids: Vec<i64> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
        let mut url = "/xrpc/tools.cairn.admin.listAuditLog?limit=25".to_string();
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={}", urlencoding::encode(c)));
        }
        let (_, body) = get_query(h.addr, &url, Some(&jwt)).await;
        for e in body["entries"].as_array().unwrap() {
            seen_ids.push(e["id"].as_i64().unwrap());
        }
        cursor = body
            .get("cursor")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen_ids.len(), 60);
    let mut sorted = seen_ids.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(sorted, seen_ids, "pages should concatenate in DESC order");
    let mut uniq = seen_ids.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 60, "no duplicates across pages");
    h.writer.shutdown().await.unwrap();
}

// ========== writer-produced rows: reason passthrough + cross-module invariant ==========

#[tokio::test]
async fn writer_produced_row_reason_is_exact_passthrough() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;

    // Go through the writer for a real label_applied audit row.
    let req = ApplyLabelRequest {
        actor_did: MOD_DID.into(),
        uri: "at://did:plc:target/col/rec".into(),
        cid: Some("bafytest".into()),
        val: "spam".into(),
        exp: None,
        moderator_reason: Some("caught by heuristic #7".into()),
    };
    h.writer.apply_label(req).await.unwrap();

    let jwt = build_jwt(ADMIN_DID, "tools.cairn.admin.listAuditLog");
    let (_, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listAuditLog?action=label_applied",
        Some(&jwt),
    )
    .await;
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let reason = entries[0]["reason"].as_str().unwrap();

    // Reason is opaque JSON — we parse only in the test to verify the
    // schema documented on AUDIT_REASON_SCHEMA round-trips intact.
    let parsed: Value = serde_json::from_str(reason).unwrap();
    assert_eq!(parsed["val"], "spam");
    assert_eq!(parsed["neg"], false);
    assert_eq!(parsed["moderator_reason"], "caught by heuristic #7");

    h.writer.shutdown().await.unwrap();
}

/// Cross-module invariant (documented at src/server/admin/list_labels.rs):
/// listLabels filters by moderator actor by joining `labels` to
/// `audit_log` on `(uri, created_at)` — the audit row supplies the
/// `actor_did` because `labels` itself has no moderator column. This
/// requires `labels.created_at == audit_log.created_at` for the same
/// operation. Lock that invariant here so a future writer refactor
/// that timestamps label row and audit row separately breaks this
/// test instead of silently breaking listLabels' actor filter.
#[tokio::test]
async fn label_applied_audit_shares_created_at_with_labels_row() {
    let h = spawn().await;
    grant_role(&h.pool, ADMIN_DID, "admin").await;

    let req = ApplyLabelRequest {
        actor_did: MOD_DID.into(),
        uri: "at://did:plc:target/col/rec".into(),
        cid: Some("bafytest".into()),
        val: "spam".into(),
        exp: None,
        moderator_reason: None,
    };
    let event = h.writer.apply_label(req).await.unwrap();

    let uri = "at://did:plc:target/col/rec";
    let label_row = sqlx::query!("SELECT created_at FROM labels WHERE seq = ?1", event.seq,)
        .fetch_one(&h.pool)
        .await
        .unwrap();

    let audit_row = sqlx::query!(
        "SELECT created_at, actor_did FROM audit_log
         WHERE action = 'label_applied' AND target = ?1
         ORDER BY id DESC LIMIT 1",
        uri,
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();

    assert_eq!(
        label_row.created_at, audit_row.created_at,
        "labels.created_at must equal audit_log.created_at (listLabels join key)"
    );
    assert_eq!(
        audit_row.actor_did, MOD_DID,
        "audit_log.actor_did must be the moderator DID supplied to apply_label"
    );

    h.writer.shutdown().await.unwrap();
}
