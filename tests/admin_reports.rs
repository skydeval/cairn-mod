//! Integration tests for `tools.cairn.admin.{listReports, getReport,
//! resolveReport, flagReporter}` (#15), plus a slim full-flow test
//! covering the write-side chain:
//! createReport (#14) → listReports → getReport → resolveReport with
//! applyLabel → direct-SQL verification of the final state across
//! reports, labels, and audit_log.
//!
//! Cross-session note from #13: every authenticated call needs a
//! fresh JWT — jti replay rejects reuse. All test helpers below call
//! `build_jwt()` inline per request.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::{
    AdminConfig, CreateReportConfig, admin_router, create_report_router, spawn_writer, storage,
};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";

// ---------- JWT + resolver helpers (same pattern as tests/admin_labels.rs) ----------

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
        [(MODERATOR_DID.to_string(), did_doc(MODERATOR_DID))].into(),
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

async fn spawn(admin_cfg: AdminConfig) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();
    let writer = spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
    )
    .await
    .unwrap();

    let router = admin_router(pool.clone(), writer.clone(), auth_ctx(), admin_cfg);
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

/// Harness that mounts BOTH `admin_router` and `create_report_router`.
/// Used by the slim full-flow test.
struct FullHarness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    writer: cairn_mod::WriterHandle,
    addr: SocketAddr,
}

async fn spawn_full() -> FullHarness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();
    let writer = spawn_writer(
        pool.clone(),
        cairn_mod::SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
    )
    .await
    .unwrap();

    let create_cfg = CreateReportConfig {
        db_path: path.clone(),
        ..CreateReportConfig::default()
    };
    let cr_router = create_report_router(pool.clone(), auth_ctx(), create_cfg);
    let adm_router = admin_router(
        pool.clone(),
        writer.clone(),
        auth_ctx(),
        AdminConfig::default(),
    );
    let router = cr_router.merge(adm_router);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });
    FullHarness {
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

/// Seed a pending report directly via SQL so tests don't depend on
/// createReport's behavior. Returns the row's id.
async fn seed_report(pool: &Pool<Sqlite>, reported_by: &str, reason: Option<&str>) -> i64 {
    let created_at = "2026-04-23T00:00:00.000Z";
    let reason_type = "com.atproto.moderation.defs#reasonSpam";
    let subject_type = "account";
    let subject_did = "did:plc:target0000000000000000000";
    sqlx::query_scalar!(
        "INSERT INTO reports
             (created_at, reported_by, reason_type, reason,
              subject_type, subject_did, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')
         RETURNING id",
        created_at,
        reported_by,
        reason_type,
        reason,
        subject_type,
        subject_did,
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

// ---------- HTTP helpers ----------

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

// ========== listReports ==========

#[tokio::test]
async fn list_reports_returns_newest_first_without_reason_body() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let _ = seed_report(&h.pool, "did:plc:reporter1", Some("body A")).await;
    let _ = seed_report(&h.pool, "did:plc:reporter2", Some("body B")).await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listReports");
    let (status, body) = get_query(h.addr, "/xrpc/tools.cairn.admin.listReports", Some(&jwt)).await;
    assert_eq!(status, 200);
    let reports = body["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 2);
    // DESC order — newest first.
    assert!(reports[0]["id"].as_i64().unwrap() > reports[1]["id"].as_i64().unwrap());
    // Anti-leak: no reason field in list projection.
    for r in reports {
        assert!(
            r.get("reason").is_none(),
            "listReports must not include reason: {r}"
        );
    }

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_reports_filters_by_status() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let id = seed_report(&h.pool, "did:plc:r", None).await;
    let _ = seed_report(&h.pool, "did:plc:r", None).await;
    // Mark the first as resolved.
    sqlx::query!(
        "UPDATE reports SET status='resolved', resolved_at='2026-04-23T00:00:01.000Z' WHERE id = ?1",
        id
    )
    .execute(&h.pool)
    .await
    .unwrap();

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listReports");
    let (_, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listReports?status=pending",
        Some(&jwt),
    )
    .await;
    let reports = body["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0]["status"], "pending");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_reports_filters_by_reported_by() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let _ = seed_report(&h.pool, "did:plc:reporter1", None).await;
    let _ = seed_report(&h.pool, "did:plc:reporter2", None).await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listReports");
    let (_, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.listReports?reportedBy=did:plc:reporter1",
        Some(&jwt),
    )
    .await;
    let reports = body["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0]["reportedBy"], "did:plc:reporter1");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_reports_pagination_desc_no_gaps_no_dupes() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    for _ in 0..60 {
        seed_report(&h.pool, "did:plc:r", None).await;
    }

    let mut seen_ids: Vec<i64> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listReports");
        let mut url = "/xrpc/tools.cairn.admin.listReports?limit=25".to_string();
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={}", urlencoding::encode(c)));
        }
        let (_, body) = get_query(h.addr, &url, Some(&jwt)).await;
        for r in body["reports"].as_array().unwrap() {
            seen_ids.push(r["id"].as_i64().unwrap());
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
    // Each page DESC, each successive page's ids < previous; overall
    // strictly decreasing.
    let mut sorted = seen_ids.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(sorted, seen_ids, "pages should concatenate in DESC order");
    let mut uniq = seen_ids.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 60, "no duplicates across pages");

    h.writer.shutdown().await.unwrap();
}

// ========== getReport ==========

#[tokio::test]
async fn get_report_returns_full_reason_body() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let id = seed_report(&h.pool, "did:plc:r", Some("full body here")).await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.getReport");
    let (status, body) = get_query(
        h.addr,
        &format!("/xrpc/tools.cairn.admin.getReport?id={id}"),
        Some(&jwt),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["id"], id);
    assert_eq!(body["reason"], "full body here");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_report_missing_id_returns_404_report_not_found() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.getReport");
    let (status, body) = get_query(
        h.addr,
        "/xrpc/tools.cairn.admin.getReport?id=99999",
        Some(&jwt),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(body["error"], "ReportNotFound");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_report_missing_id_param_returns_400() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.getReport");
    let (status, body) = get_query(h.addr, "/xrpc/tools.cairn.admin.getReport", Some(&jwt)).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");

    h.writer.shutdown().await.unwrap();
}

// ========== resolveReport ==========

#[tokio::test]
async fn resolve_report_without_apply_label_marks_resolved() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let id = seed_report(&h.pool, "did:plc:r", Some("body")).await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.resolveReport");
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.resolveReport",
        Some(&jwt),
        &[],
        &serde_json::json!({"id": id, "reason": "spam confirmed"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "resolved");
    assert_eq!(body["resolvedBy"], MODERATOR_DID);
    assert_eq!(body["resolutionReason"], "spam confirmed");

    // Underlying DB state.
    let row = sqlx::query!(
        "SELECT status, resolved_by, resolution_label, resolution_reason FROM reports WHERE id = ?1",
        id
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(row.status, "resolved");
    assert_eq!(row.resolved_by.as_deref(), Some(MODERATOR_DID));
    assert_eq!(row.resolution_label, None);
    assert_eq!(row.resolution_reason.as_deref(), Some("spam confirmed"));

    // Single audit entry: report_resolved. No label_applied because
    // applyLabel wasn't supplied.
    let audit_actions: Vec<String> =
        sqlx::query_scalar!("SELECT action FROM audit_log ORDER BY id")
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(audit_actions, vec!["report_resolved"]);

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn resolve_report_with_apply_label_atomic_label_plus_status() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let id = seed_report(&h.pool, "did:plc:reporter", Some("body")).await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.resolveReport");
    let payload = serde_json::json!({
        "id": id,
        "applyLabel": {
            "uri": "at://did:plc:target/col/rkey",
            "val": "spam",
        },
        "reason": "confirmed",
    });
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.resolveReport",
        Some(&jwt),
        &[],
        &payload,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "resolved");
    assert_eq!(body["resolutionLabel"], "spam");

    // Labels row.
    let label_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM labels WHERE uri = 'at://did:plc:target/col/rkey' AND val = 'spam'"
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(label_count, 1);

    // Audit rows in logical order: label_applied THEN report_resolved
    // (§G — insertion order reflects logical sequence).
    let actions: Vec<String> = sqlx::query_scalar!("SELECT action FROM audit_log ORDER BY id")
        .fetch_all(&h.pool)
        .await
        .unwrap();
    assert_eq!(actions, vec!["label_applied", "report_resolved"]);

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn resolve_report_double_resolve_returns_invalid_request() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let id = seed_report(&h.pool, "did:plc:r", None).await;

    let jwt1 = build_jwt(MODERATOR_DID, "tools.cairn.admin.resolveReport");
    let (s1, _) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.resolveReport",
        Some(&jwt1),
        &[],
        &serde_json::json!({"id": id}),
    )
    .await;
    assert_eq!(s1, 200);

    let jwt2 = build_jwt(MODERATOR_DID, "tools.cairn.admin.resolveReport");
    let (s2, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.resolveReport",
        Some(&jwt2),
        &[],
        &serde_json::json!({"id": id}),
    )
    .await;
    assert_eq!(s2, 400);
    assert_eq!(body["error"], "InvalidRequest");
    // Anti-leak: message doesn't include timestamps or resolver DID.
    let msg = body["message"].as_str().unwrap_or("");
    assert!(
        !msg.contains("2026") && !msg.contains(MODERATOR_DID),
        "double-resolve message leaked detail: {msg:?}"
    );

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn resolve_report_missing_id_returns_report_not_found() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.resolveReport");
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.resolveReport",
        Some(&jwt),
        &[],
        &serde_json::json!({"id": 99999}),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(body["error"], "ReportNotFound");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn resolve_report_invalid_label_value_pre_check_leaves_state_untouched() {
    // Atomicity test via pre-check (§B from last turn): bad applyLabel
    // fails validation BEFORE any writer transaction starts. Assert
    // report still pending, no label row, and crucially no audit row
    // — audit is for successful actions per §F10, not attempt logs.
    let h = spawn(AdminConfig {
        label_values: Some(vec!["spam".into(), "nudity".into()]),
    })
    .await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let id = seed_report(&h.pool, "did:plc:r", None).await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.resolveReport");
    let payload = serde_json::json!({
        "id": id,
        "applyLabel": {
            "uri": "at://did:plc:target/col/rkey",
            "val": "harassment",
        },
    });
    let (status, body) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.resolveReport",
        Some(&jwt),
        &[],
        &payload,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidLabelValue");

    // Report still pending.
    let status_str: String = sqlx::query_scalar!("SELECT status FROM reports WHERE id = ?1", id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(status_str, "pending");
    // No labels.
    let label_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM labels")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(label_count, 0);
    // No audit rows — failed validation is NOT logged to audit.
    let audit_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(audit_count, 0, "failed validation must not write audit");

    h.writer.shutdown().await.unwrap();
}

// ========== flagReporter ==========

#[tokio::test]
async fn flag_reporter_flag_then_unflag_roundtrip() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let target = "did:plc:abusivereporter000000000000";

    let jwt1 = build_jwt(MODERATOR_DID, "tools.cairn.admin.flagReporter");
    let (s1, _) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.flagReporter",
        Some(&jwt1),
        &[],
        &serde_json::json!({"did": target, "suppressed": true, "reason": "abusive"}),
    )
    .await;
    assert_eq!(s1, 200);

    // Row present.
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM suppressed_reporters WHERE did = ?1",
        target
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);

    // Unflag.
    let jwt2 = build_jwt(MODERATOR_DID, "tools.cairn.admin.flagReporter");
    let (s2, _) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.flagReporter",
        Some(&jwt2),
        &[],
        &serde_json::json!({"did": target, "suppressed": false}),
    )
    .await;
    assert_eq!(s2, 200);

    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM suppressed_reporters WHERE did = ?1",
        target
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(count, 0);

    // Audit: flagged then unflagged.
    let actions: Vec<String> = sqlx::query_scalar!("SELECT action FROM audit_log ORDER BY id")
        .fetch_all(&h.pool)
        .await
        .unwrap();
    assert_eq!(actions, vec!["reporter_flagged", "reporter_unflagged"]);

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn flag_reporter_idempotent_unflag_of_never_flagged() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.flagReporter");
    let (status, _) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.flagReporter",
        Some(&jwt),
        &[],
        &serde_json::json!({"did": "did:plc:neverflagged000000000000000", "suppressed": false}),
    )
    .await;
    // Unflag of never-flagged succeeds (idempotent); audit row records
    // the operator intent.
    assert_eq!(status, 200);
    let action: String = sqlx::query_scalar!("SELECT action FROM audit_log LIMIT 1")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(action, "reporter_unflagged");

    h.writer.shutdown().await.unwrap();
}

// ========== Shared auth/CORS checks across the 4 endpoints ==========

#[tokio::test]
async fn report_endpoints_reject_any_origin_header() {
    let h = spawn(AdminConfig::default()).await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    for (method, path, body) in [
        ("GET", "/xrpc/tools.cairn.admin.listReports", None),
        ("GET", "/xrpc/tools.cairn.admin.getReport?id=1", None),
        (
            "POST",
            "/xrpc/tools.cairn.admin.resolveReport",
            Some(serde_json::json!({"id": 1})),
        ),
        (
            "POST",
            "/xrpc/tools.cairn.admin.flagReporter",
            Some(serde_json::json!({"did": "did:plc:x", "suppressed": true})),
        ),
    ] {
        let jwt = build_jwt(MODERATOR_DID, "tools.cairn.admin.listReports");
        let status = if method == "GET" {
            let (s, _) = get_query(h.addr, path, Some(&jwt)).await;
            // We need Origin header; re-issue with extra header via post_json
            // pathway isn't available for GET. Use get_with_origin helper below.
            let _ = s;
            get_with_origin(h.addr, path, &jwt).await
        } else {
            let (s, _) = post_json(
                h.addr,
                path,
                Some(&jwt),
                &[("origin", "https://x.example.com")],
                &body.unwrap(),
            )
            .await;
            s
        };
        assert_eq!(status, 403, "{method} {path} must reject Origin header");
    }
    h.writer.shutdown().await.unwrap();
}

async fn get_with_origin(addr: SocketAddr, path_with_query: &str, auth: &str) -> u16 {
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
    let (mut send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(path_with_query)
        .header("host", "127.0.0.1")
        .header("authorization", format!("Bearer {auth}"))
        .header("origin", "https://x.example.com")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = send.send_request(req).await.unwrap();
    resp.status().as_u16()
}

// ========== Full-flow integration (slim version, §C (i)) ==========

#[tokio::test]
async fn full_flow_create_list_get_resolve_writes_across_all_tables() {
    let h = spawn_full().await;
    grant_role(&h.pool, MODERATOR_DID, "mod").await;

    // 1. createReport via #14 endpoint.
    let jwt_cr = build_jwt(MODERATOR_DID, "com.atproto.moderation.createReport");
    let (s_cr, body_cr) = post_json(
        h.addr,
        "/xrpc/com.atproto.moderation.createReport",
        Some(&jwt_cr),
        &[],
        &serde_json::json!({
            "reasonType": "com.atproto.moderation.defs#reasonSpam",
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": "did:plc:target0000000000000000000",
            },
            "reason": "seen spamming",
        }),
    )
    .await;
    assert_eq!(s_cr, 200);
    let report_id = body_cr["id"].as_i64().unwrap();

    // 2. listReports shows it without the reason body.
    let jwt_lr = build_jwt(MODERATOR_DID, "tools.cairn.admin.listReports");
    let (_, body_lr) =
        get_query(h.addr, "/xrpc/tools.cairn.admin.listReports", Some(&jwt_lr)).await;
    let listed = body_lr["reports"].as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], report_id);
    assert!(listed[0].get("reason").is_none());

    // 3. getReport shows the full reason.
    let jwt_gr = build_jwt(MODERATOR_DID, "tools.cairn.admin.getReport");
    let (_, body_gr) = get_query(
        h.addr,
        &format!("/xrpc/tools.cairn.admin.getReport?id={report_id}"),
        Some(&jwt_gr),
    )
    .await;
    assert_eq!(body_gr["reason"], "seen spamming");

    // 4. resolveReport with applyLabel.
    let jwt_rr = build_jwt(MODERATOR_DID, "tools.cairn.admin.resolveReport");
    let (s_rr, body_rr) = post_json(
        h.addr,
        "/xrpc/tools.cairn.admin.resolveReport",
        Some(&jwt_rr),
        &[],
        &serde_json::json!({
            "id": report_id,
            "applyLabel": {
                "uri": "at://did:plc:target0000000000000000000/col/rkey",
                "val": "spam",
            },
            "reason": "confirmed",
        }),
    )
    .await;
    assert_eq!(s_rr, 200);
    assert_eq!(body_rr["status"], "resolved");
    assert_eq!(body_rr["resolutionLabel"], "spam");

    // 5. Direct SQL: state across all 3 tables.
    // reports: resolved, resolved_by = moderator, resolution_label=spam.
    let rp = sqlx::query!(
        "SELECT status, resolved_by, resolution_label, resolution_reason FROM reports WHERE id = ?1",
        report_id
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(rp.status, "resolved");
    assert_eq!(rp.resolved_by.as_deref(), Some(MODERATOR_DID));
    assert_eq!(rp.resolution_label.as_deref(), Some("spam"));
    assert_eq!(rp.resolution_reason.as_deref(), Some("confirmed"));

    // labels: one row, from the resolve path.
    let label_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM labels WHERE uri = 'at://did:plc:target0000000000000000000/col/rkey' AND val = 'spam'"
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(label_count, 1);

    // audit_log: label_applied THEN report_resolved, IDs strictly
    // increasing so the ordering is a durable property of the
    // transaction not a query-time quirk.
    let rows = sqlx::query!("SELECT id, action FROM audit_log ORDER BY id")
        .fetch_all(&h.pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].action, "label_applied");
    assert_eq!(rows[1].action, "report_resolved");
    assert!(rows[0].id < rows[1].id);

    h.writer.shutdown().await.unwrap();
}
