//! Integration tests for the PDS-forwarded createReport dispatch
//! path (#96, refactored in #102 to dispatch-not-mount). The mount
//! point is the user-direct `create_report_router`; this file
//! exercises the trusted-PDS branch by seeding `xrpc_trusted_pdses`
//! and verifying the dispatch lands a row via the gateway-path
//! logic (skipping pre-gates, accepting `reportedBy` from the body).
//!
//! Coverage:
//! - trusted PDS happy paths (account-level + record-level subjects)
//! - row insertion side-effects (subject_type / subject_did /
//!   subject_uri / subject_cid populated correctly)
//! - reasonType allowlist enforcement on the dispatched path
//! - reportedBy DID-syntax validation on the dispatched path
//! - record-level URI validation on the dispatched path
//! - the "untrusted issuer falls through to user-direct path"
//!   regression check (post-#102 — replaces the pre-#102
//!   "untrusted PDS → 403" case which is no longer applicable)
//! - missing auth → 401

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use cairn_mod::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
use cairn_mod::auth::{AuthConfig, AuthContext};
use cairn_mod::xrpc_gateway::add_trusted_pds;
use cairn_mod::{CreateReportConfig, create_report_router, storage};
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};
use serde_json::{Value, json};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:plc:cairn0000000000000000000000";
const PDS_DID: &str = "did:web:pds.example.com";
const REPORTER_DID: &str = "did:plc:reporter000000000000000000";
const TARGET_DID: &str = "did:plc:target000000000000000000";
const MODERATOR_OWNER_DID: &str = "did:plc:m000000000000000000000000";
const LXM: &str = "com.atproto.moderation.createReport";

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

fn build_jwt(iss: &str) -> String {
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
        "lxm": LXM,
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

fn mock_auth() -> Arc<AuthContext> {
    // Resolver knows about both PDS_DID (the trusted-PDS issuer)
    // and another DID used for the "untrusted falls through to
    // user-direct" regression case. Both have the same test key
    // so we sign with one keypair.
    let resolver = Arc::new(MockResolver(Mutex::new(
        [
            (PDS_DID.to_string(), did_doc(PDS_DID)),
            (REPORTER_DID.to_string(), did_doc(REPORTER_DID)),
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

// ---------- Membership-table seeding strategies ----------

#[derive(Clone, Copy)]
enum SeedAs {
    /// PDS DID is in `xrpc_trusted_pdses` — dispatch fires.
    TrustedPds,
    /// Membership table is empty — request falls through to the
    /// user-direct path.
    UntrustedIssuer,
}

// ---------- Harness ----------

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    addr: SocketAddr,
}

async fn spawn(seed: SeedAs) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();

    if matches!(seed, SeedAs::TrustedPds) {
        add_trusted_pds(&pool, PDS_DID, Some("test"), MODERATOR_OWNER_DID)
            .await
            .unwrap();
    }

    // Generous user-direct caps so they don't accidentally clip
    // the untrusted-fallthrough test results.
    let config = CreateReportConfig {
        db_path: path,
        per_did_limit: 100,
        global_pending_cap: 10_000,
        ..CreateReportConfig::default()
    };

    let router = create_report_router(pool.clone(), mock_auth(), config);
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
    let jwt = build_jwt(PDS_DID);
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

    // Side effect: row in reports with reported_by from BODY (not iss)
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
    assert_eq!(
        row.reported_by, REPORTER_DID,
        "trusted-PDS path uses body's reportedBy"
    );
    assert_ne!(row.reported_by, PDS_DID, "iss should not be the reporter");
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
    let jwt = build_jwt(PDS_DID);
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
async fn untrusted_issuer_falls_through_to_user_direct_path() {
    // Pre-#102: an "untrusted PDS" issuer hitting createReport got
    // 403 from the gateway router's membership middleware.
    // Post-#102: createReport is mounted on the user-direct router;
    // an untrusted issuer is just a regular service-auth caller —
    // the user-direct path accepts the report (200), and the
    // resulting row has `reported_by = claims.iss` (NOT the body's
    // reportedBy field, which the user-direct shape ignores).
    let h = spawn(SeedAs::UntrustedIssuer).await;
    let jwt = build_jwt(REPORTER_DID); // not in xrpc_trusted_pdses
    // Send a body with a `reportedBy` field — the user-direct path
    // ignores unknown fields, so this is harmless.
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": repo_ref(TARGET_DID),
        "reportedBy": "did:plc:imposter000000000000000000",
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");
    let id = view["id"].as_i64().unwrap();

    // Critical: reported_by is the JWT iss, NOT the body's reportedBy.
    // The user-direct path does not honor the spoofed body field.
    let row = sqlx::query!("SELECT reported_by FROM reports WHERE id = ?1", id,)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(row.reported_by, REPORTER_DID, "user-direct path uses iss");
    assert_ne!(
        row.reported_by, "did:plc:imposter000000000000000000",
        "user-direct path must ignore body's spoofed reportedBy"
    );
}

#[tokio::test]
async fn unknown_reason_type_returns_400_on_dispatched_path() {
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID);
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
async fn malformed_reported_by_returns_400_on_dispatched_path() {
    // Defense-in-depth: even though the PDS is trusted, a
    // malformed reportedBy (not DID-shaped) must not poison the
    // table. The dispatched path validates the body field.
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID);
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
async fn malformed_request_body_returns_400_on_dispatched_path() {
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID);
    // Missing required `subject` and `reportedBy` fields for the
    // dispatched path's CreateReportRequest shape.
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
    assert_eq!(view["error"].as_str(), Some("AuthenticationRequired"));
}

#[tokio::test]
async fn record_level_report_with_malformed_uri_returns_400_on_dispatched_path() {
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID);
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
async fn reported_by_field_is_taken_verbatim_from_body_on_dispatched_path() {
    // §A10 trust model on the dispatched path: the PDS asserts the
    // user's identity via reportedBy. The dispatched path takes
    // that field verbatim (vs the user-direct path which uses
    // claims.iss as reported_by).
    let h = spawn(SeedAs::TrustedPds).await;
    let jwt = build_jwt(PDS_DID);
    let body = json!({
        "reasonType": "com.atproto.moderation.defs#reasonOther",
        "subject": repo_ref(TARGET_DID),
        "reportedBy": REPORTER_DID,
    });
    let (status, view) = post_create_report(h.addr, &jwt, &body).await;
    assert_eq!(status, 200, "{view}");
    let id = view["id"].as_i64().unwrap();
    let row = sqlx::query!("SELECT reported_by FROM reports WHERE id = ?1", id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    // The body's reportedBy, not the JWT's PDS DID.
    assert_eq!(row.reported_by, REPORTER_DID);
    assert_ne!(row.reported_by, PDS_DID);
}
