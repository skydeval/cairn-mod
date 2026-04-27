//! Integration tests for `cairn_mod::did_document_router` (L3, §5.4).
//!
//! - Happy path: spawn a Writer to bootstrap `signing_keys`, GET the
//!   endpoint, assert the on-the-wire shape + key material.
//! - Empty signing_keys: 503 with the expected error body.
//! - Agreement: the wire JSON round-trips through Cairn's own
//!   consumer-side `DidDocument` parser (src/auth/did.rs). Drift
//!   between emitter and consumer would break the auth flow — this
//!   test catches that at CI time.

use std::net::SocketAddr;
use std::time::Duration;

use cairn_mod::auth::did::DidDocument;
use cairn_mod::config::Config;
use cairn_mod::{SigningKey, did_document_router, spawn_writer, storage};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
const SERVICE_DID: &str = "did:web:labeler.test";
const SERVICE_ENDPOINT: &str = "https://labeler.test";

fn test_config() -> Config {
    // Construct via JSON to avoid `non_exhaustive` fiddling and keep
    // the test isolated from future field additions. `db_path` and
    // `signing_key_path` are required by Config but not consumed by
    // did_document_router — any placeholder path suffices.
    serde_json::from_value(serde_json::json!({
        "service_did": SERVICE_DID,
        "service_endpoint": SERVICE_ENDPOINT,
        "db_path": "/tmp/cairn-test-placeholder.db",
        "signing_key_path": "/tmp/cairn-test-placeholder.hex",
    }))
    .expect("config deserializes")
}

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
    addr: SocketAddr,
}

async fn spawn_bare_router() -> Harness {
    // Pool + migrations, no writer — signing_keys table is empty.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.unwrap();
    let router = did_document_router(pool.clone(), test_config());
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

async fn spawn_router_with_writer() -> (Harness, cairn_mod::WriterHandle) {
    let h = spawn_bare_router().await;
    let writer = spawn_writer(
        h.pool.clone(),
        SigningKey::from_bytes(hex::decode(TEST_PRIV_HEX).unwrap().try_into().unwrap()),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
    )
    .await
    .unwrap();
    (h, writer)
}

async fn get(addr: SocketAddr, path: &str) -> (u16, String, Option<String>) {
    use http_body_util::{BodyExt as _, Empty};
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
        .uri(path)
        .header("host", "127.0.0.1")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), send.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        String::from_utf8(body.to_vec()).unwrap_or_default(),
        content_type,
    )
}

#[tokio::test]
async fn happy_path_returns_well_formed_did_document() {
    let (h, writer) = spawn_router_with_writer().await;

    let (status, body, ct) = get(h.addr, "/.well-known/did.json").await;
    assert_eq!(status, 200);
    assert_eq!(ct.as_deref(), Some("application/json"));
    let doc: Value = serde_json::from_str(&body).unwrap();

    assert_eq!(doc["id"], SERVICE_DID);
    assert_eq!(doc["@context"][0], "https://www.w3.org/ns/did/v1");
    assert_eq!(doc["@context"][1], "https://w3id.org/security/multikey/v1");

    let vm = &doc["verificationMethod"][0];
    assert_eq!(vm["id"], format!("{SERVICE_DID}#atproto_label"));
    assert_eq!(vm["type"], "Multikey");
    assert_eq!(vm["controller"], SERVICE_DID);
    let multibase = vm["publicKeyMultibase"].as_str().unwrap();
    assert!(
        multibase.starts_with('z'),
        "multibase must be z-prefixed: {multibase}"
    );

    // And the multibase we emitted matches what the writer stored.
    let stored: String =
        sqlx::query_scalar!("SELECT public_key_multibase FROM signing_keys WHERE id = 1")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(multibase, stored);

    let svc = &doc["service"][0];
    assert_eq!(svc["id"], "#atproto_labeler");
    assert_eq!(svc["type"], "AtprotoLabeler");
    assert_eq!(svc["serviceEndpoint"], SERVICE_ENDPOINT);

    writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn empty_signing_keys_returns_503() {
    let h = spawn_bare_router().await;
    let (status, body, _) = get(h.addr, "/.well-known/did.json").await;
    assert_eq!(status, 503);
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["error"], "ServiceUnavailable");
}

/// Agreement test: the wire JSON this emitter produces must be
/// parseable by the consumer-side `DidDocument` struct in
/// `src/auth/did.rs`, and `find_verification_method("#atproto_label")`
/// must return the single Multikey entry. Emitter/consumer drift
/// would silently break the auth verification flow; this test
/// surfaces it at CI time.
#[tokio::test]
async fn wire_output_parses_via_production_did_document_consumer() {
    let (h, writer) = spawn_router_with_writer().await;
    let (status, body, _) = get(h.addr, "/.well-known/did.json").await;
    assert_eq!(status, 200);

    let parsed: DidDocument = serde_json::from_str(&body).expect("consumer parse");
    assert_eq!(parsed.id, SERVICE_DID);

    let vm = parsed
        .find_verification_method("#atproto_label")
        .expect("consumer finds labeler key");
    assert_eq!(vm.r#type, "Multikey");
    assert!(vm.public_key_multibase.starts_with('z'));

    writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn unrelated_path_returns_404() {
    // Router must not shadow other .well-known paths — future
    // sibling endpoints (lexicons under #18, etc.) are composed
    // independently.
    let h = spawn_bare_router().await;
    let (status, _, _) = get(h.addr, "/.well-known/something-else").await;
    assert_eq!(status, 404);
}
