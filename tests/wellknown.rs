//! Integration tests for `cairn_mod::wellknown_router` (§8 + §F13).
//!
//! The unit tests in `src/server/wellknown.rs` cover the bundle's
//! shape (exact file set, JSON parse, id-matches-stem). These
//! integration tests cover the HTTP contract: correct status,
//! content-type, body bytes, and 404 shapes.

use std::net::SocketAddr;
use std::time::Duration;

use cairn_mod::wellknown_router;
use serde_json::Value;
use tokio::net::TcpListener;

/// Bring up the wellknown_router on an ephemeral port. Router is
/// stateless so tests can reuse one instance across multiple
/// requests.
async fn spawn() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, wellknown_router().into_make_service())
            .await
            .ok();
    });
    addr
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

const ALL_LEXICONS: &[&str] = &[
    "applyLabel",
    "defs",
    "flagReporter",
    "getAuditLog",
    "getReport",
    "listAuditLog",
    "listLabels",
    "listReports",
    "negateLabel",
    "resolveReport",
];

#[tokio::test]
async fn every_lexicon_serves_with_correct_shape() {
    let addr = spawn().await;
    for stem in ALL_LEXICONS {
        let path = format!("/.well-known/lexicons/tools/cairn/admin/{stem}.json");
        let (status, body, content_type) = get(addr, &path).await;
        assert_eq!(status, 200, "{stem}: status");
        assert_eq!(
            content_type.as_deref(),
            Some("application/json"),
            "{stem}: content-type"
        );
        let doc: Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("{stem}: parse: {e}"));
        assert_eq!(
            doc["id"].as_str(),
            Some(format!("tools.cairn.admin.{stem}").as_str()),
            "{stem}: id"
        );
    }
}

#[tokio::test]
async fn served_bytes_match_on_disk_file() {
    // Pin the "served bytes equal on-disk bytes" contract with one
    // exemplar — cheaper than walking every file, sufficient to
    // catch serde re-serialization (which would re-order fields,
    // normalize whitespace, etc.).
    let addr = spawn().await;
    let (status, body, _) = get(
        addr,
        "/.well-known/lexicons/tools/cairn/admin/applyLabel.json",
    )
    .await;
    assert_eq!(status, 200);
    let on_disk = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/lexicons/tools/cairn/admin/applyLabel.json"
    ))
    .unwrap();
    assert_eq!(
        body, on_disk,
        "served bytes must be byte-identical to on-disk file"
    );
}

#[tokio::test]
async fn unknown_lexicon_name_returns_404() {
    let addr = spawn().await;
    let (status, body, _) = get(
        addr,
        "/.well-known/lexicons/tools/cairn/admin/doesNotExist.json",
    )
    .await;
    assert_eq!(status, 404);
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["error"], "NotFound");
}

#[tokio::test]
async fn missing_json_extension_returns_404() {
    // Extension-less aliases are not served — the filename we
    // embed ends with `.json` and that's the only form we honor.
    let addr = spawn().await;
    let (status, _, _) = get(addr, "/.well-known/lexicons/tools/cairn/admin/applyLabel").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn non_admin_nsid_tree_returns_404() {
    // The router only matches `tools/cairn/admin/{name}` — other
    // NSID trees (tools/other, app/bsky/whatever) are not served.
    let addr = spawn().await;
    let (status, _, _) = get(addr, "/.well-known/lexicons/tools/other/something.json").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn unrelated_well_known_path_returns_404() {
    // `.well-known/did.json` is a future sibling endpoint (its own
    // issue); this router must NOT serve it.
    let addr = spawn().await;
    let (status, _, _) = get(addr, "/.well-known/did.json").await;
    assert_eq!(status, 404);
}
