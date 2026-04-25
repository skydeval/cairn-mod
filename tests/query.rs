//! Integration tests for `com.atproto.label.queryLabels` (§F3).
//!
//! Like the subscribeLabels suite, each test spins up a real axum server
//! on an ephemeral port and issues live HTTP requests. We use the
//! transport-level behavior as the check — response status, headers, JSON
//! body — instead of calling the handler directly, because the router
//! composition (CORS layer, ConnectInfo, Extensions) is itself part of
//! what #6 is delivering.

use std::net::SocketAddr;
use std::time::Duration;

use cairn_mod::{
    ApplyLabelRequest, NegateLabelRequest, SigningKey, SubscribeConfig, WriterHandle, spawn_writer,
    storage, subscribe_router,
};
use serde_json::Value;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;

const SERVICE_DID: &str = "did:plc:3jzfcijpj2z2a4pdagfkktq6";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";
const OTHER_DID: &str = "did:plc:someoneelse00000000000000";
const TEST_KEY_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

struct Harness {
    _dir: TempDir,
    _pool: Pool<Sqlite>,
    writer: WriterHandle,
    addr: SocketAddr,
}

fn test_key() -> SigningKey {
    let bytes: [u8; 32] = hex::decode(TEST_KEY_HEX)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    SigningKey::from_bytes(bytes)
}

async fn spawn_harness() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.expect("open pool");
    let writer = spawn_writer(
        pool.clone(),
        test_key(),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
    )
    .await
    .expect("spawn writer");

    let router = subscribe_router(pool.clone(), writer.clone(), SubscribeConfig::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
    });

    Harness {
        _dir: dir,
        _pool: pool,
        writer,
        addr,
    }
}

fn apply(uri: &str, val: &str) -> ApplyLabelRequest {
    ApplyLabelRequest {
        actor_did: MODERATOR_DID.to_string(),
        uri: uri.to_string(),
        cid: None,
        val: val.to_string(),
        exp: None,
        moderator_reason: None,
    }
}

fn negate(uri: &str, val: &str) -> NegateLabelRequest {
    NegateLabelRequest {
        actor_did: MODERATOR_DID.to_string(),
        uri: uri.to_string(),
        val: val.to_string(),
        moderator_reason: None,
    }
}

async fn http_get(addr: SocketAddr, query: &str) -> (u16, Value, hyper::HeaderMap) {
    // Minimal HTTP/1.1 client via hyper. Faster than pulling in reqwest;
    // gives us raw header access for the CORS test.
    use http_body_util::BodyExt as _;
    use http_body_util::Empty;
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

    let uri_path = format!("/xrpc/com.atproto.label.queryLabels?{query}");
    let req = hyper::Request::builder()
        .method("GET")
        .uri(&uri_path)
        .header("host", "127.0.0.1")
        .body(Empty::<Bytes>::new())
        .expect("build request");

    let resp = tokio::time::timeout(Duration::from_secs(5), send.send_request(req))
        .await
        .expect("request timeout")
        .expect("request");

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("parse json")
    };
    (status, json, headers)
}

fn labels_array(json: &Value) -> &Vec<Value> {
    json.get("labels").unwrap().as_array().unwrap()
}

fn make_uri(n: usize) -> String {
    format!("at://did:plc:subject{n:026}/app.bsky.feed.post/x")
}

// ========== Tests ==========

#[tokio::test]
async fn single_apply_returns_label() {
    let h = spawn_harness().await;
    let uri = make_uri(1);
    h.writer.apply_label(apply(&uri, "spam")).await.unwrap();

    let query = format!("uriPatterns={}", urlencoding::encode(&uri));
    let (status, body, _) = http_get(h.addr, &query).await;
    assert_eq!(status, 200);
    let labels = labels_array(&body);
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0]["uri"], uri);
    assert_eq!(labels[0]["val"], "spam");
    // sig is typed-bytes per §16.1.
    assert!(labels[0]["sig"]["$bytes"].is_string());

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn negated_label_excluded_from_results() {
    let h = spawn_harness().await;
    let uri = make_uri(1);
    h.writer.apply_label(apply(&uri, "spam")).await.unwrap();
    h.writer.negate_label(negate(&uri, "spam")).await.unwrap();

    let query = format!("uriPatterns={}", urlencoding::encode(&uri));
    let (status, body, _) = http_get(h.addr, &query).await;
    assert_eq!(status, 200);
    assert_eq!(labels_array(&body).len(), 0);

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn reapply_after_negation_appears_again() {
    let h = spawn_harness().await;
    let uri = make_uri(1);
    h.writer.apply_label(apply(&uri, "spam")).await.unwrap();
    h.writer.negate_label(negate(&uri, "spam")).await.unwrap();
    h.writer.apply_label(apply(&uri, "spam")).await.unwrap();

    let query = format!("uriPatterns={}", urlencoding::encode(&uri));
    let (status, body, _) = http_get(h.addr, &query).await;
    assert_eq!(status, 200);
    let labels = labels_array(&body);
    assert_eq!(labels.len(), 1, "latest event is apply, must appear");
    assert_eq!(labels[0]["val"], "spam");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn expired_label_excluded_from_results() {
    let h = spawn_harness().await;
    let uri = make_uri(1);
    // `exp` in the past.
    h.writer
        .apply_label(ApplyLabelRequest {
            actor_did: MODERATOR_DID.to_string(),
            uri: uri.clone(),
            cid: None,
            val: "tempban".to_string(),
            exp: Some("2020-01-01T00:00:00.000Z".to_string()),
            moderator_reason: None,
        })
        .await
        .unwrap();

    let query = format!("uriPatterns={}", urlencoding::encode(&uri));
    let (_, body, _) = http_get(h.addr, &query).await;
    assert_eq!(labels_array(&body).len(), 0, "expired label must be hidden");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn prefix_pattern_matches_all_under_prefix() {
    let h = spawn_harness().await;
    let a = "at://did:plc:subjectAAAAAAAAAAAAAAAAAAAA/app.bsky.feed.post/x";
    let b = "at://did:plc:subjectAAAAAAAAAAAAAAAAAAAA/app.bsky.feed.post/y";
    let c = "at://did:plc:subjectBBBBBBBBBBBBBBBBBBBB/app.bsky.feed.post/z";
    for uri in [a, b, c] {
        h.writer.apply_label(apply(uri, "spam")).await.unwrap();
    }

    let prefix = "at://did:plc:subjectAAAAAAAAAAAAAAAAAAAA*";
    let query = format!("uriPatterns={}", urlencoding::encode(prefix));
    let (_, body, _) = http_get(h.addr, &query).await;
    let labels = labels_array(&body);
    assert_eq!(labels.len(), 2, "two URIs under the prefix");
    let uris: Vec<String> = labels
        .iter()
        .map(|l| l["uri"].as_str().unwrap().to_string())
        .collect();
    assert!(uris.contains(&a.to_string()));
    assert!(uris.contains(&b.to_string()));
    assert!(!uris.contains(&c.to_string()));

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn exact_pattern_matches_only_exact_uri() {
    let h = spawn_harness().await;
    let a = "at://did:plc:subjectAAAAAAAAAAAAAAAAAAAA/app.bsky.feed.post/x";
    let b = "at://did:plc:subjectAAAAAAAAAAAAAAAAAAAA/app.bsky.feed.post/y";
    for uri in [a, b] {
        h.writer.apply_label(apply(uri, "spam")).await.unwrap();
    }

    let query = format!("uriPatterns={}", urlencoding::encode(a));
    let (_, body, _) = http_get(h.addr, &query).await;
    let labels = labels_array(&body);
    assert_eq!(labels.len(), 1, "exact-match returns only one");
    assert_eq!(labels[0]["uri"], a);

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn sources_filter_excludes_when_not_in_list() {
    let h = spawn_harness().await;
    let uri = make_uri(1);
    h.writer.apply_label(apply(&uri, "spam")).await.unwrap();

    // Caller asks for a DID we don't emit as.
    let query = format!(
        "uriPatterns={}&sources={}",
        urlencoding::encode(&uri),
        urlencoding::encode(OTHER_DID)
    );
    let (status, body, _) = http_get(h.addr, &query).await;
    assert_eq!(status, 200, "sources filter returns empty, not error");
    assert_eq!(labels_array(&body).len(), 0);

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn sources_filter_includes_when_cairn_did_present() {
    let h = spawn_harness().await;
    let uri = make_uri(1);
    h.writer.apply_label(apply(&uri, "spam")).await.unwrap();

    let query = format!(
        "uriPatterns={}&sources={}&sources={}",
        urlencoding::encode(&uri),
        urlencoding::encode(OTHER_DID),
        urlencoding::encode(SERVICE_DID),
    );
    let (_, body, _) = http_get(h.addr, &query).await;
    assert_eq!(
        labels_array(&body).len(),
        1,
        "Cairn's DID in sources → included"
    );

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn missing_uri_patterns_returns_invalid_request() {
    let h = spawn_harness().await;
    let (status, body, _) = http_get(h.addr, "").await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_uri_pattern_returns_invalid_request() {
    let h = spawn_harness().await;
    let query = format!("uriPatterns={}", urlencoding::encode("notanuri"));
    let (status, body, _) = http_get(h.addr, &query).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "InvalidRequest");

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn limit_out_of_range_returns_invalid_request() {
    let h = spawn_harness().await;
    let uri_owned = make_uri(1);
    let uri = urlencoding::encode(&uri_owned);

    for bad in ["0", "251", "-1", "abc"] {
        let query = format!("uriPatterns={uri}&limit={bad}");
        let (status, body, _) = http_get(h.addr, &query).await;
        assert_eq!(status, 400, "limit={bad} must reject");
        assert_eq!(body["error"], "InvalidRequest");
    }

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn unknown_subject_returns_empty_labels() {
    let h = spawn_harness().await;
    let uri = make_uri(999);
    let query = format!("uriPatterns={}", urlencoding::encode(&uri));
    let (status, body, _) = http_get(h.addr, &query).await;
    assert_eq!(status, 200);
    assert_eq!(labels_array(&body).len(), 0);

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn cors_header_any_origin_on_get_response() {
    let h = spawn_harness().await;
    let uri_owned = make_uri(1);
    let uri = urlencoding::encode(&uri_owned);
    let query = format!("uriPatterns={uri}");
    let (_, _, headers) = http_get(h.addr, &query).await;

    // §F3: accepts any origin.
    let allow_origin = headers
        .get("access-control-allow-origin")
        .expect("CORS allow-origin header must be present");
    assert_eq!(
        allow_origin.to_str().unwrap(),
        "*",
        "allow-origin should be wildcard for a public read endpoint"
    );
    // Credentials must never be echoed (§F3).
    assert!(
        headers.get("access-control-allow-credentials").is_none(),
        "allow-credentials must not be set"
    );

    h.writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn pagination_across_three_pages_no_gaps_no_dupes() {
    let h = spawn_harness().await;

    // 120 labels under a common prefix so one uriPatterns covers them all.
    let prefix = "at://did:plc:pagination000000000000000000/app.bsky.feed.post/";
    let n = 120;
    for i in 0..n {
        h.writer
            .apply_label(apply(&format!("{prefix}{i:03}"), "spam"))
            .await
            .unwrap();
    }

    let pattern = format!("{prefix}*");
    let mut all_uris: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let mut query = format!("uriPatterns={}&limit=50", urlencoding::encode(&pattern),);
        if let Some(c) = &cursor {
            query.push_str(&format!("&cursor={}", urlencoding::encode(c)));
        }
        let (status, body, _) = http_get(h.addr, &query).await;
        assert_eq!(status, 200);
        let labels = labels_array(&body);
        for l in labels {
            all_uris.push(l["uri"].as_str().unwrap().to_string());
        }
        cursor = body
            .get("cursor")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(
        all_uris.len(),
        n as usize,
        "expected all {n} tuples across pages"
    );
    let mut uniq = all_uris.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), n as usize, "no duplicates across pages");

    h.writer.shutdown().await.unwrap();
}

/// Pagination semantics under concurrent writes (§F3 is best-effort, not
/// snapshot-consistent). The test documents the expected behavior: the
/// cursor prevents re-returning tuples already served, but new labels
/// written mid-traversal may or may not appear depending on their seq
/// relative to the cursor.
#[tokio::test]
async fn pagination_tolerates_interleaved_writes() {
    let h = spawn_harness().await;

    let prefix = "at://did:plc:interleave0000000000000000/app.bsky.feed.post/";
    for i in 0..60 {
        h.writer
            .apply_label(apply(&format!("{prefix}{i:03}"), "spam"))
            .await
            .unwrap();
    }

    let pattern = format!("{prefix}*");

    // Page 1 (limit=50).
    let (_, body, _) = http_get(
        h.addr,
        &format!("uriPatterns={}&limit=50", urlencoding::encode(&pattern)),
    )
    .await;
    let page_one: Vec<String> = labels_array(&body)
        .iter()
        .map(|l| l["uri"].as_str().unwrap().to_string())
        .collect();
    let cursor = body
        .get("cursor")
        .and_then(|c| c.as_str())
        .expect("cursor expected since 60 > 50");

    assert_eq!(page_one.len(), 50);

    // Interleave: write 10 new labels (60..70) between pages.
    for i in 60..70 {
        h.writer
            .apply_label(apply(&format!("{prefix}{i:03}"), "spam"))
            .await
            .unwrap();
    }

    // Page 2 with cursor.
    let (_, body, _) = http_get(
        h.addr,
        &format!(
            "uriPatterns={}&limit=50&cursor={}",
            urlencoding::encode(&pattern),
            urlencoding::encode(cursor)
        ),
    )
    .await;
    let page_two: Vec<String> = labels_array(&body)
        .iter()
        .map(|l| l["uri"].as_str().unwrap().to_string())
        .collect();

    // Invariant 1: no duplicates across pages (cursor prevents them).
    for uri in &page_two {
        assert!(
            !page_one.contains(uri),
            "page 2 must not repeat page 1 entries; duplicate {uri}"
        );
    }

    // Invariant 2: page 2 is non-empty (the remaining 10 originals + some
    // or all of the newly-written 10 should appear; exactly which of the
    // new ones is an implementation detail — the point is queryLabels is
    // point-in-time-per-page, not snapshot-consistent across pages).
    assert!(
        !page_two.is_empty(),
        "page 2 must include the remaining 10 + interleaved writes visible to this page"
    );

    h.writer.shutdown().await.unwrap();
}
