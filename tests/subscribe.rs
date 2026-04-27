//! Integration tests for `com.atproto.label.subscribeLabels` (§F4).
//!
//! Each test spins up a real axum server on an ephemeral port and
//! connects via `tokio-tungstenite`. We exercise the full stack:
//! axum upgrade → our handler → proto-blue CBOR framing → tungstenite
//! on the client side. Mocking at any layer would hide real regressions
//! (e.g., a frame-ordering bug that only shows up under WS fragmentation).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cairn_mod::{
    ApplyLabelRequest, SigningKey, SubscribeConfig, WriterHandle, spawn_writer, storage,
    subscribe_router,
};
use futures_util::{SinkExt as _, Stream, StreamExt as _};
use proto_blue_lex_cbor::decode_all;
use proto_blue_lex_data::LexValue;
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

const SERVICE_DID: &str = "did:plc:3jzfcijpj2z2a4pdagfkktq6";
const MODERATOR_DID: &str = "did:plc:moderator0000000000000000";
const TEST_KEY_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

struct Harness {
    _dir: TempDir,
    pool: Pool<Sqlite>,
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

/// Spin up a fresh SQLite DB, a writer, and an axum server on an ephemeral
/// port. Config overrides match the test's needs — short ping/pong so the
/// lifecycle tests don't wait 30s per beat.
async fn spawn_harness(config: SubscribeConfig) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cairn.db");
    let pool = storage::open(&path).await.expect("open pool");
    let writer = spawn_writer(
        pool.clone(),
        test_key(),
        SERVICE_DID.to_string(),
        None,
        cairn_mod::RetentionConfig::default(),
        cairn_mod::ReasonVocabulary::defaults(),
        cairn_mod::StrikePolicy::defaults(),
        cairn_mod::LabelEmissionPolicy::defaults(),
        cairn_mod::PolicyAutomationPolicy::defaults(),
    )
    .await
    .expect("spawn writer");

    let router = subscribe_router(pool.clone(), writer.clone(), config);

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
        pool,
        writer,
        addr,
    }
}

fn apply(uri_suffix: &str, val: &str) -> ApplyLabelRequest {
    ApplyLabelRequest {
        actor_did: MODERATOR_DID.to_string(),
        uri: format!("at://did:plc:subject{uri_suffix:0>26}/app.bsky.feed.post/x"),
        cid: None,
        val: val.to_string(),
        exp: None,
        moderator_reason: None,
    }
}

fn ws_url(addr: SocketAddr, cursor: Option<&str>) -> String {
    let base = format!("ws://{addr}/xrpc/com.atproto.label.subscribeLabels");
    match cursor {
        None => base,
        Some(c) => format!("{base}?cursor={c}"),
    }
}

/// Decode one WS binary message (header + body concatenated CBOR) into
/// its pair of `LexValue`s.
fn parse_frame(bytes: &[u8]) -> (LexValue, LexValue) {
    let parts = decode_all(bytes).expect("decode frame");
    assert_eq!(parts.len(), 2, "frame must be exactly 2 CBOR objects");
    (parts[0].clone(), parts[1].clone())
}

/// Extract the `t` tag from a header, panicking if missing or wrong type.
fn header_t(header: &LexValue) -> String {
    match header {
        LexValue::Map(m) => match m.get("t") {
            Some(LexValue::String(s)) => s.clone(),
            _ => panic!("header missing `t`"),
        },
        _ => panic!("header is not a map"),
    }
}

fn header_op(header: &LexValue) -> i64 {
    match header {
        LexValue::Map(m) => match m.get("op") {
            Some(LexValue::Integer(n)) => *n,
            _ => panic!("header missing `op`"),
        },
        _ => panic!("header is not a map"),
    }
}

fn body_field<'a>(body: &'a LexValue, key: &str) -> Option<&'a LexValue> {
    match body {
        LexValue::Map(m) => m.get(key),
        _ => panic!("body not a map"),
    }
}

fn body_seq(body: &LexValue) -> i64 {
    match body_field(body, "seq") {
        Some(LexValue::Integer(n)) => *n,
        _ => panic!("body missing `seq`"),
    }
}

async fn recv_binary<S>(ws: &mut S) -> Vec<u8>
where
    S: Stream<Item = Result<ClientMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("ws timeout")
            .expect("ws stream ended")
            .expect("ws error");
        match msg {
            ClientMessage::Binary(b) => return b.to_vec(),
            ClientMessage::Ping(_) | ClientMessage::Pong(_) => continue,
            other => panic!("unexpected ws message: {other:?}"),
        }
    }
}

// ========== Tests ==========

/// Wait until the server-side WebSocket handler has registered its
/// broadcast receiver. The client's `connect_async` returns as soon as
/// the HTTP 101 upgrade completes; the handler task starts *afterward*
/// and subscribes asynchronously. Tests that emit an event and expect
/// the subscriber to see it must wait for this sync point first, or
/// they race the subscribe() call and miss the broadcast.
async fn wait_for_subscriber(writer: &WriterHandle, expected: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while writer.receiver_count() < expected {
        if std::time::Instant::now() > deadline {
            panic!(
                "subscriber never registered: receiver_count={} expected={}",
                writer.receiver_count(),
                expected
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn live_only_no_cursor_receives_new_events() {
    let h = spawn_harness(SubscribeConfig::default()).await;

    let (mut ws, _) = connect_async(ws_url(h.addr, None)).await.expect("connect");

    wait_for_subscriber(&h.writer, 1).await;

    // Apply a label — subscriber should receive it.
    let event = h
        .writer
        .apply_label(apply("1", "spam"))
        .await
        .expect("apply");

    let bytes = recv_binary(&mut ws).await;
    let (header, body) = parse_frame(&bytes);
    assert_eq!(header_op(&header), 1);
    assert_eq!(header_t(&header), "#labels");
    assert_eq!(body_seq(&body), event.seq);

    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn cursor_zero_emits_outdated_then_replays_all() {
    let h = spawn_harness(SubscribeConfig::default()).await;

    // Pre-populate 3 labels.
    for i in 1..=3 {
        h.writer
            .apply_label(apply(&i.to_string(), "spam"))
            .await
            .expect("apply");
    }

    let (mut ws, _) = connect_async(ws_url(h.addr, Some("0")))
        .await
        .expect("connect");

    // First frame: #info OutdatedCursor.
    let bytes = recv_binary(&mut ws).await;
    let (header, body) = parse_frame(&bytes);
    assert_eq!(header_t(&header), "#info");
    match body_field(&body, "name") {
        Some(LexValue::String(s)) => assert_eq!(s, "OutdatedCursor"),
        _ => panic!("missing name"),
    }

    // Next 3 frames: #labels with seq 1, 2, 3.
    for expected_seq in 1..=3 {
        let bytes = recv_binary(&mut ws).await;
        let (header, body) = parse_frame(&bytes);
        assert_eq!(header_t(&header), "#labels");
        assert_eq!(body_seq(&body), expected_seq);
    }

    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn cursor_midstream_replays_from_there_no_outdated() {
    let h = spawn_harness(SubscribeConfig::default()).await;

    for i in 1..=5 {
        h.writer
            .apply_label(apply(&i.to_string(), "spam"))
            .await
            .expect("apply");
    }

    let (mut ws, _) = connect_async(ws_url(h.addr, Some("2")))
        .await
        .expect("connect");

    // Expect frames 3, 4, 5 — no #info.
    for expected_seq in 3..=5 {
        let bytes = recv_binary(&mut ws).await;
        let (header, body) = parse_frame(&bytes);
        assert_eq!(header_t(&header), "#labels", "seq {expected_seq}");
        assert_eq!(body_seq(&body), expected_seq);
    }

    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn cursor_beyond_head_emits_future_cursor_and_closes() {
    let h = spawn_harness(SubscribeConfig::default()).await;
    h.writer
        .apply_label(apply("1", "spam"))
        .await
        .expect("apply");

    // head = 1. Ask for 99.
    let (mut ws, _) = connect_async(ws_url(h.addr, Some("99")))
        .await
        .expect("connect");

    let bytes = recv_binary(&mut ws).await;
    let (header, body) = parse_frame(&bytes);
    assert_eq!(header_op(&header), -1, "error frame op = -1");
    match body_field(&body, "error") {
        Some(LexValue::String(s)) => assert_eq!(s, "FutureCursor"),
        _ => panic!("missing error"),
    }

    // Next message must be a Close.
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timeout")
        .expect("end of stream");
    match msg {
        Ok(ClientMessage::Close(_)) | Err(_) => {}
        other => panic!("expected close, got {other:?}"),
    }

    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn malformed_cursor_closes_1008_no_frame() {
    let h = spawn_harness(SubscribeConfig::default()).await;

    let (mut ws, _) = connect_async(ws_url(h.addr, Some("notanumber")))
        .await
        .expect("connect");

    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timeout")
        .expect("stream")
        .expect("recv");
    match msg {
        ClientMessage::Close(Some(frame)) => {
            // tungstenite reports CloseCode::Policy == 1008.
            assert_eq!(
                u16::from(frame.code),
                1008,
                "malformed cursor must close with 1008"
            );
        }
        other => panic!("expected Close(1008), got {other:?}"),
    }

    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn backfill_then_live_no_duplicates_no_gaps() {
    let h = spawn_harness(SubscribeConfig::default()).await;

    // Prime 3 labels.
    for i in 1..=3 {
        h.writer
            .apply_label(apply(&i.to_string(), "spam"))
            .await
            .expect("apply");
    }

    let (mut ws, _) = connect_async(ws_url(h.addr, Some("1")))
        .await
        .expect("connect");

    // Backfill should deliver 2, 3.
    for expected in [2, 3] {
        let bytes = recv_binary(&mut ws).await;
        let (_, body) = parse_frame(&bytes);
        assert_eq!(body_seq(&body), expected);
    }

    // Now push more — live phase.
    for i in 4..=6 {
        h.writer
            .apply_label(apply(&i.to_string(), "spam"))
            .await
            .expect("apply");
    }
    for expected in [4, 5, 6] {
        let bytes = recv_binary(&mut ws).await;
        let (_, body) = parse_frame(&bytes);
        assert_eq!(body_seq(&body), expected);
    }

    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn negation_replay_excludes_original_apply_but_keeps_negation() {
    let h = spawn_harness(SubscribeConfig::default()).await;

    // apply then negate.
    let applied = h
        .writer
        .apply_label(apply("1", "spam"))
        .await
        .expect("apply");
    let negated = h
        .writer
        .negate_label(cairn_mod::NegateLabelRequest {
            actor_did: MODERATOR_DID.to_string(),
            uri: applied.label.uri.clone(),
            val: "spam".to_string(),
            moderator_reason: None,
        })
        .await
        .expect("negate");

    let (mut ws, _) = connect_async(ws_url(h.addr, Some("0")))
        .await
        .expect("connect");

    // First: #info OutdatedCursor.
    let bytes = recv_binary(&mut ws).await;
    let (header, _) = parse_frame(&bytes);
    assert_eq!(header_t(&header), "#info");

    // Then: only the negation frame, seq=negated.seq. The apply (seq=1)
    // is hidden because a later neg exists for the tuple.
    let bytes = recv_binary(&mut ws).await;
    let (header, body) = parse_frame(&bytes);
    assert_eq!(header_t(&header), "#labels");
    assert_eq!(body_seq(&body), negated.seq);

    // Make sure no more label frames follow within a short window — the
    // apply should NOT appear. We bound the check by connecting live and
    // seeing whether any further label frames arrive; none should.
    let outcome = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    match outcome {
        Err(_) => { /* timeout: no further frames, as expected */ }
        Ok(Some(Ok(ClientMessage::Ping(_)))) => { /* ping is fine */ }
        Ok(other) => panic!("unexpected frame after negation: {other:?}"),
    }

    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn per_ip_cap_rejects_ninth_connection() {
    let h = spawn_harness(SubscribeConfig {
        per_ip_cap: 8,
        ..SubscribeConfig::default()
    })
    .await;

    let mut keep = Vec::new();
    for _ in 0..8 {
        let (ws, _) = connect_async(ws_url(h.addr, None)).await.expect("connect");
        keep.push(ws);
    }

    // 9th from the same IP (127.0.0.1) — the server returns 503 before
    // upgrade. tokio-tungstenite surfaces this as a connect error.
    let result = connect_async(ws_url(h.addr, None)).await;
    assert!(
        result.is_err(),
        "9th concurrent subscriber from 127.0.0.1 must be rejected; got {result:?}"
    );

    for mut ws in keep {
        let _ = ws.close(None).await;
    }
    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn client_sending_application_data_gets_closed() {
    let h = spawn_harness(SubscribeConfig::default()).await;

    let (mut ws, _) = connect_async(ws_url(h.addr, None)).await.expect("connect");

    // Client sends a text frame — §F4 says server must close.
    ws.send(ClientMessage::Text("hello".into()))
        .await
        .expect("send");

    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timeout")
        .expect("stream end")
        .expect("recv");
    match msg {
        ClientMessage::Close(Some(frame)) => {
            assert_eq!(u16::from(frame.code), 1008);
        }
        other => panic!("expected Close(1008), got {other:?}"),
    }

    h.writer.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn writer_shutdown_closes_subscribers() {
    let h = spawn_harness(SubscribeConfig::default()).await;

    let (mut ws, _) = connect_async(ws_url(h.addr, None)).await.expect("connect");

    // Shutting down the writer drops the broadcast Sender → receivers see
    // RecvError::Closed → handler sends a Close frame.
    h.writer.shutdown().await.expect("shutdown");

    // The server should close the connection.
    let outcome = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
    let msg = outcome
        .expect("timeout waiting for shutdown close")
        .expect("stream end")
        .expect("recv");
    match msg {
        ClientMessage::Close(_) => {}
        other => panic!("expected Close, got {other:?}"),
    }
}

#[tokio::test]
async fn head_at_join_boundary_prevents_replay_duplicate() {
    // Regression check: an event emitted right as the subscriber joins
    // appears exactly once, not once via replay and once via live. The
    // writer subscribes first then reads head, which means an event with
    // seq == head_at_join gets replayed by the query (seq <= head) and
    // filtered out by the live-phase skip (seq <= head_at_join).
    let h = spawn_harness(SubscribeConfig::default()).await;

    let _ = h.writer.apply_label(apply("1", "spam")).await.unwrap();
    let _ = h.writer.apply_label(apply("2", "spam")).await.unwrap();

    let (mut ws, _) = connect_async(ws_url(h.addr, Some("1")))
        .await
        .expect("connect");

    // Replay should yield seq=2.
    let bytes = recv_binary(&mut ws).await;
    let (_, body) = parse_frame(&bytes);
    assert_eq!(body_seq(&body), 2);

    // A new event after the subscription is live. Must arrive exactly once.
    let _ = h.writer.apply_label(apply("3", "spam")).await.unwrap();
    let bytes = recv_binary(&mut ws).await;
    let (_, body) = parse_frame(&bytes);
    assert_eq!(body_seq(&body), 3);

    // And we must NOT see a duplicate of seq=2.
    let outcome = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    match outcome {
        Err(_) => { /* expected: no more frames */ }
        Ok(Some(Ok(ClientMessage::Ping(_)))) => {}
        Ok(other) => panic!("unexpected extra frame: {other:?}"),
    }

    let _ = Arc::new(h.pool); // silence unused warning on pool
    h.writer.shutdown().await.expect("shutdown");
}
