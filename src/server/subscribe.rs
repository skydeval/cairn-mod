//! `com.atproto.label.subscribeLabels` handler (§F4).
//!
//! Per-connection state machine:
//!
//! 1. Parse `?cursor=...` — live-only (absent), replay-from-seq (valid int),
//!    or malformed (close 1008, no frame).
//! 2. Acquire a subscriber permit from the limiter; reject overflow with
//!    HTTP 503 before upgrade (cheaper than upgrade-then-close).
//! 3. Register the broadcast receiver *before* reading `head_at_join`
//!    from SQLite so live events that happen during replay are buffered,
//!    not dropped.
//! 4. Replay phase: emit `#info OutdatedCursor` if the cursor sits below
//!    the retention floor, then stream stored rows `cursor < seq ≤
//!    head_at_join` in 1000-row batches, honoring §F4's negation-hiding
//!    rule (apply events with a later negation are excluded; the negation
//!    itself remains).
//! 5. Live phase: drain the broadcast receiver, discarding `seq ≤
//!    head_at_join` (already replayed in phase 4). Interleave with a
//!    30s ping timer and a 90s pong timeout; close on client-sent data
//!    frames, on `broadcast::RecvError::Lagged` (slow subscriber), and on
//!    `RecvError::Closed` (writer shutting down).

use std::sync::Arc;
use std::time::Instant;

use axum::Extension;
use axum::extract::ConnectInfo;
use axum::extract::Query;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use bytes::Bytes;
use futures_util::stream::StreamExt as _;
use futures_util::{SinkExt as _, stream::SplitSink};
use proto_blue_lex_cbor::encode as cbor_encode;
use proto_blue_lex_data::LexValue;
use serde::Deserialize;
use sqlx::{Pool, Sqlite};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tokio::sync::broadcast;
use tokio::time::{MissedTickBehavior, interval};

use crate::error::{Error, Result};
use crate::label::Label;
use crate::signing::label_to_lex_value_with_sig;
use crate::writer::{LabelEvent, WriterHandle};

use super::SubscribeConfig;
use super::limits::Limiter;

/// WebSocket close code for "policy violation" (RFC 6455 §7.4.1) — used
/// for malformed cursors and for client-sent application data frames.
const CLOSE_POLICY_VIOLATION: u16 = 1008;
/// Normal closure (RFC 6455) — client/server disconnect cleanly.
const CLOSE_NORMAL: u16 = 1000;
/// Going away (RFC 6455) — writer shutting down, slow subscribers.
const CLOSE_GOING_AWAY: u16 = 1001;

// ---------- Query params + cursor decoding ----------

#[derive(Debug, Deserialize)]
pub(super) struct CursorParams {
    cursor: Option<String>,
}

/// Parsed intent behind the `cursor` query param. Malformed is distinct
/// from "integer outside a useful range" — the latter maps to a frame
/// (OutdatedCursor or FutureCursor); the former to a protocol close.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CursorDecision {
    /// No cursor. Stream live events only.
    LiveOnly,
    /// Replay stored events with `seq > from_exclusive` up to
    /// `head_at_join`, optionally emitting `#info OutdatedCursor` first.
    Replay {
        emit_outdated: bool,
        from_exclusive: i64,
    },
    /// Cursor exceeds current head — emit `#error FutureCursor`, close.
    FutureCursor,
    /// Not a signed 64-bit integer — WS close 1008, no frame.
    Malformed,
}

/// Decide a `CursorDecision` from the raw query string + DB state.
/// `oldest_retained` is `None` when the table is empty; treat as 1 so
/// cursor=0 still triggers the OutdatedCursor path.
pub(super) fn decide_cursor(
    raw: Option<&str>,
    oldest_retained: Option<i64>,
    head: i64,
) -> CursorDecision {
    let Some(raw) = raw else {
        return CursorDecision::LiveOnly;
    };
    let Ok(c) = raw.parse::<i64>() else {
        return CursorDecision::Malformed;
    };
    if c > head {
        return CursorDecision::FutureCursor;
    }
    let oldest = oldest_retained.unwrap_or(1);
    if c <= 0 || c < oldest {
        // Replay starts at the oldest retained seq (which means the first
        // emitted frame has seq == oldest_retained). Query uses strict
        // `>`, so from_exclusive is one below oldest. Clamped at 0 for
        // the empty-table case.
        CursorDecision::Replay {
            emit_outdated: true,
            from_exclusive: (oldest - 1).max(0),
        }
    } else {
        CursorDecision::Replay {
            emit_outdated: false,
            from_exclusive: c,
        }
    }
}

// ---------- Frame encoding ----------

/// Build a single WS binary message = header CBOR + body CBOR
/// concatenated (§F4 "two DAG-CBOR objects per message").
fn frame_bytes(header: LexValue, body: LexValue) -> Result<Bytes> {
    let mut out = cbor_encode(&header)?;
    out.extend_from_slice(&cbor_encode(&body)?);
    Ok(Bytes::from(out))
}

fn header(op: i64, t: Option<&str>) -> LexValue {
    let mut m = BTreeMap::new();
    m.insert("op".to_string(), LexValue::Integer(op));
    if let Some(t) = t {
        m.insert("t".to_string(), LexValue::String(t.to_string()));
    }
    LexValue::Map(m)
}

/// `#labels` frame for a single committed event.
pub(super) fn labels_frame(seq: i64, label: &Label) -> Result<Bytes> {
    let h = header(1, Some("#labels"));
    let mut body = BTreeMap::new();
    body.insert("seq".to_string(), LexValue::Integer(seq));
    body.insert(
        "labels".to_string(),
        LexValue::Array(vec![label_to_lex_value_with_sig(label)?]),
    );
    frame_bytes(h, LexValue::Map(body))
}

/// `#info` frame. In v1, `name` is always `"OutdatedCursor"`.
pub(super) fn info_frame(name: &str, message: Option<&str>) -> Result<Bytes> {
    let h = header(1, Some("#info"));
    let mut body = BTreeMap::new();
    body.insert("name".to_string(), LexValue::String(name.to_string()));
    if let Some(m) = message {
        body.insert("message".to_string(), LexValue::String(m.to_string()));
    }
    frame_bytes(h, LexValue::Map(body))
}

/// Error frame (`op: -1`). §F4 declares only `FutureCursor` for v1.
pub(super) fn error_frame(error: &str, message: Option<&str>) -> Result<Bytes> {
    let h = header(-1, None);
    let mut body = BTreeMap::new();
    body.insert("error".to_string(), LexValue::String(error.to_string()));
    if let Some(m) = message {
        body.insert("message".to_string(), LexValue::String(m.to_string()));
    }
    frame_bytes(h, LexValue::Map(body))
}

// ---------- Axum handler ----------

pub(super) async fn handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<CursorParams>,
    Extension(state): Extension<AppState>,
) -> axum::response::Response {
    // Cap check before upgrade: cheaper to reject here than to upgrade a
    // doomed connection. §F4: "Excess connections close immediately."
    let Some(permit) = state.limiter.try_acquire(addr.ip()) else {
        return (StatusCode::SERVICE_UNAVAILABLE, "subscriber cap reached").into_response();
    };

    // Register the broadcast receiver and observe the shutdown signal
    // SYNCHRONOUSLY, before the 101 upgrade response is produced. Two
    // races close here:
    //
    // 1. Handler-level: `ws.on_upgrade(closure)` returns a Response; axum
    //    sends the 101, the client's `connect_async` resolves, and only
    //    then is the closure task scheduled. If `subscribe()` lived inside
    //    the closure, a client that called apply() immediately after
    //    connect_async returned could broadcast to zero receivers and
    //    silently drop the event.
    //
    // 2. Tokio-broadcast-internal: `Sender::subscribe` bumps
    //    `num_receivers` before taking the tail lock to snapshot the
    //    receiver's initial `next` position. A `send` that interleaves
    //    between fetch_add and the tail lock sees the incremented count,
    //    writes at the current tail, and advances past it — the new
    //    receiver's `next` then points *past* the just-sent event.
    //    Holding both calls pre-upgrade means no send can interleave
    //    before the client is able to observe the upgrade completing.
    //
    // Moving these calls out of the closure is a production correctness
    // property: any real client doing apply-then-observe without a sync
    // point would otherwise hit the same race.
    let bcast = state.writer.subscribe();
    let shutdown_rx = state.writer.shutdown_signal();

    ws.on_upgrade(move |socket| async move {
        let permit = permit; // RAII: released when this task ends.
        if let Err(err) = run_subscription(socket, state, params.cursor, bcast, shutdown_rx).await {
            tracing::warn!(%addr, error = %err, "subscribeLabels connection ended with error");
        }
        drop(permit);
    })
}

/// Concrete state carried into the handler. Kept local to this module so
/// higher-level wiring isn't forced to mention the limiter type or the
/// writer handle directly — `super::router` passes what's needed.
#[derive(Clone)]
pub(super) struct AppState {
    pub pool: Pool<Sqlite>,
    pub writer: WriterHandle,
    pub limiter: Arc<Limiter>,
    pub config: Arc<SubscribeConfig>,
}

async fn run_subscription(
    socket: WebSocket,
    state: AppState,
    cursor_raw: Option<String>,
    bcast: broadcast::Receiver<LabelEvent>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    // `bcast` and `shutdown_rx` are created in `handler` before the 101
    // upgrade response is produced — see the comment there for the race
    // this ordering closes. This function receives them as parameters
    // precisely so they exist before the client can observe the upgrade.
    let (mut sink, mut stream) = socket.split();

    // Retention floor (read-side): oldest seq whose row is newer than the
    // retention cutoff. Sweep is deferred — this floor enforces the
    // subscriber-visible invariant regardless of whether stale rows
    // have been swept.
    let oldest_retained = query_oldest_retained(&state.pool, &state.config).await?;
    let head_at_join = query_current_head(&state.pool).await?;

    let decision = decide_cursor(cursor_raw.as_deref(), oldest_retained, head_at_join);

    match decision {
        CursorDecision::Malformed => {
            // §F4: close 1008, no frame.
            let _ = sink
                .send(Message::Close(Some(CloseFrame {
                    code: CLOSE_POLICY_VIOLATION,
                    reason: Utf8Bytes::from_static("invalid cursor"),
                })))
                .await;
            Ok(())
        }
        CursorDecision::FutureCursor => {
            let frame = error_frame("FutureCursor", Some(&format!("head={head_at_join}")))?;
            let _ = sink.send(Message::Binary(frame)).await;
            let _ = sink
                .send(Message::Close(Some(CloseFrame {
                    code: CLOSE_NORMAL,
                    reason: Utf8Bytes::from_static("FutureCursor"),
                })))
                .await;
            Ok(())
        }
        CursorDecision::LiveOnly => {
            // No replay happened, so no seq has been emitted yet. Pass 0
            // as the "last emitted" threshold: broadcast receivers created
            // pre-upgrade only hold post-subscribe events, so every seq
            // they carry is by construction one the client has not yet
            // seen. Passing `head_at_join` here (the committed head at
            // query time) would erroneously skip an event that was
            // applied *between* the pre-upgrade subscribe and the head
            // query — a narrow window, but deterministically hit by a
            // client that connect-then-apply's quickly.
            live_tail(&mut sink, &mut stream, bcast, shutdown_rx, 0, &state).await
        }
        CursorDecision::Replay {
            emit_outdated,
            from_exclusive,
        } => {
            if emit_outdated {
                let oldest_str = oldest_retained
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "0".into());
                let frame = info_frame(
                    "OutdatedCursor",
                    Some(&format!("oldest_retained_seq={oldest_str}")),
                )?;
                sink.send(Message::Binary(frame)).await.ok();
            }

            replay_range(
                &mut sink,
                &state.pool,
                from_exclusive,
                head_at_join,
                &state.config,
            )
            .await?;

            live_tail(
                &mut sink,
                &mut stream,
                bcast,
                shutdown_rx,
                head_at_join,
                &state,
            )
            .await
        }
    }
}

type WsSink = SplitSink<WebSocket, Message>;

/// `skip_seq_at_or_below` is the largest seq already emitted via replay
/// (or 0 for `LiveOnly`, where nothing has been emitted yet). Events
/// received here with `seq <= skip_seq_at_or_below` were already served
/// via the replay path and are dropped to avoid double-emission.
async fn live_tail(
    sink: &mut WsSink,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    mut bcast: broadcast::Receiver<LabelEvent>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    skip_seq_at_or_below: i64,
    state: &AppState,
) -> Result<()> {
    let mut ping_timer = interval(state.config.ping_interval);
    ping_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Skip the immediately-firing first tick; a ping at t=0 is noise on a
    // just-established connection.
    ping_timer.tick().await;

    let mut last_pong = Instant::now();

    loop {
        tokio::select! {
            biased;
            // Broadcast receive.
            res = bcast.recv() => match res {
                Ok(event) => {
                    // Skip events already served during replay.
                    if event.seq <= skip_seq_at_or_below {
                        continue;
                    }
                    let frame = labels_frame(event.seq, &event.label)?;
                    if sink.send(Message::Binary(frame)).await.is_err() {
                        return Ok(()); // client is gone
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Slow subscriber — §F4 says close, no info frame.
                    let _ = sink.send(Message::Close(Some(CloseFrame {
                        code: CLOSE_GOING_AWAY,
                        reason: Utf8Bytes::from_static("subscriber lagged past buffer"),
                    }))).await;
                    return Ok(());
                }
                Err(broadcast::error::RecvError::Closed) => {
                    // Writer shutting down.
                    let _ = sink.send(Message::Close(Some(CloseFrame {
                        code: CLOSE_GOING_AWAY,
                        reason: Utf8Bytes::from_static("server shutting down"),
                    }))).await;
                    return Ok(());
                }
            },

            // Client-side frame.
            msg = stream.next() => match msg {
                None | Some(Err(_)) => return Ok(()), // socket closed or errored
                Some(Ok(Message::Close(_))) => return Ok(()),
                Some(Ok(Message::Pong(_))) => {
                    last_pong = Instant::now();
                }
                Some(Ok(Message::Ping(_))) => {
                    // Axum auto-replies with Pong on its own, but an explicit
                    // Ping from the client is legitimate — count it as
                    // liveness too.
                    last_pong = Instant::now();
                }
                Some(Ok(Message::Text(_) | Message::Binary(_))) => {
                    // §F4: "Any application data frame received from the
                    // client results in immediate connection close."
                    let _ = sink.send(Message::Close(Some(CloseFrame {
                        code: CLOSE_POLICY_VIOLATION,
                        reason: Utf8Bytes::from_static("client must not send application data"),
                    }))).await;
                    return Ok(());
                }
            },

            // Writer shutdown signal.
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    let _ = sink.send(Message::Close(Some(CloseFrame {
                        code: CLOSE_GOING_AWAY,
                        reason: Utf8Bytes::from_static("server shutting down"),
                    }))).await;
                    return Ok(());
                }
            },

            // Ping timer.
            _ = ping_timer.tick() => {
                if last_pong.elapsed() > state.config.pong_timeout {
                    let _ = sink.send(Message::Close(Some(CloseFrame {
                        code: CLOSE_GOING_AWAY,
                        reason: Utf8Bytes::from_static("pong timeout"),
                    }))).await;
                    return Ok(());
                }
                if sink.send(Message::Ping(Bytes::new())).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

// ---------- Storage queries ----------

async fn query_current_head(pool: &Pool<Sqlite>) -> Result<i64> {
    let v: Option<i64> = sqlx::query_scalar!(r#"SELECT MAX(seq) AS "max_seq?: i64" FROM labels"#)
        .fetch_one(pool)
        .await?;
    Ok(v.unwrap_or(0))
}

/// Live retention floor: oldest visible `seq` whose row's `created_at`
/// is within `retention_days` of `now`. Returns `None` for an empty
/// (or wholly-expired) table. When `retention_days = None`, returns
/// the `MIN(seq)` across ALL rows (no cutoff applied).
///
/// This is the same logic the subscribeLabels handler uses for its
/// `OutdatedCursor` decisions — exposed as a public helper so the §F4
/// sweep invariant test (#12) can assert that running the sweep does
/// **not** change this value for a fixed `retention_days` config. If
/// a future refactor switches floor computation from live SQL to a
/// stored value, that test catches the regression.
pub async fn current_retention_floor(
    pool: &Pool<Sqlite>,
    retention_days: Option<u32>,
) -> Result<Option<i64>> {
    let cfg = SubscribeConfig {
        retention_days,
        ..SubscribeConfig::default()
    };
    query_oldest_retained(pool, &cfg).await
}

async fn query_oldest_retained(
    pool: &Pool<Sqlite>,
    config: &SubscribeConfig,
) -> Result<Option<i64>> {
    match config.retention_days {
        None => {
            let v: Option<i64> =
                sqlx::query_scalar!(r#"SELECT MIN(seq) AS "min_seq?: i64" FROM labels"#)
                    .fetch_one(pool)
                    .await?;
            Ok(v)
        }
        Some(days) => {
            let cutoff_ms = crate::writer::epoch_ms_now() - (days as i64) * 86_400_000;
            let v: Option<i64> = sqlx::query_scalar!(
                r#"SELECT MIN(seq) AS "min_seq?: i64" FROM labels WHERE created_at >= ?1"#,
                cutoff_ms
            )
            .fetch_one(pool)
            .await?;
            Ok(v)
        }
    }
}

/// Stream replay frames in batches. Negation-hiding: exclude `neg=0`
/// rows that have a later `neg=1` row for the same `(src, uri, val)`.
async fn replay_range(
    sink: &mut WsSink,
    pool: &Pool<Sqlite>,
    from_exclusive: i64,
    head: i64,
    config: &SubscribeConfig,
) -> Result<()> {
    let mut cursor = from_exclusive;
    loop {
        let batch = sqlx::query!(
            r#"SELECT
                 seq      AS "seq!: i64",
                 ver      AS "ver!: i64",
                 src, uri, cid, val,
                 neg      AS "neg!: i64",
                 cts, exp, sig
               FROM labels l1
               WHERE l1.seq > ?1
                 AND l1.seq <= ?2
                 AND NOT (
                   l1.neg = 0
                   AND EXISTS (
                     SELECT 1 FROM labels l2
                     WHERE l2.src = l1.src
                       AND l2.uri = l1.uri
                       AND l2.val = l1.val
                       AND l2.neg = 1
                       AND l2.seq > l1.seq
                   )
                 )
               ORDER BY l1.seq ASC
               LIMIT ?3"#,
            cursor,
            head,
            config.batch_size,
        )
        .fetch_all(pool)
        .await?;

        if batch.is_empty() {
            return Ok(());
        }

        for row in &batch {
            let sig: [u8; 64] = row.sig.as_slice().try_into().map_err(|_| {
                Error::Signing(format!(
                    "corrupt sig in labels.seq={}: expected 64 bytes, got {}",
                    row.seq,
                    row.sig.len()
                ))
            })?;
            let label = Label {
                ver: row.ver,
                src: row.src.clone(),
                uri: row.uri.clone(),
                cid: row.cid.clone(),
                val: row.val.clone(),
                neg: row.neg != 0,
                cts: row.cts.clone(),
                exp: row.exp.clone(),
                sig: Some(sig),
            };
            let frame = labels_frame(row.seq, &label)?;
            if sink.send(Message::Binary(frame)).await.is_err() {
                return Ok(());
            }
        }

        cursor = batch.last().expect("non-empty checked above").seq;
        if cursor >= head {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_absent_is_live_only() {
        let d = decide_cursor(None, Some(1), 10);
        assert_eq!(d, CursorDecision::LiveOnly);
    }

    #[test]
    fn cursor_zero_triggers_outdated_and_replay_from_oldest() {
        let d = decide_cursor(Some("0"), Some(5), 10);
        assert_eq!(
            d,
            CursorDecision::Replay {
                emit_outdated: true,
                from_exclusive: 4,
            }
        );
    }

    #[test]
    fn cursor_below_oldest_triggers_outdated() {
        let d = decide_cursor(Some("3"), Some(5), 10);
        assert_eq!(
            d,
            CursorDecision::Replay {
                emit_outdated: true,
                from_exclusive: 4,
            }
        );
    }

    #[test]
    fn cursor_at_or_above_oldest_within_head_is_plain_replay() {
        assert_eq!(
            decide_cursor(Some("5"), Some(5), 10),
            CursorDecision::Replay {
                emit_outdated: false,
                from_exclusive: 5,
            }
        );
        assert_eq!(
            decide_cursor(Some("7"), Some(5), 10),
            CursorDecision::Replay {
                emit_outdated: false,
                from_exclusive: 7,
            }
        );
    }

    #[test]
    fn cursor_exceeds_head_is_future() {
        assert_eq!(
            decide_cursor(Some("11"), Some(5), 10),
            CursorDecision::FutureCursor
        );
    }

    #[test]
    fn cursor_non_integer_is_malformed() {
        assert_eq!(
            decide_cursor(Some("abc"), Some(5), 10),
            CursorDecision::Malformed
        );
        assert_eq!(
            decide_cursor(Some(""), Some(5), 10),
            CursorDecision::Malformed
        );
    }

    #[test]
    fn empty_table_cursor_zero_replays_nothing_but_emits_outdated() {
        // oldest_retained=None (empty), head=0.
        let d = decide_cursor(Some("0"), None, 0);
        assert_eq!(
            d,
            CursorDecision::Replay {
                emit_outdated: true,
                from_exclusive: 0,
            }
        );
    }

    #[test]
    fn labels_frame_starts_with_op_and_t_header() {
        let label = Label {
            ver: 1,
            src: "did:plc:x".into(),
            uri: "at://did:plc:x/a/b".into(),
            cid: None,
            val: "spam".into(),
            neg: false,
            cts: "2026-04-22T12:00:00.000Z".into(),
            exp: None,
            sig: Some([0xAA; 64]),
        };
        let bytes = labels_frame(1, &label).expect("frame");
        // The header is a 2-key map {op, t}; DAG-CBOR encodes map-with-2
        // keys as 0xA2. Verifies structure without a full CBOR parse.
        assert_eq!(bytes[0], 0xA2, "first byte of header must be 2-key map");
        // The #labels tag must appear somewhere in the header.
        assert!(
            bytes.windows(7).any(|w| w == b"#labels"),
            "labels frame must contain #labels tag"
        );
    }

    #[test]
    fn info_frame_carries_outdated_cursor_name() {
        let bytes = info_frame("OutdatedCursor", Some("oldest=5")).expect("frame");
        assert!(
            bytes
                .windows("OutdatedCursor".len())
                .any(|w| w == b"OutdatedCursor"),
            "info frame must contain OutdatedCursor"
        );
    }

    #[test]
    fn error_frame_op_minus_one() {
        let bytes = error_frame("FutureCursor", None).expect("frame");
        // Header `{op: -1}` — 1-key map = 0xA1.
        assert_eq!(bytes[0], 0xA1);
        assert!(
            bytes
                .windows("FutureCursor".len())
                .any(|w| w == b"FutureCursor"),
            "error frame must contain FutureCursor"
        );
    }
}
