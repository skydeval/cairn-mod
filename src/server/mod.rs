//! HTTP server: XRPC endpoints over axum.
//!
//! Currently exposes one route — `GET /xrpc/com.atproto.label.subscribeLabels`
//! (§F4, WebSocket). Other endpoints land in their respective issues: the
//! binary wire-up (main.rs serving a long-lived listener) is parked until
//! #8 (queryLabels) so both public endpoints compose into one router.
//!
//! Design notes:
//!
//! - [`SubscribeConfig`] centralizes every runtime knob §F4 mentions: per-IP
//!   cap, global cap, batch size, ping/pong cadence, retention window.
//!   `Default` values match §F4 defaults so operators only override what
//!   their deployment requires.
//! - The [`router`] constructor takes ownership of a [`Pool<Sqlite>`] and a
//!   [`WriterHandle`]; both clone cheaply. The limiter is created here and
//!   wrapped in `Arc` so tests can inspect it with [`Limiter::snapshot`].
//! - [`serve`] is a thin helper over `axum::serve`, mostly to keep
//!   integration tests from reimplementing the listen/accept dance.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::Router;
use axum::http::Method;
use axum::routing::get;
use sqlx::{Pool, Sqlite};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

use crate::error::Result;
use crate::writer::WriterHandle;

pub mod limits;
mod query;
pub(crate) mod subscribe;

pub use limits::Limiter;

/// Tunables for the subscribeLabels endpoint. All defaults match §F4.
#[derive(Debug, Clone)]
pub struct SubscribeConfig {
    /// Maximum concurrent subscribers from one IP (§F4 default 8).
    pub per_ip_cap: usize,
    /// Maximum concurrent subscribers overall (§F4 default 256).
    pub global_cap: usize,
    /// Replay batch size in rows (§F4 "up to 1000 sequence rows per batch").
    pub batch_size: i64,
    /// Ping cadence (§F4 "30s").
    pub ping_interval: Duration,
    /// Pong silence that closes the connection (§F4 "90s").
    pub pong_timeout: Duration,
    /// Rolling retention window. `None` disables the read-side floor
    /// (useful in tests and when an operator wants unbounded replay).
    /// Default per §F4: 180 days.
    pub retention_days: Option<u32>,
}

impl Default for SubscribeConfig {
    fn default() -> Self {
        Self {
            per_ip_cap: 8,
            global_cap: 256,
            batch_size: 1000,
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(90),
            retention_days: Some(180),
        }
    }
}

/// Build a router exposing the public label endpoints. The caller owns
/// the pool and writer; dropping all cloned `WriterHandle`s signals
/// shutdown.
///
/// CORS is applied to `queryLabels` only (§F3 "accepts requests from any
/// origin"). subscribeLabels is WebSocket — browsers don't apply CORS to
/// WS connections the same way, and the WS handshake rejects cross-
/// origin reads at the Sec-WebSocket-* layer. Credentials are never
/// echoed (`allow_credentials` defaults to false on `CorsLayer`).
pub fn router(pool: Pool<Sqlite>, writer: WriterHandle, config: SubscribeConfig) -> Router {
    let limiter = Limiter::new(config.global_cap, config.per_ip_cap);
    let state = subscribe::AppState {
        pool,
        writer,
        limiter,
        config: Arc::new(config),
    };

    let query_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::OPTIONS]);

    Router::new()
        .route(
            "/xrpc/com.atproto.label.subscribeLabels",
            get(subscribe::handler),
        )
        .route(
            "/xrpc/com.atproto.label.queryLabels",
            get(query::handler).layer(query_cors),
        )
        .layer(Extension(state))
}

/// Serve `router` on `addr`. Returns when the listener errors or the
/// surrounding runtime shuts down.
pub async fn serve(router: Router, addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
