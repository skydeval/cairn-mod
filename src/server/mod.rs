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

pub mod admin;
mod create_report;
pub mod did_document;
pub mod health;
pub mod limits;
pub mod public;
mod query;
pub(crate) mod strike_state;
pub(crate) mod subscribe;
pub mod wellknown;
pub mod xrpc;

pub use admin::{AdminConfig, admin_router};
pub use create_report::{CreateReportConfig, create_report_router};
pub use public::public_router;
pub use subscribe::current_retention_floor;

/// Sweep-execution policy for the subscribeLabels retention sweep (§F4
/// retention task). Distinct from [`SubscribeConfig::retention_days`] —
/// that field is the cutoff source of truth (read-side floor + write-
/// side cutoff); this struct holds *how* the sweep runs, not *when*
/// the cutoff lies. Operators tune the two independently:
///
/// - `[subscribe].retention_days` (logical owner: [`SubscribeConfig`])
///   sets the rolling window ("180 days back").
/// - `[retention]` (logical owner: this struct) sets sweep schedule
///   and batching ("run at 04:00 UTC, 1000 rows per transaction").
///
/// Defaults match §F4 prose: sweep enabled, runs daily at 04:00 UTC,
/// 1000-row batches.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// Master toggle for the scheduled sweep. When `false`, no
    /// scheduled sweep runs; the manual CLI / admin-XRPC path still
    /// works (operators retain explicit control). Default `true`.
    pub sweep_enabled: bool,
    /// UTC hour-of-day (0..=23) at which the scheduled sweep fires.
    /// Default 4 (04:00 UTC — quiet hour for most operator regions,
    /// matches §F4 example).
    pub sweep_run_at_utc_hour: u8,
    /// Rows per DELETE transaction. Larger batches are throughput-
    /// efficient but hold the writer for longer; smaller batches let
    /// normal label writes interleave with finer granularity. Default
    /// 1000. Distinct from [`SubscribeConfig::batch_size`] (replay
    /// batching is latency-sensitive, sweep batching is throughput-
    /// sensitive — tune independently).
    pub sweep_batch_size: i64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            sweep_enabled: true,
            sweep_run_at_utc_hour: 4,
            sweep_batch_size: 1000,
        }
    }
}
pub use did_document::did_document_router;
pub use health::health_router;
pub use limits::Limiter;
pub use wellknown::wellknown_router;

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
