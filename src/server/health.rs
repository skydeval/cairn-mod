//! `/health` and `/ready` orchestrator probe endpoints (#23).
//!
//! Both endpoints are unauthenticated, cheap, and mirror the route
//! pattern of [`super::did_document_router`].
//!
//! # `/health` — liveness probe
//!
//! Returns 200 with a fixed `{"status": "ok", "version": "..."}` body
//! whenever the process is alive enough to respond. Kubernetes-style
//! liveness semantics: a failing probe means "restart the pod." No
//! dependencies are checked because every dependency is
//! already something whose failure warrants `/ready` flipping to
//! degraded — baking them into `/health` would cause needless pod
//! restarts on transient DB hiccups.
//!
//! # `/ready` — readiness probe
//!
//! Returns 200 when every check passes, 503 when any check fails. The
//! body shape is identical in both cases so orchestrators and humans
//! can inspect individual checks without status-code-driven parsing:
//!
//! ```json
//! {
//!   "status": "ok" | "degraded",
//!   "version": "<cargo pkg version>",
//!   "checks": {
//!     "database":     "ok" | "failed",
//!     "signing_key":  "ok" | "failed",
//!     "label_stream": "ok" | "degraded"
//!   }
//! }
//! ```
//!
//! Checks run in parallel via [`tokio::join!`]; they are independent
//! and the pool accepts concurrent read traffic.
//!
//! ## Why each check is meaningful
//!
//! - **database**: the SQLite pool has to respond to a trivial query.
//!   Every request path that writes a label or audit row funnels
//!   through it; an unreachable pool means we cannot serve traffic.
//! - **signing_key**: `signing_keys` must have at least one row with
//!   `valid_to IS NULL`. This is the same readiness condition
//!   [`super::did_document_router`] uses — without a signing key row,
//!   `/.well-known/did.json` 503s and consumers cannot verify labels.
//! - **label_stream**: the writer task is still reachable and
//!   heartbeating. Flipped to `degraded` if the writer's
//!   `shutdown_signal` has fired, or if
//!   `server_instance_lease.last_heartbeat` is older than
//!   [`LEASE_STALE_MS`] (60s). Reuses the lease-staleness constant
//!   deliberately: /ready's "degraded" threshold aligns with the
//!   lease-handoff boundary, so there is exactly one system-wide
//!   notion of "this writer is dead." Two different thresholds would
//!   be inconsistent.
//!
//! The `database` and `signing_key` checks use a two-variant status
//! (`ok | failed`); `label_stream` uses `ok | degraded`. The distinction
//! is load-bearing — a stream lagging behind the heartbeat window is a
//! different operational state from a pool that cannot execute a
//! query — and is preserved in the type system rather than collapsed
//! into a single tri-state enum.
//!
//! ## Known gap
//!
//! A writer task that is alive and heartbeating but wedged on
//! processing WriteCommand messages would pass the label_stream check
//! here. Closing that gap requires adding a `Ping` WriteCommand variant
//! so `/ready` can exercise the actual command path; deliberately out
//! of scope for #23.

use axum::Extension;
use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;
use sqlx::{Pool, Sqlite};

use crate::writer::{LEASE_STALE_MS, WriterHandle, epoch_ms_now};

/// Build a router exposing `GET /health` and `GET /ready`.
///
/// Both routes are unauthenticated. Compose into the live binary via
/// [`axum::Router::merge`] alongside the other per-feature routers.
pub fn health_router(pool: Pool<Sqlite>, writer: WriterHandle) -> Router {
    let state = HealthState { pool, writer };
    Router::new()
        .route("/health", get(handle_health))
        .route("/ready", get(handle_ready))
        .layer(Extension(state))
}

/// Router state carries a [`WriterHandle`] (not just
/// `writer.shutdown_signal()`) deliberately: when the last handle is
/// dropped, the writer task's mpsc receiver closes and the task
/// shuts itself down. Storing the handle keeps the writer alive for
/// as long as the router is serving, rather than having /ready
/// silently flip to `degraded` the first time it's probed.
#[derive(Clone)]
struct HealthState {
    pool: Pool<Sqlite>,
    writer: WriterHandle,
}

// ----- Status types -----
//
// Three distinct enums instead of one tri-state. Each field's domain
// is modeled explicitly in the type system; a future refactor that
// reaches for `Status::Degraded` on `database` would not compile.

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum OkOrDegraded {
    Ok,
    Degraded,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum OkOrFailed {
    Ok,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum HealthStatus {
    Ok,
}

// ----- Response types -----

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: HealthStatus,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct ReadyResponse {
    status: OkOrDegraded,
    version: &'static str,
    checks: ReadyChecks,
}

#[derive(Debug, Serialize)]
struct ReadyChecks {
    database: OkOrFailed,
    signing_key: OkOrFailed,
    label_stream: OkOrDegraded,
}

// ----- Handlers -----

async fn handle_health() -> Response {
    let body = HealthResponse {
        status: HealthStatus::Ok,
        version: env!("CARGO_PKG_VERSION"),
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn handle_ready(Extension(state): Extension<HealthState>) -> Response {
    let shutdown_rx = state.writer.shutdown_signal();
    let (database, signing_key, label_stream) = tokio::join!(
        check_database(&state.pool),
        check_signing_key(&state.pool),
        check_label_stream(&state.pool, &shutdown_rx),
    );
    let overall = match (database, signing_key, label_stream) {
        (OkOrFailed::Ok, OkOrFailed::Ok, OkOrDegraded::Ok) => OkOrDegraded::Ok,
        _ => OkOrDegraded::Degraded,
    };
    let code = match overall {
        OkOrDegraded::Ok => StatusCode::OK,
        OkOrDegraded::Degraded => StatusCode::SERVICE_UNAVAILABLE,
    };
    let body = ReadyResponse {
        status: overall,
        version: env!("CARGO_PKG_VERSION"),
        checks: ReadyChecks {
            database,
            signing_key,
            label_stream,
        },
    };
    (code, Json(body)).into_response()
}

// ----- Individual checks -----

async fn check_database(pool: &Pool<Sqlite>) -> OkOrFailed {
    match sqlx::query("SELECT 1").execute(pool).await {
        Ok(_) => OkOrFailed::Ok,
        Err(_) => OkOrFailed::Failed,
    }
}

async fn check_signing_key(pool: &Pool<Sqlite>) -> OkOrFailed {
    match sqlx::query_scalar!("SELECT COUNT(*) FROM signing_keys WHERE valid_to IS NULL")
        .fetch_one(pool)
        .await
    {
        Ok(n) if n > 0 => OkOrFailed::Ok,
        _ => OkOrFailed::Failed,
    }
}

async fn check_label_stream(
    pool: &Pool<Sqlite>,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) -> OkOrDegraded {
    if *shutdown_rx.borrow() {
        return OkOrDegraded::Degraded;
    }
    let row = sqlx::query_scalar!("SELECT last_heartbeat FROM server_instance_lease WHERE id = 1")
        .fetch_optional(pool)
        .await;
    match row {
        Ok(Some(hb)) => {
            let age_ms = (epoch_ms_now() - hb).max(0);
            if age_ms < LEASE_STALE_MS {
                OkOrDegraded::Ok
            } else {
                OkOrDegraded::Degraded
            }
        }
        _ => OkOrDegraded::Degraded,
    }
}
