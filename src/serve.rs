//! `cairn serve` lifecycle — the long-running-process entry point (L4).
//!
//! Composes every per-feature router built in earlier issues (#13/#14/
//! #15/#17 admin + createReport, #6/#7 public, #18 lexicons, L3
//! did.json) into a single axum Router, fronted by the Writer task from
//! #4. Signal handling + bounded-drain graceful shutdown run here too.
//!
//! The [`run`] function is a library entry point so tests can drive it
//! without spawning a subprocess. `main.rs` wraps this with signal
//! acquisition and exit-code mapping.
//!
//! # Startup sequence — ordering is load-bearing
//!
//! The numbered comments inside [`run`] are the durable invariant. In
//! particular: **the Writer task (which bootstraps the signing_keys
//! row via #4's `ensure_signing_key_row`) MUST complete spawn before
//! the HTTP listener binds.** Otherwise `/.well-known/did.json` (L3)
//! returns 503 ServiceUnavailable for the brief window between bind
//! and writer-ready. Reorder at your peril; the
//! `happy_startup_releases_lease_on_shutdown` test would catch a
//! functional break, but reviewers catching the ordering at code time
//! is cheaper than debugging a flaky 503.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use crate::auth::{AuthConfig, AuthContext};
use crate::cli::error::CliError;
use crate::config::Config;
use crate::error::Error;
use crate::signing_key::SigningKey;
use crate::{
    admin_router, create_report_router, did_document_router, spawn_writer, storage,
    subscribe_router, wellknown_router,
};

/// How long we give in-flight handlers to drain after the shutdown
/// signal fires. After this, the server aborts; Writer shutdown
/// still runs so the single-instance lease is released.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Run the Cairn server until `shutdown` resolves.
///
/// `shutdown` is typically a `tokio::signal::ctrl_c()` / SIGTERM
/// future in production and a `oneshot::Receiver` in tests. On
/// resolution the HTTP listener stops accepting new connections and
/// axum's `with_graceful_shutdown` drains active requests (bounded by
/// [`DRAIN_TIMEOUT`]). After HTTP drains — or the timeout fires —
/// the Writer task is shut down explicitly so the
/// `server_instance_lease` row is released for the next start.
pub async fn run<F>(config: Config, shutdown: F) -> Result<(), CliError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // Validate the config at the entry point. `Config::load`
    // validates too, but tests and embedders can construct a
    // `Config` directly via deserialization; re-running validate is
    // cheap and prevents "hold a misconfigured server open" bugs.
    config
        .validate()
        .map_err(|e| CliError::Config(e.to_string()))?;

    // Step 1: load the signing key from disk. Before anything that
    // opens a port — a §5.1 permission failure here must not race
    // with a listener accepting traffic.
    let key = SigningKey::load_from_file(&config.signing_key_path)?;

    // Step 2: open the SQLite pool. Creates the file + runs embedded
    // migrations (§F5 WAL mode, 5s busy_timeout).
    let pool = storage::open(&config.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))?;

    // Step 3: spawn the Writer task. This ALSO acquires the
    // single-instance lease (§F5) and bootstraps the signing_keys
    // row (#4's `ensure_signing_key_row`). Both completions are
    // prerequisites for serving /.well-known/did.json (L3); the
    // Writer's lease also gates the whole write path, so if two
    // `cairn serve` start simultaneously the loser exits here with
    // `LeaseConflict`.
    let writer = spawn_writer(pool.clone(), key, config.service_did.clone())
        .await
        .map_err(map_spawn_writer_error)?;

    // Step 4: auth context (DID resolver + JWT replay cache, #11).
    // No network IO at construction — only when a request arrives.
    let auth = Arc::new(AuthContext::new(AuthConfig {
        service_did: config.service_did.clone(),
        ..AuthConfig::default()
    }));

    // Step 5: compose the full router. Each per-feature constructor
    // owns its own Extension state; `.merge` layers them side-by-side.
    // Order is cosmetic — axum matches by route, not by merge order.
    let router = admin_router(
        pool.clone(),
        writer.clone(),
        auth.clone(),
        config.admin.clone().into(),
    )
    .merge(create_report_router(
        pool.clone(),
        auth.clone(),
        crate::CreateReportConfig {
            db_path: config.db_path.clone(),
            ..crate::CreateReportConfig::default()
        },
    ))
    .merge(subscribe_router(
        pool.clone(),
        writer.clone(),
        crate::SubscribeConfig::default(),
    ))
    .merge(wellknown_router())
    .merge(did_document_router(pool.clone(), config.clone()));

    // Step 6: bind the HTTP listener. MUST come after step 3 — see
    // the module-level note on the L3 ordering invariant.
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .map_err(|source| CliError::BindFailed {
            addr: config.bind_addr,
            source,
        })?;
    // Re-read the bound addr in case the config asked for port 0
    // (ephemeral) — tests rely on this for fixture wiring.
    let local_addr = listener.local_addr().unwrap_or(config.bind_addr);

    tracing::info!(
        bind_addr = %local_addr,
        service_did = %config.service_did,
        "cairn listening; lease acquired"
    );

    // Step 7: serve until `shutdown` resolves. `with_graceful_shutdown`
    // stops accepting new connections when the future completes; in-
    // flight handlers drain until the listener's internal state says
    // they're done. We wrap the whole thing in a DRAIN_TIMEOUT so a
    // misbehaving handler can't keep the process alive indefinitely.
    let serve_fut = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown);

    let serve_outcome = tokio::time::timeout(DRAIN_TIMEOUT, serve_fut).await;

    // Step 8: shut the Writer down regardless of HTTP outcome so the
    // lease is released. A lingering lease is a deployment bug
    // (operator has to wait LEASE_STALE_MS or delete the row by hand)
    // — the clean path should always release.
    if let Err(e) = writer.shutdown().await {
        tracing::warn!(error = %e, "writer shutdown failed during serve exit");
    }

    match serve_outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(CliError::Startup(format!("axum serve error: {e}"))),
        Err(_elapsed) => {
            tracing::warn!(
                drain_timeout_secs = DRAIN_TIMEOUT.as_secs(),
                "HTTP drain timeout exceeded; forcing exit"
            );
            Ok(())
        }
    }
}

/// Translate the Writer's startup errors into CliError variants.
/// The lease-conflict case is its own exit code (§F5 single-instance
/// invariant); everything else maps to a generic startup failure.
fn map_spawn_writer_error(e: Error) -> CliError {
    match e {
        Error::LeaseHeld {
            instance_id,
            age_secs,
        } => CliError::LeaseConflict {
            instance_id,
            age_secs,
        },
        other => CliError::Startup(format!("writer spawn: {other}")),
    }
}
