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
    admin_router, create_report_router, did_document_router, health_router, public_router, storage,
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
/// `DRAIN_TIMEOUT`). After HTTP drains — or the timeout fires —
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
    // Resolve the v1.4 moderation surface (#47 / #48) before
    // handing it to the writer task. Both resolvers honor operator
    // overrides + per-field defaults; ship-defaults if the
    // [moderation_reasons] / [strike_policy] sections are absent.
    let reason_vocabulary = crate::moderation::reasons::ReasonVocabulary::from_config(&config)
        .map_err(|e| CliError::Startup(format!("moderation reasons: {e}")))?;
    let strike_policy = crate::moderation::policy::StrikePolicy::from_config(&config)
        .map_err(|e| CliError::Startup(format!("strike policy: {e}")))?;
    let label_emission_policy = crate::labels::policy::LabelEmissionPolicy::from_config(&config)
        .map_err(|e| CliError::Startup(format!("label emission policy: {e}")))?;
    let policy_automation_policy =
        crate::policy::automation::PolicyAutomationPolicy::from_config(&config)
            .map_err(|e| CliError::Startup(format!("policy automation: {e}")))?;
    // §F22 #71's cross-block check: every rule's reason_codes
    // must exist in [moderation_reasons]. Config::validate already
    // ran this once at config load, but repeat here in case the
    // process was constructed via a different path (test
    // embedders, future hot-reload).
    policy_automation_policy
        .validate_reason_codes_against(&reason_vocabulary)
        .map_err(|e| CliError::Startup(format!("policy automation: {e}")))?;

    // §F23 / #87. Resolve the [pds_admin] policy and, if
    // enabled, instantiate the configured backend. v1.7 ships
    // only OzoneBackend (bsky-PDS); v1.8 will add LocusBackend
    // selection here. When disabled (or [pds_admin] omitted
    // entirely), the bridge is None and the writer's
    // post-recordAction dispatch is a no-op.
    let pds_admin_policy = crate::pds_admin::PdsAdminPolicy::from_config(&config)
        .map_err(|e| CliError::Startup(format!("pds_admin: {e}")))?;
    let pds_admin_bridge = build_pds_admin_bridge(&pds_admin_policy)?;

    // §F23 / §A15 / #90 — startup probe. Runs once before the
    // writer task spawns so an obviously-misconfigured pds_url or
    // admin password surfaces at boot rather than on the first
    // moderation action. Failure does NOT block startup (per
    // §A15): the operator-facing log line is the entire interface,
    // and the first real call retries naturally. Skipped when no
    // bridge was constructed.
    if let Some(bridge) = pds_admin_bridge.as_ref() {
        run_pds_admin_startup_probe(bridge).await;
    }

    // v1.8.8: realtime stream consumer (v2 §5, chainlink #147).
    // Spawned only when the operator set
    // [pds_admin.rust.stream].enabled = true; the OperatorOptIn
    // capability + pin gate is additionally enforced per
    // connection attempt inside subscribe_mod_events (an
    // unpinned/unadvertised family parks the consumer dormant,
    // re-evaluated with backoff). HardStop (auth/role rejection
    // at upgrade) ends the task; a process restart is the v1.8.8
    // clear mechanism.
    if let Some(bridge) = pds_admin_bridge.as_ref()
        && let Some(crate::pds_admin::PdsAdminBackendConfig::Rust(rust_cfg)) =
            bridge.policy.backend.as_ref()
        && rust_cfg.stream.enabled
    {
        let status = Arc::new(crate::pds_admin::rust::stream::StreamStatus::default());
        let consumer = crate::pds_admin::rust::stream::StreamConsumer::new(
            bridge.backend.clone(),
            pool.clone(),
            rust_cfg.stream.clone(),
            status,
        );
        tokio::spawn(consumer.run());
        tracing::info!(
            include_audit_chain = rust_cfg.stream.include_audit_chain,
            "pds_admin: realtime stream consumer spawned (subscribeModEvents)"
        );
    }

    // v1.8.13: capture the backend for the create-report router before
    // `pds_admin_bridge` is moved into the writer spawn below.
    let create_report_backend = pds_admin_bridge.as_ref().map(|b| b.backend.clone());

    let writer = crate::writer::spawn_with_pds_admin(
        pool.clone(),
        key,
        config.service_did.clone(),
        crate::SubscribeConfig::default().retention_days,
        config.retention.clone().into(),
        reason_vocabulary,
        strike_policy.clone(),
        label_emission_policy,
        policy_automation_policy,
        pds_admin_bridge,
    )
    .await
    .map_err(map_spawn_writer_error)?;

    // Step 3.5: §F1 startup verify (#8). Compare local [labeler]
    // config against the published `app.bsky.labeler.service`
    // record on the operator's PDS. Drift / absent / unreachable
    // each fail-start with a distinct exit code so orchestrators
    // (and operators) can branch.
    //
    // Placed AFTER spawn_writer so we benefit from the
    // single-instance lease (no point verifying for a server that
    // can't run anyway) and BEFORE bind so a drifting labeler
    // doesn't accept traffic. Failure releases the lease via
    // writer.shutdown() before returning the error.
    if let Err(verify_err) = verify::verify_service_record(&config).await {
        if let Err(e) = writer.shutdown().await {
            tracing::warn!(error = %e, "writer shutdown failed during verify-induced exit");
        }
        return Err(verify_err);
    }

    // Step 4: auth context (DID resolver + JWT replay cache, #11).
    // No network IO at construction — only when a request arrives.
    //
    // The DID resolver is constructed explicitly so it can be
    // shared between AuthContext (outbound + admin-XRPC, #11) and
    // XrpcAuthService (inbound xrpc_gateway, #93). Sharing the
    // resolver gives both layers the same SSRF filter and the
    // same `did:web:` resolution behavior; #93's prompt locked
    // this decision (architecture call A8 / "DID resolver: extend
    // existing resolver if needed; do not fork").
    let auth_config = AuthConfig {
        service_did: config.service_did.clone(),
        ..AuthConfig::default()
    };
    let did_resolver: Arc<dyn crate::auth::did::DidResolver> =
        Arc::new(crate::auth::did::HttpDidResolver::new(
            auth_config.plc_directory_url.clone(),
            auth_config.resolver_timeout,
        ));
    let auth = Arc::new(AuthContext::with_resolver(
        auth_config,
        did_resolver.clone(),
    ));

    // Step 5: compose the full router. Each per-feature constructor
    // owns its own Extension state; `.merge` layers them side-by-side.
    // Order is cosmetic — axum matches by route, not by merge order.
    // Compose AdminConfig from multiple Config sources. The
    // [admin].label_values allowlist comes from AdminConfigToml's
    // From impl; the trust-chain identity surface
    // (service_did / service_endpoint / declared_label_values)
    // lives elsewhere in Config and is set explicitly here so the
    // From impl stays narrow.
    let admin_cfg = {
        let mut c: crate::AdminConfig = config.admin.clone().into();
        c.service_did = config.service_did.clone();
        c.service_endpoint = config.service_endpoint.clone();
        c.declared_label_values = config.labeler.as_ref().map(|l| l.label_values.clone());
        c
    };
    let mut router = admin_router(
        pool.clone(),
        writer.clone(),
        auth.clone(),
        admin_cfg,
        strike_policy.clone(),
    )
    .merge(create_report_router(
        pool.clone(),
        auth.clone(),
        crate::CreateReportConfig {
            db_path: config.db_path.clone(),
            ..crate::CreateReportConfig::default()
        },
        // v1.8.13: the Rust-PDS backend (if configured) so a private
        // kryphocron report can be decoded at ingest.
        create_report_backend,
    ))
    .merge(subscribe_router(
        pool.clone(),
        writer.clone(),
        crate::SubscribeConfig::default(),
    ))
    .merge(public_router(
        pool.clone(),
        auth.clone(),
        strike_policy.clone(),
        config.service_did.clone(),
    ))
    .merge(wellknown_router())
    .merge(did_document_router(pool.clone(), config.clone()))
    .merge(health_router(pool.clone(), writer.clone()));

    // §F23 inbound surface / #91-#93. Mount the inbound XRPC
    // gateway when [xrpc_gateway].enabled = true. Disabled-by-
    // default so operators upgrading from v1.6 see no new
    // behavior. Auth verification (#93) is wired via tower
    // middleware on the gateway router; replay cache (#94) and
    // per-NSID handler bodies (#95-#98) land in subsequent
    // issues.
    if let Some(gateway_cfg) = crate::xrpc_gateway::XrpcGatewayConfig::from_config(&config)
        .map_err(|e| CliError::Startup(format!("xrpc_gateway: {e}")))?
    {
        let xrpc_auth = Arc::new(crate::xrpc_gateway::XrpcAuthService::new(
            gateway_cfg.clone(),
            did_resolver.clone(),
        ));
        let xrpc_replay_cache = Arc::new(crate::xrpc_gateway::XrpcReplayCache::new(
            gateway_cfg.replay_cache_ttl,
        ));
        tracing::info!(
            service_did = %gateway_cfg.service_did,
            clock_skew_tolerance_seconds = gateway_cfg.clock_skew_tolerance.as_secs(),
            replay_cache_ttl_seconds = gateway_cfg.replay_cache_ttl.as_secs(),
            "xrpc_gateway enabled: routes mounted at /xrpc/* (auth + membership + replay all wired; handler bodies pending #95-#98)"
        );
        let xrpc_handler_state = crate::xrpc_gateway::XrpcGatewayState {
            writer: writer.clone(),
            pool: pool.clone(),
            service_did: gateway_cfg.service_did.clone(),
        };
        router = router.merge(crate::xrpc_gateway::build_router(
            gateway_cfg,
            xrpc_auth,
            pool.clone(),
            xrpc_replay_cache,
            xrpc_handler_state,
        ));
    }

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

    // Step 7: serve until `shutdown` resolves, then bound the drain
    // phase to DRAIN_TIMEOUT. `with_graceful_shutdown` stops accepting
    // new connections when the future completes; in-flight handlers
    // drain until the listener's internal state says they're done.
    // The drain timer starts only after shutdown has actually been
    // observed — wrapping the whole serve future in a timeout (the
    // earlier implementation) made the server spontaneously exit
    // after 30s regardless of whether any signal had fired (#19).
    let (drain_start_tx, drain_start_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_wrapper = async move {
        shutdown.await;
        // Forward the shutdown edge to the drain timer. A send failure
        // means the receiver has been dropped (server exiting another
        // way) — fine, drain_timer is no longer relevant.
        let _ = drain_start_tx.send(());
    };

    let serve_fut = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_wrapper);

    // Drain timer: parked on the oneshot until shutdown fires, then
    // sleeps DRAIN_TIMEOUT. If `serve_fut` resolves first (clean drain)
    // the sender is dropped, the oneshot resolves Err, and this future
    // pends forever so the other select arm always wins.
    let drain_timer = async move {
        match drain_start_rx.await {
            Ok(()) => tokio::time::sleep(DRAIN_TIMEOUT).await,
            Err(_) => std::future::pending::<()>().await,
        }
    };

    enum Outcome {
        Clean,
        AxumError(std::io::Error),
        DrainTimeout,
    }

    let outcome = tokio::select! {
        res = serve_fut => match res {
            Ok(()) => Outcome::Clean,
            Err(e) => Outcome::AxumError(e),
        },
        _ = drain_timer => Outcome::DrainTimeout,
    };

    // Step 8: shut the Writer down regardless of HTTP outcome so the
    // lease is released. A lingering lease is a deployment bug
    // (operator has to wait LEASE_STALE_MS or delete the row by hand)
    // — the clean path should always release.
    if let Err(e) = writer.shutdown().await {
        tracing::warn!(error = %e, "writer shutdown failed during serve exit");
    }

    match outcome {
        Outcome::Clean => Ok(()),
        Outcome::AxumError(e) => Err(CliError::Startup(format!("axum serve error: {e}"))),
        Outcome::DrainTimeout => {
            tracing::warn!(
                drain_timeout_secs = DRAIN_TIMEOUT.as_secs(),
                "drain timeout exceeded after shutdown signal; forcing exit"
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

/// Construct the §F23 PDS-admin bridge from the resolved policy.
///
/// `Ok(None)` when the bridge is disabled (operator omitted
/// `[pds_admin]` entirely, or set `enabled = false`). `Ok(Some)`
/// when the policy resolves a backend successfully. `Err` when
/// the backend constructor fails (almost always a transient
/// reqwest TLS-config issue; treated as a startup failure since
/// the operator declared the bridge enabled).
///
/// v1.7 has only the [`Ozone`](crate::pds_admin::PdsAdminBackendConfig::Ozone)
/// variant; v1.8 will add `Locus` selection here.
fn build_pds_admin_bridge(
    policy: &crate::pds_admin::PdsAdminPolicy,
) -> Result<Option<crate::pds_admin::PdsAdminBridge>, CliError> {
    if !policy.enabled {
        return Ok(None);
    }
    let backend_config = policy.backend.as_ref().ok_or_else(|| {
        // Defensive: #83's resolver guarantees `backend` is
        // Some(_) when enabled. Reaching this means a future
        // resolver change broke the invariant.
        CliError::Startup(
            "pds_admin: enabled but no backend resolved (config-resolver invariant violated)"
                .into(),
        )
    })?;
    let backend: Arc<dyn crate::pds_admin::PdsAdminBackend> = match backend_config {
        crate::pds_admin::PdsAdminBackendConfig::Ozone(ozone_cfg) => {
            let backend = crate::pds_admin::OzoneBackend::new(ozone_cfg)
                .map_err(|e| CliError::Startup(format!("pds_admin ozone backend: {e}")))?;
            tracing::info!(
                pds_url = %ozone_cfg.pds_url,
                "pds_admin: Ozone backend (bsky-PDS) initialized"
            );
            Arc::new(backend)
        }
        crate::pds_admin::PdsAdminBackendConfig::Rust(rust_cfg) => {
            // v1.8.1: real construction. Boot requires all three
            // gates to have passed: validated_rust_from_toml (config
            // resolution), validate_audit_divergence_acknowledgment
            // (inspector-only posture), and RustBackend::new (key
            // load + DID checks) here.
            let backend = crate::pds_admin::RustBackend::new(rust_cfg)
                .map_err(|e| CliError::Startup(format!("pds_admin rust backend: {e}")))?;
            let backend = Arc::new(backend);
            // Background capability refresh (§5.2): holds only a
            // Weak, so the task exits when the bridge drops.
            crate::pds_admin::RustBackend::spawn_capability_refresh(
                &backend,
                rust_cfg.capability_refresh_interval,
            );
            tracing::info!(
                pds_url = %rust_cfg.pds_url,
                "pds_admin: Rust backend (inspector-only in v1.8.1) initialized"
            );
            backend
        }
    };
    Ok(Some(crate::pds_admin::PdsAdminBridge {
        policy: policy.clone(),
        backend,
    }))
}

/// Run the §A15 / #90 startup probe against the configured
/// PDS-admin backend.
///
/// Logs once at INFO on success and once at WARN/ERROR on
/// failure — that line is the entire operator interface for
/// the probe. Returns `()`: per §A15, probe failure does NOT
/// block startup (the first real call retries; transient
/// network blips at boot shouldn't gate `cairn serve` from
/// coming up).
///
/// Severity selection mirrors the recordAction-dispatch
/// convention from `crate::pds_admin::dispatch::log_call_outcome`:
/// `Transient` (including its rate-limited sub-classification) →
/// WARN; everything operator-actionable
/// (`Auth` / `Validation` / `Terminal` / `Unsupported` /
/// `ArchitecturallyForbidden` / `CapabilityNotAdvertised`) →
/// ERROR.
async fn run_pds_admin_startup_probe(bridge: &crate::pds_admin::PdsAdminBridge) {
    use crate::pds_admin::BackendError;
    let result = bridge.backend.probe().await;
    match result {
        Ok(report) => {
            tracing::info!(
                backend = report.backend_name,
                pds_url = %report.pds_url,
                detected_version = ?report.detected_version,
                capabilities = ?report.capabilities,
                "pds_admin probe successful"
            );
        }
        Err(ref e) => {
            let category = e.variant_name();
            let message = e.message();
            let retry_after_seconds = e.retry_after_seconds();
            let error_code = e.error_code();
            match e {
                BackendError::Transient(_) => tracing::warn!(
                    error_category = category,
                    retry_after_seconds = ?retry_after_seconds,
                    error_code = ?error_code,
                    error = %message,
                    "pds_admin probe failed transiently; cairn-mod will continue starting (first real call will retry)"
                ),
                _ => tracing::error!(
                    error_category = category,
                    error_code = ?error_code,
                    error = %message,
                    "pds_admin probe failed: operator-actionable misconfiguration. \
                     cairn-mod will continue starting; first real call will retry, \
                     but moderation actions will fail until the underlying issue is fixed."
                ),
            }
        }
    }
}

/// §F1 startup verify (#8). Inline `mod verify` to keep the
/// scope local to `serve.rs` per the session decision; extract
/// to a free-standing module if the surface grows past ~80
/// lines.
mod verify {
    use crate::cli::error::CliError;
    use crate::cli::pds::{PdsClient, PdsError};
    use crate::config::Config;
    use crate::service_record::{self, RECORD_COLLECTION, RECORD_RKEY};
    use serde_json::Value;

    /// Verify that the local `[labeler]` config renders to the same
    /// content-hash as the `app.bsky.labeler.service` record
    /// currently published on the operator's PDS.
    ///
    /// Returns Ok(()) on a match (also logs an info-level success
    /// line). Returns one of three [`CliError`] variants on
    /// failure:
    ///
    /// - `ServiceRecordDrift`        — record exists but differs
    /// - `ServiceRecordAbsent`       — record not found on PDS
    /// - `ServiceRecordUnreachable`  — transport failure during fetch
    ///
    /// Local-render failures (`service_record::render` returning
    /// `Err(RenderError)`) surface as `CliError::Config` per the
    /// session D2 fail-closed decision: those signal a malformed
    /// `[labeler]` block, distinct from PDS-comparison failures.
    pub(super) async fn verify_service_record(config: &Config) -> Result<(), CliError> {
        // Labeler-absent → no §F1 service record applies → verify
        // is a no-op. This intentionally narrows the verify gate
        // to deployments that have declared a labeler. Configs
        // without a [labeler] block are running some other
        // workflow (test harness, custom embedder); refusing to
        // start would be heavy-handed for a feature that doesn't
        // apply. NOT a general opt-out — operator-facing
        // deployments that publish a labeler always have
        // [labeler] set.
        let Some(labeler_cfg) = config.labeler.as_ref() else {
            tracing::info!(
                "no [labeler] config block — skipping service record verify (#8 narrow scope)"
            );
            return Ok(());
        };
        // [labeler] without [operator] is a real misconfig: the
        // operator declared a labeler but didn't tell us where to
        // verify against. Fail-closed per session D2.
        let operator_cfg = config.operator.as_ref().ok_or_else(|| {
            CliError::Config(
                "[labeler] is configured but [operator] is missing — verify needs operator.pds_url"
                    .into(),
            )
        })?;

        // Render the local record with a sentinel createdAt — the
        // value is irrelevant since content_hash strips it.
        let local_record = service_record::render(labeler_cfg, "1970-01-01T00:00:00.000Z")
            .map_err(|e| CliError::Config(format!("could not render local service record: {e}")))?;
        let local_hash = service_record::content_hash(&local_record);

        let pds = PdsClient::new(&operator_cfg.pds_url).map_err(|e| {
            CliError::ServiceRecordUnreachable {
                pds_url: operator_cfg.pds_url.clone(),
                cause: e.to_string(),
            }
        })?;
        let fetched = match pds
            .get_record(&config.service_did, RECORD_COLLECTION, RECORD_RKEY)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => {
                return Err(CliError::ServiceRecordAbsent {
                    pds_url: operator_cfg.pds_url.clone(),
                    service_did: config.service_did.clone(),
                });
            }
            Err(PdsError::Network { source, .. }) => {
                return Err(CliError::ServiceRecordUnreachable {
                    pds_url: operator_cfg.pds_url.clone(),
                    cause: source.to_string(),
                });
            }
            Err(other) => {
                return Err(CliError::ServiceRecordUnreachable {
                    pds_url: operator_cfg.pds_url.clone(),
                    cause: other.to_string(),
                });
            }
        };

        let pds_hash = service_record::content_hash_value(fetched.value.clone());
        if local_hash == pds_hash {
            tracing::info!(
                cid = ?fetched.cid,
                "service record verified: local config matches PDS"
            );
            return Ok(());
        }

        // Drift: build a per-field human-readable summary so the
        // operator-facing error message names exactly what differs
        // without dumping raw JSON.
        let summary = drift_summary(&local_record, &fetched.value);
        tracing::error!(
            pds_url = %operator_cfg.pds_url,
            "service record drift detected — see error for details"
        );
        Err(CliError::ServiceRecordDrift {
            pds_url: operator_cfg.pds_url.clone(),
            service_did: config.service_did.clone(),
            summary,
        })
    }

    /// Build the drift summary block. Compares the four
    /// comparison-relevant fields of an
    /// `app.bsky.labeler.service` record (label values,
    /// definition count, reason types, subject types) and
    /// surfaces only the ones that differ. Inputs:
    ///
    /// - `local`  — the rendered local `ServiceRecord`
    /// - `pds`    — the PDS-returned record body, opaque
    ///   `serde_json::Value`. We read scalar fields out of the
    ///   Value rather than deserializing into `ServiceRecord`
    ///   to avoid the `&'static str` problem on the struct.
    fn drift_summary(local: &service_record::ServiceRecord, pds: &Value) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        let local_lv = &local.policies.label_values;
        let pds_lv = pds_label_values(pds);
        if local_lv != &pds_lv {
            let _ = writeln!(out, "  - label values:");
            let _ = writeln!(out, "      local:     {local_lv:?}");
            let _ = writeln!(out, "      published: {pds_lv:?}");
        }

        let local_defs = local.policies.label_value_definitions.len();
        let pds_defs = pds_definition_count(pds);
        if local_defs != pds_defs {
            let _ = writeln!(out, "  - label value definitions:");
            let _ = writeln!(out, "      local:     {local_defs} entries");
            let _ = writeln!(out, "      published: {pds_defs} entries");
        }

        let local_rt = &local.reason_types;
        let pds_rt = pds_string_array(pds, "reasonTypes");
        if local_rt != &pds_rt {
            let _ = writeln!(out, "  - reason types:");
            let _ = writeln!(out, "      local:     {local_rt:?}");
            let _ = writeln!(out, "      published: {pds_rt:?}");
        }

        let local_st = &local.subject_types;
        let pds_st = pds_string_array(pds, "subjectTypes");
        if local_st != &pds_st {
            let _ = writeln!(out, "  - subject types:");
            let _ = writeln!(out, "      local:     {local_st:?}");
            let _ = writeln!(out, "      published: {pds_st:?}");
        }

        // The hashes are unequal but our four-field comparison
        // didn't surface anything. That's a definition-content
        // drift (severity / blurs / locales drift inside a
        // definition with the same identifier set). Name it
        // explicitly so the operator knows what to look at.
        if out.is_empty() {
            out.push_str(
                "  - per-label definition contents (severity / blurs / locales) differ; \
                 inspect the published record alongside the local config to identify which.\n",
            );
        }

        // Trim trailing newline; the `#[error("...")]` template
        // already includes one.
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }

    fn pds_label_values(v: &Value) -> Vec<String> {
        v.get("policies")
            .and_then(|p| p.get("labelValues"))
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn pds_definition_count(v: &Value) -> usize {
        v.get("policies")
            .and_then(|p| p.get("labelValueDefinitions"))
            .and_then(|x| x.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    }

    fn pds_string_array(v: &Value, key: &str) -> Vec<String> {
        v.get(key)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::{
            BlursToml, LabelValueDefinitionToml, LabelerConfigToml, LocaleToml, SeverityToml,
        };

        fn sample_cfg() -> LabelerConfigToml {
            LabelerConfigToml {
                label_values: vec!["spam".into()],
                label_value_definitions: vec![LabelValueDefinitionToml {
                    identifier: "spam".into(),
                    severity: SeverityToml::Alert,
                    blurs: BlursToml::None,
                    default_setting: None,
                    adult_only: None,
                    locales: vec![LocaleToml {
                        lang: "en".into(),
                        name: "Spam".into(),
                        description: "x".into(),
                    }],
                }],
                reason_types: vec![],
                subject_types: vec!["account".into()],
                subject_collections: vec![],
            }
        }

        #[test]
        fn drift_summary_label_values_differ() {
            let local = service_record::render(&sample_cfg(), "1970-01-01T00:00:00.000Z").unwrap();
            let pds_value = serde_json::json!({
                "policies": { "labelValues": ["other"] },
            });
            let s = drift_summary(&local, &pds_value);
            assert!(s.contains("label values"));
            assert!(s.contains("\"spam\""));
            assert!(s.contains("\"other\""));
            assert!(!s.contains("reason types"), "no drift on reasonTypes here");
        }

        #[test]
        fn drift_summary_definition_count_differs() {
            let local = service_record::render(&sample_cfg(), "1970-01-01T00:00:00.000Z").unwrap();
            let pds_value = serde_json::json!({
                "policies": {
                    "labelValues": ["spam"],
                    "labelValueDefinitions": [],
                },
                "subjectTypes": ["account"],
            });
            let s = drift_summary(&local, &pds_value);
            assert!(s.contains("label value definitions"));
            assert!(s.contains("local:     1 entries"));
            assert!(s.contains("published: 0 entries"));
        }

        #[test]
        fn drift_summary_falls_back_when_no_top_level_field_differs() {
            let local = service_record::render(&sample_cfg(), "1970-01-01T00:00:00.000Z").unwrap();
            // Same top-level shape; only inner definition contents
            // differ — the four scalar comparisons don't catch it.
            let pds_value = serde_json::json!({
                "policies": {
                    "labelValues": ["spam"],
                    "labelValueDefinitions": [{
                        "identifier": "spam",
                        "severity": "inform",
                        "blurs": "content",
                        "locales": [{ "lang": "fr", "name": "Spam", "description": "y" }],
                    }],
                },
                "subjectTypes": ["account"],
            });
            let s = drift_summary(&local, &pds_value);
            assert!(
                s.contains("per-label definition contents"),
                "fallback message expected; got: {s}"
            );
        }
    }
}
