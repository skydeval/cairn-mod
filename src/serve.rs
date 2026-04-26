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
    admin_router, create_report_router, did_document_router, health_router, spawn_writer, storage,
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
    let writer = spawn_writer(
        pool.clone(),
        key,
        config.service_did.clone(),
        crate::SubscribeConfig::default().retention_days,
        config.retention.clone().into(),
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
    let auth = Arc::new(AuthContext::new(AuthConfig {
        service_did: config.service_did.clone(),
        ..AuthConfig::default()
    }));

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
    let router = admin_router(pool.clone(), writer.clone(), auth.clone(), admin_cfg)
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
        .merge(did_document_router(pool.clone(), config.clone()))
        .merge(health_router(pool.clone(), writer.clone()));

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
