//! Rust-PDS backend (Aurora-Locus and other ATProto Rust PDSes) —
//! v1.8.1 foundation skeleton (§4.1).
//!
//! v1.8.1 posture: **inspector-only**. The only successful
//! Aurora-side call is the `describeCapabilities` probe; every
//! other trait method returns
//! [`BackendError::CapabilityNotAdvertised`] (account actions) or
//! [`BackendError::ArchitecturallyForbidden`] (label methods, per
//! the §F4 invariant — same posture as `OzoneBackend`). v1.8.2's
//! protocol-parity release wires real `emitEvent`-mapped behavior
//! into the account-action methods.
//!
//! Auth is per-call ES256K service-auth JWT ([`service_auth`]) —
//! no OAuth, no session, no token cache (umbrella §5.1). The
//! operator provisions cairn-mod's DID doc and Aurora-side
//! `admin_roles` grant out-of-band (§5.1 of the v1.8.1 doc).

pub mod action_types;
pub mod audit_types;
pub mod batch_types;
mod emit_event;
pub mod read_types;
pub mod service_auth;
pub mod stream_ingest;
pub mod stream_types;
pub mod upstream_verify;

use action_types::{ActionResponse, AppealDecision, BlobSubject, ReportResolution, SubjectStatus};
use audit_types::{AuditEntryLookup, AuditTrailFilter, AuditTrailPage, AuroraAuditEntry};
use emit_event::{EmitEventAction, EmitEventDispatch, EmitEventSubject};
use read_types::{
    AppealDetail, AppealView, EventWithContext, ListAppealsFilter, PaginatedResponse,
    QueryEventsFilter, QueryStatusesFilter, StatusWithContext, SubjectContextResponse,
    SubjectHistoryFilter,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use k256::ecdsa::SigningKey;
use url::Url;

use super::backend::{
    BackendActionId, BackendError, BackendInitError, LABEL_BRIDGE_INVARIANT_REASON,
    PdsAdminBackend, ProbeReport,
};
use super::config::RustBackendConfig;
use super::ozone::{OzoneBackend, decode_xrpc_error_envelope, parse_retry_after_seconds};
use super::types::{
    CapabilityClassification, CapabilitySet, CapabilityVersion, DescribeCapabilitiesResponse,
    Subject, classification_for, parse_capability_string,
};
use service_auth::{mint_service_auth_jwt, validate_did_syntax};

/// NSID of the capability probe endpoint. The probe NSID itself is
/// deliberately NOT a capability family (see the doctrine comment
/// on [`super::types::CAPABILITY_CLASSIFICATIONS`]); it's the transport for
/// capability negotiation.
const DESCRIBE_CAPABILITIES_NSID: &str = "tools.aurora.describeCapabilities";

/// NSID of the unified moderation-action endpoint (v1.8.2, §4.3).
const EMIT_EVENT_NSID: &str = "tools.aurora.admin.emitEvent";

/// Capability family gating the emitEvent-mapped action verbs
/// (suffix-less; registered in `CAPABILITY_CLASSIFICATIONS`).
const EMIT_EVENT_FAMILY: &str = "mod-events-emit";

/// Wire string embedded in `CapabilityNotAdvertised` returns when
/// the target PDS doesn't advertise the emitEvent family.
const ACCOUNT_ACTION_CAPABILITY: &str = "mod-events-emit-v1";

/// NSIDs of the moderator-read endpoints (v1.8.3, §4.4).
const QUERY_EVENTS_NSID: &str = "tools.aurora.moderator.queryEvents";
const QUERY_STATUSES_NSID: &str = "tools.aurora.moderator.queryStatuses";

/// Capability family gating the moderator-read endpoints —
/// `moderator-activity-v1` ships on queryEvents and is shared by
/// queryStatuses (and getEvent, unconsumed at v1.8.3) per Aurora's
/// route attribution at `admin.rs:471-491`.
const MODERATOR_ACTIVITY_FAMILY: &str = "moderator-activity";

/// Wire string embedded in `CapabilityNotAdvertised` returns for
/// the read methods.
const MODERATOR_ACTIVITY_CAPABILITY: &str = "moderator-activity-v1";

/// NSIDs + capability families of the v1.8.4 moderator-read
/// endpoints (§4.4/§4.5; attribution per Aurora `admin.rs:463-520`).
const GET_EVENT_NSID: &str = "tools.aurora.moderator.getEvent";
const GET_SUBJECT_CONTEXT_NSID: &str = "tools.aurora.moderator.getSubjectContext";
const GET_SUBJECT_HISTORY_NSID: &str = "tools.aurora.moderator.getSubjectHistory";
const LIST_APPEALS_NSID: &str = "tools.aurora.moderator.listAppeals";
const GET_APPEAL_NSID: &str = "tools.aurora.moderator.getAppeal";
const SUBJECT_CONTEXT_FAMILY: &str = "subject-context";
const SUBJECT_CONTEXT_CAPABILITY: &str = "subject-context-v1";
const SUBJECT_HISTORY_FAMILY: &str = "subject-history";
const SUBJECT_HISTORY_CAPABILITY: &str = "subject-history-v1";
const APPEALS_FAMILY: &str = "appeals";
const APPEALS_CAPABILITY: &str = "appeals-v1";

/// NSIDs + capability family of the v1.8.6 audit-trail reads
/// (admin namespace — Aurora attributes `audit-trail-v1` to
/// getAuditTrail only; cairn-mod gates both reads on the shared
/// family per v2 LB-1).
const GET_AUDIT_TRAIL_NSID: &str = "tools.aurora.admin.getAuditTrail";
const GET_AUDIT_ENTRY_NSID: &str = "tools.aurora.admin.getAuditEntry";
const AUDIT_TRAIL_FAMILY: &str = "audit-trail";
const AUDIT_TRAIL_CAPABILITY: &str = "audit-trail-v1";

/// NSIDs of the v1.8.7 dedicated batch endpoints (all POST;
/// routes at Aurora `admin.rs:544-573`). Aurora attributes
/// `batch-takedown-v1` to `batchTakedownAccounts` with the other
/// batch routes sharing the family — the shipped
/// shared-attribution pattern.
const BATCH_TAKEDOWN_ACCOUNTS_NSID: &str = "tools.aurora.admin.batchTakedownAccounts";
const BATCH_SUSPEND_ACCOUNTS_NSID: &str = "tools.aurora.admin.batchSuspendAccounts";
const BATCH_RESTORE_ACCOUNTS_NSID: &str = "tools.aurora.admin.batchRestoreAccounts";
const BATCH_TAKEDOWN_RECORDS_NSID: &str = "tools.aurora.admin.batchTakedownRecords";

/// Capability family gating all four dedicated batch methods
/// (v1.8.7 §8.1). First **OperatorOptIn** registry consumer: the
/// dispatch gate requires advertisement AND an operator
/// `pinned_versions` entry for the family — advertisement alone
/// is not consent for destructive batch surfaces.
const BATCH_TAKEDOWN_FAMILY: &str = "batch-takedown";

/// Wire string embedded in `CapabilityNotAdvertised` returns for
/// the dedicated batch methods (both the not-advertised and the
/// advertised-but-unpinned refusals).
const BATCH_TAKEDOWN_CAPABILITY: &str = "batch-takedown-v1";

/// NSID of the v1.8.8 realtime stream endpoint (WebSocket GET
/// upgrade; Aurora `admin.rs:675-684`).
const SUBSCRIBE_MOD_EVENTS_NSID: &str = "tools.aurora.admin.subscribeModEvents";

/// Capability family gating the stream (v1.8.8 §8) — the second
/// OperatorOptIn family after v1.8.7's `batch-takedown`; the gate
/// requires advertisement AND a `pinned_versions` entry.
const MOD_EVENTS_STREAM_FAMILY: &str = "mod-events-stream";

/// Wire string embedded in `CapabilityNotAdvertised` returns for
/// the stream method.
const MOD_EVENTS_STREAM_CAPABILITY: &str = "mod-events-stream-v1";

/// The Rust-PDS backend (v1.8.1 skeleton).
///
/// Holds the per-call signing identity in memory — the private key
/// is loaded from the env var named by
/// `RustBackendConfig::service_signing_key_env` at construction
/// and never touches disk afterward. Key persistence semantics are
/// the operator's env-var mechanism (systemd credential,
/// sops-encrypted file, …); cairn-mod doesn't participate.
pub struct RustBackend {
    /// HTTP client; connection pool shared across calls, built
    /// with the configured `request_timeout`.
    client: reqwest::Client,
    /// Target Rust PDS base URL.
    pds_url: Url,
    /// cairn-mod's service DID — the `iss` of every minted JWT.
    service_did: String,
    /// secp256k1 private key, in memory only.
    signing_key: SigningKey,
    /// Target PDS's service DID — the `aud` of every minted JWT.
    target_service_did: String,
    /// Last-refreshed capability advertisement. `Arc<RwLock>`
    /// because the `capability_refresh_interval` background task
    /// refreshes it while dispatch paths read it; both sides hold
    /// the lock briefly and never across an await.
    capabilities: Arc<RwLock<CapabilitySet>>,
    /// Operator-declared required capability wire strings,
    /// verified against the advertised set on every probe.
    required_capabilities: BTreeSet<String>,
    /// Operator-pinned versions per family (parsed from the
    /// validated config). No runtime consumer at v1.8.1 beyond
    /// operator-facing Debug output; version-selection consults it
    /// from v1.8.2 onward.
    pinned_versions: BTreeMap<String, CapabilityVersion>,
    /// Per-request HTTP timeout (also baked into `client`); kept
    /// for operator-facing diagnostics.
    request_timeout: Duration,
}

impl RustBackend {
    /// Construct a [`RustBackend`] from validated config (§4.1).
    ///
    /// Fallible — startup fails at boot if any step fails, per
    /// v1.7 convention:
    ///
    /// 1. Read the env var named by `service_signing_key_env` and
    ///    decode it as a **hex-encoded 32-byte secp256k1 scalar**
    ///    (64 hex chars). This matches Aurora's own raw-scalar key
    ///    handling (`SigningKey::from_slice`); PKCS8/PEM wrapping
    ///    is deliberately not required of operators.
    /// 2. Load into a [`SigningKey`].
    /// 3. Syntactically validate `service_did` and
    ///    `target_service_did` (defense-in-depth; the config
    ///    validator already checked them).
    /// 4. Build the HTTP client with `request_timeout`.
    /// 5. Initialize the capability set to empty — the first
    ///    `probe` populates it.
    ///
    /// Does NOT perform network I/O; the startup probe (§A15) is a
    /// separate call site, same as `OzoneBackend`.
    pub fn new(config: &RustBackendConfig) -> Result<Self, BackendInitError> {
        Self::new_with_key_source(config, &|name| std::env::var(name))
    }

    /// [`Self::new`] with an injectable env reader — the same
    /// test-seam convention `validated_rust_from_toml` uses so
    /// tests never need [`std::env::set_var`] (which became
    /// `unsafe` in Rust 2024).
    pub fn new_with_key_source<F>(
        config: &RustBackendConfig,
        read_env: &F,
    ) -> Result<Self, BackendInitError>
    where
        F: Fn(&str) -> Result<String, std::env::VarError>,
    {
        let env_name = &config.service_signing_key_env;
        let key_hex = read_env(env_name).map_err(|_| {
            BackendInitError::Rust(format!("env var ${env_name} is not set or is not unicode"))
        })?;
        let key_hex = key_hex.trim();
        if key_hex.is_empty() {
            return Err(BackendInitError::Rust(format!(
                "env var ${env_name} is empty (expected a hex-encoded 32-byte secp256k1 private key)"
            )));
        }
        let key_bytes = hex::decode(key_hex).map_err(|e| {
            BackendInitError::Rust(format!(
                "env var ${env_name} is not valid hex (expected a hex-encoded 32-byte secp256k1 private key): {e}"
            ))
        })?;
        let signing_key = SigningKey::from_slice(&key_bytes).map_err(|e| {
            BackendInitError::Rust(format!(
                "env var ${env_name} does not hold a valid secp256k1 private key \
                 (expected 32 bytes / 64 hex chars): {e}"
            ))
        })?;

        validate_did_syntax(&config.service_did)
            .map_err(|e| BackendInitError::Rust(format!("service_did: {e}")))?;
        validate_did_syntax(&config.target_service_did)
            .map_err(|e| BackendInitError::Rust(format!("target_service_did: {e}")))?;

        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .user_agent(concat!("cairn-mod/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| BackendInitError::HttpClient(e.to_string()))?;

        // Config validation guaranteed each pinned value parses via
        // `CapabilityVersion::parse_suffix`; re-parse defensively
        // and skip (rather than panic on) anything that doesn't.
        let pinned_versions = config
            .pinned_versions
            .iter()
            .filter_map(|(family, version)| {
                CapabilityVersion::parse_suffix(version).map(|v| (family.clone(), v))
            })
            .collect();

        Ok(Self {
            client,
            pds_url: config.pds_url.clone(),
            service_did: config.service_did.clone(),
            signing_key,
            target_service_did: config.target_service_did.clone(),
            capabilities: Arc::new(RwLock::new(CapabilitySet::empty())),
            required_capabilities: config.required_capabilities.iter().cloned().collect(),
            pinned_versions,
            request_timeout: config.request_timeout,
        })
    }

    /// Spawn the `capability_refresh_interval` background task
    /// (§5.2).
    ///
    /// The task holds only a [`std::sync::Weak`] reference — when
    /// the backend drops at shutdown, the next tick's upgrade
    /// fails and the task exits. Probe failures during refresh are
    /// logged at WARN and the previous capability set is kept.
    ///
    /// Returns `None` when no tokio runtime is active (e.g. unit
    /// tests constructing a backend outside a runtime); the
    /// periodic refresh is an online concern only.
    pub fn spawn_capability_refresh(
        backend: &Arc<Self>,
        interval: Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return None;
        };
        let weak = Arc::downgrade(backend);
        Some(handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // interval()'s first tick fires immediately; consume it
            // so the first background refresh happens one full
            // interval after startup (the §A15 startup probe
            // already covers time zero).
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(backend) = weak.upgrade() else { break };
                if let Err(e) = backend.probe().await {
                    tracing::warn!(
                        target: "cairn_mod::pds_admin::rust::capability",
                        error = %e,
                        "rust backend capability refresh probe failed; keeping previous capability set"
                    );
                }
            }
        }))
    }

    /// Shared `emitEvent` dispatch (v1.8.2, §4.4): capability
    /// check → per-call JWT → POST → HTTP error mapping →
    /// response parse. Returns Aurora's `eventId`.
    ///
    /// The capability check runs per-dispatch, not at
    /// construction (§5.1) — the background refresh can change
    /// the advertised set, and "your PDS stopped advertising a
    /// capability we need" is a deployment health signal the
    /// operator should see at the moment it bites.
    async fn dispatch_emit_event(
        &self,
        dispatch: &EmitEventDispatch<'_>,
    ) -> Result<ActionResponse, BackendError> {
        // Blocking read — guards never cross an await point.
        {
            let caps = self
                .capabilities
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !caps.has(EMIT_EVENT_FAMILY) {
                return Err(BackendError::CapabilityNotAdvertised(
                    ACCOUNT_ACTION_CAPABILITY.to_string(),
                ));
            }
            // Version-selection (§5.2): Aurora advertises only v1
            // and cairn-mod handles only v1, so the selection is
            // trivial — but the read exercises the machinery that
            // branches when a v2 ever lands (AutoAdvance family).
            let _advertised_version = caps
                .version_of(EMIT_EVENT_FAMILY)
                .expect("has() returned true for the same family");
        }

        let jwt = mint_service_auth_jwt(
            &self.signing_key,
            &self.service_did,
            &self.target_service_did,
            EMIT_EVENT_NSID,
            3600,
        )
        .map_err(|e| BackendError::Auth(e.to_string()))?;

        let url = self.xrpc_url(EMIT_EVENT_NSID)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(&jwt)
            .json(dispatch)
            .send()
            .await
            .map_err(OzoneBackend::map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(parse_retry_after_seconds);
            let body_bytes = response.bytes().await.unwrap_or_default();
            return Err(map_rust_backend_http_error(
                status,
                &body_bytes,
                retry_after,
            ));
        }

        let body_bytes = response
            .bytes()
            .await
            .map_err(OzoneBackend::map_reqwest_error)?;
        let parsed: ActionResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| BackendError::Transient(format!("emitEvent response parse: {e}")))?;
        Ok(parsed)
    }

    /// Shared moderator-read dispatch (v1.8.3, §4.4): capability
    /// gate → per-call JWT → **GET with URL query parameters**
    /// (Aurora's read endpoints take axum `Query` extractors, not
    /// JSON bodies) → HTTP error mapping → response parse.
    ///
    /// Both read endpoints gate on the single shared
    /// `moderator-activity` family (Aurora attributes the
    /// extension to queryEvents; queryStatuses shares it without
    /// re-declaring).
    async fn dispatch_moderator_read<F, T>(
        &self,
        capability_family: &'static str,
        capability_wire: &'static str,
        nsid: &'static str,
        filter: &F,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<T, BackendError>
    where
        F: serde::Serialize + Sync,
        T: serde::de::DeserializeOwned,
    {
        // Blocking read — guards never cross an await point.
        {
            let caps = self
                .capabilities
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !caps.has(capability_family) {
                return Err(BackendError::CapabilityNotAdvertised(
                    capability_wire.to_string(),
                ));
            }
            // Version-selection trivially v1 (§5.1); the read
            // exercises the machinery for a future v2.
            let _advertised_version = caps
                .version_of(capability_family)
                .expect("has() returned true for the same family");
        }

        let jwt = mint_service_auth_jwt(
            &self.signing_key,
            &self.service_did,
            &self.target_service_did,
            nsid,
            3600,
        )
        .map_err(|e| BackendError::Auth(e.to_string()))?;

        // Pagination params ride the same query string as the
        // filter (Aurora flattens PaginationParams into both
        // param structs).
        let mut pagination: Vec<(&str, String)> = Vec::with_capacity(2);
        if let Some(c) = cursor {
            pagination.push(("cursor", c.to_string()));
        }
        if let Some(n) = limit {
            pagination.push(("limit", n.to_string()));
        }

        let url = self.xrpc_url(nsid)?;
        let response = self
            .client
            .get(url)
            .query(filter)
            .query(&pagination)
            .bearer_auth(&jwt)
            .send()
            .await
            .map_err(OzoneBackend::map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(parse_retry_after_seconds);
            let body_bytes = response.bytes().await.unwrap_or_default();
            return Err(map_rust_backend_http_error(
                status,
                &body_bytes,
                retry_after,
            ));
        }

        let body_bytes = response
            .bytes()
            .await
            .map_err(OzoneBackend::map_reqwest_error)?;
        serde_json::from_slice(&body_bytes)
            .map_err(|e| BackendError::Transient(format!("{nsid} response parse: {e}")))
    }

    /// Shared dedicated-batch dispatch (v1.8.7, §4.1): capability
    /// gate (including the OperatorOptIn pin requirement, §8.1) →
    /// per-call JWT → POST JSON → HTTP error mapping → parse
    /// [`batch_types::BatchOutcome`]. Mirrors
    /// [`Self::dispatch_emit_event`]'s shape, parameterized on
    /// NSID + body because the four batch endpoints are distinct
    /// routes rather than one polymorphic endpoint.
    ///
    /// Per-subject upstream failures abort the whole batch
    /// transaction (Aurora's whole-tx atomicity contract) and
    /// arrive as a structured error body whose message carries
    /// `failingSubject` (index) and `failingSubjectId`; the
    /// standard XRPC-envelope mapping preserves both in the
    /// captured message — no new error variant.
    async fn dispatch_batch<B>(
        &self,
        nsid: &'static str,
        body: &B,
    ) -> Result<batch_types::BatchOutcome, BackendError>
    where
        B: serde::Serialize + Sync,
    {
        // Blocking read — guards never cross an await point.
        {
            let caps = self
                .capabilities
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !caps.has(BATCH_TAKEDOWN_FAMILY) {
                return Err(BackendError::CapabilityNotAdvertised(
                    BATCH_TAKEDOWN_CAPABILITY.to_string(),
                ));
            }
            let _advertised_version = caps
                .version_of(BATCH_TAKEDOWN_FAMILY)
                .expect("has() returned true for the same family");
        }

        // OperatorOptIn gate (v1.8.7 §8.1 — first runtime consumer
        // of the classification registry): for an OperatorOptIn
        // family, advertisement alone is not consent. The operator
        // opts in with a `[pds_admin.rust.pinned_versions]` entry
        // for the family; an unpinned family refuses dispatch with
        // the same `CapabilityNotAdvertised` shape ("operator
        // didn't opt in" and "upstream doesn't offer it" are both
        // capability-unavailable to the caller).
        if classification_for(BATCH_TAKEDOWN_FAMILY)
            == Some(CapabilityClassification::OperatorOptIn)
            && !self.pinned_versions.contains_key(BATCH_TAKEDOWN_FAMILY)
        {
            tracing::warn!(
                target: "cairn_mod::pds_admin::rust::capability",
                nsid,
                "batch dispatch refused: {BATCH_TAKEDOWN_FAMILY:?} is an operator-opt-in \
                 capability family and no pinned_versions entry exists; add \
                 `{BATCH_TAKEDOWN_FAMILY} = \"v1\"` under [pds_admin.rust.pinned_versions] \
                 to enable batch dispatch"
            );
            return Err(BackendError::CapabilityNotAdvertised(
                BATCH_TAKEDOWN_CAPABILITY.to_string(),
            ));
        }

        let jwt = mint_service_auth_jwt(
            &self.signing_key,
            &self.service_did,
            &self.target_service_did,
            nsid,
            3600,
        )
        .map_err(|e| BackendError::Auth(e.to_string()))?;

        let url = self.xrpc_url(nsid)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(&jwt)
            .json(body)
            .send()
            .await
            .map_err(OzoneBackend::map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(parse_retry_after_seconds);
            let body_bytes = response.bytes().await.unwrap_or_default();
            return Err(map_rust_backend_http_error(
                status,
                &body_bytes,
                retry_after,
            ));
        }

        let body_bytes = response
            .bytes()
            .await
            .map_err(OzoneBackend::map_reqwest_error)?;
        serde_json::from_slice(&body_bytes)
            .map_err(|e| BackendError::Transient(format!("{nsid} response parse: {e}")))
    }

    /// Construct the full URL for an XRPC method. Same shape as
    /// `OzoneBackend::xrpc_url` — ensure trailing slash, then join
    /// `xrpc/<nsid>`.
    fn xrpc_url(&self, nsid: &str) -> Result<Url, BackendError> {
        let mut base = self.pds_url.clone();
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        base.join(&format!("xrpc/{nsid}"))
            .map_err(|e| BackendError::Validation(format!("malformed nsid {nsid:?}: {e}")))
    }

    /// Emit the standardized unknown-family warning (umbrella
    /// §5.2 shape) for advertised strings whose family is not in
    /// [`super::types::CAPABILITY_CLASSIFICATIONS`] and was not advertised by
    /// the previous probe. First probe (previous set empty) warns
    /// once per unknown string — the operator sees the delta at
    /// boot, then only on genuine advertisement changes.
    fn warn_unknown_new_families(previous: &CapabilitySet, fresh: &CapabilitySet) {
        for wire_string in fresh.advertised_strings() {
            let Some((family, _)) = parse_capability_string(wire_string) else {
                // Malformed advertisements are ignored (advisory
                // posture); they never enter the family map.
                continue;
            };
            if classification_for(&family).is_none() && !previous.has(&family) {
                tracing::warn!(
                    target: "cairn_mod::pds_admin::rust::capability",
                    "PDS advertises capability family \"{wire_string}\" not in cairn-mod's \
                     registry; consider upgrading cairn-mod to consume it"
                );
            }
        }
    }
}

/// Map an HTTP status (with body and optional `Retry-After` hint)
/// into the matching [`BackendError`] per the v1.8.1 taxonomy
/// (§4.4).
///
/// Sub-classification markers ride the inner string so the
/// audit-writer's `retry_after_seconds` / `error_code` accessors
/// keep working: 429 carries `[sub_classification=RateLimited …]`;
/// statuses whose body parses as an XRPC error envelope carry
/// `[sub_classification=RemoteError code=X]`.
fn map_rust_backend_http_error(
    status: reqwest::StatusCode,
    body: &[u8],
    retry_after_seconds: Option<u32>,
) -> BackendError {
    let envelope = decode_xrpc_error_envelope(body);
    let describe = |fallback: &str| -> String {
        match &envelope {
            Some((code, message)) => {
                format!("[sub_classification=RemoteError code={code}] {message}")
            }
            None => {
                let lossy = String::from_utf8_lossy(body);
                let lossy = lossy.trim();
                if lossy.is_empty() {
                    format!("HTTP {status}: {fallback}")
                } else {
                    format!("HTTP {status}: {lossy}")
                }
            }
        }
    };

    match status.as_u16() {
        400 | 422 => BackendError::Validation(describe("request rejected as malformed")),
        401 | 403 => BackendError::Auth(describe(
            "service-auth rejected (check DID doc publication and the Aurora-side admin_roles grant)",
        )),
        404 | 409 | 410 => BackendError::Terminal(describe("upstream-state rejection")),
        429 => {
            let marker = match retry_after_seconds {
                Some(secs) => {
                    format!("[sub_classification=RateLimited retry_after_seconds={secs}]")
                }
                None => "[sub_classification=RateLimited]".to_string(),
            };
            BackendError::Transient(format!("{marker} HTTP 429: rate limited"))
        }
        500..=599 => BackendError::Transient(describe("upstream server error")),
        _ => BackendError::Transient(format!("unexpected HTTP {status}")),
    }
}

/// Debug excludes the signing key entirely (printing even a
/// redaction marker for key material invites log-scraping
/// confusion; the field's absence is the signal).
impl fmt::Debug for RustBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustBackend")
            .field("pds_url", &self.pds_url.as_str())
            .field("service_did", &self.service_did)
            .field("target_service_did", &self.target_service_did)
            .field("required_capabilities", &self.required_capabilities)
            .field("pinned_versions", &self.pinned_versions)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

/// Convert cairn-mod's flat subject coordinates into the wire
/// subject union (v1.8.5). Mirrors Aurora's `Subject::from_columns`
/// precedence exactly: a URI means Record (CID mandatory on the
/// strongRef wire), a CID without URI means Blob, bare DID means
/// account-level repoRef. Used by the report/appeal methods whose
/// `subjects[0]` must match the target row's stored subject by
/// variant AND identifier.
fn wire_subject_from(subject: &Subject) -> Result<EmitEventSubject<'_>, BackendError> {
    match (subject.at_uri.as_deref(), subject.cid.as_deref()) {
        (Some(uri), Some(cid)) => Ok(EmitEventSubject::record(uri, cid)),
        (Some(uri), None) => Err(BackendError::Validation(format!(
            "record-shaped subject requires a CID (Aurora's strongRef wire \
             shape has no optional CID); got at_uri={uri:?} with no cid for did {}",
            subject.did
        ))),
        (None, Some(cid)) => Ok(EmitEventSubject::blob(&subject.did, cid, None)),
        (None, None) => Ok(EmitEventSubject::account(&subject.did)),
    }
}

#[async_trait]
impl PdsAdminBackend for RustBackend {
    /// Real dispatch (v1.8.2): `{"kind": "TakedownAccount"}` via
    /// `emitEvent`. `notes` is accepted per the trait but not
    /// transmitted (§4.5-notes documented non-transmission —
    /// Aurora's wire has no notes field; cairn-mod's audit chain
    /// retains it locally).
    async fn takedown_account(
        &self,
        did: &str,
        reason: &str,
        _notes: Option<&str>,
        _precipitating_action_id: i64,
    ) -> Result<BackendActionId, BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account(did)],
            action: EmitEventAction::TakedownAccount,
            rationale: reason,
            metadata: None,
        };
        let response = self.dispatch_emit_event(&dispatch).await?;
        Ok(BackendActionId::PerEvent(response.event_id))
    }

    /// Real dispatch (v1.8.2): `{"kind": "SuspendAccount"}` with
    /// the duration riding the top-level `metadata` channel
    /// (`{"durationDays": n}`) — omitted entirely for
    /// indefinite suspensions.
    async fn suspend_account(
        &self,
        did: &str,
        reason: &str,
        duration_days: Option<u32>,
        _notes: Option<&str>,
        _precipitating_action_id: i64,
    ) -> Result<BackendActionId, BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account(did)],
            action: EmitEventAction::SuspendAccount,
            rationale: reason,
            metadata: duration_days.map(|days| serde_json::json!({ "durationDays": days })),
        };
        let response = self.dispatch_emit_event(&dispatch).await?;
        Ok(BackendActionId::PerEvent(response.event_id))
    }

    /// Real dispatch (v1.8.2): `{"kind": "RestoreAccount"}`.
    /// `prior_action_id` is accepted per the trait but not
    /// transmitted (§4.5 Option A) — Aurora reverses the
    /// account's *current* takedown state on its own. Aurora's
    /// returned `eventId` is discarded here because the trait
    /// method is unit-result; the audit row's
    /// `backend_action_id` is NULL by construction
    /// (`returns_action_id() == false`).
    async fn restore_account(
        &self,
        did: &str,
        _prior_action_id: &BackendActionId,
        reason: &str,
    ) -> Result<(), BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account(did)],
            action: EmitEventAction::RestoreAccount,
            rationale: reason,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await?;
        Ok(())
    }

    /// Real dispatch (v1.8.2, new trait method):
    /// `{"kind": "TakedownRecord"}` with a
    /// `com.atproto.repo.strongRef` subject. Aurora's wire
    /// requires both `uri` and `cid`; a subject missing either
    /// is rejected here with `Validation` — never coerced into
    /// an account-level action (§4.5.1's no-fallback rule).
    async fn takedown_record(
        &self,
        subject: &Subject,
        reason: &str,
        _notes: Option<&str>,
        _precipitating_action_id: i64,
    ) -> Result<BackendActionId, BackendError> {
        let (Some(uri), Some(cid)) = (subject.at_uri.as_deref(), subject.cid.as_deref()) else {
            return Err(BackendError::Validation(format!(
                "takedown_record requires a fully-shaped record subject \
                 (at_uri and cid both present; Aurora's strongRef wire shape \
                 has no optional CID); got at_uri={:?} cid={:?} for did {}",
                subject.at_uri.as_deref(),
                subject.cid.as_deref(),
                subject.did
            )));
        };
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::record(uri, cid)],
            action: EmitEventAction::TakedownRecord,
            rationale: reason,
            metadata: None,
        };
        let response = self.dispatch_emit_event(&dispatch).await?;
        Ok(BackendActionId::PerEvent(response.event_id))
    }

    async fn apply_label(
        &self,
        _subject: &Subject,
        _val: &str,
        _expires_days: Option<u32>,
    ) -> Result<(), BackendError> {
        // §F4 invariant — trait-level, backend-independent. Rename
        // to LABEL_BRIDGE_INVARIANT_REASON lands at v1.8.2 per
        // umbrella §4.A.2.
        Err(BackendError::ArchitecturallyForbidden(
            LABEL_BRIDGE_INVARIANT_REASON.to_string(),
        ))
    }

    async fn negate_label(&self, _subject: &Subject, _val: &str) -> Result<(), BackendError> {
        Err(BackendError::ArchitecturallyForbidden(
            LABEL_BRIDGE_INVARIANT_REASON.to_string(),
        ))
    }

    /// Real dispatch (v1.8.5): `{"kind": "DeleteAccount"}` —
    /// Admin+ role floor upstream; a Moderator-role service DID
    /// gets 403 → `Auth`.
    async fn delete_account(
        &self,
        did: &str,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account(did)],
            action: EmitEventAction::DeleteAccount,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.5): `{"kind": "QuarantineBlob"}` with
    /// a `repoBlobRef` subject.
    async fn quarantine_blob(
        &self,
        subject: &BlobSubject,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::blob(
                &subject.did,
                &subject.cid,
                subject.record_uri.as_deref(),
            )],
            action: EmitEventAction::QuarantineBlob,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.5): `{"kind": "RestoreBlob"}`.
    /// `prior_action_id` is not transmitted (unit variant on
    /// Aurora's wire); the returned event id is deliberately
    /// discarded per the v1.8.2 `restore_account` symmetry.
    async fn restore_blob(
        &self,
        subject: &BlobSubject,
        _prior_action_id: &BackendActionId,
        rationale: &str,
    ) -> Result<(), BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::blob(
                &subject.did,
                &subject.cid,
                subject.record_uri.as_deref(),
            )],
            action: EmitEventAction::RestoreBlob,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await?;
        Ok(())
    }

    /// Real dispatch (v1.8.5): `{"kind": "DeleteBlob"}` —
    /// Moderator+ upstream (the Admin gate covers only
    /// DeleteAccount and SendEmail).
    async fn delete_blob(
        &self,
        subject: &BlobSubject,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::blob(
                &subject.did,
                &subject.cid,
                subject.record_uri.as_deref(),
            )],
            action: EmitEventAction::DeleteBlob,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.5): `{"kind": "ResolveReport"}` with
    /// the report's exact subject in `subjects[0]` — Aurora
    /// validates variant AND identifier against the report row.
    async fn resolve_report(
        &self,
        subject: &Subject,
        report_id: i64,
        resolution: ReportResolution,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let wire_subject = wire_subject_from(subject)?;
        let dispatch = EmitEventDispatch {
            subjects: vec![wire_subject],
            action: EmitEventAction::ResolveReport {
                report_id,
                resolution,
            },
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.5): `{"kind": "DismissReport"}` —
    /// same subject contract as `resolve_report`.
    async fn dismiss_report(
        &self,
        subject: &Subject,
        report_id: i64,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let wire_subject = wire_subject_from(subject)?;
        let dispatch = EmitEventDispatch {
            subjects: vec![wire_subject],
            action: EmitEventAction::DismissReport { report_id },
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.5): `{"kind": "ResolveAppeal"}`.
    /// `Approve` produces a cascading reversal event id in the
    /// response. The wire field carrying the decision is named
    /// `resolution` (Aurora's `AppealResolutionDecision`).
    async fn resolve_appeal(
        &self,
        subject: &Subject,
        appeal_id: i64,
        decision: AppealDecision,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let wire_subject = wire_subject_from(subject)?;
        let dispatch = EmitEventDispatch {
            subjects: vec![wire_subject],
            action: EmitEventAction::ResolveAppeal {
                appeal_id,
                resolution: decision,
            },
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.5): `{"kind": "EscalateAppeal"}`.
    async fn escalate_appeal(
        &self,
        subject: &Subject,
        appeal_id: i64,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let wire_subject = wire_subject_from(subject)?;
        let dispatch = EmitEventDispatch {
            subjects: vec![wire_subject],
            action: EmitEventAction::EscalateAppeal { appeal_id },
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.5): `{"kind": "SendEmail"}` — Admin+
    /// role floor upstream. The recipient rides `subjects[0]`
    /// (repoRef); `subject` is the email subject line on the
    /// wire.
    async fn send_email(
        &self,
        did: &str,
        template: Option<&str>,
        subject: &str,
        body: &str,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account(did)],
            action: EmitEventAction::SendEmail {
                template: template.map(str::to_string),
                subject: subject.to_string(),
                body: body.to_string(),
            },
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.5): `{"kind": "UpdateSubjectStatus"}`
    /// — account-only tri-state; Aurora rejects non-repo
    /// subjects, so the trait takes a bare DID.
    async fn update_subject_status(
        &self,
        did: &str,
        status: SubjectStatus,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        let dispatch = EmitEventDispatch {
            subjects: vec![EmitEventSubject::account(did)],
            action: EmitEventAction::UpdateSubjectStatus { status },
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Moderator event-stream read via
    /// `GET tools.aurora.moderator.queryEvents` (v1.8.3).
    async fn query_events(
        &self,
        filter: QueryEventsFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PaginatedResponse<EventWithContext>, BackendError> {
        self.dispatch_moderator_read(
            MODERATOR_ACTIVITY_FAMILY,
            MODERATOR_ACTIVITY_CAPABILITY,
            QUERY_EVENTS_NSID,
            &filter,
            cursor,
            limit,
        )
        .await
    }

    /// Per-DID moderation-status read via
    /// `GET tools.aurora.moderator.queryStatuses` (v1.8.3).
    async fn query_statuses(
        &self,
        filter: QueryStatusesFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PaginatedResponse<StatusWithContext>, BackendError> {
        self.dispatch_moderator_read(
            MODERATOR_ACTIVITY_FAMILY,
            MODERATOR_ACTIVITY_CAPABILITY,
            QUERY_STATUSES_NSID,
            &filter,
            cursor,
            limit,
        )
        .await
    }

    /// Single-event fetch via
    /// `GET tools.aurora.moderator.getEvent` (v1.8.4). Reuses the
    /// v1.8.3 `EventWithContext` mirror — Aurora returns the same
    /// struct `queryEvents` items use.
    async fn get_event(&self, event_id: i64) -> Result<EventWithContext, BackendError> {
        #[derive(serde::Serialize)]
        struct Params {
            id: i64,
        }
        self.dispatch_moderator_read(
            MODERATOR_ACTIVITY_FAMILY,
            MODERATOR_ACTIVITY_CAPABILITY,
            GET_EVENT_NSID,
            &Params { id: event_id },
            None,
            None,
        )
        .await
    }

    /// Subject-context fetch via
    /// `GET tools.aurora.moderator.getSubjectContext` (v1.8.4).
    /// DID-scoped query parameter per Aurora's
    /// `GetSubjectContextParams { did }`.
    async fn get_subject_context(&self, did: &str) -> Result<SubjectContextResponse, BackendError> {
        #[derive(serde::Serialize)]
        struct Params<'a> {
            did: &'a str,
        }
        self.dispatch_moderator_read(
            SUBJECT_CONTEXT_FAMILY,
            SUBJECT_CONTEXT_CAPABILITY,
            GET_SUBJECT_CONTEXT_NSID,
            &Params { did },
            None,
            None,
        )
        .await
    }

    /// Subject action-history via
    /// `GET tools.aurora.moderator.getSubjectHistory` (v1.8.4).
    /// History rows are `StatusWithContext` — action rows, not
    /// events.
    async fn get_subject_history(
        &self,
        did: &str,
        filter: SubjectHistoryFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PaginatedResponse<StatusWithContext>, BackendError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Params<'a> {
            did: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            action: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            direction: Option<&'a str>,
        }
        let params = Params {
            did,
            action: filter.action.as_deref(),
            direction: filter.direction.as_deref(),
        };
        self.dispatch_moderator_read(
            SUBJECT_HISTORY_FAMILY,
            SUBJECT_HISTORY_CAPABILITY,
            GET_SUBJECT_HISTORY_NSID,
            &params,
            cursor,
            limit,
        )
        .await
    }

    /// Appeal listing via
    /// `GET tools.aurora.moderator.listAppeals` (v1.8.4).
    async fn list_appeals(
        &self,
        filter: ListAppealsFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PaginatedResponse<AppealView>, BackendError> {
        self.dispatch_moderator_read(
            APPEALS_FAMILY,
            APPEALS_CAPABILITY,
            LIST_APPEALS_NSID,
            &filter,
            cursor,
            limit,
        )
        .await
    }

    /// Single-appeal fetch (with lifecycle timeline) via
    /// `GET tools.aurora.moderator.getAppeal` (v1.8.4). Shares the
    /// `appeals` gate with `list_appeals`.
    async fn get_appeal(&self, appeal_id: i64) -> Result<AppealDetail, BackendError> {
        #[derive(serde::Serialize)]
        struct Params {
            id: i64,
        }
        self.dispatch_moderator_read(
            APPEALS_FAMILY,
            APPEALS_CAPABILITY,
            GET_APPEAL_NSID,
            &Params { id: appeal_id },
            None,
            None,
        )
        .await
    }

    /// Paged audit-trail fetch via
    /// `GET tools.aurora.admin.getAuditTrail` (v1.8.6). Returns
    /// the page plus Aurora's whole-chain verify verdict; Path A
    /// re-verification happens caller-side (upstream_verify).
    async fn get_audit_trail(
        &self,
        filter: AuditTrailFilter,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<AuditTrailPage, BackendError> {
        self.dispatch_moderator_read(
            AUDIT_TRAIL_FAMILY,
            AUDIT_TRAIL_CAPABILITY,
            GET_AUDIT_TRAIL_NSID,
            &filter,
            cursor,
            limit,
        )
        .await
    }

    /// Single audit-entry fetch via
    /// `GET tools.aurora.admin.getAuditEntry` (v1.8.6). The
    /// lookup enum makes Aurora's 400-on-both/neither shape
    /// unrepresentable.
    async fn get_audit_entry(
        &self,
        lookup: &AuditEntryLookup,
    ) -> Result<AuroraAuditEntry, BackendError> {
        #[derive(serde::Serialize)]
        struct Params<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            id: Option<i64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            hash: Option<&'a str>,
        }
        let params = match lookup {
            AuditEntryLookup::Id(id) => Params {
                id: Some(*id),
                hash: None,
            },
            AuditEntryLookup::Hash(h) => Params {
                id: None,
                hash: Some(h),
            },
        };
        self.dispatch_moderator_read(
            AUDIT_TRAIL_FAMILY,
            AUDIT_TRAIL_CAPABILITY,
            GET_AUDIT_ENTRY_NSID,
            &params,
            None,
            None,
        )
        .await
    }

    /// Real dispatch (v1.8.7): POST `batchTakedownAccounts` with
    /// `{"dids": [...], "rationale": ...}`. Client-side cap check
    /// mirrors Aurora's `validate_batch_size` (at-cap passes);
    /// the capability + opt-in gate lives in `dispatch_batch`.
    async fn batch_takedown_accounts(
        &self,
        dids: &[String],
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<batch_types::BatchOutcome, BackendError> {
        batch_types::validate_batch_len(dids, batch_types::MAX_BATCH_SIZE, "batch")?;
        self.dispatch_batch(
            BATCH_TAKEDOWN_ACCOUNTS_NSID,
            &batch_types::BatchDidsBody { dids, rationale },
        )
        .await
    }

    /// Real dispatch (v1.8.7): POST `batchSuspendAccounts`.
    /// Indefinite-only by wire contract — no duration parameter
    /// exists to transmit.
    async fn batch_suspend_accounts(
        &self,
        dids: &[String],
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<batch_types::BatchOutcome, BackendError> {
        batch_types::validate_batch_len(dids, batch_types::MAX_BATCH_SIZE, "batch")?;
        self.dispatch_batch(
            BATCH_SUSPEND_ACCOUNTS_NSID,
            &batch_types::BatchDidsBody { dids, rationale },
        )
        .await
    }

    /// Real dispatch (v1.8.7): POST `batchRestoreAccounts`.
    /// Trait-only (LB-A): dispatches directly to Aurora with no
    /// recordAction row, no writer path, no CLI — Aurora reverses
    /// each DID's current state server-side.
    async fn batch_restore_accounts(
        &self,
        dids: &[String],
        rationale: &str,
    ) -> Result<batch_types::BatchOutcome, BackendError> {
        batch_types::validate_batch_len(dids, batch_types::MAX_BATCH_SIZE, "batch")?;
        self.dispatch_batch(
            BATCH_RESTORE_ACCOUNTS_NSID,
            &batch_types::BatchDidsBody { dids, rationale },
        )
        .await
    }

    /// Real dispatch (v1.8.7): POST `batchTakedownRecords` with
    /// bare AT-URIs — **URI-level** semantics via Aurora's
    /// empty-CID cascade convention (scoped to this endpoint
    /// exclusively, §3.3).
    async fn batch_takedown_records(
        &self,
        uris: &[String],
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<batch_types::BatchOutcome, BackendError> {
        batch_types::validate_batch_len(uris, batch_types::MAX_BATCH_SIZE, "batch")?;
        self.dispatch_batch(
            BATCH_TAKEDOWN_RECORDS_NSID,
            &batch_types::BatchUrisBody { uris, rationale },
        )
        .await
    }

    /// Real dispatch (v1.8.7): `{"kind": "DeleteAccount"}` with an
    /// N-element subjects array — cap 10
    /// (`MAX_SUBJECTS_DELETE_ACCOUNT`, the tightest multi-subject
    /// cap). Rides the shipped `mod-events-emit` gate unchanged
    /// (§8.2: multi-subject is a shape modifier, not a new
    /// capability).
    async fn delete_account_many(
        &self,
        dids: &[String],
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        batch_types::validate_batch_len(
            dids,
            batch_types::MAX_SUBJECTS_DELETE_ACCOUNT,
            "subjects",
        )?;
        let dispatch = EmitEventDispatch {
            subjects: dids.iter().map(|d| EmitEventSubject::account(d)).collect(),
            action: EmitEventAction::DeleteAccount,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.7): `{"kind": "QuarantineBlob"}`,
    /// N-element `repoBlobRef` subjects, cap 50.
    async fn quarantine_blob_many(
        &self,
        subjects: &[BlobSubject],
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        batch_types::validate_batch_len(subjects, batch_types::MAX_SUBJECTS_DEFAULT, "subjects")?;
        let dispatch = EmitEventDispatch {
            subjects: subjects
                .iter()
                .map(|s| EmitEventSubject::blob(&s.did, &s.cid, s.record_uri.as_deref()))
                .collect(),
            action: EmitEventAction::QuarantineBlob,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.7): `{"kind": "RestoreBlob"}`,
    /// N-element subjects, cap 50. Unit-result per the restore
    /// symmetry; `prior_action_id` is trait-boundary vocabulary
    /// only (nothing rides the wire).
    async fn restore_blob_many(
        &self,
        subjects: &[BlobSubject],
        _prior_action_id: &BackendActionId,
        rationale: &str,
    ) -> Result<(), BackendError> {
        batch_types::validate_batch_len(subjects, batch_types::MAX_SUBJECTS_DEFAULT, "subjects")?;
        let dispatch = EmitEventDispatch {
            subjects: subjects
                .iter()
                .map(|s| EmitEventSubject::blob(&s.did, &s.cid, s.record_uri.as_deref()))
                .collect(),
            action: EmitEventAction::RestoreBlob,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await?;
        Ok(())
    }

    /// Real dispatch (v1.8.7): `{"kind": "DeleteBlob"}`,
    /// N-element subjects, cap 25 (`MAX_SUBJECTS_DELETE_BLOB`).
    async fn delete_blob_many(
        &self,
        subjects: &[BlobSubject],
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        batch_types::validate_batch_len(
            subjects,
            batch_types::MAX_SUBJECTS_DELETE_BLOB,
            "subjects",
        )?;
        let dispatch = EmitEventDispatch {
            subjects: subjects
                .iter()
                .map(|s| EmitEventSubject::blob(&s.did, &s.cid, s.record_uri.as_deref()))
                .collect(),
            action: EmitEventAction::DeleteBlob,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.7): `{"kind": "TakedownRecord"}`,
    /// N-element strongRef subjects, cap 50. **CID-required** on
    /// every subject (S-2): Aurora's multi-subject arm performs
    /// no CID validation, so an empty CID would flow through with
    /// undefined downstream semantics — pre-reject and point
    /// URI-level callers at `batch_takedown_records`.
    async fn takedown_record_many(
        &self,
        subjects: &[Subject],
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        batch_types::validate_batch_len(subjects, batch_types::MAX_SUBJECTS_DEFAULT, "subjects")?;
        let mut wire_subjects = Vec::with_capacity(subjects.len());
        for subject in subjects {
            let Some(uri) = subject.at_uri.as_deref() else {
                return Err(BackendError::Validation(format!(
                    "takedown_record_many requires record-shaped subjects \
                     (at_uri present); got an account-shaped subject for did {}",
                    subject.did
                )));
            };
            match subject.cid.as_deref() {
                Some(cid) if !cid.is_empty() => {
                    wire_subjects.push(EmitEventSubject::record(uri, cid))
                }
                _ => {
                    return Err(BackendError::Validation(
                        "takedown_record_many requires non-empty CID; \
                         use batch_takedown_records for URI-level takedowns"
                            .to_string(),
                    ));
                }
            }
        }
        let dispatch = EmitEventDispatch {
            subjects: wire_subjects,
            action: EmitEventAction::TakedownRecord,
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.7): `{"kind": "UpdateSubjectStatus"}`
    /// — one tri-state status applied to N accounts, cap 50.
    async fn update_subject_status_many(
        &self,
        dids: &[String],
        status: SubjectStatus,
        rationale: &str,
        _precipitating_action_id: i64,
    ) -> Result<ActionResponse, BackendError> {
        batch_types::validate_batch_len(dids, batch_types::MAX_SUBJECTS_DEFAULT, "subjects")?;
        let dispatch = EmitEventDispatch {
            subjects: dids.iter().map(|d| EmitEventSubject::account(d)).collect(),
            action: EmitEventAction::UpdateSubjectStatus { status },
            rationale,
            metadata: None,
        };
        self.dispatch_emit_event(&dispatch).await
    }

    /// Real dispatch (v1.8.8): WebSocket upgrade to
    /// `subscribeModEvents` with per-connection service-auth JWT.
    /// Capability gate mirrors `dispatch_batch`'s OperatorOptIn
    /// semantics against the `mod-events-stream` family. Frames
    /// arrive as JSON text; unknown/malformed frames are skipped
    /// in the adapter (no sequence extracted → no cursor
    /// advance); transport errors surface as one final
    /// `Err(Transient)` item.
    async fn subscribe_mod_events(
        &self,
        cursor: Option<i64>,
        audit_chain_cursor: Option<i64>,
        include_audit_chain: bool,
    ) -> Result<
        std::pin::Pin<
            Box<
                dyn futures_util::Stream<Item = Result<stream_types::StreamFrame, BackendError>>
                    + Send,
            >,
        >,
        BackendError,
    > {
        // Blocking read — guards never cross an await point.
        {
            let caps = self
                .capabilities
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !caps.has(MOD_EVENTS_STREAM_FAMILY) {
                return Err(BackendError::CapabilityNotAdvertised(
                    MOD_EVENTS_STREAM_CAPABILITY.to_string(),
                ));
            }
            let _advertised_version = caps
                .version_of(MOD_EVENTS_STREAM_FAMILY)
                .expect("has() returned true for the same family");
        }
        // OperatorOptIn gate — second consumer of the v1.8.7
        // semantics: advertisement alone is not consent for a
        // long-lived ingesting connection.
        if classification_for(MOD_EVENTS_STREAM_FAMILY)
            == Some(CapabilityClassification::OperatorOptIn)
            && !self.pinned_versions.contains_key(MOD_EVENTS_STREAM_FAMILY)
        {
            tracing::warn!(
                target: "cairn_mod::pds_admin::rust::capability",
                "stream refused: {MOD_EVENTS_STREAM_FAMILY:?} is operator-opt-in and no \
                 pinned_versions entry exists; add `{MOD_EVENTS_STREAM_FAMILY} = \"v1\"` \
                 under [pds_admin.rust.pinned_versions] to enable the realtime consumer"
            );
            return Err(BackendError::CapabilityNotAdvertised(
                MOD_EVENTS_STREAM_CAPABILITY.to_string(),
            ));
        }

        let jwt = mint_service_auth_jwt(
            &self.signing_key,
            &self.service_did,
            &self.target_service_did,
            SUBSCRIBE_MOD_EVENTS_NSID,
            3600,
        )
        .map_err(|e| BackendError::Auth(e.to_string()))?;

        let mut url = self.xrpc_url(SUBSCRIBE_MOD_EVENTS_NSID)?;
        let ws_scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(ws_scheme)
            .map_err(|()| BackendError::Validation("pds_url scheme not ws-convertible".into()))?;
        {
            let mut qp = url.query_pairs_mut();
            if let Some(c) = cursor {
                qp.append_pair("cursor", &c.to_string());
            }
            if include_audit_chain {
                qp.append_pair("includeAuditChain", "true");
                if let Some(c) = audit_chain_cursor {
                    qp.append_pair("auditChainCursor", &c.to_string());
                }
            }
        }

        use tokio_tungstenite::tungstenite;
        use tungstenite::client::IntoClientRequest;
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|e| BackendError::Validation(format!("ws request build: {e}")))?;
        request.headers_mut().insert(
            tungstenite::http::header::AUTHORIZATION,
            format!("Bearer {jwt}")
                .parse()
                .map_err(|e| BackendError::Auth(format!("authorization header: {e}")))?,
        );

        let (ws, _response) =
            tokio_tungstenite::connect_async(request)
                .await
                .map_err(|e| match &e {
                    tungstenite::Error::Http(resp)
                        if resp.status() == tungstenite::http::StatusCode::UNAUTHORIZED
                            || resp.status() == tungstenite::http::StatusCode::FORBIDDEN =>
                    {
                        BackendError::Auth(format!(
                            "subscribeModEvents upgrade rejected: HTTP {}",
                            resp.status()
                        ))
                    }
                    _ => BackendError::Transient(format!("subscribeModEvents connect: {e}")),
                })?;

        use futures_util::StreamExt as _;
        let frames = ws.filter_map(|msg| async move {
            match msg {
                Ok(tungstenite::Message::Text(text)) => {
                    stream_types::parse_frame_text(text.as_str()).map(Ok)
                }
                // Binary/ping/pong are outside the JSON-text
                // contract; Close ends the stream cleanly.
                Ok(tungstenite::Message::Close(_)) | Ok(_) => None,
                Err(e) => Some(Err(BackendError::Transient(format!(
                    "websocket transport: {e}"
                )))),
            }
        });
        Ok(Box::pin(frames))
    }

    /// `describeCapabilities` probe — v1.8.1's only successful
    /// Aurora-side call (§4.3).
    async fn probe(&self) -> Result<ProbeReport, BackendError> {
        let jwt = mint_service_auth_jwt(
            &self.signing_key,
            &self.service_did,
            &self.target_service_did,
            DESCRIBE_CAPABILITIES_NSID,
            3600,
        )
        .map_err(|e| BackendError::Auth(e.to_string()))?;

        let url = self.xrpc_url(DESCRIBE_CAPABILITIES_NSID)?;
        let response = self
            .client
            .get(url)
            .bearer_auth(&jwt)
            .send()
            .await
            .map_err(OzoneBackend::map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(parse_retry_after_seconds);
            let body_bytes = response.bytes().await.unwrap_or_default();
            return Err(map_rust_backend_http_error(
                status,
                &body_bytes,
                retry_after,
            ));
        }

        let body_bytes = response
            .bytes()
            .await
            .map_err(OzoneBackend::map_reqwest_error)?;
        let parsed: DescribeCapabilitiesResponse =
            serde_json::from_slice(&body_bytes).map_err(|e| {
                BackendError::Terminal(format!(
                    "[sub_classification=RemoteError code=InvalidResponse] \
                     describeCapabilities returned a 200 with a malformed body \
                     (configured url likely doesn't point at an Aurora-compatible PDS): {e}"
                ))
            })?;

        let fresh = CapabilitySet::from_describe_capabilities(&parsed)
            .map_err(|e| BackendError::Terminal(e.to_string()))?;

        // Required-capability check (§4.3 step 5): each operator-
        // declared wire string must resolve to an advertised
        // family. Unversioned entries are treated as bare family
        // names.
        for required in &self.required_capabilities {
            let family = parse_capability_string(required)
                .map(|(family, _)| family)
                .unwrap_or_else(|| required.clone());
            if !fresh.has(&family) {
                return Err(BackendError::CapabilityNotAdvertised(required.clone()));
            }
        }

        // Swap in the fresh set; warn about unknown newly-
        // advertised families (§5.2). Lock scopes are brief and
        // never cross an await.
        let previous = {
            let mut guard = self
                .capabilities
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *guard, fresh.clone())
        };
        Self::warn_unknown_new_families(&previous, &fresh);

        Ok(ProbeReport {
            backend_name: "rust",
            pds_url: self.pds_url.as_str().to_string(),
            detected_version: Some(parsed.version),
            capabilities: fresh.advertised_strings().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 64 hex chars — a valid non-zero secp256k1 scalar.
    const TEST_KEY_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    fn fixture_config(url: &str, key_env: &str) -> RustBackendConfig {
        RustBackendConfig {
            pds_url: url::Url::parse(url).unwrap(),
            service_did: "did:web:cairn-mod.example.com".to_string(),
            service_signing_key_env: key_env.to_string(),
            service_did_document_url: None,
            target_service_did: "did:web:aurora-locus.example.com".to_string(),
            request_timeout: Duration::from_secs(30),
            capability_refresh_interval: Duration::from_secs(3600),
            required_capabilities: Vec::new(),
            pinned_versions: BTreeMap::new(),
            verification_persist: true,
            acknowledge_v1_8_1_audit_divergence: true,
            stream: crate::pds_admin::config::RustStreamConfig::default(),
        }
    }

    /// Injected env reader per the house test-seam convention —
    /// no [`std::env::set_var`] (unsafe in Rust 2024, and
    /// process-global state races parallel test threads).
    fn key_env(value: &'static str) -> impl Fn(&str) -> Result<String, std::env::VarError> {
        move |_name: &str| Ok(value.to_string())
    }

    fn backend_with_test_key(url: &str) -> RustBackend {
        RustBackend::new_with_key_source(
            &fixture_config(url, "CAIRN_SERVICE_SIGNING_KEY"),
            &key_env(TEST_KEY_HEX),
        )
        .unwrap()
    }

    #[test]
    fn construction_succeeds_from_valid_config() {
        let backend = backend_with_test_key("https://pds.example.com");
        assert_eq!(backend.service_did, "did:web:cairn-mod.example.com");
        assert!(
            backend
                .capabilities
                .read()
                .unwrap()
                .advertised_strings()
                .is_empty()
        );
        // Debug output redacts the key entirely.
        let dbg = format!("{backend:?}");
        assert!(!dbg.contains("signing_key"));
        assert!(dbg.contains("pds.example.com"));
    }

    #[test]
    fn construction_fails_on_missing_env_var() {
        let err = RustBackend::new_with_key_source(
            &fixture_config(
                "https://pds.example.com",
                "CAIRN_TEST_RUST_BACKEND_KEY_UNSET",
            ),
            &|_name| Err(std::env::VarError::NotPresent),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("CAIRN_TEST_RUST_BACKEND_KEY_UNSET"),
            "error names the env var: {msg}"
        );
    }

    #[test]
    fn construction_fails_on_invalid_key_bytes() {
        let cfg = fixture_config("https://pds.example.com", "K");
        let err = RustBackend::new_with_key_source(&cfg, &key_env("not-hex-at-all")).unwrap_err();
        assert!(err.to_string().contains("hex"), "{err}");

        // Valid hex, wrong length.
        let err = RustBackend::new_with_key_source(&cfg, &key_env("abcd")).unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err}");

        // Empty value.
        let err = RustBackend::new_with_key_source(&cfg, &key_env("  ")).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[tokio::test]
    async fn account_action_methods_return_capability_not_advertised() {
        let backend = backend_with_test_key("https://pds.example.com");

        let takedown = backend.takedown_account("did:plc:x", "spam", None, 1).await;
        assert!(matches!(
            takedown,
            Err(BackendError::CapabilityNotAdvertised(ref s)) if s == ACCOUNT_ACTION_CAPABILITY
        ));

        let suspend = backend
            .suspend_account("did:plc:x", "spam", Some(7), None, 2)
            .await;
        assert!(matches!(
            suspend,
            Err(BackendError::CapabilityNotAdvertised(_))
        ));

        let restore = backend
            .restore_account("did:plc:x", &BackendActionId::new("rust:x:1"), "resolved")
            .await;
        assert!(matches!(
            restore,
            Err(BackendError::CapabilityNotAdvertised(_))
        ));

        // takedown_record with a fully-shaped subject also gates on
        // the capability (subject validation passes, capability
        // check fails against the empty pre-probe set).
        let record = backend
            .takedown_record(
                &Subject::record("did:plc:x", "at://did:plc:x/c/r", Some("bafy1".into())),
                "spam",
                None,
                3,
            )
            .await;
        assert!(matches!(
            record,
            Err(BackendError::CapabilityNotAdvertised(_))
        ));
    }

    #[tokio::test]
    async fn takedown_record_rejects_cid_less_subject_with_validation() {
        // §4.5.1 no-fallback rule: partial record coordinates are
        // Validation at the trait boundary — checked BEFORE the
        // capability gate, so the operator sees the shape problem
        // even against an unprobed backend.
        let backend = backend_with_test_key("https://pds.example.com");

        let no_cid = backend
            .takedown_record(
                &Subject::record("did:plc:x", "at://did:plc:x/c/r", None),
                "spam",
                None,
                4,
            )
            .await;
        match no_cid {
            Err(BackendError::Validation(msg)) => {
                assert!(msg.contains("cid"), "{msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }

        // Account-shaped subject (no at_uri at all) is equally
        // malformed for a record verb.
        let no_uri = backend
            .takedown_record(&Subject::account("did:plc:x"), "spam", None, 5)
            .await;
        assert!(matches!(no_uri, Err(BackendError::Validation(_))));
    }

    #[tokio::test]
    async fn label_methods_hard_refuse_architecturally_forbidden() {
        let backend = backend_with_test_key("https://pds.example.com");

        let apply = backend
            .apply_label(&Subject::account("did:plc:x"), "spam", None)
            .await;
        match apply {
            Err(BackendError::ArchitecturallyForbidden(reason)) => {
                assert_eq!(reason, LABEL_BRIDGE_INVARIANT_REASON);
            }
            other => panic!("expected ArchitecturallyForbidden, got {other:?}"),
        }

        let negate = backend
            .negate_label(&Subject::account("did:plc:x"), "spam")
            .await;
        assert!(matches!(
            negate,
            Err(BackendError::ArchitecturallyForbidden(_))
        ));
    }

    // ===== map_rust_backend_http_error (§4.4) =====

    #[test]
    fn http_error_mapping_validation_statuses() {
        for status in [400u16, 422] {
            let e = map_rust_backend_http_error(
                reqwest::StatusCode::from_u16(status).unwrap(),
                b"{\"error\":\"InvalidRequest\",\"message\":\"bad shape\"}",
                None,
            );
            assert!(matches!(e, BackendError::Validation(_)), "HTTP {status}");
            assert_eq!(e.error_code(), Some("InvalidRequest"), "HTTP {status}");
        }
    }

    #[test]
    fn http_error_mapping_auth_statuses() {
        for status in [401u16, 403] {
            let e = map_rust_backend_http_error(
                reqwest::StatusCode::from_u16(status).unwrap(),
                b"",
                None,
            );
            assert!(matches!(e, BackendError::Auth(_)), "HTTP {status}");
        }
    }

    #[test]
    fn http_error_mapping_terminal_statuses() {
        for status in [404u16, 409, 410] {
            let e = map_rust_backend_http_error(
                reqwest::StatusCode::from_u16(status).unwrap(),
                b"",
                None,
            );
            assert!(matches!(e, BackendError::Terminal(_)), "HTTP {status}");
        }
    }

    #[test]
    fn http_error_mapping_rate_limit_carries_retry_hint() {
        let e = map_rust_backend_http_error(reqwest::StatusCode::TOO_MANY_REQUESTS, b"", Some(30));
        assert!(matches!(e, BackendError::Transient(_)));
        assert_eq!(e.retry_after_seconds(), Some(30));

        let e = map_rust_backend_http_error(reqwest::StatusCode::TOO_MANY_REQUESTS, b"", None);
        assert!(matches!(e, BackendError::Transient(_)));
        assert_eq!(e.retry_after_seconds(), None);
    }

    #[test]
    fn http_error_mapping_server_errors_transient() {
        for status in [500u16, 502, 503, 599] {
            let e = map_rust_backend_http_error(
                reqwest::StatusCode::from_u16(status).unwrap(),
                b"",
                None,
            );
            assert!(matches!(e, BackendError::Transient(_)), "HTTP {status}");
        }
        // Unclassified non-2xx defaults to Transient per §4.4.
        let e = map_rust_backend_http_error(reqwest::StatusCode::IM_A_TEAPOT, b"", None);
        assert!(matches!(e, BackendError::Transient(_)));
    }
}
