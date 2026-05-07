//! `OzoneBackend` for bsky-PDS (Phase B; #86 skeleton, #87
//! `takedown_account` body).
//!
//! Implements the [`PdsAdminBackend`] trait against the operator's
//! bsky-PDS using HTTP Basic auth (admin password from
//! `[pds_admin.ozone].admin_password_env`). v1.7 builds the surface
//! one issue at a time:
//!
//! - **#86** — struct + ctor + helper functions (`xrpc_url`,
//!   `basic_auth_header`, `map_reqwest_error`); trait impl with
//!   `unimplemented!()` placeholders for the mutating methods.
//!   Label methods return [`BackendError::ArchitecturallyForbidden`]
//!   per the §F4 architectural invariant
//!   (final v1.7 behavior; cairn-mod's own `subscribeLabels` (§F4)
//!   is the label distribution surface).
//! - **#87 (this)** — `takedown_account` body via
//!   `com.atproto.admin.updateSubjectStatus` + the wire-protocol
//!   helpers (`synthesize_action_id`, `decode_xrpc_error_envelope`,
//!   `map_status_to_backend_error`, `parse_retry_after_seconds`).
//!   Trait signature gains `precipitating_action_id: i64` on
//!   `takedown_account` / `suspend_account` so backends without a
//!   native action id (bsky-PDS) can synthesize one. Integration
//!   into the recordAction pipeline lives in
//!   [`crate::pds_admin::dispatch`].
//! - **#88** — `suspend_account` + `restore_account` bodies.
//! - **#89** — refines `apply_label`/`negate_label` docs/tests
//!   (no code change; methods already return their final value).
//! - **#90** — `probe()` startup probe trait method (per §A15).
//!
//! Construction validates the config but does NOT touch the network.

use std::fmt;

use async_trait::async_trait;
use base64::Engine as _;
use url::Url;

use crate::pds_admin::backend::{
    BackendActionId, BackendError, BackendInitError, PdsAdminBackend, ProbeReport,
};
use crate::pds_admin::config::{AdminPassword, OzoneBackendConfig};
use crate::pds_admin::types::Subject;

/// PDS-side enforcement backend for bsky-PDS.
///
/// Calls `com.atproto.admin.*` routes on the operator's bsky-PDS
/// using HTTP Basic auth (admin password from
/// `[pds_admin.ozone].admin_password_env`). The label methods
/// (`apply_label`, `negate_label`) deliberately return
/// [`BackendError::ArchitecturallyForbidden`] per the §F4
/// architectural invariant (see
/// [`crate::pds_admin::backend::F4_INVARIANT_REASON`]):
/// cairn-mod's own `subscribeLabels` (§F4) is the canonical
/// label-distribution surface to the network, and emitting
/// labels via the upstream PDS would create a duplicate
/// emission path with audit-trail divergence.
///
/// # Cloning / sharing
///
/// `Clone` is intentional. Internal state is `reqwest::Client` (a
/// reference-counted handle that shares a connection pool across
/// clones), `url::Url` (cheap clone), and [`AdminPassword`] (a
/// zeroizing newtype that allocates a fresh `String` on clone).
/// Keeping the type cloneable lets the writer task share one
/// instance across multiple in-flight calls without an `Arc` wrap
/// at every call site.
///
/// # Lifecycle
///
/// Constructed once at startup from validated [`OzoneBackendConfig`].
/// Construction does NOT probe the PDS — that's #90's
/// `probe()` trait method. Subsequent calls handle their own
/// transient-network retries (well, *will* in v1.8; v1.7 is
/// fail-loud per §A13).
#[derive(Clone)]
pub struct OzoneBackend {
    /// HTTP client. Reused across calls; reqwest's connection
    /// pool handles keepalive transparently.
    client: reqwest::Client,
    /// Base URL of the PDS, e.g. `https://bsky.example.com`.
    /// Always `https://` per #83's config validation. Trailing
    /// slash is added when constructing per-method URLs (see
    /// [`Self::xrpc_url`]) so input shape doesn't matter.
    base_url: Url,
    /// Admin password for HTTP Basic auth. Stored as the
    /// redacting / zero-on-drop newtype from #83.
    admin_password: AdminPassword,
}

impl OzoneBackend {
    /// Construct an [`OzoneBackend`] from validated config.
    ///
    /// Configures the HTTP client with the operator-set per-request
    /// timeout (resolved at config-load time per #83's clamp to
    /// 1..=60 seconds) and a `User-Agent` identifying cairn-mod.
    ///
    /// Does NOT perform network I/O. The startup probe (per §A15)
    /// is a separate call site landing in #90; this constructor
    /// stays pure so config-load can succeed even when the PDS is
    /// briefly unreachable.
    pub fn new(config: &OzoneBackendConfig) -> Result<Self, BackendInitError> {
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .user_agent(concat!("cairn-mod/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| BackendInitError::HttpClient(e.to_string()))?;

        Ok(Self {
            client,
            base_url: config.pds_url.clone(),
            admin_password: config.admin_password.clone(),
        })
    }

    /// Construct the full URL for an admin XRPC method.
    ///
    /// Mirrors the `cli/pds.rs::endpoint` pattern: ensures the base
    /// URL's path ends with `/` before joining the relative
    /// `xrpc/<nsid>` segment, so a base URL specified without a
    /// trailing slash (the typical operator-config form,
    /// `https://bsky.example.com`) joins correctly.
    ///
    /// `Url::join` is the failure mode here: it returns an error
    /// only if the joined string isn't a valid relative reference,
    /// which is impossible for the fixed `xrpc/<nsid>` shape with a
    /// non-pathological NSID. The fallible return preserves a clean
    /// error path for v1.8+ where NSIDs may come from external
    /// sources.
    pub(crate) fn xrpc_url(&self, nsid: &str) -> Result<Url, BackendError> {
        let mut base = self.base_url.clone();
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        base.join(&format!("xrpc/{nsid}"))
            .map_err(|e| BackendError::Validation(format!("malformed nsid {nsid:?}: {e}")))
    }

    /// Build the `Authorization` header value for HTTP Basic auth
    /// against the configured admin credentials.
    ///
    /// Returns the full header value `Basic <base64(admin:password)>`
    /// using base64 STANDARD (with padding) per RFC 7617 §2 — the
    /// HTTP Basic auth profile, distinct from the URL-safe variant
    /// the JWT layer in `crate::auth` uses.
    ///
    /// Reqwest exposes
    /// [`RequestBuilder::basic_auth`](reqwest::RequestBuilder::basic_auth)
    /// which would also work; the standalone helper exists so #87
    /// could byte-for-byte test the encoding without a request and
    /// so the `admin:` username (which is bsky-PDS's hard-coded
    /// admin handle, not operator-configurable) is single-sourced
    /// here. Call sites in #87+ use this helper.
    pub(crate) fn basic_auth_header(&self) -> String {
        let creds = format!("admin:{}", self.admin_password.as_str());
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
        format!("Basic {encoded}")
    }

    /// Map a `reqwest::Error` (transport-layer failure) to the
    /// matching [`BackendError`] variant. Response-body envelope
    /// decoding (the `{"error": "...", "message": "..."}` shape
    /// bsky-PDS returns for non-2xx responses) is handled by
    /// [`map_status_to_backend_error`] — this helper covers the
    /// "request never reached a status code" cases (DNS failure,
    /// connection refused, TLS handshake failure, read timeout
    /// mid-body, etc.).
    pub(crate) fn map_reqwest_error(err: reqwest::Error) -> BackendError {
        if err.is_status() {
            // Reachable only if a caller used `.error_for_status()`
            // and is mapping the result here; the mutating-method
            // bodies inspect the status before reading the body, so
            // this branch is unused in practice. Mark as transient
            // with a [sub_classification=RemoteError ...] marker so
            // the wire-level status survives the migration.
            let code = err
                .status()
                .map(|s| s.as_u16().to_string())
                .unwrap_or_default();
            BackendError::Transient(format!(
                "[sub_classification=RemoteError code={code}] {err}"
            ))
        } else {
            // Transport-level failures (DNS, TCP, TLS, timeout,
            // mid-body read) are all transient by nature.
            BackendError::Transient(err.to_string())
        }
    }
}

/// Custom Debug excludes the admin password (which has its own
/// redacting Debug already, but the outer struct's auto-Debug
/// would still print it through `AdminPassword`'s Debug impl —
/// which DOES redact, but printing a struct with a redacted-but-
/// present field in operator-facing logs is noisier than printing
/// just the URL). Skip the password field entirely.
impl fmt::Debug for OzoneBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OzoneBackend")
            .field("base_url", &self.base_url.as_str())
            .field("admin_password", &"<redacted>")
            .finish()
    }
}

// ===========================================================================
// Wire-protocol helpers (#87)
// ===========================================================================

/// Synthesize a deterministic [`BackendActionId`] for a backend
/// that doesn't return one of its own.
///
/// bsky-PDS's `com.atproto.admin.updateSubjectStatus` returns 200
/// with an empty JSON body — no action identifier. cairn-mod
/// produces one client-side so the recordAction pipeline + audit
/// row + future `restore_account` lookups have a stable handle.
///
/// Format: `ozone:{did}:{precipitating_action_id}`
/// - `ozone:` prefix identifies the backend that issued the id
///   (forward-compat for v1.8's `LocusBackend` which will use its
///   own native ids prefixed `locus:`).
/// - `{did}` carries the subject for forensic readability.
/// - `{precipitating_action_id}` is the cairn-mod-side
///   `subject_actions(id)` — guaranteed unique by SQLite, gives a
///   clean back-pointer.
fn synthesize_action_id(did: &str, precipitating_action_id: i64) -> BackendActionId {
    BackendActionId::new(format!("ozone:{did}:{precipitating_action_id}"))
}

/// Decode bsky-PDS's XRPC error-envelope JSON.
///
/// bsky-PDS returns non-2xx responses as
/// `{"error": "<code>", "message": "<human readable>"}` per the
/// XRPC spec (bsky-PDS findings §6.3). Returns `Some((code,
/// message))` when the body parses; `None` for malformed bodies
/// (which the caller treats as raw transport content).
///
/// `message` is optional in the wire shape; the helper substitutes
/// an empty string when absent.
fn decode_xrpc_error_envelope(body: &[u8]) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let code = v.get("error")?.as_str()?.to_string();
    let message = v
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    Some((code, message))
}

/// Parse a `Retry-After` header value as integer-seconds.
///
/// RFC 7231 §7.1.3 permits two forms: integer-seconds and
/// HTTP-date. v1.7 only handles integer-seconds — bsky-PDS sends
/// integers in practice, and the HTTP-date form is rare enough to
/// punt. `None` on parse failure (caller treats as "no hint").
fn parse_retry_after_seconds(header: &reqwest::header::HeaderValue) -> Option<u32> {
    header.to_str().ok()?.trim().parse::<u32>().ok()
}

/// Map an HTTP status code (with the response body and an optional
/// `Retry-After` hint) into the matching [`BackendError`] variant
/// per the v1.8.1 taxonomy.
///
/// Status-class dispositions:
/// - **400** with `InvalidRequest` and a subject/did message →
///   [`BackendError::Validation`] (the operator's request was
///   malformed in a way that names the subject).
/// - **400** otherwise → [`BackendError::Validation`] with a
///   `[sub_classification=RemoteError code={code}]` marker
///   prepended. (Status-class is request-shape; the marker
///   preserves the wire-level error code for forensics.)
/// - **401 / 403** → [`BackendError::Auth`].
/// - **404 / 409 / 410** → [`BackendError::Terminal`] with a
///   `[sub_classification=RemoteError code={code}]` marker — these
///   are upstream-state rejections, not request-shape problems.
/// - **429** → [`BackendError::Transient`] with a
///   `[sub_classification=RateLimited retry_after_seconds=N]` (or
///   `[sub_classification=RateLimited]` when no hint was supplied)
///   marker prepended. Operators query the retry hint via
///   [`BackendError::retry_after_seconds`].
/// - **500 / 502 / 503 / 504** → [`BackendError::Transient`]
///   (transient infrastructure; not auth or validation).
/// - **Other 5xx** (e.g., 599) → [`BackendError::Transient`] with
///   `[sub_classification=RemoteError code={code}]` — preserves
///   the wire-level status while keeping the operator affordance
///   ("try again later") intact for the unrecognized-server-failure
///   shape.
/// - **Other** (any non-2xx not classified above) →
///   [`BackendError::Terminal`] with
///   `[sub_classification=RemoteError code={code}]`. Defaults to
///   Terminal because we don't know whether retrying is safe for
///   an unrecognized status class.
///
/// Bodies that don't parse as the XRPC envelope fall back to
/// using the raw bytes (best-effort) for the message.
pub(crate) fn map_status_to_backend_error(
    status: reqwest::StatusCode,
    body: &[u8],
    retry_after_seconds: Option<u32>,
) -> BackendError {
    let envelope = decode_xrpc_error_envelope(body);
    let lossy_body = || String::from_utf8_lossy(body).into_owned();

    match status.as_u16() {
        400 => {
            let (code, message) =
                envelope.unwrap_or_else(|| ("InvalidRequest".to_string(), lossy_body()));
            // bsky-PDS's "InvalidRequest" with subject/did wording is
            // the request-shape failure; everything else under 400
            // is still a request-shape failure (per the v1.8.1
            // taxonomy: 400/422 are Validation by status class) but
            // carries the wire-level error code in a marker for
            // forensics.
            if code == "InvalidRequest" {
                let lower = message.to_ascii_lowercase();
                if lower.contains("subject") || lower.contains("did") {
                    return BackendError::Validation(message);
                }
            }
            BackendError::Validation(format!(
                "[sub_classification=RemoteError code={code}] {message}"
            ))
        }
        401 | 403 => {
            let message = envelope.map(|(_, m)| m).unwrap_or_else(lossy_body);
            BackendError::Auth(format!("HTTP {}: {}", status.as_u16(), message))
        }
        404 | 409 | 410 => {
            let (code, message) =
                envelope.unwrap_or_else(|| (status.as_u16().to_string(), lossy_body()));
            BackendError::Terminal(format!(
                "[sub_classification=RemoteError code={code}] {message}"
            ))
        }
        429 => {
            let message = envelope
                .map(|(_, m)| m)
                .unwrap_or_else(|| "rate limited".to_string());
            let marker = match retry_after_seconds {
                Some(n) => format!("[sub_classification=RateLimited retry_after_seconds={n}]"),
                None => "[sub_classification=RateLimited]".to_string(),
            };
            BackendError::Transient(format!("{marker} {message}"))
        }
        500 | 502 | 503 | 504 => BackendError::Transient(format!(
            "HTTP {}: {}",
            status.as_u16(),
            envelope.map(|(_, m)| m).unwrap_or_else(lossy_body)
        )),
        s if (500..600).contains(&s) => {
            // Unrecognized 5xx (e.g., 599). Still transient by
            // status class; preserve the wire-level code.
            let (code, message) =
                envelope.unwrap_or_else(|| (status.as_u16().to_string(), lossy_body()));
            BackendError::Transient(format!(
                "[sub_classification=RemoteError code={code}] {message}"
            ))
        }
        _ => {
            // Any other status class (1xx redirects we didn't follow,
            // 3xx, exotic codes). Default to Terminal — we don't know
            // whether retry is safe.
            let (code, message) =
                envelope.unwrap_or_else(|| (status.as_u16().to_string(), lossy_body()));
            BackendError::Terminal(format!(
                "[sub_classification=RemoteError code={code}] {message}"
            ))
        }
    }
}

#[async_trait]
impl PdsAdminBackend for OzoneBackend {
    /// Implements `com.atproto.admin.updateSubjectStatus` per
    /// bsky-PDS findings §6.1.
    ///
    /// Wire shape:
    /// ```json
    /// {
    ///   "subject": {
    ///     "$type": "com.atproto.admin.defs#repoRef",
    ///     "did": "did:plc:..."
    ///   },
    ///   "takedown": {
    ///     "applied": true,
    ///     "ref": "cairn-mod:action_id={id}:reason={reason}"
    ///   }
    /// }
    /// ```
    ///
    /// `notes` is intentionally NOT mirrored to the wire body —
    /// it's a cairn-mod-internal moderator artifact stored on the
    /// `subject_actions` row. Operators wanting notes propagated
    /// can put them in the reason vocabulary; the `ref` field is
    /// for cross-system forensic tracking, not narrative content.
    ///
    /// Success: bsky-PDS returns 200 with `{}` body. Since no
    /// action id is returned, this method mints one client-side
    /// (`ozone:{did}:{precipitating_action_id}` — see the
    /// `synthesize_action_id` helper below) for use by the audit
    /// row and any future `restore_account` lookup.
    async fn takedown_account(
        &self,
        did: &str,
        reason: &str,
        notes: Option<&str>,
        precipitating_action_id: i64,
    ) -> Result<BackendActionId, BackendError> {
        let _ = notes;
        let url = self.xrpc_url("com.atproto.admin.updateSubjectStatus")?;

        let body = serde_json::json!({
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": did,
            },
            "takedown": {
                "applied": true,
                "ref": format!("cairn-mod:action_id={precipitating_action_id}:reason={reason}"),
            },
        });

        let response = self
            .client
            .post(url)
            .header(reqwest::header::AUTHORIZATION, self.basic_auth_header())
            .json(&body)
            .send()
            .await
            .map_err(Self::map_reqwest_error)?;

        let status = response.status();
        if status.is_success() {
            return Ok(synthesize_action_id(did, precipitating_action_id));
        }

        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(parse_retry_after_seconds);
        let body_bytes = response.bytes().await.unwrap_or_default();
        Err(map_status_to_backend_error(
            status,
            &body_bytes,
            retry_after,
        ))
    }

    /// Implements `com.atproto.admin.updateSubjectStatus` per
    /// bsky-PDS findings §6.1, structurally identical to
    /// [`Self::takedown_account`].
    ///
    /// bsky-PDS has no separate "suspend" endpoint — suspension is
    /// expressed as a takedown that the operator (or cairn-mod's
    /// future deferred-execution layer in v1.8) lifts via
    /// [`Self::restore_account`] when the duration elapses. v1.7
    /// does NOT auto-lift; the operator runs `cairn moderator
    /// revoke <action_id>` (which fires
    /// [`crate::pds_admin::dispatch::dispatch_after_revoke_action`])
    /// manually.
    ///
    /// `duration_days` is encoded in the `ref` field so an
    /// operator inspecting the bsky-PDS admin queue can
    /// distinguish a temp suspension from an indefinite one:
    /// - `Some(n)` → `duration_days={n}` (temp_suspension)
    /// - `None`    → `duration_days=indef` (indef_suspension; same
    ///   wire effect as takedown but the cairn-mod-side action_type
    ///   is preserved for forensics)
    async fn suspend_account(
        &self,
        did: &str,
        reason: &str,
        duration_days: Option<u32>,
        notes: Option<&str>,
        precipitating_action_id: i64,
    ) -> Result<BackendActionId, BackendError> {
        let _ = notes;
        let url = self.xrpc_url("com.atproto.admin.updateSubjectStatus")?;

        let duration_token = match duration_days {
            Some(n) => format!("{n}"),
            None => "indef".to_string(),
        };
        let body = serde_json::json!({
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": did,
            },
            "takedown": {
                "applied": true,
                "ref": format!(
                    "cairn-mod:action_id={precipitating_action_id}:reason={reason}:duration_days={duration_token}"
                ),
            },
        });

        let response = self
            .client
            .post(url)
            .header(reqwest::header::AUTHORIZATION, self.basic_auth_header())
            .json(&body)
            .send()
            .await
            .map_err(Self::map_reqwest_error)?;

        let status = response.status();
        if status.is_success() {
            return Ok(synthesize_action_id(did, precipitating_action_id));
        }

        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(parse_retry_after_seconds);
        let body_bytes = response.bytes().await.unwrap_or_default();
        Err(map_status_to_backend_error(
            status,
            &body_bytes,
            retry_after,
        ))
    }

    /// Implements `com.atproto.admin.updateSubjectStatus` with
    /// `takedown.applied = false` to lift a prior takedown or
    /// suspension.
    ///
    /// `prior_action_id` is the [`BackendActionId`] from the
    /// original takedown / suspend call (synthesized by the
    /// crate-internal `synthesize_action_id` helper at the time,
    /// format `ozone:{did}:{precipitating_action_id}`). Encoded in the
    /// `ref` field for cross-system traceability — it lets an
    /// operator inspecting the bsky-PDS admin queue see "this
    /// restore corresponds to that earlier takedown."
    /// bsky-PDS itself doesn't track prior takedown ids; the
    /// parameter is purely for cairn-mod's forensic audit log
    /// + operator-readable bsky-PDS context.
    ///
    /// # Idempotent restore
    ///
    /// bsky-PDS's actual behavior on already-restored accounts
    /// is **unconfirmed** as of #89 — the wiremock tests cover
    /// both 200 (idempotent success) and 400 (Conflict) paths.
    /// Phase B verification against staging will surface which
    /// is the real-world response; if 400-Conflict is the actual
    /// shape, the dispatch path's WARN-and-continue posture is
    /// already operator-friendly (the audit row records the
    /// conflict and operators see "tried to lift; was already
    /// lifted" — which is a benign discrepancy).
    async fn restore_account(
        &self,
        did: &str,
        prior_action_id: &BackendActionId,
        reason: &str,
    ) -> Result<(), BackendError> {
        let url = self.xrpc_url("com.atproto.admin.updateSubjectStatus")?;

        let body = serde_json::json!({
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": did,
            },
            "takedown": {
                "applied": false,
                "ref": format!(
                    "cairn-mod:restore:prior_action_id={}:reason={reason}",
                    prior_action_id.as_str()
                ),
            },
        });

        let response = self
            .client
            .post(url)
            .header(reqwest::header::AUTHORIZATION, self.basic_auth_header())
            .json(&body)
            .send()
            .await
            .map_err(Self::map_reqwest_error)?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(parse_retry_after_seconds);
        let body_bytes = response.bytes().await.unwrap_or_default();
        Err(map_status_to_backend_error(
            status,
            &body_bytes,
            retry_after,
        ))
    }

    /// Returns [`BackendError::ArchitecturallyForbidden`] carrying
    /// [`crate::pds_admin::backend::F4_INVARIANT_REASON`] — cairn-mod's
    /// `subscribeLabels` (§F4) is the canonical label-distribution
    /// surface to the network, and emitting labels via the upstream
    /// PDS would create a duplicate emission path with audit-trail
    /// divergence. The §F4 invariant applies regardless of which
    /// backend the upstream PDS is. #83's action_map validation
    /// rejects configurations that would route label actions to a
    /// PDS-admin backend, so reaching this method at runtime is a
    /// configuration bug.
    async fn apply_label(
        &self,
        _subject: &Subject,
        _val: &str,
        _expires_days: Option<u32>,
    ) -> Result<(), BackendError> {
        Err(BackendError::ArchitecturallyForbidden(
            crate::pds_admin::backend::F4_INVARIANT_REASON.to_string(),
        ))
    }

    /// Returns [`BackendError::ArchitecturallyForbidden`] — same
    /// rationale as [`Self::apply_label`].
    async fn negate_label(&self, _subject: &Subject, _val: &str) -> Result<(), BackendError> {
        Err(BackendError::ArchitecturallyForbidden(
            crate::pds_admin::backend::F4_INVARIANT_REASON.to_string(),
        ))
    }

    /// Probes the configured bsky-PDS via
    /// `GET /xrpc/com.atproto.server.describeServer`.
    ///
    /// Sends the configured admin Basic credentials. bsky-PDS's
    /// `describeServer` is technically a public service-discovery
    /// endpoint and ignores the extra header in current versions
    /// (verified per bsky-PDS findings); sending auth proves the
    /// credential is parseable and at least minimally accepted,
    /// rather than deferring auth verification to the first real
    /// (mutating) call. If a future bsky-PDS version starts
    /// rejecting authenticated probes, this would surface as a
    /// startup-WARN and the probe code can be revisited.
    ///
    /// Response handling:
    /// - **200 with parseable JSON object** → `Ok(ProbeReport)`
    ///   with `detected_version = None` and `capabilities = []`
    ///   (bsky-PDS doesn't expose a version field in
    ///   describeServer's v0.4.x response shape; v1.8 may grow
    ///   this).
    /// - **200 with non-JSON or non-object body** →
    ///   `RemoteError { code: "InvalidResponse", ... }`. The URL
    ///   points at something that isn't a bsky-PDS.
    /// - **401 / 403** → `Auth(...)`. Even on a public endpoint,
    ///   401 with our admin Basic header is a strong "credentials
    ///   are misconfigured" signal.
    /// - **Other status / network errors** → status- or
    ///   transport-mapped via the crate-internal
    ///   `map_status_to_backend_error` and `map_reqwest_error`
    ///   helpers (same helpers the mutating methods use; one
    ///   source of truth for error classification).
    async fn probe(&self) -> Result<ProbeReport, BackendError> {
        let url = self.xrpc_url("com.atproto.server.describeServer")?;

        let response = self
            .client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, self.basic_auth_header())
            .send()
            .await
            .map_err(Self::map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(parse_retry_after_seconds);
            let body_bytes = response.bytes().await.unwrap_or_default();
            return Err(map_status_to_backend_error(
                status,
                &body_bytes,
                retry_after,
            ));
        }

        // 200: confirm the body is a JSON object. We don't act on
        // any specific field — describeServer's response shape is
        // operator-data (DID, available domains, T&C URLs); our
        // job is just to confirm something resembling a PDS
        // answered.
        let body_bytes = response.bytes().await.map_err(Self::map_reqwest_error)?;
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(serde_json::Value::Object(_)) => Ok(ProbeReport {
                backend_name: "ozone",
                pds_url: self.base_url.as_str().to_string(),
                detected_version: None,
                capabilities: Vec::new(),
            }),
            Ok(_) | Err(_) => Err(BackendError::Terminal(
                "[sub_classification=RemoteError code=InvalidResponse] \
                 describeServer returned a 200 with non-JSON-object body; \
                 configured pds_url likely doesn't point at a bsky-PDS"
                    .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture_config(base_url: &str) -> OzoneBackendConfig {
        OzoneBackendConfig {
            pds_url: Url::parse(base_url).unwrap(),
            admin_password: AdminPassword::new("hunter2".into()),
            request_timeout: Duration::from_secs(10),
        }
    }

    fn fixture_backend(base_url: &str) -> OzoneBackend {
        OzoneBackend::new(&fixture_config(base_url)).unwrap()
    }

    #[test]
    fn new_constructs_from_valid_config() {
        let backend = OzoneBackend::new(&fixture_config("https://bsky.example.com")).unwrap();
        assert_eq!(backend.base_url.as_str(), "https://bsky.example.com/");
    }

    #[test]
    fn debug_redacts_admin_password() {
        let backend = fixture_backend("https://bsky.example.com");
        let debug = format!("{backend:?}");
        assert!(
            !debug.contains("hunter2"),
            "Debug must not leak admin password"
        );
        assert!(
            debug.contains("<redacted>"),
            "Debug must surface the redaction marker"
        );
    }

    #[test]
    fn xrpc_url_appends_xrpc_path_to_root_base() {
        let backend = fixture_backend("https://bsky.example.com");
        let url = backend
            .xrpc_url("com.atproto.admin.updateSubjectStatus")
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://bsky.example.com/xrpc/com.atproto.admin.updateSubjectStatus"
        );
    }

    #[test]
    fn xrpc_url_handles_base_with_trailing_slash() {
        let backend = fixture_backend("https://bsky.example.com/");
        let url = backend
            .xrpc_url("com.atproto.admin.updateSubjectStatus")
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://bsky.example.com/xrpc/com.atproto.admin.updateSubjectStatus"
        );
    }

    #[test]
    fn xrpc_url_preserves_subpath_with_trailing_slash() {
        // Uncommon but supported: PDS deployed under a sub-path.
        // Without the trailing-slash fix-up, Url::join would drop
        // the "pds" segment.
        let backend = fixture_backend("https://example.com/pds/");
        let url = backend
            .xrpc_url("com.atproto.server.describeServer")
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.com/pds/xrpc/com.atproto.server.describeServer"
        );
    }

    #[test]
    fn xrpc_url_fixes_up_subpath_without_trailing_slash() {
        // The fix-up branch — input has a non-empty path and no
        // trailing slash. The helper should add the slash before
        // joining so the existing path segments aren't dropped.
        let backend = fixture_backend("https://example.com/pds");
        let url = backend
            .xrpc_url("com.atproto.server.describeServer")
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.com/pds/xrpc/com.atproto.server.describeServer"
        );
    }

    #[test]
    fn basic_auth_header_encodes_admin_credentials() {
        // Pin the encoding byte-for-byte. base64("admin:hunter2") is
        // a deterministic value that operators / CI can verify against
        // RFC 7617's reference implementation.
        let backend = fixture_backend("https://bsky.example.com");
        let header = backend.basic_auth_header();
        // base64("admin:hunter2") = "YWRtaW46aHVudGVyMg=="
        assert_eq!(header, "Basic YWRtaW46aHVudGVyMg==");
    }

    #[test]
    fn basic_auth_header_handles_password_with_colon_and_special_chars() {
        // Admin passwords can contain anything; the encoder must
        // round-trip arbitrary bytes. RFC 7617 §2.1 explicitly
        // permits colons in passwords (only the FIRST colon
        // separates user from password on decode).
        let cfg = OzoneBackendConfig {
            pds_url: Url::parse("https://bsky.example.com").unwrap(),
            admin_password: AdminPassword::new("p@ss:w/ord+special".into()),
            request_timeout: Duration::from_secs(10),
        };
        let backend = OzoneBackend::new(&cfg).unwrap();
        let header = backend.basic_auth_header();
        let prefix = "Basic ";
        assert!(header.starts_with(prefix));
        let encoded = &header[prefix.len()..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(decoded, b"admin:p@ss:w/ord+special");
    }

    #[tokio::test]
    async fn apply_label_returns_architecturally_forbidden() {
        let backend = fixture_backend("https://bsky.example.com");
        let res = backend
            .apply_label(&Subject::account("did:plc:abc"), "spam", None)
            .await;
        match res {
            Err(BackendError::ArchitecturallyForbidden(msg)) => {
                assert!(
                    msg.contains("§F4"),
                    "message cites the §F4 architectural anchor: {msg}"
                );
                assert!(
                    msg.contains("subscribeLabels"),
                    "message names subscribeLabels as the canonical surface: {msg}"
                );
            }
            other => panic!("expected ArchitecturallyForbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn negate_label_returns_architecturally_forbidden() {
        let backend = fixture_backend("https://bsky.example.com");
        let res = backend
            .negate_label(&Subject::account("did:plc:abc"), "spam")
            .await;
        match res {
            Err(BackendError::ArchitecturallyForbidden(msg)) => {
                assert!(
                    msg.contains("§F4"),
                    "message cites the §F4 architectural anchor: {msg}"
                );
                assert!(
                    msg.contains("subscribeLabels"),
                    "message names subscribeLabels as the canonical surface: {msg}"
                );
            }
            other => panic!("expected ArchitecturallyForbidden, got {other:?}"),
        }
    }

    // (Per #89: the should_panic tests for suspend_account /
    // restore_account were removed when those bodies landed.
    // Their wire-shape verification now lives in the wiremock
    // integration tests in `tests/ozone_backend.rs`.)

    // ===== Helper unit tests (#87) =====

    #[test]
    fn synthesize_action_id_format() {
        let id = synthesize_action_id("did:plc:abc", 42);
        assert_eq!(id.as_str(), "ozone:did:plc:abc:42");
    }

    #[test]
    fn synthesize_action_id_handles_negative_action_id() {
        // i64 is signed; ids should always be positive in practice
        // but the formatter should not silently corrupt negatives.
        let id = synthesize_action_id("did:plc:x", -1);
        assert_eq!(id.as_str(), "ozone:did:plc:x:-1");
    }

    #[test]
    fn decode_xrpc_envelope_extracts_code_and_message() {
        let body = br#"{"error": "InvalidRequest", "message": "subject DID malformed"}"#;
        let (code, message) = decode_xrpc_error_envelope(body).unwrap();
        assert_eq!(code, "InvalidRequest");
        assert_eq!(message, "subject DID malformed");
    }

    #[test]
    fn decode_xrpc_envelope_message_optional() {
        let body = br#"{"error": "Foo"}"#;
        let (code, message) = decode_xrpc_error_envelope(body).unwrap();
        assert_eq!(code, "Foo");
        assert_eq!(message, "");
    }

    #[test]
    fn decode_xrpc_envelope_returns_none_for_malformed_body() {
        assert!(decode_xrpc_error_envelope(b"not json").is_none());
        assert!(decode_xrpc_error_envelope(b"{}").is_none());
        assert!(decode_xrpc_error_envelope(b"[]").is_none());
        assert!(decode_xrpc_error_envelope(b"").is_none());
    }

    #[test]
    fn map_status_400_invalid_request_with_subject_message_is_validation() {
        let body =
            br#"{"error": "InvalidRequest", "message": "subject DID is malformed"}"#.as_slice();
        let err = map_status_to_backend_error(reqwest::StatusCode::BAD_REQUEST, body, None);
        match err {
            BackendError::Validation(msg) => assert!(msg.contains("subject")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn map_status_400_invalid_request_without_subject_is_validation_with_marker() {
        // 400 by status class is Validation in v1.8.1's taxonomy; the
        // wire-level error code is preserved in a marker so forensics
        // and the Step 7 outcome mapping can still pivot on it.
        let body = br#"{"error": "InvalidRequest", "message": "rate limit exceeded"}"#.as_slice();
        let err = map_status_to_backend_error(reqwest::StatusCode::BAD_REQUEST, body, None);
        match &err {
            BackendError::Validation(msg) => assert!(
                msg.contains("[sub_classification=RemoteError code=InvalidRequest]"),
                "validation message carries the RemoteError marker: {msg}"
            ),
            other => panic!("expected Validation, got {other:?}"),
        }
        assert_eq!(err.error_code(), Some("InvalidRequest"));
    }

    #[test]
    fn map_status_404_is_terminal_with_remote_error_marker() {
        // 404 / 409 / 410 are upstream-state rejections — the v1.8.1
        // taxonomy classes them as Terminal regardless of the body shape.
        let body = br#"{"error": "NotFound", "message": "subject not found"}"#.as_slice();
        let err = map_status_to_backend_error(reqwest::StatusCode::NOT_FOUND, body, None);
        match &err {
            BackendError::Terminal(msg) => {
                assert!(msg.contains("[sub_classification=RemoteError code=NotFound]"))
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert_eq!(err.error_code(), Some("NotFound"));
    }

    #[test]
    fn map_status_409_is_terminal_with_remote_error_marker() {
        let body = br#"{"error": "Conflict", "message": "already taken down"}"#.as_slice();
        let err = map_status_to_backend_error(reqwest::StatusCode::CONFLICT, body, None);
        assert!(matches!(err, BackendError::Terminal(_)));
    }

    #[test]
    fn map_status_401_is_auth() {
        let body = br#"{"error": "AuthenticationRequired", "message": "bad password"}"#.as_slice();
        let err = map_status_to_backend_error(reqwest::StatusCode::UNAUTHORIZED, body, None);
        match err {
            BackendError::Auth(msg) => {
                assert!(msg.contains("401"));
                assert!(msg.contains("bad password"));
            }
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[test]
    fn map_status_403_is_auth() {
        let err = map_status_to_backend_error(reqwest::StatusCode::FORBIDDEN, b"forbidden", None);
        assert!(matches!(err, BackendError::Auth(_)));
    }

    #[test]
    fn map_status_429_is_transient_with_rate_limited_marker_and_retry_after() {
        let body = br#"{"error": "RateLimitExceeded", "message": "calm down"}"#.as_slice();
        let err =
            map_status_to_backend_error(reqwest::StatusCode::TOO_MANY_REQUESTS, body, Some(30));
        match &err {
            BackendError::Transient(msg) => {
                assert!(
                    msg.contains("[sub_classification=RateLimited retry_after_seconds=30]"),
                    "Transient message carries the rate-limited marker: {msg}"
                );
                assert!(msg.contains("calm down"));
            }
            other => panic!("expected Transient, got {other:?}"),
        }
        assert_eq!(err.retry_after_seconds(), Some(30));
    }

    #[test]
    fn map_status_429_without_retry_after_carries_marker_only() {
        let body = br#"{"error": "RateLimitExceeded", "message": "throttled"}"#.as_slice();
        let err = map_status_to_backend_error(reqwest::StatusCode::TOO_MANY_REQUESTS, body, None);
        match &err {
            BackendError::Transient(msg) => {
                assert!(msg.starts_with("[sub_classification=RateLimited]"));
                assert!(msg.contains("throttled"));
            }
            other => panic!("expected Transient, got {other:?}"),
        }
        assert_eq!(err.retry_after_seconds(), None);
    }

    #[test]
    fn map_status_5xx_transient_is_transient() {
        for code in [500u16, 502, 503, 504] {
            let status = reqwest::StatusCode::from_u16(code).unwrap();
            let err = map_status_to_backend_error(status, b"oops", None);
            assert!(
                matches!(err, BackendError::Transient(_)),
                "{code} should be Transient"
            );
        }
    }

    #[test]
    fn map_status_other_5xx_is_transient_with_remote_error_marker() {
        // 599 is still a 5xx — Transient by status class — but carries the
        // wire-level code in a marker so dashboards filtering by code can
        // still see it.
        let err = map_status_to_backend_error(
            reqwest::StatusCode::from_u16(599).unwrap(),
            b"unrecognized server failure",
            None,
        );
        match &err {
            BackendError::Transient(msg) => {
                assert!(msg.contains("[sub_classification=RemoteError code=599]"));
            }
            other => panic!("expected Transient, got {other:?}"),
        }
    }

    #[test]
    fn map_status_unknown_class_defaults_to_terminal() {
        // 3xx redirects we didn't follow, exotic codes — default to
        // Terminal because we don't know whether retry is safe.
        let err = map_status_to_backend_error(
            reqwest::StatusCode::from_u16(304).unwrap(),
            b"not modified",
            None,
        );
        match &err {
            BackendError::Terminal(msg) => {
                assert!(msg.contains("[sub_classification=RemoteError code=304]"));
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[test]
    fn parse_retry_after_seconds_handles_integer() {
        let header = reqwest::header::HeaderValue::from_static("30");
        assert_eq!(parse_retry_after_seconds(&header), Some(30));
    }

    #[test]
    fn parse_retry_after_seconds_rejects_http_date() {
        let header = reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT");
        assert_eq!(parse_retry_after_seconds(&header), None);
    }

    #[test]
    fn parse_retry_after_seconds_handles_whitespace() {
        let header = reqwest::header::HeaderValue::from_static("  120  ");
        assert_eq!(parse_retry_after_seconds(&header), Some(120));
    }
}
