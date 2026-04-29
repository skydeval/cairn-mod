//! `OzoneBackend` skeleton for bsky-PDS (#86, v1.7; Phase B).
//!
//! Implements the [`PdsAdminBackend`] trait against the operator's
//! bsky-PDS using HTTP Basic auth (admin password from
//! `[pds_admin.ozone].admin_password_env`). v1.7 ships the structural
//! shape so subsequent issues fill in method bodies one at a time:
//!
//! - **#86 (this file)** — struct + ctor + helper functions
//!   (`xrpc_url`, `basic_auth_header`, `map_reqwest_error`); trait
//!   impl with `unimplemented!()` placeholders for the mutating
//!   methods. The label methods (`apply_label`, `negate_label`)
//!   already return [`BackendError::Unsupported`] per §A5 — that's
//!   the **final v1.7 behavior**, not a placeholder. cairn-mod's own
//!   `subscribeLabels` (§F4) is the label distribution surface;
//!   bsky-PDS doesn't implement those routes.
//! - **#87** — `takedown_account` body via
//!   `com.atproto.admin.updateSubjectStatus` + integration with the
//!   recordAction pipeline.
//! - **#88** — `suspend_account` + `restore_account` bodies.
//! - **#89** — refines the `apply_label`/`negate_label`
//!   `Unsupported` behavior (docs / tighter test surface). Code-wise
//!   nothing changes; the methods already return their final value.
//! - **#90** — `probe()` startup-probe trait method (per §A15);
//!   adds `probe()` to the trait + the OzoneBackend impl.
//!
//! Construction validates the config but does NOT touch the network.
//! Probe runs at startup separately (#90).

use std::fmt;

use async_trait::async_trait;
use base64::Engine as _;
use url::Url;

use crate::pds_admin::backend::{BackendActionId, BackendError, BackendInitError, PdsAdminBackend};
use crate::pds_admin::config::{AdminPassword, OzoneBackendConfig};
use crate::pds_admin::types::Subject;

/// PDS-side enforcement backend for bsky-PDS.
///
/// Calls `com.atproto.admin.*` routes on the operator's bsky-PDS
/// using HTTP Basic auth (admin password from
/// `[pds_admin.ozone].admin_password_env`). The label methods
/// (`apply_label`, `negate_label`) deliberately return
/// [`BackendError::Unsupported`] per §A5 in
/// `v1_7-architectural-decisions.md` — bsky-PDS doesn't implement
/// label-apply at the protocol layer, and cairn-mod's own
/// `subscribeLabels` (§F4) is the label distribution surface.
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
pub struct OzoneBackend {
    /// HTTP client. Reused across calls; reqwest's connection
    /// pool handles keepalive transparently. Consumed by the
    /// per-method call sites in #87 (`takedown_account`) and
    /// #88 (`suspend_account`, `restore_account`); not exercised
    /// by any code path in #86.
    #[allow(dead_code)]
    client: reqwest::Client,
    /// Base URL of the PDS, e.g. `https://bsky.example.com`.
    /// Always `https://` per #83's config validation. Trailing
    /// slash is added when constructing per-method URLs (see
    /// [`Self::xrpc_url`]) so input shape doesn't matter.
    base_url: Url,
    /// Admin password for HTTP Basic auth. Stored as the
    /// redacting / zero-on-drop newtype from #83. Consumed by
    /// the per-method call sites in #87 / #88 via
    /// [`Self::basic_auth_header`].
    #[allow(dead_code)]
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
    ///
    /// Lib-time consumers land in #87/#88 (the per-method call
    /// sites). #86 only exercises the helper through tests.
    #[allow(dead_code)]
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
    /// which would also work; the standalone helper exists so #87+
    /// can verify byte-for-byte encoding in unit tests without
    /// constructing a request, and so the `admin:` username (which
    /// is bsky-PDS's hard-coded admin handle, not operator-
    /// configurable) is single-sourced here.
    ///
    /// Lib-time consumers land in #87/#88. #86 only exercises the
    /// helper through tests.
    #[allow(dead_code)]
    pub(crate) fn basic_auth_header(&self) -> String {
        let creds = format!("admin:{}", self.admin_password.as_str());
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
        format!("Basic {encoded}")
    }

    /// Map a `reqwest::Error` (transport-layer failure) to the
    /// matching [`BackendError`] variant. Response-body envelope
    /// decoding (the JSON `{"error": "...", "message": "..."}`
    /// shape bsky-PDS returns) lives in #87 alongside the per-method
    /// call sites — that needs the response body, which this helper
    /// doesn't have.
    ///
    /// Categorization rules:
    /// - Timeout / connect failures → [`BackendError::Network`].
    /// - Status-code errors here are unexpected (callers in #87+
    ///   use the response body before reaching the error helper),
    ///   so this branch is best-effort and rarely hit. Mapped to
    ///   [`BackendError::RemoteError`] with the raw status code.
    /// - Everything else → [`BackendError::Network`] (unknown
    ///   transport failure; operators see the verbatim message).
    ///
    /// Consumed by #87+ at every per-method call site. Not unit-
    /// tested in #86 because `reqwest::Error` has no public
    /// constructor — testing it requires driving an actual failing
    /// HTTP request, which #87's wiremock-based tests will do.
    #[allow(dead_code)]
    pub(crate) fn map_reqwest_error(err: reqwest::Error) -> BackendError {
        if err.is_timeout() || err.is_connect() {
            BackendError::Network(err.to_string())
        } else if err.is_status() {
            let code = err
                .status()
                .map(|s| s.as_u16().to_string())
                .unwrap_or_default();
            BackendError::RemoteError {
                code,
                message: err.to_string(),
            }
        } else {
            BackendError::Network(err.to_string())
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

#[async_trait]
impl PdsAdminBackend for OzoneBackend {
    async fn takedown_account(
        &self,
        _did: &str,
        _reason: &str,
        _notes: Option<&str>,
    ) -> Result<BackendActionId, BackendError> {
        unimplemented!("OzoneBackend::takedown_account lands in chainlink #87")
    }

    async fn suspend_account(
        &self,
        _did: &str,
        _reason: &str,
        _duration_days: Option<u32>,
        _notes: Option<&str>,
    ) -> Result<BackendActionId, BackendError> {
        unimplemented!("OzoneBackend::suspend_account lands in chainlink #88")
    }

    async fn restore_account(
        &self,
        _did: &str,
        _prior_action_id: &BackendActionId,
        _reason: &str,
    ) -> Result<(), BackendError> {
        unimplemented!("OzoneBackend::restore_account lands in chainlink #88")
    }

    /// Returns [`BackendError::Unsupported`] — bsky-PDS does not
    /// implement label-apply at the protocol layer, and cairn-mod's
    /// own `subscribeLabels` (§F4) is the label distribution
    /// surface. Per §A5 in v1.7 architectural decisions; #83's
    /// action_map validation rejects configurations that would
    /// route label actions to this backend, so reaching this method
    /// at runtime is a configuration bug.
    async fn apply_label(
        &self,
        _subject: &Subject,
        _val: &str,
        _expires_days: Option<u32>,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unsupported(
            "OzoneBackend does not implement apply_label; \
             cairn-mod's subscribeLabels (§F4) is the label distribution surface \
             (see §A5 in v1.7 architectural decisions)",
        ))
    }

    /// Returns [`BackendError::Unsupported`] — same rationale as
    /// [`Self::apply_label`].
    async fn negate_label(&self, _subject: &Subject, _val: &str) -> Result<(), BackendError> {
        Err(BackendError::Unsupported(
            "OzoneBackend does not implement negate_label; \
             cairn-mod's subscribeLabels (§F4) is the label distribution surface \
             (see §A5 in v1.7 architectural decisions)",
        ))
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
    async fn apply_label_returns_unsupported() {
        let backend = fixture_backend("https://bsky.example.com");
        let res = backend
            .apply_label(&Subject::account("did:plc:abc"), "spam", None)
            .await;
        match res {
            Err(BackendError::Unsupported(msg)) => {
                assert!(
                    msg.contains("apply_label"),
                    "message names the method: {msg}"
                );
                assert!(
                    msg.contains("§A5") || msg.contains("A5"),
                    "cites §A5: {msg}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn negate_label_returns_unsupported() {
        let backend = fixture_backend("https://bsky.example.com");
        let res = backend
            .negate_label(&Subject::account("did:plc:abc"), "spam")
            .await;
        match res {
            Err(BackendError::Unsupported(msg)) => {
                assert!(
                    msg.contains("negate_label"),
                    "message names the method: {msg}"
                );
                assert!(
                    msg.contains("§A5") || msg.contains("A5"),
                    "cites §A5: {msg}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[tokio::test]
    #[should_panic(expected = "OzoneBackend::takedown_account lands in chainlink #87")]
    async fn takedown_account_panics_pointing_at_issue_87() {
        let backend = fixture_backend("https://bsky.example.com");
        let _ = backend.takedown_account("did:plc:abc", "spam", None).await;
    }

    #[tokio::test]
    #[should_panic(expected = "OzoneBackend::suspend_account lands in chainlink #88")]
    async fn suspend_account_panics_pointing_at_issue_88() {
        let backend = fixture_backend("https://bsky.example.com");
        let _ = backend
            .suspend_account("did:plc:abc", "spam", Some(7), None)
            .await;
    }

    #[tokio::test]
    #[should_panic(expected = "OzoneBackend::restore_account lands in chainlink #88")]
    async fn restore_account_panics_pointing_at_issue_88() {
        let backend = fixture_backend("https://bsky.example.com");
        let _ = backend
            .restore_account("did:plc:abc", &BackendActionId::new("prior-1"), "rehab")
            .await;
    }
}
