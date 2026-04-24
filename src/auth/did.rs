//! DID resolution (§5.4).
//!
//! Resolves `did:plc` via the PLC directory and `did:web` via HTTPS
//! `.well-known/did.json` or the path-component variant. Resolution is
//! fronted by a [`DidResolver`] trait so auth tests can inject canned
//! documents without mocking TCP/TLS.
//!
//! **did:web path-component rule (§5.4):**
//! - `did:web:example.com`        → `https://example.com/.well-known/did.json`
//! - `did:web:example.com:a:b:c` → `https://example.com/a/b/c/did.json` (NO `.well-known`)
//!
//! The difference is load-bearing for interop; a unit test pins exactly
//! this distinction.

use async_trait::async_trait;
use serde::Deserialize;

use super::ssrf::SafeDnsResolver;

/// Categorical errors surfaced by the resolver. The auth layer maps all
/// of these to a single external `AuthenticationRequired` response per
/// §4 non-enumeration; variants exist here for internal logging only.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// DID method not supported (only `did:plc` and `did:web` are
    /// handled in v1).
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),

    /// DID string is not a valid DID.
    #[error("malformed DID: {0}")]
    Malformed(String),

    /// Transport-level failure reaching the resolver endpoint (DNS,
    /// TLS, timeout, connection refused).
    #[error("network error: {0}")]
    Network(String),

    /// Resolver endpoint returned a non-2xx status.
    #[error("non-success HTTP status: {0}")]
    BadStatus(u16),

    /// Response body was not a parseable DID document.
    #[error("body parse error: {0}")]
    Parse(String),

    /// SSRF filter refused to resolve the host (loopback, private
    /// range, or other disallowed target).
    #[error("SSRF protection rejected host: {0}")]
    SsrfBlocked(String),
}

/// Minimal DID document shape. We deliberately deserialize only the
/// fields Cairn uses (`id`, `verificationMethod`) — ignoring
/// `authentication`, `assertionMethod`, `service`, etc. — so random
/// extra fields and future additions don't break parsing.
#[derive(Debug, Clone, Deserialize)]
pub struct DidDocument {
    /// DID (matches the resolved subject).
    pub id: String,
    /// All declared verification methods. Cairn's code selects one
    /// by fragment via [`DidDocument::find_verification_method`].
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
}

/// One entry in a DID document's `verificationMethod` array.
#[derive(Debug, Clone, Deserialize)]
pub struct VerificationMethod {
    /// Full verification-method identifier, e.g.
    /// `did:plc:3jzfcijpj2z2a4pdagfkktq6#atproto`.
    pub id: String,
    /// Lower-case `type` field from the DID doc. Cairn only consumes
    /// `Multikey` in v1 but we parse the string to classify.
    #[serde(rename = "type")]
    pub r#type: String,
    /// Multibase-encoded public key (typically z-prefixed base58btc).
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

impl DidDocument {
    /// Find a verification method whose `id` ends with `fragment`
    /// (e.g. `"#atproto"` for the moderator repo key, `"#atproto_label"`
    /// for the labeler signing key).
    pub fn find_verification_method(&self, fragment: &str) -> Option<&VerificationMethod> {
        self.verification_method
            .iter()
            .find(|vm| vm.id.ends_with(fragment))
    }
}

/// Pluggable resolver. Production uses [`HttpDidResolver`]; tests inject
/// a canned-document resolver to avoid hitting wiremock for every JWT
/// shape under test.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// Resolve `did` to a DID document, or return the categorical
    /// failure. Implementors must fail closed — never return a
    /// partial / default document on error.
    async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError>;
}

/// Production HTTP resolver. Uses reqwest with rustls, with a custom
/// DNS resolver ([`SafeDnsResolver`]) that filters outbound targets to
/// block SSRF.
#[derive(Debug, Clone)]
pub struct HttpDidResolver {
    client: reqwest::Client,
    plc_directory_url: String,
}

impl HttpDidResolver {
    /// Construct a production resolver with the §F11 SSRF-filtering
    /// DNS resolver wired in. `timeout` applies to both connect and
    /// overall request.
    pub fn new(plc_directory_url: String, timeout: std::time::Duration) -> Self {
        Self::with_dns_resolver(plc_directory_url, timeout, SafeDnsResolver::arc())
    }

    /// Production alternative that lets callers plug in a DNS resolver.
    /// The default [`SafeDnsResolver`] blocks loopback and private ranges
    /// — correct for prod, but integration tests pointing at wiremock on
    /// 127.0.0.1 need a pass-through resolver. Tests should live behind
    /// `#[cfg(test)]` or a deliberate test helper; this constructor is
    /// public only because it has to cross the test/lib boundary.
    pub fn with_dns_resolver<R: reqwest::dns::Resolve + 'static>(
        plc_directory_url: String,
        timeout: std::time::Duration,
        dns: std::sync::Arc<R>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .dns_resolver(dns)
            // TLS defaults to rustls per the "rustls-tls" feature we
            // enabled in Cargo.toml — no certificate validation bypass.
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("reqwest client build");
        Self {
            client,
            plc_directory_url,
        }
    }

    /// Build the URL for a `did:web` resolution per §5.4. Public for
    /// unit testing — the path-component rule is easy to get wrong and
    /// the distinction is a wire-interop guarantee.
    pub fn did_web_url(did: &str) -> Result<url::Url, ResolveError> {
        let rest = did
            .strip_prefix("did:web:")
            .ok_or_else(|| ResolveError::Malformed("not a did:web".into()))?;
        if rest.is_empty() {
            return Err(ResolveError::Malformed("empty did:web body".into()));
        }

        // Host is everything up to the first `:` (if any). Per-spec, the
        // colon separates host from path components; percent-encoded
        // ports (`%3A`) stay within the host segment.
        let mut parts = rest.splitn(2, ':');
        let host_encoded = parts.next().unwrap_or("");
        let path_segment = parts.next();

        // Host may be percent-encoded (e.g. `example.com%3A8443`). Let
        // `url::Url::parse` do the decoding when we build the full URL.
        let url_str = match path_segment {
            None => format!("https://{host_encoded}/.well-known/did.json"),
            Some(rest) => {
                // Remaining components are colon-separated path segments
                // that become slash-separated URL path.
                let path = rest.replace(':', "/");
                format!("https://{host_encoded}/{path}/did.json")
            }
        };

        url::Url::parse(&url_str).map_err(|e| ResolveError::Malformed(format!("bad url: {e}")))
    }

    async fn resolve_plc(&self, did: &str) -> Result<DidDocument, ResolveError> {
        let url = format!("{}/{}", self.plc_directory_url.trim_end_matches('/'), did);
        self.fetch_did_doc(&url).await
    }

    async fn resolve_web(&self, did: &str) -> Result<DidDocument, ResolveError> {
        let url = Self::did_web_url(did)?;
        self.fetch_did_doc(url.as_str()).await
    }

    async fn fetch_did_doc(&self, url: &str) -> Result<DidDocument, ResolveError> {
        let resp = self.client.get(url).send().await.map_err(|e| {
            // reqwest wraps SSRF rejections as client errors. We can't
            // cleanly distinguish them at runtime without downcast, so
            // we surface as Network — the effect (fail-closed) is the
            // same and logs capture the full chain.
            if e.to_string().contains("SSRF") {
                ResolveError::SsrfBlocked(url.to_string())
            } else {
                ResolveError::Network(e.to_string())
            }
        })?;
        if !resp.status().is_success() {
            return Err(ResolveError::BadStatus(resp.status().as_u16()));
        }
        resp.json::<DidDocument>()
            .await
            .map_err(|e| ResolveError::Parse(e.to_string()))
    }
}

#[async_trait]
impl DidResolver for HttpDidResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError> {
        if did.starts_with("did:plc:") {
            self.resolve_plc(did).await
        } else if did.starts_with("did:web:") {
            self.resolve_web(did).await
        } else {
            let method = did
                .strip_prefix("did:")
                .and_then(|s| s.split(':').next())
                .unwrap_or(did);
            Err(ResolveError::UnsupportedMethod(method.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_web_no_path_component_uses_well_known() {
        let url = HttpDidResolver::did_web_url("did:web:example.com").expect("ok");
        assert_eq!(url.as_str(), "https://example.com/.well-known/did.json");
    }

    #[test]
    fn did_web_path_components_drops_well_known() {
        // §5.4: colons after host become slashes; NO `.well-known` in path form.
        let url = HttpDidResolver::did_web_url("did:web:example.com:users:alice").expect("ok");
        assert_eq!(url.as_str(), "https://example.com/users/alice/did.json");
    }

    #[test]
    fn did_web_single_path_component() {
        let url = HttpDidResolver::did_web_url("did:web:example.com:user").expect("ok");
        assert_eq!(url.as_str(), "https://example.com/user/did.json");
    }

    #[test]
    fn did_web_malformed_without_method_prefix() {
        let err = HttpDidResolver::did_web_url("did:plc:xyz").expect_err("must fail");
        assert!(matches!(err, ResolveError::Malformed(_)));
    }

    #[test]
    fn did_doc_finds_method_by_fragment() {
        let doc = DidDocument {
            id: "did:plc:abc".into(),
            verification_method: vec![
                VerificationMethod {
                    id: "did:plc:abc#atproto_label".into(),
                    r#type: "Multikey".into(),
                    public_key_multibase: "zOne".into(),
                },
                VerificationMethod {
                    id: "did:plc:abc#atproto".into(),
                    r#type: "Multikey".into(),
                    public_key_multibase: "zTwo".into(),
                },
            ],
        };
        let vm = doc.find_verification_method("#atproto").expect("found");
        // ends_with("#atproto") matches the SHORT `#atproto` id, not
        // `#atproto_label`. Important distinction — moderator JWTs use
        // `#atproto` (repo key), labeler signing uses `#atproto_label`.
        assert_eq!(vm.public_key_multibase, "zTwo");
    }

    #[test]
    fn did_doc_missing_method_returns_none() {
        let doc = DidDocument {
            id: "did:plc:abc".into(),
            verification_method: vec![],
        };
        assert!(doc.find_verification_method("#atproto").is_none());
    }
}
