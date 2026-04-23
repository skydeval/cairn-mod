//! Client for the four PDS endpoints the CLI depends on (§5.3).
//!
//! - `com.atproto.server.createSession` — exchange handle+password
//!   for `accessJwt`/`refreshJwt` during `cairn login`.
//! - `com.atproto.server.refreshSession` — trade `refreshJwt` for
//!   new tokens when `accessJwt` is rejected (401 on getServiceAuth).
//! - `com.atproto.server.deleteSession` — invalidate the refresh
//!   token on `cairn logout`; §5.3 requires the PDS-side revocation
//!   in addition to local session-file cleanup.
//! - `com.atproto.server.getServiceAuth` — mint a short-lived
//!   service auth JWT for a given `aud`+`lxm`. Called fresh for
//!   every authed CLI command per §5.3 (no client-side caching).
//!
//! Uses a vanilla `reqwest::Client` — SSRF filtering (#11) applies
//! server-side to attacker-influenced URLs, but CLI URLs are
//! user-supplied (Q2 in the criteria confirmation). The module stays
//! decoupled from the server's DNS resolver.

use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Default connect + request timeout. Login/report are interactive
/// operations; 30s is generous against any reasonable PDS latency
/// while still bounding hangs.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Successful `createSession` response — the fields the CLI
/// consumes. Additional PDS-returned fields (`email`, `didDoc`,
/// `active`, ...) are ignored by serde `deny_unknown_fields` being
/// absent, and intentionally not surfaced into the session file.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub did: String,
    pub handle: String,
}

/// `refreshSession` response. Structurally mirrors `createSession`;
/// the CLI only persists the two rotated tokens.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshSessionResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
}

/// `getServiceAuth` response. `token` is an ES256K JWT the PDS
/// signs with the moderator's `#atproto` key — the CLI forwards
/// this verbatim as the `Authorization: Bearer <...>` header on the
/// Cairn request.
#[derive(Debug, Clone, Deserialize)]
struct GetServiceAuthResponse {
    token: String,
}

/// `putRecord` 200 response body.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutRecordResponse {
    pub uri: String,
    pub cid: String,
}

/// Wire shape of an XRPC error body (`{error, message}`), used to
/// surface meaningful CLI error output without echoing the whole
/// PDS response.
#[derive(Debug, Clone, Deserialize, Default)]
struct XrpcErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

/// `createSession` request body.
#[derive(Debug, Serialize)]
struct CreateSessionRequest<'a> {
    identifier: &'a str,
    password: &'a str,
}

/// Taxonomy for PDS interaction failures. Carries enough context
/// for the CLI dispatcher to map to an exit code + human-readable
/// message without leaking PDS internals.
#[derive(Debug, Error)]
pub enum PdsError {
    #[error("invalid PDS URL {url}: {source}")]
    InvalidUrl {
        url: String,
        #[source]
        source: url::ParseError,
    },
    #[error("network error contacting {url}: {source}")]
    Network {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    /// 401 from any endpoint. `context` identifies the lexicon
    /// method (`createSession` / `refreshSession` / ...) so the
    /// caller can distinguish "bad app password" from "refresh
    /// token expired" without parsing error strings.
    #[error("PDS rejected credentials on {context}: {error} — {message}")]
    Unauthorized {
        context: &'static str,
        error: String,
        message: String,
    },
    /// Any non-2xx, non-401 status.
    #[error("PDS {context} failed with status {status}: {error} — {message}")]
    UnexpectedStatus {
        context: &'static str,
        status: u16,
        error: String,
        message: String,
    },
    #[error("PDS {context} returned malformed JSON: {source}")]
    MalformedResponse {
        context: &'static str,
        #[source]
        source: reqwest::Error,
    },
    /// §F1 swap-race. Distinct from `UnexpectedStatus` so
    /// `publish-service-record` can exit with a specific message
    /// directing the operator to inspect + reconcile manually
    /// before re-running.
    #[error(
        "another process has modified the service record on the PDS since Cairn's last publish: {message}"
    )]
    SwapRace { message: String },
}

/// Thin wrapper over `reqwest::Client` pinned to one PDS base URL.
/// Construct once per `cairn` process; one instance serves the
/// whole command's lifetime.
#[derive(Debug, Clone)]
pub struct PdsClient {
    client: Client,
    base: Url,
}

impl PdsClient {
    /// Construct a client for the given PDS base URL
    /// (e.g., `https://bsky.social`). Trailing slashes are
    /// normalized away.
    pub fn new(base_url: &str) -> Result<Self, PdsError> {
        let base = Url::parse(base_url).map_err(|source| PdsError::InvalidUrl {
            url: base_url.to_string(),
            source,
        })?;
        let client = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("reqwest client build with default tls config should not fail");
        Ok(Self { client, base })
    }

    /// Inject a preconfigured `reqwest::Client`. Used by tests that
    /// need to disable TLS verification (mock PDS at plain HTTP)
    /// without plumbing feature flags through the public API.
    pub fn with_http_client(base_url: &str, client: Client) -> Result<Self, PdsError> {
        let base = Url::parse(base_url).map_err(|source| PdsError::InvalidUrl {
            url: base_url.to_string(),
            source,
        })?;
        Ok(Self { client, base })
    }

    fn endpoint(&self, lxm: &str) -> Url {
        // base.join("xrpc/<lxm>") handles missing trailing slash
        // correctly since we push a relative segment; the Url crate
        // does the right concatenation.
        let mut u = self.base.clone();
        // Ensure the path ends with `/` before joining a relative
        // path, else `join("xrpc/...")` replaces the final segment.
        if !u.path().ends_with('/') {
            u.set_path(&format!("{}/", u.path()));
        }
        u.join(&format!("xrpc/{lxm}"))
            .expect("xrpc/{lxm} always joins")
    }

    /// Exchange handle+app-password for a PDS session.
    pub async fn create_session(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<CreateSessionResponse, PdsError> {
        const CTX: &str = "createSession";
        let url = self.endpoint("com.atproto.server.createSession");
        let resp = self
            .client
            .post(url.clone())
            .json(&CreateSessionRequest {
                identifier,
                password,
            })
            .send()
            .await
            .map_err(|source| PdsError::Network {
                url: url.to_string(),
                source,
            })?;
        deserialize_or_xrpc_error(CTX, resp).await
    }

    /// Rotate access+refresh tokens using a valid refresh token.
    pub async fn refresh_session(
        &self,
        refresh_jwt: &str,
    ) -> Result<RefreshSessionResponse, PdsError> {
        const CTX: &str = "refreshSession";
        let url = self.endpoint("com.atproto.server.refreshSession");
        let resp = self
            .client
            .post(url.clone())
            .bearer_auth(refresh_jwt)
            .send()
            .await
            .map_err(|source| PdsError::Network {
                url: url.to_string(),
                source,
            })?;
        deserialize_or_xrpc_error(CTX, resp).await
    }

    /// Invalidate the refresh token server-side. Success on 2xx;
    /// callers typically treat any error here as non-fatal (local
    /// cleanup proceeds regardless, per Q3 in the criteria
    /// confirmation).
    pub async fn delete_session(&self, refresh_jwt: &str) -> Result<(), PdsError> {
        const CTX: &str = "deleteSession";
        let url = self.endpoint("com.atproto.server.deleteSession");
        let resp = self
            .client
            .post(url.clone())
            .bearer_auth(refresh_jwt)
            .send()
            .await
            .map_err(|source| PdsError::Network {
                url: url.to_string(),
                source,
            })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(classify_error(CTX, resp).await)
        }
    }

    /// Put a record at (repo, collection, rkey). When `swap_record`
    /// is `Some`, the request is conditional on the PDS's current
    /// record having that CID — §F1 swap-race detection rides on
    /// this. Used by `cairn publish-service-record` to emit the
    /// `app.bsky.labeler.service` record at rkey=self.
    ///
    /// Distinct `context` discriminators for auth failures:
    /// `"putRecord"` generally, mapped upward to a specific
    /// swap-race error via [`PdsError::SwapRace`] when the PDS's
    /// response body carries the `InvalidSwap` shape.
    pub async fn put_record(
        &self,
        access_jwt: &str,
        repo: &str,
        collection: &str,
        rkey: &str,
        record: &serde_json::Value,
        swap_record: Option<&str>,
    ) -> Result<PutRecordResponse, PdsError> {
        const CTX: &str = "putRecord";
        let url = self.endpoint("com.atproto.repo.putRecord");

        let mut body = serde_json::json!({
            "repo": repo,
            "collection": collection,
            "rkey": rkey,
            "record": record,
        });
        if let Some(cid) = swap_record {
            body.as_object_mut()
                .expect("json object")
                .insert("swapRecord".into(), serde_json::Value::String(cid.into()));
        }

        let resp = self
            .client
            .post(url.clone())
            .bearer_auth(access_jwt)
            .json(&body)
            .send()
            .await
            .map_err(|source| PdsError::Network {
                url: url.to_string(),
                source,
            })?;
        if resp.status().is_success() {
            resp.json::<PutRecordResponse>()
                .await
                .map_err(|source| PdsError::MalformedResponse {
                    context: CTX,
                    source,
                })
        } else {
            // Surface InvalidSwap as its own variant so callers can
            // branch on §F1 swap-race detection without parsing
            // error strings. Everything else falls through to the
            // generic classifier.
            let status = resp.status();
            let body = resp.json::<XrpcErrorBody>().await.unwrap_or_default();
            if body.error == "InvalidSwap" {
                return Err(PdsError::SwapRace {
                    message: body.message,
                });
            }
            Err(if status == reqwest::StatusCode::UNAUTHORIZED {
                PdsError::Unauthorized {
                    context: CTX,
                    error: body.error,
                    message: body.message,
                }
            } else {
                PdsError::UnexpectedStatus {
                    context: CTX,
                    status: status.as_u16(),
                    error: body.error,
                    message: body.message,
                }
            })
        }
    }

    /// Mint a fresh service auth JWT for calling `aud` with the
    /// given lexicon method. Returns the opaque token string; the
    /// CLI presents it as `Authorization: Bearer <token>` to Cairn.
    pub async fn get_service_auth(
        &self,
        access_jwt: &str,
        aud: &str,
        lxm: &str,
    ) -> Result<String, PdsError> {
        const CTX: &str = "getServiceAuth";
        let mut url = self.endpoint("com.atproto.server.getServiceAuth");
        url.query_pairs_mut()
            .append_pair("aud", aud)
            .append_pair("lxm", lxm);
        let resp = self
            .client
            .get(url.clone())
            .bearer_auth(access_jwt)
            .send()
            .await
            .map_err(|source| PdsError::Network {
                url: url.to_string(),
                source,
            })?;
        let body: GetServiceAuthResponse = deserialize_or_xrpc_error(CTX, resp).await?;
        Ok(body.token)
    }
}

/// Deserialize a 2xx JSON body into `T`, or classify the response
/// as an error.
async fn deserialize_or_xrpc_error<T: for<'de> Deserialize<'de>>(
    context: &'static str,
    resp: reqwest::Response,
) -> Result<T, PdsError> {
    if resp.status().is_success() {
        resp.json::<T>()
            .await
            .map_err(|source| PdsError::MalformedResponse { context, source })
    } else {
        Err(classify_error(context, resp).await)
    }
}

/// Inspect a non-2xx response and produce the right `PdsError`
/// variant. 401 is called out specifically so callers can branch on
/// "credentials rejected" vs. generic failure.
async fn classify_error(context: &'static str, resp: reqwest::Response) -> PdsError {
    let status = resp.status();
    let body = resp.json::<XrpcErrorBody>().await.unwrap_or_default();
    if status == StatusCode::UNAUTHORIZED {
        PdsError::Unauthorized {
            context,
            error: body.error,
            message: body.message,
        }
    } else {
        PdsError::UnexpectedStatus {
            context,
            status: status.as_u16(),
            error: body.error,
            message: body.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_joins_correctly_without_trailing_slash() {
        let c = PdsClient::new("https://bsky.social").unwrap();
        let u = c.endpoint("com.atproto.server.createSession");
        assert_eq!(
            u.as_str(),
            "https://bsky.social/xrpc/com.atproto.server.createSession"
        );
    }

    #[test]
    fn endpoint_joins_correctly_with_trailing_slash() {
        let c = PdsClient::new("https://bsky.social/").unwrap();
        let u = c.endpoint("com.atproto.server.createSession");
        assert_eq!(
            u.as_str(),
            "https://bsky.social/xrpc/com.atproto.server.createSession"
        );
    }

    #[test]
    fn endpoint_preserves_base_path() {
        // A PDS on a non-root path (e.g., reverse-proxied).
        let c = PdsClient::new("https://example.com/pds").unwrap();
        let u = c.endpoint("com.atproto.server.createSession");
        assert_eq!(
            u.as_str(),
            "https://example.com/pds/xrpc/com.atproto.server.createSession"
        );
    }

    #[test]
    fn invalid_url_returns_structured_error() {
        let err = PdsClient::new("not a url").unwrap_err();
        assert!(matches!(err, PdsError::InvalidUrl { .. }));
    }
}
