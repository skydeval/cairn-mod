//! ATProto service-auth verification for moderator-authenticated
//! endpoints (§5.2).
//!
//! Exposes a single high-level entry point, [`AuthContext::verify_service_auth`],
//! that implements the §5.2 pipeline end-to-end:
//!
//! 1. Alg allowlist (ES256K only — rejects `none`, `HS256`, `RS256`,
//!    `ES256`, `EdDSA`, and everything else).
//! 2. Structural: JWT has 3 base64url segments, header and payload
//!    parse, all required claims present.
//! 3. Signature: resolve the `iss` DID doc (cached), match the
//!    `#atproto` verification method, decode the `publicKeyMultibase`
//!    via proto-blue, verify the ES256K signature over the raw
//!    `header.payload` bytes.
//! 4. Claims: `aud == config.service_did` exact, `exp` in the future
//!    within skew, `iat` not more than max_iat_future in the future,
//!    `lxm == expected_lxm` exact.
//! 5. Replay: `(iss, jti)` not already in the cache; insert with the
//!    token's remaining TTL.
//!
//! Authorization (step 6 of §5.2 — "iss in moderators table with
//! required role") is **not** handled here; it lives with the admin
//! endpoints (#14–17) which own the `moderators` schema. Keeping
//! `verify_service_auth` pool-free lets it be called without any
//! storage dependency.
//!
//! Error taxonomy: [`AuthError`] has a specific variant per failure
//! category for internal logging only. At the HTTP boundary, all
//! variants should map to a single generic `AuthenticationRequired`
//! response per the §4 non-enumeration principle — per-case detail
//! must not leak to clients.

pub mod cache;
pub mod did;
pub mod jwt;
pub mod ssrf;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proto_blue_crypto::{K256Keypair, Verifier as _, k256_compress_pubkey, parse_multikey};

use cache::{CachedResolve, DidDocCache, JtiCache};
use did::{DidResolver, HttpDidResolver, ResolveError};

/// Identifier fragment for the moderator repo key in a DID document.
/// Moderator service-auth JWTs are signed by the key published at
/// `#atproto`; do NOT confuse with `#atproto_label` which is the
/// labeler's own signing key (see §5.1).
const MODERATOR_KEY_FRAGMENT: &str = "#atproto";

/// Multikey types Cairn's verifier accepts. v1 is ES256K only —
/// rotating this constant would require auditing every caller.
const ACCEPTED_JWT_ALG: &str = "ES256K";

/// Runtime configuration for the auth layer.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Cairn's own service DID. JWT `aud` must match this exactly.
    pub service_did: String,
    /// Base URL of the PLC directory. Default per §5.4.
    pub plc_directory_url: String,
    /// HTTP timeout for DID resolution (connect + read).
    pub resolver_timeout: Duration,
    /// Positive DID-doc cache TTL (§5.4: 60s).
    pub positive_cache_ttl: Duration,
    /// Negative DID-doc cache TTL (§5.4: 5s).
    pub negative_cache_ttl: Duration,
    /// Max entries in the DID-doc cache.
    pub doc_cache_size: NonZeroUsize,
    /// Max entries in the jti replay cache (§5.2: 100_000).
    pub jti_cache_size: NonZeroUsize,
    /// Clock skew tolerance for `exp` (§5.2: ±30s).
    pub clock_skew: Duration,
    /// Max amount `iat` may be in the future (§5.2: 30s).
    pub max_iat_future: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            service_did: String::new(),
            plc_directory_url: "https://plc.directory".to_string(),
            resolver_timeout: Duration::from_secs(5),
            positive_cache_ttl: Duration::from_secs(60),
            negative_cache_ttl: Duration::from_secs(5),
            doc_cache_size: NonZeroUsize::new(1024).expect("non-zero"),
            jti_cache_size: NonZeroUsize::new(100_000).expect("non-zero"),
            clock_skew: Duration::from_secs(30),
            max_iat_future: Duration::from_secs(30),
        }
    }
}

/// Successful verification result. `#[non_exhaustive]` so future
/// additions (e.g., token-issued-at for audit correlation) don't break
/// downstream matching.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedCaller {
    /// The issuing DID (moderator's DID). Used for role lookup and
    /// audit-log attribution.
    pub iss: String,
    /// The `id` of the verification method that signed this token —
    /// e.g. `did:plc:abc#atproto`. Captured for audit logs that want
    /// to record "caller X verified via key Y" so a key rotation is
    /// traceable after the fact.
    pub key_id: String,
}

/// Failure categories. Every variant must, at the HTTP boundary, map
/// to one uniform `AuthenticationRequired` response — the specific
/// reason is for internal logs only.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("JWT alg not allowed: {0}")]
    AlgRejected(String),

    #[error("JWT structure invalid: {0}")]
    Structural(#[from] jwt::JwtParseError),

    #[error("resolver error: {0}")]
    Resolve(#[from] ResolveError),

    #[error("DID doc has no `{MODERATOR_KEY_FRAGMENT}` verification method")]
    NoVerificationMethod,

    #[error("verification method has wrong key type (expected Multikey ES256K)")]
    WrongKeyType,

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("claim mismatch: {0}")]
    ClaimMismatch(&'static str),

    #[error("replay detected (iss={iss}, jti={jti})")]
    Replay { iss: String, jti: String },

    #[error("crypto error: {0}")]
    Crypto(#[from] proto_blue_crypto::CryptoError),

    #[error("system clock before unix epoch")]
    Clock,
}

/// Shareable auth handle. Construct once at server startup, clone
/// freely into per-request handlers via axum State/Extension.
pub struct AuthContext {
    config: AuthConfig,
    resolver: Arc<dyn DidResolver>,
    doc_cache: DidDocCache,
    jti_cache: JtiCache,
}

impl AuthContext {
    /// Construct with an HTTP resolver backed by rustls + SSRF-filtering
    /// DNS. Prefer [`AuthContext::with_resolver`] in tests.
    pub fn new(config: AuthConfig) -> Self {
        let resolver: Arc<dyn DidResolver> = Arc::new(HttpDidResolver::new(
            config.plc_directory_url.clone(),
            config.resolver_timeout,
        ));
        Self::with_resolver(config, resolver)
    }

    /// Dependency-inject a resolver. Test code substitutes a
    /// canned-document resolver; production uses [`AuthContext::new`].
    pub fn with_resolver(config: AuthConfig, resolver: Arc<dyn DidResolver>) -> Self {
        let doc_cache = DidDocCache::new(
            config.doc_cache_size,
            config.positive_cache_ttl,
            config.negative_cache_ttl,
        );
        let jti_cache = JtiCache::new(config.jti_cache_size);
        Self {
            config,
            resolver,
            doc_cache,
            jti_cache,
        }
    }

    /// Primary entry point. Pipeline matches §5.2 exactly; see module
    /// docs for the ordering rationale.
    pub async fn verify_service_auth(
        &self,
        token: &str,
        expected_lxm: &str,
    ) -> Result<VerifiedCaller, AuthError> {
        // 1. Alg allowlist. First so a malformed JWT with alg:none
        // can never reach any downstream step.
        let parsed = jwt::parse(token)?;
        if parsed.header.alg != ACCEPTED_JWT_ALG {
            return Err(AuthError::AlgRejected(parsed.header.alg));
        }

        // 2. Structural presence is handled by `jwt::parse` — missing
        // claims surface as JwtParseError::PayloadJson.

        // 3. Signature. Resolve DID doc (cached), match the moderator
        // key fragment, decode, verify. This happens BEFORE claim
        // checks to prevent timing-based token scanning (§5.2).
        let doc = self.resolve_did(&parsed.payload.iss).await?;
        let vm = doc
            .find_verification_method(MODERATOR_KEY_FRAGMENT)
            .ok_or(AuthError::NoVerificationMethod)?;
        let parsed_key = parse_multikey(&vm.public_key_multibase)?;
        if parsed_key.jwt_alg != ACCEPTED_JWT_ALG {
            return Err(AuthError::WrongKeyType);
        }
        let compressed = k256_compress_pubkey(&parsed_key.key_bytes)?;
        let verifier = K256Keypair::verifier_from_compressed(&compressed)?;
        let sig_ok = verifier.verify(&parsed.signing_input, &parsed.signature)?;
        if !sig_ok {
            return Err(AuthError::SignatureInvalid);
        }

        // 4. Claims.
        if parsed.payload.aud != self.config.service_did {
            return Err(AuthError::ClaimMismatch("aud"));
        }
        let now = unix_seconds()?;
        let skew = self.config.clock_skew.as_secs() as i64;
        if parsed.payload.exp < now.saturating_sub(skew) {
            return Err(AuthError::ClaimMismatch("exp"));
        }
        let max_iat_future = self.config.max_iat_future.as_secs() as i64;
        if parsed.payload.iat > now.saturating_add(max_iat_future) {
            return Err(AuthError::ClaimMismatch("iat"));
        }
        if parsed.payload.lxm != expected_lxm {
            return Err(AuthError::ClaimMismatch("lxm"));
        }

        // 5. Replay. TTL is the token's remaining validity — when the
        // token expires, the jti can be reused (impossible in practice
        // because ATProto PDSes never reissue the same jti, but the
        // cache need not remember it longer than the token is usable).
        let ttl_secs = (parsed.payload.exp - now).max(0) as u64;
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs);
        self.jti_cache
            .check_and_record(&parsed.payload.iss, &parsed.payload.jti, expires_at)
            .map_err(|_| AuthError::Replay {
                iss: parsed.payload.iss.clone(),
                jti: parsed.payload.jti.clone(),
            })?;

        Ok(VerifiedCaller {
            iss: parsed.payload.iss,
            key_id: vm.id.clone(),
        })
    }

    /// Resolve a DID, consulting the cache first. Negative-cache hits
    /// return a generic `Network` error — the specific underlying
    /// failure is not preserved because the cache entry is the
    /// decision, not the diagnosis.
    async fn resolve_did(&self, did: &str) -> Result<did::DidDocument, AuthError> {
        if let Some(cached) = self.doc_cache.get(did) {
            return match cached {
                CachedResolve::Ok(doc) => Ok(doc),
                CachedResolve::Err => Err(AuthError::Resolve(ResolveError::Network(
                    "negatively cached".into(),
                ))),
            };
        }
        match self.resolver.resolve(did).await {
            Ok(doc) => {
                self.doc_cache.insert_ok(did.to_owned(), doc.clone());
                Ok(doc)
            }
            Err(e) => {
                self.doc_cache.insert_err(did.to_owned());
                Err(AuthError::Resolve(e))
            }
        }
    }
}

fn unix_seconds() -> Result<i64, AuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| AuthError::Clock)
}
