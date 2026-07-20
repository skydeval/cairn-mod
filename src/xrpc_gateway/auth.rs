//! Inbound service-auth JWT verification for the XRPC gateway
//! (#93, v1.7).
//!
//! Sibling to [`crate::auth::AuthContext`] (which handles
//! outbound + admin-XRPC auth). Different security domain: this
//! service verifies JWTs from arbitrary upstream PDSes and their
//! users, with cairn-mod's xrpc_gateway as the audience.
//! `AuthContext` verifies JWTs from registered moderators with
//! cairn-mod's labeler as the audience.
//!
//! # Reuse from `crate::auth`
//!
//! - **JWT parsing** ([`crate::auth::jwt::parse`]): used directly.
//!   The JWT structure is identical between security domains.
//! - **DID resolution** ([`crate::auth::did::DidResolver`]): same
//!   trait, shared `Arc<dyn DidResolver>` instance plumbed through
//!   `serve.rs` so SSRF filtering and `did:web:` resolution are
//!   consistent across the two auth surfaces.
//! - **Signature primitives** (`proto_blue_crypto::{parse_multikey,
//!   k256_compress_pubkey, K256Keypair, Verifier}`): used directly.
//!
//! # Forked from `AuthContext`
//!
//! - **Error type** — distinct variants with distinct HTTP status
//!   mappings (401 vs 403) and distinct XRPC error codes
//!   ([`XrpcAuthError`]).
//! - **Replay cache** — deferred to #94. v1.7-#93 parses `jti` and
//!   stores it in [`XrpcAuthClaims`]; the replay-cache check
//!   happens in #94's separate middleware layer composed alongside
//!   this one.
//! - **Membership gate** — `xrpc_known_callers` /
//!   `xrpc_trusted_pdses` tables also land in #94. The auth layer
//!   verifies the JWT is cryptographically valid; it does NOT
//!   check whether the issuer is trusted to call this endpoint.
//!
//! # Verification pipeline (per §A8)
//!
//! 1. Algorithm allowlist (ES256K only)
//! 2. Resolve issuer DID, find `#atproto` verification method
//! 3. Verify ES256K signature against the resolved pubkey
//! 4. Validate `aud` matches [`XrpcGatewayConfig::service_did`]
//! 5. Validate `lxm` matches the request's NSID and is on the
//!    [`crate::xrpc_gateway::Nsid`] allowlist
//! 6. Validate `exp > now - clock_skew_tolerance`
//! 7. Parse `jti` into [`XrpcAuthClaims`] (no replay check yet —
//!    #94)
//!
//! Steps 2-3 run BEFORE claim checks so a malformed-JWT-with-
//! correct-claims attacker can't probe via timing differences
//! (per §A8's defensive ordering).

use std::sync::Arc;

use proto_blue_crypto::{K256Keypair, Verifier as _, k256_compress_pubkey, parse_multikey};

use crate::auth::did::DidResolver;
use crate::auth::jwt;
use crate::xrpc_gateway::Nsid;
use crate::xrpc_gateway::config::XrpcGatewayConfig;
use crate::xrpc_gateway::error::XrpcAuthError;

/// `#atproto` verification-method fragment per ATProto convention.
/// Same value `crate::auth` uses for moderator JWTs (the fragment
/// is per-DID-document, not per-security-domain).
const VERIFICATION_METHOD_FRAGMENT: &str = "#atproto";

/// JWT alg cairn-mod accepts. ES256K only — same allowlist as
/// `crate::auth`'s outbound surface; rotating this is a v1.x+
/// concern that requires auditing every caller.
const ACCEPTED_ALG: &str = "ES256K";

/// Validated claims from a successfully-verified inbound JWT.
///
/// Constructed only by [`XrpcAuthService::verify`] on the success
/// path. All fields are the post-validation values: `aud` is
/// guaranteed equal to the gateway's configured service DID;
/// `lxm` is guaranteed equal to the request's NSID; `exp` is
/// guaranteed in the future (with clock-skew tolerance).
#[derive(Debug, Clone)]
pub struct XrpcAuthClaims {
    /// Issuer DID. For `tools.ozone.*` calls this is the
    /// originating user's DID; for `createReport` this is the
    /// originating PDS's DID. Used by #95-#98 handlers to attribute
    /// the call (e.g., `reportedBy` on createReport, `actor` on
    /// emitEvent).
    pub iss: String,
    /// Audience — guaranteed equal to
    /// [`XrpcGatewayConfig::service_did`].
    pub aud: String,
    /// Method binding — guaranteed equal to the request's NSID
    /// and on the v1.7 allowlist.
    pub lxm: Nsid,
    /// Expiry as Unix seconds since epoch. JWT-spec convention is
    /// seconds (not millis); this matches `crate::auth::jwt`'s
    /// existing parser shape.
    pub exp: i64,
    /// JWT ID. v1.7-#93 parses this but does NOT deduplicate; the
    /// replay-cache check lands in #94 alongside the
    /// `xrpc_known_callers` membership gate.
    pub jti: String,
    /// Issued-at as Unix seconds since epoch. The existing JWT
    /// parser requires this field; if a future PDS sends iat-less
    /// JWTs, the parser is the single point to relax. Wrapped in
    /// `Option` here for forward-compat with that case.
    pub iat: Option<i64>,
}

/// Inbound service-auth verification service.
///
/// Construct once at server startup with a shared
/// [`Arc<dyn DidResolver>`] (the same instance
/// [`crate::auth::AuthContext`] uses, plumbed through
/// `serve.rs`). The verification entry point is [`Self::verify`].
///
/// `Clone` is intentional via the wrapping `Arc`: the auth layer
/// in [`crate::xrpc_gateway::middleware`] holds the service as
/// `Arc<XrpcAuthService>` and clones cheaply per request.
pub struct XrpcAuthService {
    config: XrpcGatewayConfig,
    did_resolver: Arc<dyn DidResolver>,
    /// Wall-clock-now-as-Unix-seconds source. Defaults to
    /// `SystemTime::now()` via [`Self::new`]; tests inject a
    /// fixed-time closure via [`Self::with_clock`] to exercise
    /// expiry and skew without relying on real wall-clock time.
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl XrpcAuthService {
    /// Production constructor. Wall-clock is `SystemTime::now()`
    /// converted to Unix seconds (saturating at 0 if the system
    /// clock is before the epoch — unreachable on any sane host).
    pub fn new(config: XrpcGatewayConfig, did_resolver: Arc<dyn DidResolver>) -> Self {
        let clock: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });
        Self {
            config,
            did_resolver,
            clock,
        }
    }

    /// Test-only constructor with a deterministic clock. Tests
    /// pass a closure returning a fixed Unix seconds value to
    /// exercise expiry / skew code paths without wall-clock
    /// dependencies — matching the QA-gate posture from #93's
    /// prompt ("no wall-clock timing in tests").
    #[cfg(test)]
    pub(crate) fn with_clock(
        config: XrpcGatewayConfig,
        did_resolver: Arc<dyn DidResolver>,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self {
            config,
            did_resolver,
            clock,
        }
    }

    /// Verify an inbound JWT against the request's NSID and the
    /// gateway's configured service DID.
    ///
    /// Pipeline order matches §A8 (alg → resolve → sig → claims).
    /// Resolve + signature run BEFORE claim checks so a probe-
    /// crafted JWT with valid claims but invalid signature can't
    /// be distinguished from one with mismatched claims via
    /// response-time timing.
    ///
    /// `nsid` is the URL-derived NSID — the middleware extracts it
    /// from `req.uri().path()` via
    /// [`crate::xrpc_gateway::nsid::extract_nsid_from_request_uri`]
    /// before calling this method.
    pub async fn verify(&self, jwt: &str, nsid: Nsid) -> Result<XrpcAuthClaims, XrpcAuthError> {
        // 1. Parse + alg allowlist. Reuses the existing JWT
        // parser; an alg-rejection short-circuits before any
        // network IO so probes hitting alg=none / alg=HS256
        // can't be used to time-distinguish auth states.
        let parsed =
            jwt::parse(jwt).map_err(|e| XrpcAuthError::InvalidJwtStructure(e.to_string()))?;
        if parsed.header.alg != ACCEPTED_ALG {
            return Err(XrpcAuthError::UnsupportedAlgorithm(parsed.header.alg));
        }

        // 2. Resolve issuer DID. We don't share the cache layer
        // with `crate::auth::AuthContext` in #93 (that's a future-
        // cycle refactor if the duplicated cache turns out to be
        // a hot path); we use the underlying DidResolver directly.
        // The shared resolver instance does mean SSRF filtering
        // and `did:web:` resolution are consistent across the two
        // auth surfaces.
        let doc = self
            .did_resolver
            .resolve(&parsed.payload.iss)
            .await
            .map_err(|e| XrpcAuthError::DidResolutionFailed {
                iss: parsed.payload.iss.clone(),
                reason: e.to_string(),
            })?;

        // 3. Find `#atproto` verification method.
        let vm = doc
            .find_verification_method(VERIFICATION_METHOD_FRAGMENT)
            .ok_or_else(|| XrpcAuthError::NoVerificationMethod {
                iss: parsed.payload.iss.clone(),
                reason: format!("no {VERIFICATION_METHOD_FRAGMENT} fragment in DID document"),
            })?;

        // 4. Verify signature. Same primitive sequence
        // `crate::auth::AuthContext` uses; intentional duplication
        // to keep XrpcAuthError variants distinct from AuthError.
        let parsed_key = parse_multikey(&vm.public_key_multibase).map_err(|e| {
            XrpcAuthError::NoVerificationMethod {
                iss: parsed.payload.iss.clone(),
                reason: format!("multibase parse: {e}"),
            }
        })?;
        if parsed_key.jwt_alg != ACCEPTED_ALG {
            return Err(XrpcAuthError::NoVerificationMethod {
                iss: parsed.payload.iss.clone(),
                reason: format!(
                    "verification method has key type {} (expected {ACCEPTED_ALG})",
                    parsed_key.jwt_alg
                ),
            });
        }
        let compressed = k256_compress_pubkey(&parsed_key.key_bytes).map_err(|e| {
            XrpcAuthError::NoVerificationMethod {
                iss: parsed.payload.iss.clone(),
                reason: format!("compress pubkey: {e}"),
            }
        })?;
        let verifier = K256Keypair::verifier_from_compressed(&compressed).map_err(|e| {
            XrpcAuthError::NoVerificationMethod {
                iss: parsed.payload.iss.clone(),
                reason: format!("verifier from pubkey: {e}"),
            }
        })?;
        let sig_ok = verifier
            .verify(&parsed.signing_input, &parsed.signature)
            .map_err(|_| XrpcAuthError::SignatureVerificationFailed {
                iss: parsed.payload.iss.clone(),
            })?;
        if !sig_ok {
            return Err(XrpcAuthError::SignatureVerificationFailed {
                iss: parsed.payload.iss.clone(),
            });
        }

        // 5. Claims: aud / lxm / exp.
        if parsed.payload.aud != self.config.service_did {
            return Err(XrpcAuthError::AudienceMismatch {
                expected: self.config.service_did.clone(),
                actual: parsed.payload.aud,
            });
        }

        // lxm-on-allowlist + lxm-matches-URL are two distinct
        // checks per the prompt's rationale: a JWT crafted for a
        // different VALID endpoint and a JWT crafted for an
        // endpoint cairn-mod doesn't support are different
        // operator-debugging stories.
        let lxm_nsid = match Nsid::from_path_segment(&parsed.payload.lxm) {
            Some(n) => n,
            None => {
                return Err(XrpcAuthError::LxmNotAllowlisted {
                    lxm: parsed.payload.lxm,
                });
            }
        };
        if lxm_nsid != nsid {
            return Err(XrpcAuthError::MethodMismatch {
                lxm: parsed.payload.lxm,
                nsid: nsid.as_path_segment().to_string(),
            });
        }

        let now = (self.clock)();
        let skew = self.config.clock_skew_tolerance.as_secs() as i64;
        if parsed.payload.exp < now.saturating_sub(skew) {
            return Err(XrpcAuthError::Expired {
                exp: parsed.payload.exp,
                now,
            });
        }

        // 6. Build the validated claims. iat is captured as
        // Some(_) since the existing parser requires it; the
        // Option wrapping is forward-compat for a future iat-less
        // path.
        Ok(XrpcAuthClaims {
            iss: parsed.payload.iss,
            aud: parsed.payload.aud,
            lxm: lxm_nsid,
            exp: parsed.payload.exp,
            jti: parsed.payload.jti,
            iat: Some(parsed.payload.iat),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    use async_trait::async_trait;
    use base64::Engine as _;
    use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _, format_multikey};

    use crate::auth::did::{DidDocument, DidResolver, ResolveError, VerificationMethod};
    use crate::xrpc_gateway::OzoneModerationNsid;

    const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
    const SERVICE_DID: &str = "did:web:cairn.example.com";
    const ISSUER_DID: &str = "did:plc:issuer0000000000000000000";
    const FIXED_NOW: i64 = 1_700_000_000;

    fn test_keypair() -> K256Keypair {
        K256Keypair::from_private_key(&hex::decode(TEST_PRIV_HEX).unwrap()).unwrap()
    }

    fn test_did_doc(did: &str) -> DidDocument {
        DidDocument {
            id: did.to_string(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#atproto"),
                r#type: "Multikey".into(),
                public_key_multibase: format_multikey(
                    "ES256K",
                    &test_keypair().public_key_compressed(),
                ),
            }],
        }
    }

    /// In-memory mock resolver. Mirrors the pattern from
    /// tests/auth.rs; preloaded with a single doc per test.
    struct MockResolver(Mutex<HashMap<String, DidDocument>>);

    impl MockResolver {
        fn with_doc(did: &str, doc: DidDocument) -> Arc<Self> {
            let mut m = HashMap::new();
            m.insert(did.to_string(), doc);
            Arc::new(Self(Mutex::new(m)))
        }
    }

    #[async_trait]
    impl DidResolver for MockResolver {
        async fn resolve(&self, did: &str) -> Result<DidDocument, ResolveError> {
            // Snapshot under the lock then drop the guard before
            // any await (clippy::await_holding_lock — the lesson
            // from #89 / #92).
            let snapshot = self.0.lock().unwrap().get(did).cloned();
            snapshot.ok_or(ResolveError::BadStatus(404))
        }
    }

    /// Build a JWT signed by the test keypair. `claims` is the
    /// payload object; `alg_header` lets tests override the
    /// header's `alg` field to exercise the alg-allowlist branch.
    fn build_jwt(claims: &serde_json::Value, alg_header: &str) -> String {
        let header = serde_json::json!({"alg": alg_header, "typ": "JWT"});
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let h = engine.encode(header.to_string());
        let p = engine.encode(claims.to_string());
        let signing_input = format!("{h}.{p}");
        let sig = test_keypair().sign(signing_input.as_bytes()).unwrap();
        format!("{h}.{p}.{}", engine.encode(sig))
    }

    fn valid_claims(lxm: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER_DID,
            "aud": SERVICE_DID,
            "exp": FIXED_NOW + 60,
            "iat": FIXED_NOW - 5,
            "jti": "jti-fixture-1",
            "lxm": lxm,
        })
    }

    fn fixed_clock() -> Arc<dyn Fn() -> i64 + Send + Sync> {
        Arc::new(|| FIXED_NOW)
    }

    fn fixture_config() -> XrpcGatewayConfig {
        XrpcGatewayConfig {
            enabled: true,
            service_did: SERVICE_DID.into(),
            clock_skew_tolerance: Duration::from_secs(30),
            replay_cache_ttl: Duration::from_secs(90),
        }
    }

    fn build_service() -> XrpcAuthService {
        let resolver = MockResolver::with_doc(ISSUER_DID, test_did_doc(ISSUER_DID));
        XrpcAuthService::with_clock(fixture_config(), resolver, fixed_clock())
    }

    // ===== Happy path =====

    #[tokio::test]
    async fn verify_succeeds_for_well_formed_jwt() {
        let svc = build_service();
        let jwt = build_jwt(&valid_claims("tools.ozone.moderation.emitEvent"), "ES256K");
        let claims = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect("valid JWT should verify");
        assert_eq!(claims.iss, ISSUER_DID);
        assert_eq!(claims.aud, SERVICE_DID);
        assert_eq!(claims.lxm, Nsid::Ozone(OzoneModerationNsid::EmitEvent));
        assert_eq!(claims.exp, FIXED_NOW + 60);
        assert_eq!(claims.jti, "jti-fixture-1");
        assert_eq!(claims.iat, Some(FIXED_NOW - 5));
    }

    // ===== Algorithm allowlist =====

    #[tokio::test]
    async fn verify_rejects_hs256_alg() {
        let svc = build_service();
        let jwt = build_jwt(&valid_claims("tools.ozone.moderation.emitEvent"), "HS256");
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("HS256 must be rejected");
        assert!(matches!(err, XrpcAuthError::UnsupportedAlgorithm(ref a) if a == "HS256"));
    }

    #[tokio::test]
    async fn verify_rejects_rs256_alg() {
        let svc = build_service();
        let jwt = build_jwt(&valid_claims("tools.ozone.moderation.emitEvent"), "RS256");
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("RS256 must be rejected");
        assert!(matches!(err, XrpcAuthError::UnsupportedAlgorithm(_)));
    }

    #[tokio::test]
    async fn verify_rejects_alg_none() {
        let svc = build_service();
        let jwt = build_jwt(&valid_claims("tools.ozone.moderation.emitEvent"), "none");
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("alg=none must be rejected (the load-bearing check)");
        assert!(matches!(err, XrpcAuthError::UnsupportedAlgorithm(_)));
    }

    // ===== Signature verification =====

    #[tokio::test]
    async fn verify_rejects_tampered_signature() {
        let svc = build_service();
        // Construct a valid JWT, then replace its signature
        // segment with one signed over different bytes. The
        // resulting token has a structurally-valid base64url
        // signature that doesn't verify against signing_input.
        let claims = valid_claims("tools.ozone.moderation.emitEvent");
        let valid = build_jwt(&claims, "ES256K");
        let mut other_claims = claims.clone();
        other_claims["jti"] = serde_json::json!("different-payload");
        let other = build_jwt(&other_claims, "ES256K");
        // Splice the second token's signature onto the first
        // token's header.payload — the bytes signed differ, so
        // verification must fail.
        let valid_parts: Vec<&str> = valid.split('.').collect();
        let other_parts: Vec<&str> = other.split('.').collect();
        let tampered = format!("{}.{}.{}", valid_parts[0], valid_parts[1], other_parts[2]);
        let err = svc
            .verify(&tampered, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("tampered signature must fail verification");
        assert!(matches!(
            err,
            XrpcAuthError::SignatureVerificationFailed { .. }
        ));
    }

    // ===== Claim mismatches =====

    #[tokio::test]
    async fn verify_rejects_audience_mismatch() {
        let svc = build_service();
        let mut claims = valid_claims("tools.ozone.moderation.emitEvent");
        claims["aud"] = serde_json::json!("did:web:other.example.com");
        let jwt = build_jwt(&claims, "ES256K");
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("aud mismatch must be rejected");
        match err {
            XrpcAuthError::AudienceMismatch { expected, actual } => {
                assert_eq!(expected, SERVICE_DID);
                assert_eq!(actual, "did:web:other.example.com");
            }
            other => panic!("expected AudienceMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_rejects_method_mismatch_when_lxm_is_different_allowlisted_nsid() {
        // JWT's lxm is one allowlisted NSID; URL is a different
        // allowlisted NSID. Cleanly distinguishable from
        // LxmNotAllowlisted (which fires when lxm isn't on the
        // allowlist at all).
        let svc = build_service();
        let jwt = build_jwt(
            &valid_claims("tools.ozone.moderation.queryStatuses"),
            "ES256K",
        );
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("lxm mismatch must be rejected");
        assert!(matches!(err, XrpcAuthError::MethodMismatch { .. }));
    }

    #[tokio::test]
    async fn verify_rejects_lxm_not_on_allowlist() {
        // JWT's lxm is a syntactically-valid NSID that's NOT on
        // cairn-mod's v1.7 allowlist. Distinct from MethodMismatch.
        let svc = build_service();
        let jwt = build_jwt(
            &valid_claims("tools.ozone.moderation.deleteRecord"),
            "ES256K",
        );
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("lxm not on v1.7 allowlist must be rejected");
        match err {
            XrpcAuthError::LxmNotAllowlisted { lxm } => {
                assert_eq!(lxm, "tools.ozone.moderation.deleteRecord");
            }
            other => panic!("expected LxmNotAllowlisted, got {other:?}"),
        }
    }

    // ===== Expiry / clock skew =====

    #[tokio::test]
    async fn verify_rejects_expired_jwt() {
        let svc = build_service();
        let mut claims = valid_claims("tools.ozone.moderation.emitEvent");
        // exp is more than `clock_skew_tolerance` (30s) before now.
        claims["exp"] = serde_json::json!(FIXED_NOW - 100);
        let jwt = build_jwt(&claims, "ES256K");
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("expired JWT must be rejected");
        match err {
            XrpcAuthError::Expired { exp, now } => {
                assert_eq!(exp, FIXED_NOW - 100);
                assert_eq!(now, FIXED_NOW);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_accepts_jwt_within_clock_skew_tolerance() {
        // `exp` is in the past but within the 30-second clock-
        // skew tolerance. Test pins that the skew window is
        // honored — operators tolerate honest client clock drift.
        let svc = build_service();
        let mut claims = valid_claims("tools.ozone.moderation.emitEvent");
        claims["exp"] = serde_json::json!(FIXED_NOW - 10); // 10s ago, well within 30s skew
        let jwt = build_jwt(&claims, "ES256K");
        let res = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await;
        assert!(
            res.is_ok(),
            "exp 10s ago should pass within 30s skew: got {res:?}"
        );
    }

    // ===== Required-claim absence =====

    #[tokio::test]
    async fn verify_rejects_jwt_with_missing_required_claim() {
        // Build a payload missing `aud`. The existing parser
        // surfaces this as a JwtParseError; we map to
        // InvalidJwtStructure (the parser doesn't distinguish
        // "missing field" from "malformed JSON" — the parser's
        // shape is what this issue inherits).
        let svc = build_service();
        let claims = serde_json::json!({
            "iss": ISSUER_DID,
            "exp": FIXED_NOW + 60,
            "iat": FIXED_NOW - 5,
            "jti": "jti-fixture-2",
            "lxm": "tools.ozone.moderation.emitEvent",
            // aud deliberately absent
        });
        let jwt = build_jwt(&claims, "ES256K");
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("missing aud must be rejected");
        assert!(matches!(err, XrpcAuthError::InvalidJwtStructure(_)));
    }

    // ===== DID resolution failure =====

    #[tokio::test]
    async fn verify_rejects_when_issuer_did_unresolvable() {
        // MockResolver only knows about ISSUER_DID; build a JWT
        // claiming a different iss the resolver doesn't have.
        let svc = build_service();
        let mut claims = valid_claims("tools.ozone.moderation.emitEvent");
        claims["iss"] = serde_json::json!("did:plc:notinresolver000000000000");
        let jwt = build_jwt(&claims, "ES256K");
        let err = svc
            .verify(&jwt, Nsid::Ozone(OzoneModerationNsid::EmitEvent))
            .await
            .expect_err("unknown issuer DID must fail resolution");
        assert!(matches!(err, XrpcAuthError::DidResolutionFailed { .. }));
    }
}
