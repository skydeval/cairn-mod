//! ES256K service-auth JWT minting for the Rust-PDS backend
//! (v1.8.1, §4.2).
//!
//! Hand-rolled, deliberately: Aurora-Locus's `verify_service_jwt`
//! accepts **DER-encoded** ECDSA signatures only (its
//! implementation choice, not an ATProto spec requirement), so the
//! JOSE-compliant JWT crates are non-interoperable here —
//! `jsonwebtoken` has no ES256K support at all, and `jwt-compact`
//! emits spec-compliant compact `R‖S` signatures that Aurora's
//! `Signature::from_der` rejects. The pipeline below mirrors
//! Aurora's own `create_service_jwt` so both sides agree on the
//! wire format.
//!
//! Kept separate from the [`RustBackend`](super::RustBackend)
//! struct so the signing logic is unit-testable in isolation.
//!
//! # Claim shape
//!
//! Header `{"alg":"ES256K","typ":"JWT"}`; payload carries `iss`,
//! `aud`, `lxm`, `exp`, `iat`, `jti` (UUIDv4). `nbf` is omitted
//! per ATProto convention; `sub` is omitted because for
//! service-auth `iss` *is* the identity. `lxm` is always present:
//! Aurora does not enforce that `lxm` matches the called endpoint,
//! but its presence selects the 1-hour `exp` cap (60s without).

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature, SigningKey};

/// Errors from [`mint_service_auth_jwt`].
///
/// Does not cross the `PdsAdminBackend` trait boundary — the
/// caller (a `RustBackend` method) maps it into
/// [`BackendError::Auth`](crate::pds_admin::BackendError::Auth)
/// before returning.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceAuthError {
    /// `iss` or `aud` failed the syntactic DID check.
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    /// The ECDSA signing operation itself failed.
    #[error("ES256K signing failed: {0}")]
    SigningFailed(String),
    /// Wall-clock time sourcing failed (system clock before the
    /// Unix epoch).
    #[error("clock failure: {0}")]
    ClockFailure(String),
}

/// Syntactic DID check: `did:` prefix, non-empty method segment,
/// non-empty method-specific identifier.
///
/// Deliberately *not* resolution — Aurora resolves cairn-mod's DID
/// doc when it verifies the JWT (§5.1); cairn-mod only rejects
/// strings that can't possibly be DIDs. Shared by the JWT minting
/// path and `RustBackend` construction.
pub(crate) fn validate_did_syntax(did: &str) -> Result<(), String> {
    let Some(rest) = did.strip_prefix("did:") else {
        return Err(format!("{did:?} does not start with `did:`"));
    };
    let Some((method, identifier)) = rest.split_once(':') else {
        return Err(format!(
            "{did:?} lacks a method-specific identifier (expected `did:<method>:<identifier>`)"
        ));
    };
    if method.is_empty() {
        return Err(format!("{did:?} has an empty DID method"));
    }
    if identifier.is_empty() {
        return Err(format!("{did:?} has an empty method-specific identifier"));
    }
    Ok(())
}

/// Mint a fresh ES256K service-auth JWT.
///
/// Every Aurora HTTP call mints a fresh token — no caching, no
/// refresh, no reuse across calls (umbrella §5.1; short-lived,
/// per-call, cheap to mint).
///
/// - `iss` — cairn-mod's service DID.
/// - `aud` — the target PDS's service DID (Aurora byte-compares
///   this against its own `service_did()`).
/// - `lxm` — the target NSID (e.g.
///   `tools.aurora.describeCapabilities`).
/// - `exp_secs` — lifetime; typically 3600 (Aurora's cap when
///   `lxm` is present per recon §1c).
///
/// Serialization is canonical-compact: `serde_json` emits no
/// whitespace, and both header and payload keys are inserted in
/// sorted order. Aurora verifies over the transmitted bytes, so
/// canonicality is a tidiness property rather than an interop
/// requirement — but it costs nothing to keep the wire form
/// deterministic (modulo the `jti` nonce and timestamps).
pub fn mint_service_auth_jwt(
    signing_key: &SigningKey,
    iss: &str,
    aud: &str,
    lxm: &str,
    exp_secs: u64,
) -> Result<String, ServiceAuthError> {
    validate_did_syntax(iss).map_err(ServiceAuthError::InvalidDid)?;
    validate_did_syntax(aud).map_err(ServiceAuthError::InvalidDid)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ServiceAuthError::ClockFailure(e.to_string()))?
        .as_secs();

    // Keys inserted in sorted order; serde_json's `preserve_order`
    // feature (enabled crate-wide) keeps insertion order on the
    // wire.
    let header = serde_json::json!({
        "alg": "ES256K",
        "typ": "JWT",
    });
    let payload = serde_json::json!({
        "aud": aud,
        "exp": now + exp_secs,
        "iat": now,
        "iss": iss,
        "jti": uuid::Uuid::new_v4().to_string(),
        "lxm": lxm,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    // k256's Signer impl hashes the message with SHA-256 before
    // signing (RFC 6979 deterministic ECDSA). DER encoding matches
    // Aurora's `Signature::from_der` verification path.
    let signature: Signature = signing_key
        .try_sign(signing_input.as_bytes())
        .map_err(|e| ServiceAuthError::SigningFailed(e.to_string()))?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());

    Ok(format!("{signing_input}.{signature_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::VerifyingKey;
    use k256::ecdsa::signature::Verifier;

    fn test_key() -> SigningKey {
        // Deterministic test scalar (any non-zero 32 bytes).
        SigningKey::from_slice(&[0x42u8; 32]).expect("valid scalar")
    }

    const ISS: &str = "did:web:cairn-mod.example.com";
    const AUD: &str = "did:web:aurora-locus.example.com";
    const LXM: &str = "tools.aurora.describeCapabilities";

    fn decode_part(part: &str) -> serde_json::Value {
        let bytes = URL_SAFE_NO_PAD.decode(part).expect("base64url no-pad");
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    #[test]
    fn mint_produces_three_dot_separated_parts() {
        let jwt = mint_service_auth_jwt(&test_key(), ISS, AUD, LXM, 3600).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| !p.is_empty()));
    }

    #[test]
    fn header_decodes_to_es256k_jwt() {
        let jwt = mint_service_auth_jwt(&test_key(), ISS, AUD, LXM, 3600).unwrap();
        let header = decode_part(jwt.split('.').next().unwrap());
        assert_eq!(header["alg"], "ES256K");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header.as_object().unwrap().len(), 2);
    }

    #[test]
    fn payload_decodes_to_expected_claim_shape() {
        let jwt = mint_service_auth_jwt(&test_key(), ISS, AUD, LXM, 3600).unwrap();
        let payload = decode_part(jwt.split('.').nth(1).unwrap());
        assert_eq!(payload["iss"], ISS);
        assert_eq!(payload["aud"], AUD);
        assert_eq!(payload["lxm"], LXM);
        // jti is a parseable UUIDv4.
        let jti = payload["jti"].as_str().unwrap();
        assert!(uuid::Uuid::parse_str(jti).is_ok());
        // nbf and sub omitted per ATProto convention (§4.2).
        assert!(payload.get("nbf").is_none());
        assert!(payload.get("sub").is_none());
    }

    #[test]
    fn signature_verifies_against_public_key_via_der() {
        let key = test_key();
        let jwt = mint_service_auth_jwt(&key, ISS, AUD, LXM, 3600).unwrap();
        let (signing_input, sig_b64) = jwt.rsplit_once('.').unwrap();
        let sig_der = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        // Aurora's verification path: DER-parse then verify over
        // the transmitted header.payload bytes.
        let signature = Signature::from_der(&sig_der).expect("DER-encoded signature");
        VerifyingKey::from(&key)
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature verifies");
    }

    #[test]
    fn exp_and_iat_reflect_exp_secs() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = mint_service_auth_jwt(&test_key(), ISS, AUD, LXM, 900).unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payload = decode_part(jwt.split('.').nth(1).unwrap());
        let iat = payload["iat"].as_u64().unwrap();
        let exp = payload["exp"].as_u64().unwrap();
        assert!((before..=after).contains(&iat));
        assert_eq!(exp, iat + 900);
    }

    #[test]
    fn invalid_iss_did_returns_invalid_did() {
        for bad in ["", "not-a-did", "did:", "did:web", "did:web:", "did::x"] {
            let err = mint_service_auth_jwt(&test_key(), bad, AUD, LXM, 3600).unwrap_err();
            assert!(
                matches!(err, ServiceAuthError::InvalidDid(_)),
                "expected InvalidDid for iss {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn invalid_aud_did_returns_invalid_did() {
        let err =
            mint_service_auth_jwt(&test_key(), ISS, "aurora.example.com", LXM, 3600).unwrap_err();
        assert!(matches!(err, ServiceAuthError::InvalidDid(_)));
    }

    #[test]
    fn fresh_jwt_per_mint_no_reuse() {
        // Per-call semantics (§4.2): two mints produce distinct
        // tokens (jti nonce differs even at identical timestamps).
        let key = test_key();
        let a = mint_service_auth_jwt(&key, ISS, AUD, LXM, 3600).unwrap();
        let b = mint_service_auth_jwt(&key, ISS, AUD, LXM, 3600).unwrap();
        assert_ne!(a, b);
    }
}
