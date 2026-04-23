//! Manual JWT parsing + ES256K signature verification.
//!
//! We don't use `jsonwebtoken` because it has no ES256K support — we'd
//! have to hand-verify the signature either way, and owning the parser
//! removes an auth-critical dependency from the supply chain. ~40 lines
//! is worth the audit surface.
//!
//! JWT structure: `base64url(header).base64url(payload).base64url(sig)`.
//! Signature is computed over the raw ASCII bytes of the first two
//! segments (with the literal `.` between them) — NOT over the decoded
//! values (§RFC 7515 §5).

use base64::Engine as _;
use serde::Deserialize;

/// Header fields Cairn inspects. `typ` and `kid` are optional and
/// ignored by the verifier — the allowlist lives on `alg`.
#[derive(Debug, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    #[serde(default)]
    pub typ: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
}

/// Claims for ATProto service auth (§5.2). Every field is required —
/// `#[serde(deny_unknown_fields)]` is deliberately NOT set because the
/// PDS may include future claims Cairn doesn't know about yet; presence
/// of extra claims is not a rejection reason.
#[derive(Debug, Deserialize)]
pub struct JwtPayload {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub lxm: String,
}

#[derive(Debug)]
pub struct ParsedJwt {
    pub header: JwtHeader,
    pub payload: JwtPayload,
    /// Raw bytes `header.payload` (dot-joined, un-decoded). This is what
    /// the ES256K signature covers per RFC 7515 §5.
    pub signing_input: Vec<u8>,
    /// Raw 64-byte `(r, s)` compact signature. ATProto's ES256K uses
    /// this form, not DER.
    pub signature: Vec<u8>,
}

/// Parse-only: no signature check, no claim check. Callers verify in
/// the order prescribed by §5.2 (alg → structural → sig → claims →
/// replay → authz).
pub fn parse(token: &str) -> Result<ParsedJwt, JwtParseError> {
    let mut it = token.split('.');
    let header_b64 = it.next().ok_or(JwtParseError::Structure)?;
    let payload_b64 = it.next().ok_or(JwtParseError::Structure)?;
    let sig_b64 = it.next().ok_or(JwtParseError::Structure)?;
    if it.next().is_some() {
        return Err(JwtParseError::Structure);
    }
    if header_b64.is_empty() || payload_b64.is_empty() || sig_b64.is_empty() {
        return Err(JwtParseError::Structure);
    }

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_bytes = engine
        .decode(header_b64)
        .map_err(|_| JwtParseError::Base64)?;
    let payload_bytes = engine
        .decode(payload_b64)
        .map_err(|_| JwtParseError::Base64)?;
    let signature = engine.decode(sig_b64).map_err(|_| JwtParseError::Base64)?;

    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtParseError::HeaderJson)?;
    let payload: JwtPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| JwtParseError::PayloadJson)?;

    // Signing input is the UN-DECODED first two segments joined by `.`.
    let mut signing_input = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
    signing_input.extend_from_slice(header_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload_b64.as_bytes());

    Ok(ParsedJwt {
        header,
        payload,
        signing_input,
        signature,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum JwtParseError {
    #[error("JWT structure invalid (not three non-empty segments)")]
    Structure,
    #[error("JWT segment failed base64url decode")]
    Base64,
    #[error("JWT header is not valid JSON or is missing required fields")]
    HeaderJson,
    #[error("JWT payload is not valid JSON or is missing required claims")]
    PayloadJson,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn encode_jwt(header: &str, payload: &str, sig: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(sig)
        )
    }

    #[test]
    fn parses_well_formed_jwt() {
        let token = encode_jwt(
            r#"{"alg":"ES256K","typ":"JWT"}"#,
            r#"{"iss":"did:plc:a","aud":"did:plc:b","exp":100,"iat":50,"jti":"j","lxm":"m"}"#,
            &[0x42; 64],
        );
        let jwt = parse(&token).expect("parse");
        assert_eq!(jwt.header.alg, "ES256K");
        assert_eq!(jwt.payload.iss, "did:plc:a");
        assert_eq!(jwt.payload.aud, "did:plc:b");
        assert_eq!(jwt.payload.exp, 100);
        assert_eq!(jwt.payload.lxm, "m");
        assert_eq!(jwt.signature.len(), 64);
        // Signing input must be the un-decoded head.payload bytes.
        assert!(jwt.signing_input.contains(&b'.'));
    }

    #[test]
    fn rejects_wrong_segment_count() {
        assert!(matches!(
            parse("only.two").unwrap_err(),
            JwtParseError::Structure
        ));
        assert!(matches!(
            parse("a.b.c.d").unwrap_err(),
            JwtParseError::Structure
        ));
        assert!(matches!(parse("").unwrap_err(), JwtParseError::Structure));
    }

    #[test]
    fn rejects_empty_segments() {
        assert!(matches!(
            parse("a..c").unwrap_err(),
            JwtParseError::Structure
        ));
        assert!(matches!(
            parse(".b.c").unwrap_err(),
            JwtParseError::Structure
        ));
    }

    #[test]
    fn rejects_non_base64() {
        let token = "!!!.???.@@@";
        assert!(matches!(parse(token).unwrap_err(), JwtParseError::Base64));
    }

    #[test]
    fn rejects_missing_claims() {
        let token = encode_jwt(
            r#"{"alg":"ES256K"}"#,
            r#"{"iss":"x"}"#, // missing aud/exp/iat/jti/lxm
            &[0; 64],
        );
        assert!(matches!(
            parse(&token).unwrap_err(),
            JwtParseError::PayloadJson
        ));
    }

    #[test]
    fn rejects_missing_alg_in_header() {
        let token = encode_jwt(
            r#"{"typ":"JWT"}"#,
            r#"{"iss":"did:plc:a","aud":"did:plc:b","exp":100,"iat":50,"jti":"j","lxm":"m"}"#,
            &[0; 64],
        );
        assert!(matches!(
            parse(&token).unwrap_err(),
            JwtParseError::HeaderJson
        ));
    }

    #[test]
    fn signing_input_is_un_decoded_bytes() {
        let header = r#"{"alg":"ES256K"}"#;
        let payload =
            r#"{"iss":"did:plc:a","aud":"did:plc:b","exp":100,"iat":50,"jti":"j","lxm":"m"}"#;
        let token = encode_jwt(header, payload, &[0; 64]);
        let jwt = parse(&token).expect("parse");

        // Signing input must NOT equal the decoded bytes; it must be the
        // encoded segments with a literal dot. This is the RFC 7515 §5
        // rule that trips up hand-written verifiers.
        assert!(jwt.signing_input != format!("{header}.{payload}").as_bytes());
        assert_eq!(
            jwt.signing_input,
            format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header),
                URL_SAFE_NO_PAD.encode(payload)
            )
            .into_bytes()
        );
    }
}
