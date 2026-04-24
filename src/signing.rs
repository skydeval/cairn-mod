//! Label canonical encoding, signing, and verification (§6.2, §6.3, §F2).
//!
//! The canonical encoding is ATProto DAG-CBOR / DRISL: sorted map keys
//! (length-first, then byte order), shortest-form integers, no floats, no
//! indefinite-length items. proto-blue's `lex_cbor::encode` implements the
//! profile; byte-level parity against `@atproto/api` is pinned by the
//! fixture corpus at `tests/fixtures/signature-corpus/`.
//!
//! Signing pipeline per §6.2:
//!   label (sig removed, ver included) -> LexValue -> canonical CBOR
//!     -> SHA-256 -> k256::sign_prehash (RFC 6979) -> low-S normalize
//!     -> raw 64-byte (r, s) compact.
//!
//! Verification is the symmetric path through proto-blue's `verify_signature`
//! with `allow_malleable: false`, which rejects high-S signatures at the
//! verifier — the boundary at which a malicious or buggy external high-S
//! sig could enter the system.

use std::collections::BTreeMap;

use proto_blue_crypto::{
    K256Keypair, Signer as _, format_did_key, k256_compress_pubkey, parse_multikey,
    verify_signature,
};
use proto_blue_lex_cbor::encode;
use proto_blue_lex_data::LexValue;

use crate::error::{Error, Result};
use crate::label::Label;
use crate::signing_key::SigningKey;

/// Build the `LexValue::Map` used for canonical encoding per §6.2.
///
/// Rules applied here (each a §6.2 constraint the fixture corpus pins):
/// - `sig` is always omitted (step 3).
/// - `ver` is always present (step 2).
/// - `neg` is omitted when `false` (schema default) and present as `true`
///   otherwise — matches `@atproto/api`'s `omitFalse` behavior.
/// - `cid` and `exp` are omitted when absent (never encoded as null: DAG-CBOR
///   draws a hard line between "field absent" and "field present with null
///   value," and the spec prescribes absence).
fn label_to_lex_value(label: &Label) -> LexValue {
    let mut m = BTreeMap::new();
    m.insert("ver".to_string(), LexValue::Integer(label.ver));
    m.insert("src".to_string(), LexValue::String(label.src.clone()));
    m.insert("uri".to_string(), LexValue::String(label.uri.clone()));
    if let Some(cid) = &label.cid {
        m.insert("cid".to_string(), LexValue::String(cid.clone()));
    }
    m.insert("val".to_string(), LexValue::String(label.val.clone()));
    if label.neg {
        m.insert("neg".to_string(), LexValue::Bool(true));
    }
    m.insert("cts".to_string(), LexValue::String(label.cts.clone()));
    if let Some(exp) = &label.exp {
        m.insert("exp".to_string(), LexValue::String(exp.clone()));
    }
    LexValue::Map(m)
}

/// Canonical CBOR bytes of `label` with `sig` omitted — the exact byte
/// sequence that gets SHA-256'd before signing (§6.2 step 5 input).
///
/// Exposed for the parity corpus test, which compares these bytes to the
/// `.cbor` fixture produced by `@atproto/api`.
pub fn canonical_bytes(label: &Label) -> Result<Vec<u8>> {
    Ok(encode(&label_to_lex_value(label))?)
}

/// Build the wire-format `LexValue` for a *signed* label — same field rules
/// as the canonical pre-signing form but **also includes** `sig` as
/// `LexValue::Bytes`.
///
/// Used by the subscribeLabels frame encoder: the `#labels` body embeds each
/// label in full, sig included, so consumers can verify per §6.3.
///
/// Errors when `label.sig` is `None` — the wire encoding requires a signed
/// label, and callers should have either just signed it or loaded a signed
/// row from storage.
pub fn label_to_lex_value_with_sig(label: &Label) -> Result<LexValue> {
    let sig = label
        .sig
        .ok_or_else(|| Error::Signing("wire encoding requires signed label".into()))?;
    let LexValue::Map(mut m) = label_to_lex_value(label) else {
        unreachable!("label_to_lex_value always returns a Map")
    };
    m.insert("sig".to_string(), LexValue::Bytes(sig.to_vec()));
    Ok(LexValue::Map(m))
}

/// Sign `label` with `key`, returning a raw 64-byte compact `(r, s)` signature.
///
/// Pipeline matches §6.2 end-to-end: strip `sig`, canonical-encode, SHA-256,
/// RFC 6979 sign-prehash, low-S normalize. proto-blue's `K256Keypair::sign`
/// performs the last three steps atomically.
pub fn sign_label(key: &SigningKey, label: &Label) -> Result<[u8; 64]> {
    let keypair = K256Keypair::from_private_key(key.expose_secret())?;
    let bytes = canonical_bytes(label)?;
    let sig = keypair.sign(&bytes)?;
    sig.as_slice().try_into().map_err(|_| {
        Error::Signing(format!(
            "proto-blue returned non-64-byte signature ({} bytes)",
            sig.len()
        ))
    })
}

/// Verify that `label.sig` is a valid signature by the key encoded in
/// `public_key_multibase` over the canonical CBOR of `label` with `sig`
/// removed (§6.3).
///
/// `public_key_multibase` is the `publicKeyMultibase` form published at the
/// labeler's `#atproto_label` verification method. Only ES256K (secp256k1)
/// keys are accepted — ATProto label signatures are defined only for that
/// curve. The DID-document fetch path is out of scope here and lives in #11.
///
/// Rejects high-S signatures at the boundary: proto-blue's verifier calls
/// `normalize_s()` and returns `Ok(false)` when the input was high-S,
/// regardless of whether the (r, normalize_s(s)) pair would have verified.
/// This is the security-relevant property for malleability resistance.
pub fn verify_label(public_key_multibase: &str, label: &Label) -> Result<()> {
    let sig = label
        .sig
        .ok_or_else(|| Error::Signing("label has no signature".into()))?;

    let parsed = parse_multikey(public_key_multibase)?;
    if parsed.jwt_alg != "ES256K" {
        return Err(Error::Signing(format!(
            "expected ES256K label key, got {}",
            parsed.jwt_alg
        )));
    }
    let compressed = k256_compress_pubkey(&parsed.key_bytes)?;
    let did = format_did_key("ES256K", &compressed);

    let bytes = canonical_bytes(label)?;
    let ok = verify_signature(&did, &bytes, &sig, false)?;
    if !ok {
        return Err(Error::Signing("signature verification failed".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_label() -> Label {
        Label {
            ver: 1,
            src: "did:plc:test".to_string(),
            uri: "at://did:plc:subject/app.bsky.feed.post/abc123".to_string(),
            cid: None,
            val: "spam".to_string(),
            neg: false,
            cts: "2026-04-22T12:00:00.000Z".to_string(),
            exp: None,
            sig: None,
        }
    }

    #[test]
    fn canonical_encoding_omits_sig_and_defaults() {
        // Build two labels differing only in `sig` presence; canonical bytes
        // must be identical because sig is stripped before encoding.
        let l1 = fixture_label();
        let mut l2 = fixture_label();
        l2.sig = Some([0u8; 64]);

        let b1 = canonical_bytes(&l1).expect("encode l1");
        let b2 = canonical_bytes(&l2).expect("encode l2");
        assert_eq!(b1, b2, "sig-present vs sig-absent must canonicalize equal");

        // neg=false: byte sequence must not contain the UTF-8 for "neg".
        assert!(
            !b1.windows(3).any(|w| w == b"neg"),
            "neg=false must be omitted from canonical form"
        );
    }

    #[test]
    fn wire_encoding_includes_sig_and_pre_sign_does_not() {
        // Concrete anti-confusion test for the two-encoder split:
        // - label_to_lex_value_with_sig embeds the 64 sig bytes verbatim.
        // - canonical_bytes (the signing input) must never contain them.
        // A marker sig of repeated 0xCD is deliberately chosen: 0xCD is not
        // a valid ASCII character (so CID/uri/val text strings can't contain
        // it) and is not a valid DAG-CBOR structural byte for our field
        // shapes, so accidental collisions in unrelated encoded content
        // won't mask a real bug.
        let marker: [u8; 64] = [0xCD; 64];
        let mut label = fixture_label();
        label.sig = Some(marker);

        let presign = canonical_bytes(&label).expect("canonical");
        let wire = encode(&label_to_lex_value_with_sig(&label).expect("with_sig"))
            .expect("encode with_sig");

        assert!(
            wire.windows(64).any(|w| w == marker),
            "wire encoding must contain the 64 sig bytes contiguously"
        );
        assert!(
            !presign.windows(64).any(|w| w == marker),
            "pre-sign encoding must NOT contain sig bytes — any match means sig leaked into the signing input"
        );

        // Also assert the wire encoding rejects an unsigned label, since
        // callers should have either signed-then-encoded or loaded from
        // a row that already carries sig.
        let mut unsigned = fixture_label();
        unsigned.sig = None;
        let err = label_to_lex_value_with_sig(&unsigned)
            .expect_err("unsigned label must not wire-encode");
        assert!(matches!(err, Error::Signing(_)), "got {err:?}");
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        use proto_blue_crypto::Keypair as _;

        let key = SigningKey::from_bytes([0x42; 32]);
        let mut label = fixture_label();
        label.sig = Some(sign_label(&key, &label).expect("sign"));

        // Reconstruct the multibase that verify_label expects.
        let kp = K256Keypair::from_private_key(key.expose_secret()).unwrap();
        let multibase = proto_blue_crypto::format_multikey("ES256K", &kp.public_key_compressed());

        verify_label(&multibase, &label).expect("verify should pass");
    }

    #[test]
    fn signature_is_64_bytes() {
        let key = SigningKey::from_bytes([0x11; 32]);
        let sig = sign_label(&key, &fixture_label()).expect("sign");
        assert_eq!(sig.len(), 64);
    }
}
