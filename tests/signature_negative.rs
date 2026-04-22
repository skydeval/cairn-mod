//! Negative paths the signing boundary must reject (§F2).
//!
//! - A label tampered with after signing.
//! - A signature verified against the wrong key.
//! - A *high-S* signature. proto-blue's emission path already normalizes
//!   to low-S; this test covers the ingress side, where a malicious or
//!   buggy external signer could submit a (r, n-s) variant. §F2 treats
//!   high-S rejection at emit AND verify as the full invariant, and the
//!   verify-side check is what keeps it airtight.

use cairn_mod::{Label, SigningKey, sign_label, verify_label};

const PRIV_HEX_A: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";
// Independent secp256k1 key material — different scalar, different pubkey.
const PRIV_HEX_B: &str = "3a9c1f42d5e8b7c6a01d2f8e4b0c7d3a5f6e9c8b1d2a4f7e0c3b5a8d6f1e4c9b";

fn key(hex_str: &str) -> SigningKey {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    SigningKey::from_bytes(bytes)
}

/// Derive the `publicKeyMultibase` that `verify_label` expects from a
/// hex-encoded private key. Computed via proto-blue so the test boundary
/// matches what production uses.
fn multibase_from_hex(hex_str: &str) -> String {
    use proto_blue_crypto::{K256Keypair, Keypair as _, format_multikey};
    let bytes = hex::decode(hex_str).expect("hex");
    let kp = K256Keypair::from_private_key(&bytes).expect("k256 from priv");
    format_multikey("ES256K", &kp.public_key_compressed())
}

fn base_label() -> Label {
    Label {
        ver: 1,
        src: "did:plc:3jzfcijpj2z2a4pdagfkktq6".to_string(),
        uri: "at://did:plc:3jzfcijpj2z2a4pdagfkktq6/app.bsky.feed.post/3k5jy6qyfh22".to_string(),
        cid: None,
        val: "spam".to_string(),
        neg: false,
        cts: "2026-04-22T12:00:00.000Z".to_string(),
        exp: None,
        sig: None,
    }
}

#[test]
fn tampered_label_is_rejected() {
    let k = key(PRIV_HEX_A);
    let mut label = base_label();
    label.sig = Some(sign_label(&k, &label).expect("sign"));

    // Mutate a signed field after signing. Verify must reject.
    label.val = "harassment".to_string();

    let err = verify_label(&multibase_from_hex(PRIV_HEX_A), &label)
        .expect_err("verify must reject tampered label");
    assert!(
        matches!(err, cairn_mod::Error::Signing(_)),
        "expected Signing error, got {err:?}"
    );
}

#[test]
fn wrong_key_is_rejected() {
    let k = key(PRIV_HEX_A);
    let mut label = base_label();
    label.sig = Some(sign_label(&k, &label).expect("sign"));

    // Verify with B's multibase — a completely unrelated key.
    let wrong_multibase = multibase_from_hex(PRIV_HEX_B);
    let err =
        verify_label(&wrong_multibase, &label).expect_err("verify must reject wrong-key signature");
    assert!(
        matches!(err, cairn_mod::Error::Signing(_)),
        "expected Signing error, got {err:?}"
    );
}

/// secp256k1 curve order n. Big-endian, 32 bytes.
///
/// Used to flip a low-S signature into the equivalent high-S form:
/// given valid (r, s) with s <= (n-1)/2, the pair (r, n-s) is also a
/// mathematically valid ECDSA signature over the same message, but
/// must be rejected as non-canonical per BIP-62 / ATProto requirements.
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Compute `n - s` as 32-byte big-endian unsigned subtraction. Panics if s
/// exceeds n, which cannot occur for a well-formed low-S ECDSA signature.
fn high_s_from_low(low_sig: [u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&low_sig[..32]);

    let s = &low_sig[32..];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let a = SECP256K1_ORDER[i] as u16;
        let b = s[i] as u16 + borrow;
        if a >= b {
            out[32 + i] = (a - b) as u8;
            borrow = 0;
        } else {
            out[32 + i] = (a + 0x100 - b) as u8;
            borrow = 1;
        }
    }
    assert_eq!(borrow, 0, "s exceeded n — malformed signature");
    out
}

#[test]
fn high_s_signature_is_rejected() {
    let k = key(PRIV_HEX_A);
    let mut label = base_label();
    let low_sig = sign_label(&k, &label).expect("sign");

    // Sanity: the pipeline emits a low-S signature. s is the second half,
    // and its top byte must be < 0x80 for it to be in the lower half of n.
    assert!(
        low_sig[32] < 0x80,
        "emit-side pipeline should produce low-S; got top-byte {:02x}",
        low_sig[32]
    );

    // Flip into the mathematically-equivalent high-S form.
    let high_sig = high_s_from_low(low_sig);
    assert!(
        high_sig[32] >= 0x80,
        "flip must produce high-S; got top-byte {:02x}",
        high_sig[32]
    );
    assert_ne!(low_sig, high_sig, "flip must actually change the bytes");

    label.sig = Some(high_sig);
    let err = verify_label(&multibase_from_hex(PRIV_HEX_A), &label)
        .expect_err("verify must reject high-S signature");
    assert!(
        matches!(err, cairn_mod::Error::Signing(_)),
        "expected Signing error, got {err:?}"
    );
}

#[test]
fn missing_signature_is_rejected() {
    // verify_label on a label with sig=None must error, not panic.
    let label = base_label();
    let err = verify_label(&multibase_from_hex(PRIV_HEX_A), &label)
        .expect_err("verify on unsigned label must error");
    assert!(
        matches!(err, cairn_mod::Error::Signing(_)),
        "expected Signing error, got {err:?}"
    );
}
