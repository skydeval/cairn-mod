//! Known-answer regression test for `sign_label`.
//!
//! One hand-authored `Label` + one hardcoded 32-byte private key produces
//! one hardcoded expected signature. Independent of the parity corpus on
//! purpose: if someone "cleans up" `label_to_lex_value` and accidentally
//! changes field inclusion/ordering semantics, the parity test will catch
//! it — but the parity corpus can itself be regenerated. This KAT can't
//! be: changing the expected hex is a deliberate, reviewable act.
//!
//! The hand-authored values match `01-minimal` from the parity corpus so
//! the two tests corroborate rather than duplicate coverage.

use cairn_mod::{Label, SigningKey, sign_label};

/// Private key hex, shared with the parity corpus generator.
const PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

/// Expected raw 64-byte compact `(r, s)` signature for the label below.
///
/// If this value changes, either:
///
/// - the signing pipeline changed (bug — investigate), or
/// - RFC 6979 / low-S changed (upstream bug, or you broke determinism), or
/// - the canonical encoding changed (bug — parity corpus should also fail).
///
/// Never bless a change by regenerating this string without writing why in
/// the commit message.
const EXPECTED_SIG_HEX: &str = concat!(
    "2408a9ad267d35fa34f561cca79e8c9de884a3b7b1c4202a8f1f263b153a95f2",
    "02b9372f2b1402f2edd24f8c24632244d93a2ac2ee9abd0aa2866cc88dd7086c",
);

fn decode_hex_32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

#[test]
fn known_answer() {
    let key = SigningKey::from_bytes(decode_hex_32(PRIV_HEX));
    let label = Label {
        ver: 1,
        src: "did:plc:3jzfcijpj2z2a4pdagfkktq6".to_string(),
        uri: "at://did:plc:3jzfcijpj2z2a4pdagfkktq6/app.bsky.feed.post/3k5jy6qyfh22".to_string(),
        cid: None,
        val: "spam".to_string(),
        neg: false,
        cts: "2026-04-22T12:00:00.000Z".to_string(),
        exp: None,
        sig: None,
    };

    let actual = sign_label(&key, &label).expect("sign");
    assert_eq!(
        hex::encode(actual),
        EXPECTED_SIG_HEX,
        "sign_label produced a different signature than the locked-in expectation"
    );
}
