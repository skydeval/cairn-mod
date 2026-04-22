//! Byte-exact parity: `cairn_mod`'s canonical encoder + signer must produce
//! output identical to `@atproto/crypto` + `@ipld/dag-cbor` for every fixture
//! in `tests/fixtures/signature-corpus/`. See that directory's README for
//! the pinned reference versions and the fixture matrix.
//!
//! A divergence here is the load-bearing signal §F2 exists to catch: it
//! means emitted Cairn labels will not verify in the wider ATProto ecosystem.
//! Do not "fix" this test by regenerating fixtures — fix the encoder or
//! investigate the proto-blue / TS-reference delta.

use std::fs;
use std::path::{Path, PathBuf};

use cairn_mod::{Label, SigningKey, canonical_bytes, sign_label, verify_label};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signature-corpus")
}

#[derive(serde::Deserialize)]
struct KeyMeta {
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: String,
    #[serde(rename = "privateKeyHex")]
    private_key_hex: String,
}

fn load_key() -> (SigningKey, String) {
    let meta: KeyMeta = serde_json::from_str(
        &fs::read_to_string(fixture_dir().join("KEY.json")).expect("read KEY.json"),
    )
    .expect("parse KEY.json");
    let bytes: [u8; 32] = hex::decode(&meta.private_key_hex)
        .expect("decode hex")
        .try_into()
        .expect("32-byte key");
    (SigningKey::from_bytes(bytes), meta.public_key_multibase)
}

/// Parse a fixture `.json` (which does not contain `sig`) into a `Label`.
/// Uses `serde_json::Value` as an intermediate because `Label` intentionally
/// omits serde derives — its fields are managed at the Rust boundary, the
/// wire schema lives in `label_to_lex_value`.
fn parse_fixture_json(path: &Path) -> Label {
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).expect("read fixture json"))
            .expect("parse fixture json");
    let o = v.as_object().expect("fixture json is an object");

    Label {
        ver: o["ver"].as_i64().expect("ver i64"),
        src: o["src"].as_str().expect("src str").to_string(),
        uri: o["uri"].as_str().expect("uri str").to_string(),
        cid: o.get("cid").and_then(|v| v.as_str()).map(String::from),
        val: o["val"].as_str().expect("val str").to_string(),
        neg: o.get("neg").and_then(|v| v.as_bool()).unwrap_or(false),
        cts: o["cts"].as_str().expect("cts str").to_string(),
        exp: o.get("exp").and_then(|v| v.as_str()).map(String::from),
        sig: None,
    }
}

fn fixture_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fixture_dir())
        .expect("read corpus dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            // Accept only NN-*.json; ignore KEY.json, package.json, node_modules, etc.
            if name.ends_with(".json") && name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                Some(name.trim_end_matches(".json").to_string())
            } else {
                None
            }
        })
        .collect();
    names.sort();
    assert!(
        !names.is_empty(),
        "no fixtures found in {}",
        fixture_dir().display()
    );
    names
}

/// First diverging byte offset + hex context, for readable parity failures.
fn first_diff(a: &[u8], b: &[u8]) -> Option<String> {
    if a == b {
        return None;
    }
    let limit = a.len().min(b.len());
    for i in 0..limit {
        if a[i] != b[i] {
            let lo = i.saturating_sub(4);
            let hi = (i + 8).min(limit);
            return Some(format!(
                "diff at offset {i}: cairn={:02x} expected={:02x} (context cairn={}, expected={})",
                a[i],
                b[i],
                hex::encode(&a[lo..hi]),
                hex::encode(&b[lo..hi]),
            ));
        }
    }
    Some(format!(
        "length mismatch: cairn={} expected={}",
        a.len(),
        b.len()
    ))
}

#[test]
fn cbor_bytes_match_reference_for_every_fixture() {
    let dir = fixture_dir();
    for name in fixture_names() {
        let label = parse_fixture_json(&dir.join(format!("{name}.json")));
        let actual = canonical_bytes(&label).expect("encode");
        let expected = fs::read(dir.join(format!("{name}.cbor"))).expect("read .cbor");

        if let Some(diff) = first_diff(&actual, &expected) {
            panic!("{name}: CBOR parity failure: {diff}");
        }
    }
}

#[test]
fn signatures_match_reference_for_every_fixture() {
    let (key, _multibase) = load_key();
    let dir = fixture_dir();
    for name in fixture_names() {
        let label = parse_fixture_json(&dir.join(format!("{name}.json")));
        let actual = sign_label(&key, &label).expect("sign");
        let expected = fs::read(dir.join(format!("{name}.sig"))).expect("read .sig");

        if let Some(diff) = first_diff(&actual, &expected) {
            panic!("{name}: signature parity failure: {diff}");
        }
    }
}

#[test]
fn reference_signatures_verify_in_cairn() {
    // Symmetric check: even if `sign_label` output matches, we want to confirm
    // `verify_label` accepts signatures produced by the TS reference chain —
    // this is the ingress path, where proto-blue's parity to @atproto/api
    // verification is what keeps Cairn-emitted labels verifying in the wild.
    let (_key, multibase) = load_key();
    let dir = fixture_dir();
    for name in fixture_names() {
        let mut label = parse_fixture_json(&dir.join(format!("{name}.json")));
        let sig_bytes: [u8; 64] = fs::read(dir.join(format!("{name}.sig")))
            .expect("read .sig")
            .try_into()
            .expect("sig is 64 bytes");
        label.sig = Some(sig_bytes);

        verify_label(&multibase, &label)
            .unwrap_or_else(|e| panic!("{name}: reference signature did not verify in Cairn: {e}"));
    }
}
