//! Integration tests for `SigningKey::load_from_file` (§5.1).
//!
//! Unit tests in `src/credential_file.rs` cover the mode/owner
//! predicates; this file covers the full end-to-end load contract:
//! hex parsing, length check, mode check, and the
//! `SIGNING_KEY_ENV_REJECTED` env-var guardrail.
//!
//! Env-override coverage is tricky because `std::env::set_var` on
//! Rust 2024 is `unsafe` (cannot cross the crate's
//! `#![forbid(unsafe_code)]`). The guardrail's unit-level behavior is
//! already covered by `credential_file::reject_env_override` tests;
//! the integration-level check is a smoke that a normally-running
//! process with the env var unset loads the key correctly.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use cairn_mod::signing_key::{KeyLoadError, SigningKey};

const GOOD_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

fn write_key(
    dir: &tempfile::TempDir,
    name: &str,
    contents: &[u8],
    mode: u32,
) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn loads_valid_hex_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_key(&dir, "key", GOOD_HEX.as_bytes(), 0o600);
    let _key = SigningKey::load_from_file(&path).expect("load");
    // We can't inspect the bytes from outside (Debug redacts, no
    // getter), so "no error" is the assertion. Derived pubkey use
    // is covered by the writer/signing tests that already exercise
    // SigningKey via from_bytes.
}

#[test]
fn accepts_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_key(&dir, "key", format!("{GOOD_HEX}\n").as_bytes(), 0o600);
    SigningKey::load_from_file(&path).expect("load with trailing newline");
}

#[test]
fn accepts_leading_and_trailing_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_key(&dir, "key", format!("  {GOOD_HEX}  \n").as_bytes(), 0o600);
    SigningKey::load_from_file(&path).expect("load with surrounding whitespace");
}

#[test]
fn rejects_wider_mode_before_reading_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_key(&dir, "key", GOOD_HEX.as_bytes(), 0o644);
    let err = SigningKey::load_from_file(&path).unwrap_err();
    assert!(
        matches!(err, KeyLoadError::CredentialFile(_)),
        "got {err:?}"
    );
}

#[test]
fn rejects_non_hex_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_key(&dir, "key", b"this is not hex at all", 0o600);
    let err = SigningKey::load_from_file(&path).unwrap_err();
    assert!(matches!(err, KeyLoadError::NotHex { .. }), "got {err:?}");
}

#[test]
fn rejects_wrong_length() {
    let dir = tempfile::tempdir().unwrap();
    // 30 hex chars → 15 bytes, not 32.
    let path = write_key(&dir, "key", b"abcdef0123456789abcdef0123456789", 0o600);
    let err = SigningKey::load_from_file(&path).unwrap_err();
    match err {
        KeyLoadError::WrongLength { got, .. } => assert_eq!(got, 16),
        other => panic!("expected WrongLength, got {other:?}"),
    }
}

#[test]
fn rejects_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonexistent");
    let err = SigningKey::load_from_file(&path).unwrap_err();
    assert!(
        matches!(err, KeyLoadError::CredentialFile(_)),
        "got {err:?}"
    );
}
