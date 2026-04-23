//! Integration tests for `cairn_mod::cli::session` — §5.3 on-disk
//! contract.
//!
//! Coverage:
//! - roundtrip (save → load → assert equality)
//! - wider permissions rejected (chmod 0644 after save)
//! - absent file returns `Ok(None)` (distinguishes "not logged in"
//!   from "session broken")
//! - unsupported version rejected (write JSON with `"version": 2`
//!   and assert the load error)
//! - malformed JSON rejected with the right error variant
//! - atomic-write-under-racing-readers stress: readers hot-looping
//!   while a writer persists many distinct sessions must never see
//!   partial JSON. This exercises the POSIX `rename(2)` atomicity
//!   guarantee the save path depends on — `cairn report`'s
//!   auto-refresh-then-persist flow rewrites the session file on
//!   every PDS 401-then-refresh round-trip, so partial reads at
//!   runtime would be a real bug.
//!
//! Ownership (`ForeignOwner`) is covered by the unit test on
//! `check_owner` in src/cli/session.rs — exercising the integration
//! path would require `chown(2)` to a foreign UID, which requires
//! root.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use cairn_mod::cli::session::{self, SESSION_VERSION, SessionError, SessionFile};
use tempfile::TempDir;

fn sample() -> SessionFile {
    SessionFile {
        version: SESSION_VERSION,
        cairn_server_url: "https://labeler.example".into(),
        cairn_service_did: "did:web:labeler.example".into(),
        pds_url: "https://bsky.social".into(),
        moderator_did: "did:plc:testmoderator0000000000000".into(),
        moderator_handle: "alice.bsky.social".into(),
        access_jwt: "access-token".into(),
        refresh_jwt: "refresh-token".into(),
    }
}

fn path_in(dir: &TempDir) -> PathBuf {
    dir.path().join("session.json")
}

#[test]
fn roundtrip_save_load_equal() {
    let dir = tempfile::tempdir().unwrap();
    let p = path_in(&dir);
    let original = sample();
    original.save(&p).unwrap();

    // File exists at 0600 after save.
    let meta = fs::metadata(&p).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    let loaded = SessionFile::load(&p).unwrap().expect("session present");
    assert_eq!(loaded, original);
}

#[test]
fn absent_file_returns_none_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let p = path_in(&dir);
    assert!(!p.exists());
    let loaded = SessionFile::load(&p).unwrap();
    assert!(loaded.is_none());
}

#[test]
fn wider_permissions_rejected_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let p = path_in(&dir);
    sample().save(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    let err = SessionFile::load(&p).unwrap_err();
    match err {
        SessionError::InsecurePermissions { mode, .. } => assert_eq!(mode, 0o644),
        other => panic!("expected InsecurePermissions, got {other:?}"),
    }
}

#[test]
fn unsupported_version_rejected_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let p = path_in(&dir);
    // Write a valid-looking session with a bumped version directly
    // via serde — bypass SessionFile::save so we can set a version
    // the type system would otherwise constrain.
    let bad = serde_json::json!({
        "version": 2,
        "cairn_server_url": "https://labeler.example",
        "cairn_service_did": "did:web:labeler.example",
        "pds_url": "https://bsky.social",
        "moderator_did": "did:plc:x",
        "moderator_handle": "x",
        "access_jwt": "a",
        "refresh_jwt": "r"
    });
    fs::write(&p, serde_json::to_vec(&bad).unwrap()).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();

    let err = SessionFile::load(&p).unwrap_err();
    match err {
        SessionError::UnsupportedVersion {
            found, expected, ..
        } => {
            assert_eq!(found, 2);
            assert_eq!(expected, SESSION_VERSION);
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn malformed_json_rejected_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let p = path_in(&dir);
    fs::write(&p, b"{ this is not valid json").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();

    let err = SessionFile::load(&p).unwrap_err();
    assert!(
        matches!(err, SessionError::Malformed { .. }),
        "expected Malformed, got {err:?}"
    );
}

#[test]
fn delete_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let p = path_in(&dir);
    // Delete of absent file is Ok.
    session::delete(&p).unwrap();
    // And with file present.
    sample().save(&p).unwrap();
    assert!(p.exists());
    session::delete(&p).unwrap();
    assert!(!p.exists());
    // Idempotent second call.
    session::delete(&p).unwrap();
}

#[test]
fn save_creates_parent_directory_with_tight_mode() {
    let dir = tempfile::tempdir().unwrap();
    // Two-deep path so save() has to create both levels.
    let nested = dir.path().join("config/cairn/session.json");
    sample().save(&nested).unwrap();
    assert!(nested.exists());
    // Inner dir `cairn/` should be 0700.
    let inner = dir.path().join("config/cairn");
    let mode = fs::metadata(&inner).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "inner session directory should be tightened to 0700, got {mode:o}"
    );
}

/// Stress test for the POSIX `rename(2)` atomicity guarantee that
/// `SessionFile::save` relies on. §5.3's auto-refresh flow rewrites
/// the session file on every PDS 401 — a concurrent `cairn` process
/// loading the session mid-rewrite must never see a partial JSON
/// body.
///
/// Reader thread contract:
/// - `Ok(None)` → file transiently absent (ENOENT during rename);
///   acceptable.
/// - `Ok(Some(s))` → version check passed; acceptable.
/// - `Err(SessionError::Io(_))` → transient fs error (e.g., ENOENT
///   racing with the rename); acceptable.
/// - `Err(SessionError::Malformed { .. })` → FAIL; this would mean
///   a reader observed a half-written file.
/// - Any other error variant → FAIL (unexpected).
#[test]
fn atomic_write_under_racing_readers_never_yields_partial_json() {
    let dir = tempfile::tempdir().unwrap();
    let p = Arc::new(path_in(&dir));

    // Seed an initial valid session before readers start.
    sample().save(&p).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..8 {
        let p = Arc::clone(&p);
        let stop = Arc::clone(&stop);
        readers.push(thread::spawn(move || {
            let mut reads = 0u64;
            while !stop.load(Ordering::Relaxed) {
                match SessionFile::load(&p) {
                    Ok(None) => {}
                    Ok(Some(s)) => assert_eq!(s.version, SESSION_VERSION),
                    Err(SessionError::Io(_)) => {}
                    Err(e @ SessionError::Malformed { .. }) => {
                        panic!("reader observed partial JSON: {e:?}")
                    }
                    Err(other) => panic!("unexpected reader error: {other:?}"),
                }
                reads += 1;
            }
            reads
        }));
    }

    // Writer: many rewrites with distinct content, simulating the
    // auto-refresh flow.
    for i in 0..500 {
        let mut s = sample();
        s.access_jwt = format!("access-{i}");
        s.refresh_jwt = format!("refresh-{i}");
        s.save(&p).unwrap();
    }

    // Give readers a beat to exercise the post-write state, then
    // stop.
    thread::sleep(Duration::from_millis(20));
    stop.store(true, Ordering::Relaxed);

    let mut total_reads = 0u64;
    for r in readers {
        total_reads += r.join().unwrap();
    }
    // Sanity: readers actually ran.
    assert!(
        total_reads > 0,
        "no reads observed — reader threads didn't run"
    );
}
