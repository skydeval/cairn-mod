//! Subprocess smoke test for the `cairn serve` binary (L4).
//!
//! Library-level tests in `tests/serve.rs` drive
//! `cairn_mod::serve::run` directly and cover the lifecycle
//! mechanics. This file pins the last-mile contract: the actual
//! compiled `cairn` binary starts under a config, serves a request,
//! exits 0 on SIGTERM, and releases the lease so a follow-on start
//! succeeds.
//!
//! The test is slower than the library ones (it spawns a real
//! process and polls the listener) and Unix-only (SIGTERM delivery
//! via `rustix::process::kill_process`). On non-Unix platforms the
//! test body is compiled out and the file is effectively empty.

#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process};
use tempfile::TempDir;

const TEST_PRIV_HEX: &str = "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

fn cairn_bin() -> PathBuf {
    // Cargo sets this for integration tests to the path of the
    // just-built binary. Preferred over resolving via target/debug.
    PathBuf::from(env!("CARGO_BIN_EXE_cairn"))
}

fn free_port() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn write_config(dir: &TempDir, addr: SocketAddr) -> PathBuf {
    let db_path = dir.path().join("cairn.db");
    let key_path = dir.path().join("signing-key.hex");
    fs::write(&key_path, TEST_PRIV_HEX).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

    let config_path = dir.path().join("cairn.toml");
    let body = format!(
        r#"service_did = "did:web:labeler.test"
service_endpoint = "https://labeler.test"
bind_addr = "{addr}"
db_path = "{}"
signing_key_path = "{}"
"#,
        db_path.display(),
        key_path.display(),
    );
    let mut f = fs::File::create(&config_path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    config_path
}

fn wait_ready(addr: SocketAddr, deadline: Instant) {
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("binary at {addr} did not become ready in time");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn binary_serves_then_exits_cleanly_on_sigterm() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port();
    let config_path = write_config(&dir, addr);

    let mut child = Command::new(cairn_bin())
        .arg("serve")
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cairn serve");

    wait_ready(addr, Instant::now() + Duration::from_secs(10));

    // Smoke: hit an unauthenticated endpoint that the full wire-up
    // should be serving. We don't parse the body — just prove the
    // binary+config+router end-to-end is up.
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    stream
        .write_all(b"GET /.well-known/did.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    use std::io::Read as _;
    stream.read_to_end(&mut buf).unwrap();
    let head = std::str::from_utf8(&buf[..buf.len().min(64)]).unwrap_or("");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "expected 200 on /.well-known/did.json, got: {head}"
    );

    // Send SIGTERM.
    let pid = Pid::from_raw(child.id() as i32).expect("non-zero pid");
    kill_process(pid, Signal::TERM).expect("SIGTERM");

    // Wait for clean exit (bounded — graceful drain is 30s in
    // production, but an idle server should exit promptly).
    let exit = child
        .wait_timeout(Duration::from_secs(15))
        .expect("child exits")
        .expect("exit status");
    assert_eq!(
        exit.code(),
        Some(0),
        "cairn serve must exit 0 on SIGTERM; got {exit:?}"
    );

    // Lease must be released — start a second cairn serve against
    // the same DB and confirm it succeeds. This is the real-world
    // "systemctl restart" contract.
    let addr2 = free_port();
    let config2 = rewrite_addr(&config_path, addr2);
    let mut child2 = Command::new(cairn_bin())
        .arg("serve")
        .arg("--config")
        .arg(&config2)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn second cairn serve");
    wait_ready(addr2, Instant::now() + Duration::from_secs(10));

    // Clean up.
    let pid2 = Pid::from_raw(child2.id() as i32).unwrap();
    kill_process(pid2, Signal::TERM).unwrap();
    let exit2 = child2
        .wait_timeout(Duration::from_secs(15))
        .expect("second child exits")
        .expect("exit status");
    assert_eq!(exit2.code(), Some(0));
}

/// Rewrite the `bind_addr` line of a config file in place (returns
/// a new path with the substitution applied). Cheaper than
/// re-running `write_config` because the key + db paths stay the
/// same, letting the second start exercise the already-migrated DB.
fn rewrite_addr(src: &std::path::Path, new_addr: SocketAddr) -> PathBuf {
    let body = fs::read_to_string(src).unwrap();
    let rewritten = body
        .lines()
        .map(|line| {
            if line.starts_with("bind_addr") {
                format!("bind_addr = \"{new_addr}\"")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let out = src.with_extension("toml.addr2");
    fs::write(&out, rewritten).unwrap();
    out
}

// ---------- std::process::Child::wait_timeout shim ----------

/// `std::process::Child` doesn't expose a timeout in stable Rust yet
/// (wait_timeout crate provides it, but the test's dependency
/// footprint is already large). Hand-rolled polling with a modest
/// budget is fine for a one-off test.
trait WaitTimeout {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl WaitTimeout for std::process::Child {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.try_wait()? {
                Some(status) => return Ok(Some(status)),
                None => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}
