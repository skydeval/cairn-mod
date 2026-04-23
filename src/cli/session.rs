//! CLI session file — §5.3.
//!
//! The session file caches the PDS session tokens the CLI obtains at
//! `cairn login` time. Each subsequent authed command asks the PDS
//! for a **fresh** service auth JWT (via `getServiceAuth`) using the
//! access token stored here; the CLI never mints service auth JWTs
//! itself. §5.3 is explicit that this file is a *moderator
//! credential equivalent to the PDS app password*; the on-disk
//! invariants below are designed to catch any drift from that
//! security posture.
//!
//! On-disk invariants checked on every load:
//! - Mode exactly `0o600`. Wider → reject.
//! - File owned by the current effective UID. Mismatch → reject.
//! - `version` field equals [`SESSION_VERSION`]. Mismatch → reject.
//!
//! Writes are atomic: tempfile in the same directory (created with
//! mode `0o600` via `tempfile::NamedTempFile`, which uses
//! `O_CREAT | O_EXCL` with the target permissions set at open-time on
//! Unix), fsync, `rename(2)` into place. Same-directory POSIX rename
//! is atomic — `cairn report`'s auto-refresh-then-persist flow
//! relies on this.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Current schema version written to disk. A load that finds a
/// different value refuses to proceed rather than trying to migrate —
/// a schema change warrants an explicit `cairn login` re-auth.
pub const SESSION_VERSION: u32 = 1;

/// Env-var override for the session file path. §5.3 names this as
/// the scripted/CI escape hatch: pre-bake a session on a secure
/// machine and point CI at it via secret management.
pub const SESSION_FILE_ENV: &str = "CAIRN_SESSION_FILE";

/// Relative path under the config dir where the session lands when
/// no env override is set.
const DEFAULT_RELATIVE_PATH: &str = "cairn/session.json";

/// Cached PDS session + Cairn server identity. Everything needed to
/// mint a service auth JWT at the PDS and send the result to Cairn,
/// minus the moderator's actual signing key (which lives at the PDS).
///
/// Wire shape is serde-stable — a field addition requires bumping
/// [`SESSION_VERSION`] to force re-login.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionFile {
    /// Schema version. Validated on load; see [`SESSION_VERSION`].
    pub version: u32,
    /// Base URL of the Cairn labeler this session targets (e.g.,
    /// `https://labeler.example`). `cairn report --cairn-server`
    /// overrides per-invocation but the session-stored value is the
    /// default.
    pub cairn_server_url: String,
    /// Cairn's service DID, resolved at `cairn login` time from
    /// `<cairn_server_url>/.well-known/did.json` (or supplied via
    /// `--cairn-did` while #18's endpoint is pending). Used as `aud`
    /// on every `getServiceAuth` call.
    pub cairn_service_did: String,
    /// Moderator's PDS base URL (e.g., `https://bsky.social`). Auth
    /// source for every authed CLI call.
    pub pds_url: String,
    /// Authoritative moderator DID, taken from the `createSession`
    /// response — never from user-supplied `--handle`. Becomes `iss`
    /// on the PDS-minted service auth JWT.
    pub moderator_did: String,
    /// Moderator handle at login time, preserved for display only.
    /// The DID above is the identity of record.
    pub moderator_handle: String,
    /// Short-lived PDS access token. Presented to PDS
    /// `getServiceAuth` and refreshed on 401.
    pub access_jwt: String,
    /// Long-lived PDS refresh token. Presented to PDS
    /// `refreshSession` when `access_jwt` expires.
    pub refresh_jwt: String,
}

/// Error taxonomy for session-file operations. Surfaces enough
/// context to the CLI dispatcher to choose the right exit code (see
/// criterion G) without leaking the session contents.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("session file {path} has insecure permissions (mode {mode:o}); expected 600")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("session file {path} is owned by another user")]
    ForeignOwner { path: PathBuf },
    #[error(
        "session file {path} has unsupported version {found} (expected {expected}); re-run `cairn login`"
    )]
    UnsupportedVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("session file {path} is malformed: {source}")]
    Malformed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("could not resolve a config directory (set {env} to override)", env = SESSION_FILE_ENV)]
    NoConfigDir,
    #[error("cairn CLI on this platform is not supported in v1; use a POSIX filesystem and set {env}", env = SESSION_FILE_ENV)]
    UnsupportedPlatform,
}

// The shared credential-file checker (§5.1 + §5.3) reports failures in
// its own terms. Map into SessionError so callers keep getting the
// session-specific variants they already branch on.
impl From<crate::credential_file::CredentialFileError> for SessionError {
    fn from(e: crate::credential_file::CredentialFileError) -> Self {
        use crate::credential_file::CredentialFileError as C;
        match e {
            C::Io(io) => SessionError::Io(io),
            C::InsecurePermissions { path, mode } => {
                SessionError::InsecurePermissions { path, mode }
            }
            C::ForeignOwner { path } => SessionError::ForeignOwner { path },
            C::UnsupportedPlatform => SessionError::UnsupportedPlatform,
            // Session file loading never reject-on-env-override; the
            // session module has no env-var override semantics for its
            // credential bytes. If we ever get this variant it's a
            // misuse; surface as Io to keep the taxonomy small.
            C::EnvOverrideRejected { env } => SessionError::Io(io::Error::other(format!(
                "unexpected env-override rejection for {env}"
            ))),
        }
    }
}

/// Resolve the session path: `CAIRN_SESSION_FILE` env var first,
/// otherwise `<config_dir>/cairn/session.json` per XDG.
pub fn default_path() -> Result<PathBuf, SessionError> {
    default_path_with_env(|k| std::env::var_os(k))
}

/// Injection seam: test doubles the env lookup without mutating
/// process-global state (and without triggering `unsafe` under the
/// crate-level `forbid(unsafe_code)` lint).
fn default_path_with_env<F>(get: F) -> Result<PathBuf, SessionError>
where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    if let Some(p) = get(SESSION_FILE_ENV) {
        return Ok(PathBuf::from(p));
    }
    let base = dirs::config_dir().ok_or(SessionError::NoConfigDir)?;
    Ok(base.join(DEFAULT_RELATIVE_PATH))
}

impl SessionFile {
    /// Load a session from the given path.
    ///
    /// Returns `Ok(None)` when the file is absent — callers distinguish
    /// "not logged in" from "session is broken" via this shape.
    ///
    /// All three on-disk invariants (mode, owner, version) are
    /// checked before the JSON body is parsed.
    pub fn load(path: &Path) -> Result<Option<Self>, SessionError> {
        match fs::metadata(path) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        // §5.3 mode + owner invariants via the shared checker (§5.1 +
        // §5.3 share the rule set — see src/credential_file.rs).
        crate::credential_file::check_mode_and_owner(path)?;

        let bytes = fs::read(path)?;
        let session: SessionFile =
            serde_json::from_slice(&bytes).map_err(|source| SessionError::Malformed {
                path: path.to_path_buf(),
                source,
            })?;
        if session.version != SESSION_VERSION {
            return Err(SessionError::UnsupportedVersion {
                path: path.to_path_buf(),
                found: session.version,
                expected: SESSION_VERSION,
            });
        }
        Ok(Some(session))
    }

    /// Atomically write the session to `path` with mode `0o600`.
    ///
    /// Writes to a sibling tempfile (0600 at create-time), fsyncs,
    /// then `rename`s. `cairn report`'s auto-refresh-then-persist
    /// flow relies on this being atomic under concurrent readers.
    pub fn save(&self, path: &Path) -> Result<(), SessionError> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "session path has no parent")
        })?;
        fs::create_dir_all(parent)?;

        // Tighten directory mode at creation time; no-op if the
        // directory already existed with a looser mode (operator's
        // choice).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }

        // NamedTempFile creates with 0600 on Unix by default
        // (O_CREAT|O_EXCL with explicit mode at open-time). rename
        // preserves that mode.
        let mut tempfile = NamedTempFile::new_in(parent)?;
        let body = serde_json::to_vec_pretty(self).expect("SessionFile serializes");
        {
            use std::io::Write as _;
            tempfile.write_all(&body)?;
            tempfile.as_file().sync_all()?;
        }
        tempfile.persist(path).map_err(|e| e.error)?;
        Ok(())
    }
}

/// Idempotent removal of the session file. `Ok(())` regardless of
/// whether the file existed — `cairn logout` treats "already gone"
/// as success.
pub fn delete(path: &Path) -> Result<(), SessionError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

// mode + owner checks moved to `crate::credential_file`. Unit tests
// for the underlying predicates live there; the `wider_permissions_
// rejected_on_load` integration test still covers the session-side
// mapping (the `From<CredentialFileError> for SessionError` impl).

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_path_respects_env_override() {
        let p = default_path_with_env(|k| {
            assert_eq!(k, SESSION_FILE_ENV);
            Some("/tmp/cairn-override.json".into())
        })
        .unwrap();
        assert_eq!(p, PathBuf::from("/tmp/cairn-override.json"));
    }

    #[test]
    fn default_path_without_env_falls_back_to_config_dir() {
        let p = default_path_with_env(|_| None).unwrap();
        assert!(
            p.ends_with(DEFAULT_RELATIVE_PATH),
            "fallback path must end with {DEFAULT_RELATIVE_PATH}, got {p:?}"
        );
    }
}
