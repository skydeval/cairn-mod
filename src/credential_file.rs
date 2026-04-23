//! Shared file-permission invariants for on-disk credentials (§5.1 + §5.3).
//!
//! Both the labeler's private signing key (§5.1, read once at startup by
//! `cairn serve`) and the CLI's PDS session file (§5.3, rewritten on each
//! auto-refresh) live on disk with identical security requirements:
//!
//! - Mode exactly `0o600`. Wider → reject at load time.
//! - Owned by the current effective UID. Mismatch → reject.
//! - File-only input. Env-var-delivered key material is rejected at a
//!   higher layer (see [`reject_env_override`]).
//!
//! Extracting this check into one place means a future tightening (say,
//! rejecting setuid files too) lands once and covers both surfaces.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Error surface for credential-file invariants. Session and signing-key
/// modules each map these to their own error taxonomies with `From`
/// conversions so callers never see a bare `CredentialFileError` in the
/// top-level CLI error — the wrapping surfaces the context (*which*
/// credential failed).
#[derive(Debug, Error)]
pub enum CredentialFileError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("credential file {path} has insecure permissions (mode {mode:o}); expected 600")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("credential file {path} is owned by another user")]
    ForeignOwner { path: PathBuf },
    #[error(
        "{env} is set — key material is file-only (§5.1); unset the env var and use the file path"
    )]
    EnvOverrideRejected { env: &'static str },
    #[error("cairn CLI on this platform is not supported in v1; use a POSIX filesystem")]
    UnsupportedPlatform,
}

/// Unix mode + owner invariants. `Ok(())` only if the file's mode is
/// exactly `0o600` and the file's owner UID equals the current effective
/// UID.
pub fn check_mode_and_owner(path: &Path) -> Result<(), CredentialFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path)?;
        let mode = meta.mode() & 0o777;
        check_mode(path, mode)?;
        let current = current_uid();
        check_owner(path, meta.uid(), current)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(CredentialFileError::UnsupportedPlatform)
    }
}

/// Refuse startup if `env` is set in the process environment. §5.1
/// rejects env-var-delivered signing-key material; this is the
/// codified guardrail.
pub fn reject_env_override(env: &'static str) -> Result<(), CredentialFileError> {
    if std::env::var_os(env).is_some() {
        Err(CredentialFileError::EnvOverrideRejected { env })
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn check_mode(path: &Path, mode: u32) -> Result<(), CredentialFileError> {
    if mode == 0o600 {
        Ok(())
    } else {
        Err(CredentialFileError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        })
    }
}

/// Ownership predicate. Pure function so tests can exercise the
/// foreign-owner branch without needing `chown(2)` to a non-current UID.
#[cfg(unix)]
fn check_owner(path: &Path, file_uid: u32, current_uid: u32) -> Result<(), CredentialFileError> {
    if file_uid == current_uid {
        Ok(())
    } else {
        Err(CredentialFileError::ForeignOwner {
            path: path.to_path_buf(),
        })
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_owner_accepts_matching_uid() {
        assert!(check_owner(Path::new("x"), 1000, 1000).is_ok());
    }

    #[test]
    fn check_owner_rejects_foreign_uid() {
        let err = check_owner(Path::new("x"), 0, 1000).unwrap_err();
        assert!(matches!(err, CredentialFileError::ForeignOwner { .. }));
    }

    #[test]
    fn check_mode_accepts_0600() {
        assert!(check_mode(Path::new("x"), 0o600).is_ok());
    }

    #[test]
    fn check_mode_rejects_wider_modes() {
        for bad in [0o644, 0o640, 0o666, 0o700, 0o755, 0o777] {
            let err = check_mode(Path::new("x"), bad).unwrap_err();
            assert!(
                matches!(
                    err,
                    CredentialFileError::InsecurePermissions { mode, .. } if mode == bad
                ),
                "expected InsecurePermissions for mode {bad:o}, got {err:?}"
            );
        }
    }

    #[test]
    fn reject_env_override_passes_when_unset() {
        // Pick a name no real test harness would set.
        assert!(reject_env_override("CAIRN_DOES_NOT_EXIST_FOR_TEST").is_ok());
    }
}
