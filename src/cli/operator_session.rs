//! Operator PDS session file (§F1).
//!
//! The operator is the DID that OWNS the labeler's PDS account —
//! distinct from moderators (§5.2, §5.3) who authenticate to Cairn.
//! Both use §5.3 file-permission invariants via the shared
//! [`crate::credential_file`] helper, but the files are separate:
//! different credentials, different paths, different lifetimes.
//!
//! Written by `cairn operator-login`, read by
//! `cairn publish-service-record`. Path lives in `config.operator.
//! session_path` — no XDG default because operator ops are deployment-
//! scoped (systemd service, release playbook) rather than user-scoped.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Current schema version. A load finding a different value refuses
/// to proceed and asks the operator to re-run `cairn operator-login`.
pub const OPERATOR_SESSION_VERSION: u32 = 1;

/// Wire shape of the operator session file. Deliberately narrower
/// than the moderator `SessionFile` from #16 — operator ops talk to
/// the PDS, not to Cairn, so cairn_server_url / cairn_service_did
/// would be inapplicable and misleading.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorSession {
    pub version: u32,
    /// The PDS the operator authenticated against.
    pub pds_url: String,
    /// Authoritative operator DID from `createSession`, not whatever
    /// handle the operator typed.
    pub operator_did: String,
    /// Handle at login time. Display only; the DID is identity.
    pub operator_handle: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
}

#[derive(Debug, Error)]
pub enum OperatorSessionError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("operator session file {path} is malformed: {source}")]
    Malformed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "operator session file {path} has unsupported version {found} (expected {expected}); re-run `cairn operator-login`"
    )]
    UnsupportedVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("{0}")]
    CredentialFile(#[from] crate::credential_file::CredentialFileError),
}

impl OperatorSession {
    /// Load the session at `path`. Returns `Ok(None)` if absent so
    /// `publish-service-record` can distinguish "not logged in"
    /// from "session broken." All §5.3 file invariants (mode, owner,
    /// platform) checked before parsing.
    pub fn load(path: &Path) -> Result<Option<Self>, OperatorSessionError> {
        match fs::metadata(path) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        crate::credential_file::check_mode_and_owner(path)?;

        let bytes = fs::read(path)?;
        let session: OperatorSession =
            serde_json::from_slice(&bytes).map_err(|source| OperatorSessionError::Malformed {
                path: path.to_path_buf(),
                source,
            })?;
        if session.version != OPERATOR_SESSION_VERSION {
            return Err(OperatorSessionError::UnsupportedVersion {
                path: path.to_path_buf(),
                found: session.version,
                expected: OPERATOR_SESSION_VERSION,
            });
        }
        Ok(Some(session))
    }

    /// Atomic write identical to the moderator session-file flow:
    /// sibling tempfile at 0600 (O_CREAT | O_EXCL open mode),
    /// fsync, `rename(2)`. Same POSIX guarantee the auto-refresh
    /// path relies on.
    pub fn save(&self, path: &Path) -> Result<(), OperatorSessionError> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "session path has no parent")
        })?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
        let mut tmp = NamedTempFile::new_in(parent)?;
        let body = serde_json::to_vec_pretty(self).expect("OperatorSession serializes");
        {
            use std::io::Write as _;
            tmp.write_all(&body)?;
            tmp.as_file().sync_all()?;
        }
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }
}

/// Idempotent file removal — same contract as
/// [`crate::cli::session::delete`].
pub fn delete(path: &Path) -> Result<(), OperatorSessionError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
