//! Signing-key newtype (§5.1).
//!
//! The wrapper enforces the §5.1 compile-time guarantees:
//! - Key bytes are never printed via `Debug` (custom redacting impl).
//! - Key material is never serialized (no `Serialize` / `Deserialize` impl).
//! - Memory holding key bytes is cleared on drop (`Zeroize` + `ZeroizeOnDrop`).
//!
//! The runtime-safe load path (file-only input, mode `0600` check,
//! owner check, explicit env-var rejection) is enforced at
//! [`SigningKey::load_from_file`] — the entry point used by
//! `cairn serve`.

use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::credential_file::{self, CredentialFileError};

/// Env var whose presence `cairn serve` refuses at startup (§5.1).
/// Codifying this rejection here prevents an "ergonomics" PR later
/// adding a `CAIRN_SIGNING_KEY=<hex>` escape hatch — any such change
/// breaks this constant's test.
pub const SIGNING_KEY_ENV_REJECTED: &str = "CAIRN_SIGNING_KEY";

/// Error surface for the file-based key loader.
#[derive(Debug, Error)]
pub enum KeyLoadError {
    #[error("signing key file: {0}")]
    CredentialFile(#[from] CredentialFileError),
    #[error(
        "signing key file {path} is not valid hex (expected 64 hex chars, optional trailing newline)"
    )]
    NotHex { path: PathBuf },
    #[error("signing key file {path} decodes to {got} bytes; expected 32")]
    WrongLength { path: PathBuf, got: usize },
}

/// 32-byte k256 (secp256k1) private signing-key material.
///
/// Deliberately omitted traits:
/// - `Serialize` / `Deserialize` — key bytes never leave the process as data.
/// - `Clone` — `ZeroizeOnDrop` assumes a single owner.
/// - `PartialEq` / `Eq` — equality would require constant-time comparison
///   (via the `subtle` crate); add it there if a caller actually needs it.
/// - `Display` — same redaction rationale as `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey([u8; 32]);

impl SigningKey {
    /// Wrap raw key bytes.
    ///
    /// Callers must source the bytes safely (§5.1: file-only, mode `0600`,
    /// owner check, env-var rejection).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32-byte scalar. Intentionally `pub(crate)`: the
    /// only in-tree consumer is `crate::signing`, which needs the bytes to
    /// construct a `K256Keypair`. The name flags the invariant breach
    /// (§5.1 "never serialized, never printed") so it isn't reached for
    /// casually.
    pub(crate) fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// Load a signing key from `path`. Enforces §5.1 end-to-end:
    ///
    /// 1. Refuse if [`SIGNING_KEY_ENV_REJECTED`] is set — key material
    ///    is file-only.
    /// 2. File mode exactly `0o600`, owned by current effective UID
    ///    (shared with the session-file invariant).
    /// 3. Contents parsed as hex (64 chars, optional trailing
    ///    newline/whitespace).
    /// 4. Decoded length must be 32 bytes.
    ///
    /// Intermediate buffers holding the decoded bytes are explicitly
    /// zeroized before drop so key material has one owner (the
    /// returned `SigningKey`) by the time this function returns.
    pub fn load_from_file(path: &Path) -> Result<Self, KeyLoadError> {
        credential_file::reject_env_override(SIGNING_KEY_ENV_REJECTED)?;
        credential_file::check_mode_and_owner(path)?;

        // Read as owned bytes so we can zeroize on drop rather than
        // leaving the file content in an unzeroized `String`.
        let mut raw = std::fs::read(path)
            .map_err(|e| KeyLoadError::CredentialFile(CredentialFileError::Io(e)))?;
        // Trim surrounding ASCII whitespace (newlines, spaces) without
        // allocating.
        let start = raw
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(raw.len());
        let end = raw
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map(|i| i + 1)
            .unwrap_or(0);
        let trimmed = &raw[start..end];

        let mut decoded = match hex::decode(trimmed) {
            Ok(v) => v,
            Err(_) => {
                raw.zeroize();
                return Err(KeyLoadError::NotHex {
                    path: path.to_path_buf(),
                });
            }
        };
        raw.zeroize();

        if decoded.len() != 32 {
            let got = decoded.len();
            decoded.zeroize();
            return Err(KeyLoadError::WrongLength {
                path: path.to_path_buf(),
                got,
            });
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        decoded.zeroize();

        // `[u8; 32]` is Copy — `from_bytes(bytes)` receives its own
        // copy and the local `bytes` still holds the scalar.
        // Zeroize the local before returning so SigningKey is the
        // sole remaining owner of the material.
        let key = SigningKey::from_bytes(bytes);
        bytes.zeroize();
        Ok(key)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::SigningKey;

    #[test]
    fn debug_redacts_bytes() {
        let key = SigningKey::from_bytes([0xAB; 32]);
        let dbg = format!("{key:?}");
        assert_eq!(dbg, "SigningKey(<redacted>)");
        assert!(!dbg.contains("AB"));
        assert!(!dbg.contains("ab"));
        assert!(!dbg.contains("171")); // 0xAB in decimal
    }
}
