//! Signing-key newtype (§5.1).
//!
//! The wrapper enforces the §5.1 compile-time guarantees:
//! - Key bytes are never printed via `Debug` (custom redacting impl).
//! - Key material is never serialized (no `Serialize` / `Deserialize` impl).
//! - Memory holding key bytes is cleared on drop (`Zeroize` + `ZeroizeOnDrop`).
//!
//! The runtime-safe load path (file-only input, mode `0600` check,
//! owner check, explicit env-var rejection) is enforced where the key
//! is first consumed, not at wrap time.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
