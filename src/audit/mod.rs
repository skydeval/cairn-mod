//! Audit-log hash chain (#39, v1.3).
//!
//! The chain layers cryptographic tamper-detection on top of §F10's
//! existing `audit_log` table. Two columns (`prev_hash`, `row_hash`)
//! are filled at INSERT time by every v1.3+ append path:
//!
//! ```text
//! row_hash = SHA-256(prev_hash || dag_cbor_canonical(row_content))
//! ```
//!
//! Pre-v1.3 rows have NULL hashes until [`cairn audit-rebuild`](#40)
//! backfills them. The v1.3 chain is rooted at
//! [`hash::GENESIS_PREV_HASH`] and rebuild's pre-rebuild chain is
//! similarly rooted at GENESIS — they're two independent chains
//! sharing the same physical table.
//!
//! Trust horizon: only post-migration rows carry the integrity claim.
//! Pre-rebuild rows are hashed for completeness but unattested — an
//! attacker could have tampered before the rebuild ran.

pub mod append;
pub mod hash;
