//! Audit-log hash-chain primitive (#39, v1.3).
//!
//! Pure function `compute_audit_row_hash` plus the `GENESIS_PREV_HASH`
//! sentinel. Called by both append paths (writer-task-mediated and
//! pool-direct) so the hash implementation is single-sourced — drift
//! between the paths is impossible by construction.
//!
//! The hash construction matches the existing label-signing posture
//! (§6.2): proto-blue's `lex_cbor::encode` for canonical DAG-CBOR + an
//! ATProto-conventional SHA-256. No new dep, no parallel canonical
//! scheme.
//!
//! ```text
//! row_hash = SHA-256(prev_hash || dag_cbor_canonical(row_content))
//! ```
//!
//! `row_content` is a CBOR map of the row's audit fields, deliberately
//! excluding the SQL-level `id`, `prev_hash`, and `row_hash` columns:
//!
//! - `id` is a primary key, not an audit semantic. The chain locks
//!   ordering via prev_hash; an attacker reordering rows would break
//!   every affected row's prev_hash link, so id-in-hash adds no
//!   integrity power.
//! - `prev_hash` and `row_hash` are the chain fields themselves
//!   (including either would be circular).

use std::collections::BTreeMap;

use proto_blue_lex_cbor::encode;
use proto_blue_lex_data::LexValue;

use crate::error::{Error, Result};

/// Sentinel used as `prev_hash` for the genesis row of any audit chain.
/// Documented value: 32 zero bytes.
///
/// The append path falls back to this sentinel whenever the latest
/// audit_log row has `NULL row_hash` — i.e., the table is empty, or it
/// only contains pre-v1.3 rows that haven't been backfilled yet. After
/// `cairn audit-rebuild` (#40) runs, pre-v1.3 rows form their own chain
/// rooted at this same sentinel; the post-migration chain is unaffected.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// Borrowed view of an audit row's hash-relevant content.
///
/// Field set is the audit_log columns minus the SQL/chain plumbing
/// (`id`, `prev_hash`, `row_hash`). Optional columns are `Option<&str>`;
/// absence is encoded as field-omission in the canonical CBOR (matching
/// the §6.2 / `@atproto/api` convention of "absent != null").
pub struct AuditRowForHashing<'a> {
    /// Internal wall-clock epoch-ms (matches the `created_at INTEGER`
    /// column).
    pub created_at: i64,
    /// Audit-action discriminator (e.g. `"label_applied"`).
    pub action: &'a str,
    /// DID of the moderator/admin/operator that triggered the action.
    pub actor_did: &'a str,
    /// Optional target identifier (AT-URI, DID, report id, etc.).
    pub target: Option<&'a str>,
    /// Optional CID pin on the target.
    pub target_cid: Option<&'a str>,
    /// `"success"` or `"failure"`.
    pub outcome: &'a str,
    /// Optional structured-JSON or free-text payload.
    pub reason: Option<&'a str>,
}

/// Compute the row hash for `row` chained from `prev_hash`.
///
/// `Err` only on the (unreachable in practice) case that proto-blue's
/// canonical encoder rejects the constructed `LexValue` — every field
/// is a bounded scalar or string here, so the encoder cannot fail
/// under valid inputs. The fallible signature is preserved for symmetry
/// with the rest of the signing surface and to keep the door open for
/// future field types that may push the encoder into refusal cases.
pub fn compute_audit_row_hash(
    prev_hash: &[u8; 32],
    row: &AuditRowForHashing<'_>,
) -> Result<[u8; 32]> {
    let canonical = encode(&audit_row_to_lex_value(row))?;
    let mut input = Vec::with_capacity(prev_hash.len() + canonical.len());
    input.extend_from_slice(prev_hash);
    input.extend_from_slice(&canonical);
    Ok(proto_blue_crypto::sha256(&input))
}

/// Build the `LexValue::Map` representation of the row's hash-relevant
/// content. proto-blue's canonical encoder applies the §6.2 sort
/// (length-first, then byte order) over the map keys; callers don't
/// need to pre-sort.
///
/// Optional fields are conditionally inserted so absence canonicalizes
/// as "key omitted" rather than "key with null value." The two encodings
/// produce different hashes, so this distinction is load-bearing for
/// chain integrity.
fn audit_row_to_lex_value(row: &AuditRowForHashing<'_>) -> LexValue {
    let mut m = BTreeMap::new();
    m.insert("created_at".to_string(), LexValue::Integer(row.created_at));
    m.insert(
        "action".to_string(),
        LexValue::String(row.action.to_string()),
    );
    m.insert(
        "actor_did".to_string(),
        LexValue::String(row.actor_did.to_string()),
    );
    if let Some(target) = row.target {
        m.insert("target".to_string(), LexValue::String(target.to_string()));
    }
    if let Some(target_cid) = row.target_cid {
        m.insert(
            "target_cid".to_string(),
            LexValue::String(target_cid.to_string()),
        );
    }
    m.insert(
        "outcome".to_string(),
        LexValue::String(row.outcome.to_string()),
    );
    if let Some(reason) = row.reason {
        m.insert("reason".to_string(), LexValue::String(reason.to_string()));
    }
    LexValue::Map(m)
}

/// Decode a stored `row_hash` blob into a 32-byte array. Returns
/// `Err(Error::Signing)` if the blob length is wrong — that's a DB
/// corruption case the caller surfaces as an internal error.
pub fn parse_stored_hash(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        Error::Signing(format!(
            "stored audit row_hash has wrong length: {} bytes (expected 32)",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_row<'a>() -> AuditRowForHashing<'a> {
        AuditRowForHashing {
            created_at: 1_776_902_400_000,
            action: "label_applied",
            actor_did: "did:plc:moderator0000000000000000",
            target: Some("at://did:plc:target/col/r"),
            target_cid: Some("bafytest"),
            outcome: "success",
            reason: Some(r#"{"val":"spam","neg":false,"moderator_reason":null}"#),
        }
    }

    #[test]
    fn deterministic_for_same_input() {
        let h1 = compute_audit_row_hash(&GENESIS_PREV_HASH, &fixture_row()).unwrap();
        let h2 = compute_audit_row_hash(&GENESIS_PREV_HASH, &fixture_row()).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic");
    }

    #[test]
    fn genesis_sentinel_is_32_zero_bytes() {
        assert_eq!(GENESIS_PREV_HASH, [0u8; 32]);
    }

    #[test]
    fn different_prev_hash_produces_different_row_hash() {
        let h1 = compute_audit_row_hash(&GENESIS_PREV_HASH, &fixture_row()).unwrap();
        let h2 = compute_audit_row_hash(&[1u8; 32], &fixture_row()).unwrap();
        assert_ne!(h1, h2, "prev_hash must affect row_hash");
    }

    #[test]
    fn different_action_produces_different_row_hash() {
        let mut row_a = fixture_row();
        row_a.action = "label_applied";
        let mut row_b = fixture_row();
        row_b.action = "label_negated";
        let h1 = compute_audit_row_hash(&GENESIS_PREV_HASH, &row_a).unwrap();
        let h2 = compute_audit_row_hash(&GENESIS_PREV_HASH, &row_b).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn absent_optional_differs_from_empty_string() {
        // Field-absent vs. field-present-with-empty-string canonicalize
        // differently; chain integrity depends on this distinction.
        let mut row_absent = fixture_row();
        row_absent.target = None;
        let mut row_empty = fixture_row();
        row_empty.target = Some("");
        let h_absent = compute_audit_row_hash(&GENESIS_PREV_HASH, &row_absent).unwrap();
        let h_empty = compute_audit_row_hash(&GENESIS_PREV_HASH, &row_empty).unwrap();
        assert_ne!(
            h_absent, h_empty,
            "absent target and empty target must hash distinctly"
        );
    }

    #[test]
    fn parse_stored_hash_round_trip() {
        let computed = compute_audit_row_hash(&GENESIS_PREV_HASH, &fixture_row()).unwrap();
        let parsed = parse_stored_hash(&computed).unwrap();
        assert_eq!(parsed, computed);
    }

    #[test]
    fn parse_stored_hash_rejects_wrong_length() {
        let too_short = [0u8; 20];
        assert!(parse_stored_hash(&too_short).is_err());
        let too_long = [0u8; 64];
        assert!(parse_stored_hash(&too_long).is_err());
    }

    #[test]
    fn chain_link_locks_ordering() {
        // Build a 3-row chain: H1 = H(GENESIS, row1); H2 = H(H1, row2);
        // H3 = H(H2, row3). Then verify that swapping row2 and row3's
        // content while keeping H2/H3 untouched would not match
        // recomputation — i.e., the chain detects reordering.
        let row1 = AuditRowForHashing {
            created_at: 1,
            action: "label_applied",
            actor_did: "did:plc:m1",
            target: None,
            target_cid: None,
            outcome: "success",
            reason: None,
        };
        let row2 = AuditRowForHashing {
            created_at: 2,
            action: "label_negated",
            actor_did: "did:plc:m1",
            target: None,
            target_cid: None,
            outcome: "success",
            reason: None,
        };
        let row3 = AuditRowForHashing {
            created_at: 3,
            action: "report_resolved",
            actor_did: "did:plc:m2",
            target: None,
            target_cid: None,
            outcome: "success",
            reason: None,
        };

        let h1 = compute_audit_row_hash(&GENESIS_PREV_HASH, &row1).unwrap();
        let h2 = compute_audit_row_hash(&h1, &row2).unwrap();
        let h3 = compute_audit_row_hash(&h2, &row3).unwrap();

        // Recompute as if rows 2 and 3 were swapped in commit order.
        // h2_swapped = H(h1, row3), h3_swapped = H(h2_swapped, row2).
        // Both swapped hashes differ from the originals, proving the
        // chain detects the reorder.
        let h2_swapped = compute_audit_row_hash(&h1, &row3).unwrap();
        let h3_swapped = compute_audit_row_hash(&h2_swapped, &row2).unwrap();
        assert_ne!(h2, h2_swapped);
        assert_ne!(h3, h3_swapped);
    }
}
