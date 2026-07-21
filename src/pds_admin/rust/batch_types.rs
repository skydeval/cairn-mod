//! Batch dispatch types + cap constants (v1.8.7, v2 §4.1/§7,
//! chainlink #143).
//!
//! Mirrors Aurora-Locus's dedicated-batch wire surface
//! (`BatchAccountsInput`/`BatchAccountsOutput`,
//! `aurora_admin.rs:1402-1431`; `BatchRecordsInput`, `:1463-1468`
//! at `2ffeb1a`) and the batch cap constants (`MAX_BATCH_SIZE`,
//! `:1387`; multi-subject caps, `:437-439`). The cap values
//! byte-match Aurora's — client-side validation is an optimization
//! and honest-error courtesy, not the authority; Aurora
//! re-validates and a drifted upstream cap surfaces as its 400
//! through the normal error mapping (§7).

use serde::{Deserialize, Serialize};

use super::super::backend::BackendError;
use super::action_types::SnapshotRef;

/// Dedicated-batch endpoint cap — Aurora's `MAX_BATCH_SIZE`
/// (`aurora_admin.rs:1387`). Applies to all four
/// `tools.aurora.admin.batch*` endpoints cairn-mod consumes.
pub const MAX_BATCH_SIZE: usize = 50;

/// Multi-subject `emitEvent` default cap — Aurora's
/// `MAX_SUBJECTS_DEFAULT` (`aurora_admin.rs:437`).
pub const MAX_SUBJECTS_DEFAULT: usize = 50;

/// Multi-subject cap for `DeleteAccount` — Aurora's
/// `MAX_SUBJECTS_DELETE_ACCOUNT` (`aurora_admin.rs:438`).
pub const MAX_SUBJECTS_DELETE_ACCOUNT: usize = 10;

/// Multi-subject cap for `DeleteBlob` — Aurora's
/// `MAX_SUBJECTS_DELETE_BLOB` (`aurora_admin.rs:439`).
pub const MAX_SUBJECTS_DELETE_BLOB: usize = 25;

/// Mirror of Aurora's `BatchAccountsOutput` — the response shape
/// shared by all four dedicated batch endpoints cairn-mod
/// consumes (v2 §4.1).
///
/// Per Aurora's whole-tx atomicity contract (its Arc 4 §8.4.2 /
/// chainlink #113 doc comment): a returned response always
/// corresponds to a landed chain row AND every per-subject
/// mutation having succeeded — partial success is not a state the
/// caller can observe, so `affected_count` equals the input length
/// on success. String ids per the v1.8.5 convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchOutcome {
    /// Aurora's moderation-event id for the batch.
    pub event_id: String,
    /// Aurora's audit-chain entry id (one chain entry per batch;
    /// subjects ride its `cascade_subjects`).
    pub audit_entry_id: String,
    /// Number of subjects mutated. Equals the input length on
    /// success (whole-tx atomicity — see the type doc).
    pub affected_count: u32,
    /// Per-subject snapshot list captured pre-mutation.
    #[serde(default)]
    pub snapshots: Vec<SnapshotRef>,
}

/// Wire body for the DID-list batch endpoints
/// (`batchTakedownAccounts` / `batchSuspendAccounts` /
/// `batchRestoreAccounts`) — mirror of Aurora's
/// `BatchAccountsInput`.
// Transient Phase-1 allow: consumed by the Phase-2 dispatch
// bodies (chainlink #143).
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BatchDidsBody<'a> {
    pub dids: &'a [String],
    pub rationale: &'a str,
}

/// Wire body for `batchTakedownRecords` — mirror of Aurora's
/// `BatchRecordsInput`. URI-level semantics: Aurora expands each
/// URI into an empty-CID cascade row ("URI-level takedown, no CID
/// anchor"); the empty-CID convention is scoped to this endpoint
/// only (v2 §3.3).
// Transient Phase-1 allow: consumed by the Phase-2 dispatch
// bodies (chainlink #143).
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BatchUrisBody<'a> {
    pub uris: &'a [String],
    pub rationale: &'a str,
}

/// Client-side mirror of Aurora's `validate_batch_size`
/// (`aurora_admin.rs:1516-1533`): empty input rejected, `> limit`
/// rejected (at-cap passes). Error messages match Aurora's shapes
/// so operators see the same text regardless of which side
/// rejects.
// Transient Phase-1 allow: consumed by the Phase-2 dispatch
// bodies (chainlink #143).
#[allow(dead_code)]
pub(crate) fn validate_batch_len<T>(
    items: &[T],
    limit: usize,
    label: &str,
) -> Result<(), BackendError> {
    if items.is_empty() {
        return Err(BackendError::Validation(format!(
            "{label} must contain at least one entry"
        )));
    }
    if items.len() > limit {
        return Err(BackendError::Validation(format!(
            "{} length {} exceeds limit of {}",
            label,
            items.len(),
            limit
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cap_constants_byte_match_aurora() {
        // Pinned against aurora_admin.rs:437-439 and :1387 at
        // 2ffeb1a (v2 §7).
        assert_eq!(MAX_BATCH_SIZE, 50);
        assert_eq!(MAX_SUBJECTS_DEFAULT, 50);
        assert_eq!(MAX_SUBJECTS_DELETE_ACCOUNT, 10);
        assert_eq!(MAX_SUBJECTS_DELETE_BLOB, 25);
    }

    #[test]
    fn batch_outcome_parses_aurora_output_and_tolerates_extra_fields() {
        let wire = json!({
            "eventId": "evt-100",
            "auditEntryId": "chain-200",
            "affectedCount": 3,
            "snapshots": [],
            "someFutureField": true
        });
        let parsed: BatchOutcome = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.event_id, "evt-100");
        assert_eq!(parsed.audit_entry_id, "chain-200");
        assert_eq!(parsed.affected_count, 3);
        assert!(parsed.snapshots.is_empty());
    }

    #[test]
    fn batch_bodies_serialize_camel_case() {
        let dids = vec!["did:plc:a".to_string(), "did:plc:b".to_string()];
        let body = BatchDidsBody {
            dids: &dids,
            rationale: "spam ring",
        };
        assert_eq!(
            serde_json::to_value(&body).unwrap(),
            json!({"dids": ["did:plc:a", "did:plc:b"], "rationale": "spam ring"})
        );
        let uris = vec!["at://did:plc:a/app.bsky.feed.post/r1".to_string()];
        let body = BatchUrisBody {
            uris: &uris,
            rationale: "policy",
        };
        assert_eq!(
            serde_json::to_value(&body).unwrap(),
            json!({"uris": ["at://did:plc:a/app.bsky.feed.post/r1"], "rationale": "policy"})
        );
    }

    #[test]
    fn validate_batch_len_boundaries() {
        // At-cap passes (Aurora uses `> limit`); cap+1 rejects;
        // empty rejects. Message shapes match Aurora's
        // validate_batch_size.
        let at_cap: Vec<u8> = vec![0; 50];
        assert!(validate_batch_len(&at_cap, 50, "batch").is_ok());

        let over: Vec<u8> = vec![0; 51];
        match validate_batch_len(&over, 50, "batch") {
            Err(BackendError::Validation(msg)) => {
                assert_eq!(msg, "batch length 51 exceeds limit of 50");
            }
            other => panic!("expected Validation, got {other:?}"),
        }

        let empty: Vec<u8> = Vec::new();
        match validate_batch_len(&empty, 50, "batch") {
            Err(BackendError::Validation(msg)) => {
                assert_eq!(msg, "batch must contain at least one entry");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
