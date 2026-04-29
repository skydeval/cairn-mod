//! Shared types for the PDS-admin outbound bridge (§F23, #84,
//! v1.7).
//!
//! v1.7 introduces one new shared type: [`Subject`], the
//! identity carried by [`crate::pds_admin::PdsAdminBackend`]'s
//! label methods (`apply_label` / `negate_label`). The other
//! trait methods (account-level actions like `takedown_account`)
//! take a bare `did: &str` because the backend's wire shape
//! identifies accounts by DID alone; only the record-level
//! label surface needs the (DID, AT-URI, CID) triple.
//!
//! # Why a new type rather than reusing
//! [`crate::labels::emission::ActionForEmission`]
//!
//! `ActionForEmission` is the v1.5 label-emission projection —
//! it carries action-stream context (`action_type`,
//! `expires_at`, `reason_codes`) that doesn't belong on a
//! label-target identity. The [`PdsAdminBackend`] trait is
//! decoupled from cairn-mod's recordAction stream; backends can
//! be exercised by future direct-CLI tools (#99) and
//! cross-cutting tests, not just by the recorder. A minimal
//! pds_admin-local [`Subject`] keeps the trait's contract
//! independent of any one caller's projection.
//!
//! [`PdsAdminBackend`]: crate::pds_admin::PdsAdminBackend

use serde::{Deserialize, Serialize};

/// Subject of a label apply / negate call.
///
/// ATProto subjects have three coordinates:
/// - **DID** (always required): the account's DID. For
///   account-level labels this is the only relevant field.
/// - **AT-URI** (optional): present when the label targets a
///   specific record (e.g., `at://did:plc:.../app.bsky.feed.post/abc`).
///   Absent for account-level labels.
/// - **CID** (optional): present when the label pins a specific
///   record version. Absent when the label targets all
///   versions of a record OR the account.
///
/// The convention mirrors v1.5's
/// [`crate::labels::emission::ActionForEmission`]'s embedded
/// (subject_did, subject_uri, cid) triple, but without the
/// action-stream context fields. v1.7 trait callers project
/// from whatever domain shape they have (the recorder's
/// `RecordActionRequest`, an `ActionForEmission`, or operator
/// CLI input) into this minimal identity.
///
/// # Validation
///
/// Construction is unconditional — the type doesn't enforce
/// that `did.starts_with("did:")` or that `at_uri` parses as
/// AT-URI. v1.7 trait implementations validate at the wire
/// boundary (the backend's HTTP request layer in #86–#90);
/// pre-validation lives in the recorder's
/// [`crate::writer`]'s `route_subject` helper for the
/// recordAction path. The trait callers may call this type's
/// constructors with already-validated inputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subject {
    /// Account DID. Always present. Account-level labels target
    /// this DID directly; record-level labels still attribute
    /// to the parent account via this field for strike-state
    /// rollup (the same convention `subject_actions.subject_did`
    /// uses in v1.4-v1.6).
    pub did: String,
    /// AT-URI for record-level labels. `None` for account-level
    /// labels.
    pub at_uri: Option<String>,
    /// CID for record-version-pinned labels. `None` for
    /// "all versions of this record" or for account-level
    /// labels.
    pub cid: Option<String>,
}

impl Subject {
    /// Construct a [`Subject`] from a DID with no record-level
    /// or version-level qualification. Use this for
    /// account-level label targets.
    pub fn account(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            at_uri: None,
            cid: None,
        }
    }

    /// Construct a [`Subject`] for a record (versioned or not).
    /// `at_uri` should be a full `at://did:.../collection/rkey`
    /// URI; the parent repo DID is supplied separately so
    /// callers don't have to re-parse the URI to recover it.
    /// Pass `cid = None` to label all versions; pass
    /// `cid = Some(...)` to pin a specific record version.
    pub fn record(did: impl Into<String>, at_uri: impl Into<String>, cid: Option<String>) -> Self {
        Self {
            did: did.into(),
            at_uri: Some(at_uri.into()),
            cid,
        }
    }

    /// `true` when the subject is account-level (no AT-URI).
    /// Convenience for trait implementations that branch on
    /// account-vs-record path.
    pub fn is_account_level(&self) -> bool {
        self.at_uri.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_constructor_omits_uri_and_cid() {
        let s = Subject::account("did:plc:abc");
        assert_eq!(s.did, "did:plc:abc");
        assert!(s.at_uri.is_none());
        assert!(s.cid.is_none());
        assert!(s.is_account_level());
    }

    #[test]
    fn record_constructor_with_cid_pins_version() {
        let s = Subject::record(
            "did:plc:abc",
            "at://did:plc:abc/app.bsky.feed.post/xyz",
            Some("bafy123".to_string()),
        );
        assert_eq!(s.did, "did:plc:abc");
        assert_eq!(
            s.at_uri.as_deref(),
            Some("at://did:plc:abc/app.bsky.feed.post/xyz")
        );
        assert_eq!(s.cid.as_deref(), Some("bafy123"));
        assert!(!s.is_account_level());
    }

    #[test]
    fn record_constructor_without_cid_targets_all_versions() {
        let s = Subject::record(
            "did:plc:abc",
            "at://did:plc:abc/app.bsky.feed.post/xyz",
            None,
        );
        assert!(s.cid.is_none());
        assert!(s.at_uri.is_some());
        assert!(!s.is_account_level());
    }

    #[test]
    fn subject_serde_roundtrips() {
        let s = Subject::record(
            "did:plc:abc",
            "at://did:plc:abc/app.bsky.feed.post/xyz",
            Some("bafy123".into()),
        );
        let json = serde_json::to_string(&s).unwrap();
        let back: Subject = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
