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

use std::collections::BTreeMap;
use std::fmt;

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

// ===========================================================================
// Cross-release type-system foundation
// ===========================================================================
//
// The types below are the v1.8.1 ground-truth-stable foundation consumed
// by v1.8.2 onward. They land here because §5.1's additive-only rule
// requires later releases to use existing types — but they don't have
// v1.8.1 callers themselves.
//
// Surface-dependent siblings (Subject as a polymorphic Aurora-Locus
// shape, OAuthScope + credential types, Capability/CapabilitySet +
// describeCapabilities parser, PaginationRequest + PaginationOrdering)
// defer to their first cross-release consumer per the umbrella's
// types-deferred-to-first-consumer carve-out — see chainlinks #106-#109
// for tracking.

/// Versioned suffix on a capability family string, parsed from the
/// trailing `-vN` segment.
///
/// Capability strings advertised by Aurora-Locus follow a
/// `family-vN` convention where `family` is the human-readable
/// surface name (e.g. `subject-context`) and `vN` is a
/// monotonically-increasing version tag. `CapabilityVersion` wraps
/// that integer.
///
/// # Why `u32` and not semver
///
/// The Aurora-Locus capability advertisement contract is
/// monotonic-increment per family (`v1` → `v2` → `v3`); breaking
/// changes ship as a new major version of the family string itself,
/// not as a semver bump. Adopting semver here would add
/// expressiveness the wire surface doesn't use and would bend the
/// `parse_suffix` parser into accepting forms (`v1.2.3`,
/// `v1-rc1`) that don't appear in advertisements. Adding semver
/// later is a series-level revision per the v1.8 lock-ins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityVersion(pub u32);

impl CapabilityVersion {
    /// Parse a `vN` suffix into a [`CapabilityVersion`].
    ///
    /// Accepts `"v0"`, `"v1"`, `"v17"`, `"v999"`. Rejects:
    /// - missing or non-`v` prefix (`""`, `"1"`, `"V1"`),
    /// - non-numeric tail (`"v0a"`, `"v1.0"`, `"v1-rc1"`),
    /// - empty tail (`"v"`),
    /// - leading whitespace or other surrounding noise.
    ///
    /// Returns `None` for any of those — the caller decides
    /// whether unparseable means "treat as unversioned" or
    /// "reject the advertisement."
    pub fn parse_suffix(s: &str) -> Option<Self> {
        let n = s.strip_prefix('v')?;
        if n.is_empty() {
            return None;
        }
        n.parse::<u32>().ok().map(CapabilityVersion)
    }
}

impl fmt::Display for CapabilityVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Split a capability string `family-vN` into its `(family, version)`
/// components.
///
/// Returns `None` for unversioned strings (no `-v` segment) and for
/// strings whose suffix isn't a valid [`CapabilityVersion::parse_suffix`]
/// input. The family substring is whatever precedes the final `-v`;
/// multi-dash families like `tools-aurora-foo-v3` parse to
/// `("tools-aurora-foo", v3)`.
///
/// Best-effort: treats only the **last** `-v` occurrence as the
/// version separator, so a family that legitimately contains `-v`
/// elsewhere (e.g. a hypothetical `early-vintage-loader-v2`)
/// resolves correctly to `("early-vintage-loader", v2)`.
pub fn parse_capability_string(s: &str) -> Option<(String, CapabilityVersion)> {
    let (family, suffix) = s.rsplit_once("-v")?;
    if family.is_empty() {
        return None;
    }
    // CapabilityVersion::parse_suffix expects a leading `v`.
    let with_v = format!("v{suffix}");
    let version = CapabilityVersion::parse_suffix(&with_v)?;
    Some((family.to_string(), version))
}

/// Operator-policy classification for a capability family.
///
/// Aurora-Locus advertises capabilities at fine granularity; cairn-mod
/// classifies each family by how the operator should treat its
/// presence/absence transitions.
///
/// - [`Self::AutoAdvance`]: cairn-mod automatically uses the highest
///   advertised version on every cap-set refresh. Suitable for
///   read-only / monotonically-improving families where moving forward
///   carries no operator risk.
/// - [`Self::OperatorOptIn`]: cairn-mod requires the operator to
///   explicitly pin a version (or accept the default at config time).
///   Suitable for families whose new versions could change behavior
///   the operator has tested against a specific version.
///
/// The registry is empty in v1.8.1 — no families are classified yet
/// because no cap-gated trait method consumers exist. Populated by
/// later v1.8.x releases as they introduce consumers (see
/// [`CAPABILITY_CLASSIFICATIONS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityClassification {
    /// Auto-advance to highest advertised version on cap-set refresh.
    AutoAdvance,
    /// Operator must explicitly pin a version; cap-set refresh does
    /// not change the in-use version without operator action.
    OperatorOptIn,
}

/// Static registry mapping capability family → classification.
///
/// Populated at v1.8.1 with the families v1.8.2's protocol-parity
/// release consumes for its emitEvent-mapped action verbs. Entries
/// are **suffix-less family names** (no `-vN`) — Aurora advertises
/// wire strings like `mod-events-emit-v1`; [`parse_capability_string`]
/// yields the family and version separately, and
/// [`classification_for`] exact-matches on the family alone.
/// v1.8.1 has no runtime consumer of these entries beyond the
/// probe's advertised-set bookkeeping; v1.8.2 wires the real
/// consumers. Later v1.8.x releases extend the slice as they
/// introduce consumers:
///
// v1.8.3: tools.aurora.moderator.* (queryStatuses, queryEvents)
// v1.8.4: tools.aurora.moderator.* (getSubjectContext)
// v1.8.6: tools.aurora.admin.* (audit-trail family)
// v1.8.8: tools.aurora.admin.* (subscribeModEvents)
// v1.8.9: tools.aurora.admin.* (instance-metrics, runtime-settings)
// v1.8.10: tools.aurora.ops.*
// v1.8.12: tools.aurora.ops.kryphocron.* (three families registered;
//          no consumer until v1.8.13+ — substrate wiring only)
///
/// `tools.aurora.describeCapabilities` is intentionally NOT a
/// capability — it's the probe NSID itself, not a feature gated by
/// advertisement.
pub static CAPABILITY_CLASSIFICATIONS: &[(&str, CapabilityClassification)] = &[
    // Aurora advertises `mod-events-emit-v1` (recon §1b); v1.8.2's
    // emitEvent-mapped action verbs consume this family. AutoAdvance:
    // read-side detection of a monotonically-versioned surface with
    // no operator risk in moving forward.
    ("mod-events-emit", CapabilityClassification::AutoAdvance),
    // Aurora advertises `moderator-activity-v1` on
    // tools.aurora.moderator.queryEvents; queryStatuses (and
    // getEvent, unconsumed until v1.8.4) share the family without
    // re-declaring it (Aurora route attribution, admin.rs:471-491).
    // v1.8.3's read methods consume it. AutoAdvance: read-only
    // surface, no operator risk in advancing.
    ("moderator-activity", CapabilityClassification::AutoAdvance),
    // Aurora advertises `subject-context-v1` on
    // `tools.aurora.moderator.getSubjectContext` (attribution per
    // Aurora `admin.rs:484-502`); v1.8.4's `get_subject_context`
    // consumes it. AutoAdvance: read-only surface.
    ("subject-context", CapabilityClassification::AutoAdvance),
    // Aurora advertises `subject-history-v1` on
    // `tools.aurora.moderator.getSubjectHistory`; v1.8.4's
    // `get_subject_history` consumes it. AutoAdvance: read-only.
    ("subject-history", CapabilityClassification::AutoAdvance),
    // Aurora advertises `appeals-v1` on
    // `tools.aurora.moderator.listAppeals`, with `getAppeal`
    // sharing per Aurora's attribution model (`admin.rs:503-520`);
    // v1.8.4's `list_appeals`/`get_appeal` consume it.
    // AutoAdvance: read-only surface.
    ("appeals", CapabilityClassification::AutoAdvance),
    // Aurora advertises `audit-trail-v1` on
    // `tools.aurora.admin.getAuditTrail` (attribution per Aurora
    // `admin.rs:641-649`; getAuditEntry is bare-role-gated and
    // shares cairn-mod's gate); v1.8.6's audit reads consume it.
    // AutoAdvance: read-only surface.
    ("audit-trail", CapabilityClassification::AutoAdvance),
    // Aurora advertises `batch-takedown-v1` on
    // `tools.aurora.admin.batchTakedownAccounts` with the other
    // five batch routes sharing the family (attribution per
    // Aurora `admin.rs:544-573`); v1.8.7's four dedicated batch
    // methods consume it. **OperatorOptIn — the registry's first
    // such entry, and its first runtime consumer**: destructive
    // batch surfaces don't activate on advertisement alone. The
    // dispatch gate additionally requires an operator
    // `[pds_admin.rust.pinned_versions]` entry for the family
    // (`batch-takedown = "v1"`); unpinned dispatch refuses with
    // `CapabilityNotAdvertised`. See
    // `rust::RustBackend::dispatch_batch`.
    ("batch-takedown", CapabilityClassification::OperatorOptIn),
    // Aurora advertises `mod-events-stream-v1` on
    // `tools.aurora.admin.subscribeModEvents` (single-route
    // attribution, admin.rs:675-684); v1.8.8's realtime consumer
    // dispatches on it. **OperatorOptIn — the second such entry**
    // (audit-trail is AutoAdvance): a long-lived ingesting
    // WebSocket doesn't activate on advertisement alone; the
    // operator opts in with `mod-events-stream = "v1"` under
    // `[pds_admin.rust.pinned_versions]` (plus
    // `[pds_admin.rust.stream].enabled = true`).
    ("mod-events-stream", CapabilityClassification::OperatorOptIn),
    // Aurora advertises `instance-metrics-v1` on
    // `tools.aurora.ops.getInstanceMetrics` (the one ops-namespace
    // consumption; admin.rs:243-249); v1.8.9's metrics read
    // consumes it. AutoAdvance: read-only visibility surface.
    ("instance-metrics", CapabilityClassification::AutoAdvance),
    // Aurora advertises `runtime-settings-v1` on
    // `tools.aurora.admin.getRuntimeSetting` with setRuntimeSetting
    // sharing (admin.rs:685-700); v1.8.9 consumes both.
    // **OperatorOptIn — the third such entry** (family-level: the
    // pin gates read AND write; the write mutates PDS-global
    // config under a SuperAdmin floor upstream).
    ("runtime-settings", CapabilityClassification::OperatorOptIn),
    // Aurora advertises `kryphocron-read-v1` as the single cohort
    // capability across its ten kryphocron read/control routes
    // (admin.rs:717-767); registered at v1.8.12, first consumer
    // v1.8.13+. **OperatorOptIn — the fourth such entry**: the
    // family gates decode of private content
    // (`tools.kryphocron.feed.postPrivate` is the sole NSID
    // carrying `encodedContent`), and content access is consent
    // territory — operators opt in via
    // `[pds_admin.rust.pinned_versions]`.
    ("kryphocron-read", CapabilityClassification::OperatorOptIn),
    // Aurora advertises `kryphocron-rotation-v1` on
    // `tools.aurora.ops.kryphocron.triggerRotation`
    // (admin.rs:708-712); registered at v1.8.12, unconsumed.
    // AutoAdvance: genuinely pure operational visibility —
    // rotation state and batch identifiers, no per-account data,
    // no `encodedContent`.
    ("kryphocron-rotation", CapabilityClassification::AutoAdvance),
    // Aurora advertises `kryphocron-overrides-v1` on the two
    // per-account override routes (getAccountOverrides /
    // setAccountOverride, admin.rs:769-782); registered at
    // v1.8.12, unconsumed. AutoAdvance on the precise basis
    // (design §4.2, R1 S-1): this family's OperatorOptIn axis is
    // decode of private content, and neither overrides endpoint
    // returns `encodedContent` (`postPrivate` is the sole
    // carrier). The endpoints ARE SuperAdmin-gated per-account
    // policy mutations at Aurora, audit-chained upstream — but
    // cairn-mod consumes no ops-operator endpoints regardless.
    (
        "kryphocron-overrides",
        CapabilityClassification::AutoAdvance,
    ),
];

/// Look up a family's classification in the registry.
///
/// Returns `None` for unknown families (operator-side custom
/// capabilities, or families whose consumer hasn't shipped yet).
/// Callers decide whether unknown means "skip" or "warn" or
/// "fail-loud."
pub fn classification_for(family: &str) -> Option<CapabilityClassification> {
    CAPABILITY_CLASSIFICATIONS
        .iter()
        .find(|(name, _)| *name == family)
        .map(|(_, c)| *c)
}

/// One advertised capability, split into its family + version
/// coordinates (v1.8.1, §4.3).
///
/// `family` is the **suffix-less** family name (e.g.
/// `mod-events-emit`); the version travels separately. Produced by
/// parsing an Aurora-advertised wire string (`mod-events-emit-v1`)
/// via [`parse_capability_string`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Suffix-less family name (e.g. `mod-events-emit`).
    pub family: String,
    /// Version parsed from the wire string's `-vN` tail.
    pub version: CapabilityVersion,
}

/// Errors from building a [`CapabilitySet`] out of a
/// `describeCapabilities` response.
///
/// Reserved surface: at v1.8.1 [`CapabilitySet::from_describe_capabilities`]
/// never produces it — malformed extension names are *ignored*
/// (advisory-advertisement posture per umbrella §5.3), not fatal.
/// The variant exists so a future strict mode can fail the probe
/// without changing the constructor's signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityParseError {
    /// The response was structurally unusable. Never produced at
    /// v1.8.1; reserved for future strict parsing modes.
    #[error("malformed describeCapabilities response: {0}")]
    MalformedResponse(String),
}

/// The last-refreshed capability advertisement from the upstream
/// PDS (v1.8.1, §4.3).
///
/// Built from a [`DescribeCapabilitiesResponse`] by
/// [`Self::from_describe_capabilities`]; consulted by the probe's
/// required-capability check and (v1.8.2+) by capability-gated
/// trait methods. `inner` keeps the **highest** advertised version
/// per family so auto-advance selection (umbrella §5.3) is a plain
/// map lookup; `raw` keeps every advertised wire string verbatim
/// for debugging and operator-facing probe reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    /// family → highest advertised version.
    inner: BTreeMap<String, CapabilityVersion>,
    /// Raw advertised strings as received, in wire order.
    raw: Vec<String>,
}

impl CapabilitySet {
    /// The empty set — the state between construction and the
    /// first successful probe.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a set from Aurora's `describeCapabilities` response.
    ///
    /// Walks `extensions`, parsing each `name` via
    /// [`parse_capability_string`]. Names that don't match the
    /// `<family>-v<int>` shape are kept in the raw list but do not
    /// enter the family map — cairn-mod does not fail the probe on
    /// malformed advertisements (advisory posture, umbrella §5.3).
    /// When a family is advertised at multiple versions, the
    /// highest wins (auto-advance selection input).
    pub fn from_describe_capabilities(
        response: &DescribeCapabilitiesResponse,
    ) -> Result<Self, CapabilityParseError> {
        let mut inner: BTreeMap<String, CapabilityVersion> = BTreeMap::new();
        let mut raw = Vec::with_capacity(response.extensions.len());
        for ext in &response.extensions {
            raw.push(ext.name.clone());
            if let Some((family, version)) = parse_capability_string(&ext.name) {
                inner
                    .entry(family)
                    .and_modify(|v| *v = (*v).max(version))
                    .or_insert(version);
            }
        }
        Ok(Self { inner, raw })
    }

    /// Whether the upstream advertises any version of `family`.
    /// `family` is suffix-less (`mod-events-emit`, not
    /// `mod-events-emit-v1`).
    pub fn has(&self, family: &str) -> bool {
        self.inner.contains_key(family)
    }

    /// Highest advertised version for `family`, if advertised.
    pub fn version_of(&self, family: &str) -> Option<CapabilityVersion> {
        self.inner.get(family).copied()
    }

    /// Raw advertised strings as received from the upstream.
    pub fn advertised_strings(&self) -> &[String] {
        &self.raw
    }
}

/// cairn-mod-side mirror of Aurora's `describeCapabilities` wire
/// response (recon §1b; Aurora `src/api/admin.rs` — fields
/// `families`, `extensions`, `implementation`, `version`,
/// `camelCase` on the wire).
///
/// `families` is deliberately opaque: per umbrella §5.3 the
/// advertised list is an advisory capability-detection signal, not
/// an endpoint enumeration — cairn-mod's own
/// [`CAPABILITY_CLASSIFICATIONS`] registry is authoritative for
/// what the backend knows about.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeCapabilitiesResponse {
    /// Namespace → leaf-method-name arrays. Opaque at v1.8.1;
    /// cairn-mod doesn't consume this directly.
    pub families: serde_json::Value,
    /// Advertised capability strings (each `name` follows the
    /// `<kebab-family>-v<int>` convention).
    pub extensions: Vec<CapabilityExtension>,
    /// Upstream implementation identifier (`"aurora-locus"`).
    pub implementation: String,
    /// Upstream package version (e.g. `"0.10.0"`).
    pub version: String,
}

/// One advertised extension entry in
/// [`DescribeCapabilitiesResponse::extensions`].
///
/// Aurora omits `value` from the wire when not applicable
/// (`skip_serializing_if` on its side); serde's `Option` default
/// handles the absent key.
#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityExtension {
    /// Capability wire string, e.g. `mod-events-emit-v1`.
    pub name: String,
    /// Optional structured payload (e.g. an event-variant list).
    /// `None` when absent from the wire.
    pub value: Option<serde_json::Value>,
}

/// Opaque pagination cursor.
///
/// cairn-mod does not parse the inner string — it's whatever the
/// upstream PDS produced. Operators round-trip it verbatim from a
/// page response into the next page request.
///
/// The full `PaginationRequest` shape (limit + cursor + ordering)
/// defers to the first cross-release consumer because the
/// `ordering` question depends on Aurora-Locus's actual paginated-
/// read surface (see the deferred-types chainlink). The cursor
/// newtype itself is wire-shape-independent and lands here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginationCursor(pub String);

impl fmt::Display for PaginationCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A read row from Aurora-Locus's audit-trail surface.
///
/// Used by future cross-release consumers (v1.8.6+) that read
/// upstream audit rows for forensics, hash-chain verification,
/// or operator-facing display. v1.8.1 lands the type so v1.8.2-
/// v1.8.10 can refer to it under §5.1's additive-only rule;
/// no v1.8.1 code path constructs this.
///
/// `upstream_action` is `serde_json::Value` because the action
/// shape is the upstream's responsibility. Operators querying for
/// specific action shapes do their own JSON-path navigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTrailEntryRead {
    /// Upstream-assigned identifier (e.g., Aurora-Locus's
    /// `audit_chain_entry.id` or equivalent).
    pub upstream_id: String,
    /// Upstream-assigned monotonic sequence number used for
    /// chain-walk ordering. Distinct from `upstream_id` so the
    /// upstream can use opaque ids for forensics while
    /// preserving a sortable iteration key.
    pub upstream_seq: u64,
    /// Wall-clock epoch milliseconds when the upstream recorded
    /// the row. Matches v1.7's audit-row timestamp encoding.
    pub timestamp_epoch_ms: i64,
    /// Action payload as the upstream emitted it. Untyped at
    /// this layer; consumer-side types may project it via
    /// `serde_json::from_value`.
    pub upstream_action: serde_json::Value,
    /// Predecessor row's hash, if the upstream maintains a hash
    /// chain. `None` when the upstream doesn't expose chain
    /// links or when this row is the chain head.
    pub hash_chain_predecessor: Option<String>,
    /// Upstream-supplied signature over this row's
    /// canonicalized contents. Stored verbatim; verification
    /// happens at the consumer-side per the v1.8.6 audit-trail
    /// reader's contract.
    pub hash_chain_signature: String,
}

/// A write row destined for Aurora-Locus's audit-trail surface.
///
/// Used by future cross-release consumers (v1.8.5+) that write
/// upstream audit rows from cairn-mod-side actions. v1.8.1 lands
/// the type so v1.8.2-v1.8.10 can refer to it under §5.1's
/// additive-only rule; no v1.8.1 code path constructs this.
///
/// `subjects` is `Vec<serde_json::Value>` because the polymorphic
/// `Subject` type is deferred to first consumer (chainlink #106).
/// When `Subject` lands, this field's type tightens to
/// `Vec<Subject>` — a non-additive shape change that will require
/// the consuming release to coordinate with cairn-mod's release
/// notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTrailEntryWrite {
    /// Upstream-side batch identifier — Aurora-Locus's
    /// polymorphic `emitEvent` aggregates multiple subjects
    /// under one batch.
    pub batch_id: String,
    // TODO(#106): tighten Vec<serde_json::Value> to Vec<Subject>
    // when the polymorphic Subject type lands at its first
    // consumer step.
    /// Subjects this batch operates on. Untyped at this layer
    /// pending the polymorphic `Subject` type's first-consumer
    /// definition (see chainlink #106).
    pub subjects: Vec<serde_json::Value>,
    /// Event payload — Aurora-Locus's `emitEvent` variant
    /// shape. Untyped at this layer pending the typed
    /// `EventPayload` discriminator's first-consumer definition
    /// at v1.8.3.
    pub event_payload: serde_json::Value,
    /// Wall-clock epoch milliseconds when cairn-mod prepared
    /// the batch. The upstream records its own receipt time
    /// separately; this field is the cairn-mod-side wall clock.
    pub timestamp_epoch_ms: i64,
}

#[cfg(test)]
mod cross_release_type_tests {
    use super::*;

    // ----- CapabilityVersion -----

    #[test]
    fn capability_version_parses_well_formed_suffix() {
        assert_eq!(
            CapabilityVersion::parse_suffix("v0"),
            Some(CapabilityVersion(0))
        );
        assert_eq!(
            CapabilityVersion::parse_suffix("v1"),
            Some(CapabilityVersion(1))
        );
        assert_eq!(
            CapabilityVersion::parse_suffix("v17"),
            Some(CapabilityVersion(17))
        );
        assert_eq!(
            CapabilityVersion::parse_suffix("v999"),
            Some(CapabilityVersion(999))
        );
    }

    #[test]
    fn capability_version_rejects_malformed_suffix() {
        assert_eq!(CapabilityVersion::parse_suffix(""), None);
        assert_eq!(CapabilityVersion::parse_suffix("v"), None);
        assert_eq!(CapabilityVersion::parse_suffix("1"), None);
        assert_eq!(CapabilityVersion::parse_suffix("V1"), None); // uppercase rejected
        assert_eq!(CapabilityVersion::parse_suffix("v0a"), None);
        assert_eq!(CapabilityVersion::parse_suffix("v1.0"), None);
        assert_eq!(CapabilityVersion::parse_suffix("v1-rc1"), None);
        assert_eq!(CapabilityVersion::parse_suffix(" v1"), None); // leading whitespace
    }

    #[test]
    fn capability_version_orders_numerically() {
        assert!(CapabilityVersion(1) < CapabilityVersion(2));
        assert!(CapabilityVersion(9) < CapabilityVersion(10));
        assert_eq!(
            CapabilityVersion(5).max(CapabilityVersion(3)),
            CapabilityVersion(5)
        );
    }

    #[test]
    fn capability_version_displays_with_v_prefix() {
        assert_eq!(format!("{}", CapabilityVersion(7)), "v7");
    }

    // ----- parse_capability_string -----

    #[test]
    fn parse_capability_string_splits_well_formed() {
        assert_eq!(
            parse_capability_string("queue-query-v1"),
            Some(("queue-query".to_string(), CapabilityVersion(1)))
        );
        assert_eq!(
            parse_capability_string("subject-context-v2"),
            Some(("subject-context".to_string(), CapabilityVersion(2)))
        );
    }

    #[test]
    fn parse_capability_string_handles_multi_dash_family() {
        // The split takes the LAST `-v` only.
        assert_eq!(
            parse_capability_string("tools-aurora-foo-v3"),
            Some(("tools-aurora-foo".to_string(), CapabilityVersion(3)))
        );
    }

    #[test]
    fn parse_capability_string_rejects_unversioned() {
        assert_eq!(parse_capability_string("queue-query"), None);
        assert_eq!(parse_capability_string("plain"), None);
    }

    #[test]
    fn parse_capability_string_rejects_malformed_suffix() {
        assert_eq!(parse_capability_string("queue-query-v"), None);
        assert_eq!(parse_capability_string("queue-query-v0a"), None);
        assert_eq!(parse_capability_string("queue-query-v1.0"), None);
    }

    #[test]
    fn parse_capability_string_rejects_empty_family() {
        assert_eq!(parse_capability_string("-v1"), None);
        assert_eq!(parse_capability_string(""), None);
    }

    // ----- CapabilityClassification + registry -----

    #[test]
    fn capability_classifications_registry_shape() {
        // Pinned: any change to this constant requires a
        // coordinated release decision (capability-gated trait
        // surface activation, per the v1.8.x rollout plan).
        // v1.8.1 populated mod-events-emit (consumed by v1.8.2's
        // action verbs); v1.8.3 adds moderator-activity; v1.8.4
        // adds the three read families (subject-context,
        // subject-history, appeals); v1.8.6 adds audit-trail;
        // v1.8.7 adds batch-takedown — the first OperatorOptIn
        // entry AND the first runtime consumer of the
        // classification; v1.8.8 adds mod-events-stream (second
        // OperatorOptIn); v1.8.9 adds instance-metrics
        // (AutoAdvance) + runtime-settings (third OperatorOptIn);
        // v1.8.12 adds the three kryphocron substrate families —
        // kryphocron-read (fourth OperatorOptIn: gates decode of
        // private content) + kryphocron-rotation and
        // kryphocron-overrides (AutoAdvance: neither returns
        // encodedContent) — registered ahead of their first
        // consumer (v1.8.13+).
        // Entries are suffix-less family names.
        assert_eq!(CAPABILITY_CLASSIFICATIONS.len(), 13);
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[0],
            ("mod-events-emit", CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[1],
            ("moderator-activity", CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[2],
            ("subject-context", CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[3],
            ("subject-history", CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[4],
            ("appeals", CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[5],
            ("audit-trail", CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[6],
            ("batch-takedown", CapabilityClassification::OperatorOptIn)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[7],
            ("mod-events-stream", CapabilityClassification::OperatorOptIn)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[8],
            ("instance-metrics", CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[9],
            ("runtime-settings", CapabilityClassification::OperatorOptIn)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[10],
            ("kryphocron-read", CapabilityClassification::OperatorOptIn)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[11],
            ("kryphocron-rotation", CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            CAPABILITY_CLASSIFICATIONS[12],
            (
                "kryphocron-overrides",
                CapabilityClassification::AutoAdvance
            )
        );
        // No entry may carry a version suffix — classification_for
        // exact-matches on the suffix-less family that
        // parse_capability_string yields.
        for (family, _) in CAPABILITY_CLASSIFICATIONS {
            assert!(
                parse_capability_string(family).is_none(),
                "registry entry {family:?} carries a -vN suffix; entries must be suffix-less families"
            );
        }
    }

    #[test]
    fn classification_for_finds_v1_8_1_entries() {
        assert_eq!(
            classification_for("mod-events-emit"),
            Some(CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            classification_for("moderator-activity"),
            Some(CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            classification_for("subject-context"),
            Some(CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            classification_for("subject-history"),
            Some(CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            classification_for("appeals"),
            Some(CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            classification_for("audit-trail"),
            Some(CapabilityClassification::AutoAdvance)
        );
        // The wire string (with suffix) is NOT a family and must
        // not match.
        assert_eq!(classification_for("mod-events-emit-v1"), None);
    }

    #[test]
    fn classification_for_returns_none_for_unknown() {
        assert_eq!(classification_for("anything"), None);
        assert_eq!(classification_for(""), None);
    }

    #[test]
    fn classification_for_lookup_mechanism() {
        // Sanity-check the lookup mechanism against a
        // test-local slice so we don't have to wait for
        // v1.8.3+ to verify it works.
        const TEST_REGISTRY: &[(&str, CapabilityClassification)] = &[
            ("auto-family", CapabilityClassification::AutoAdvance),
            ("opt-in-family", CapabilityClassification::OperatorOptIn),
        ];
        let lookup = |name: &str| {
            TEST_REGISTRY
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, c)| *c)
        };
        assert_eq!(
            lookup("auto-family"),
            Some(CapabilityClassification::AutoAdvance)
        );
        assert_eq!(
            lookup("opt-in-family"),
            Some(CapabilityClassification::OperatorOptIn)
        );
        assert_eq!(lookup("unknown"), None);
    }

    // ----- Capability / CapabilitySet (§8, v1.8.1) -----

    fn response_with(extensions: &[&str]) -> DescribeCapabilitiesResponse {
        DescribeCapabilitiesResponse {
            families: serde_json::json!({}),
            extensions: extensions
                .iter()
                .map(|n| CapabilityExtension {
                    name: (*n).to_string(),
                    value: None,
                })
                .collect(),
            implementation: "aurora-locus".to_string(),
            version: "0.10.0".to_string(),
        }
    }

    #[test]
    fn capability_set_empty_has_no_capabilities() {
        let set = CapabilitySet::empty();
        assert!(!set.has("mod-events-emit"));
        assert_eq!(set.version_of("mod-events-emit"), None);
        assert!(set.advertised_strings().is_empty());
    }

    #[test]
    fn capability_set_builds_from_mock_response() {
        let set = CapabilitySet::from_describe_capabilities(&response_with(&[
            "mod-events-emit-v1",
            "audit-trail-v1",
        ]))
        .unwrap();
        assert!(set.has("mod-events-emit"));
        assert!(set.has("audit-trail"));
        assert_eq!(
            set.version_of("mod-events-emit"),
            Some(CapabilityVersion(1))
        );
    }

    #[test]
    fn capability_set_ignores_malformed_extension_names() {
        // Missing -v<int> suffix → kept in raw, absent from the
        // family map; the probe does not fail.
        let set = CapabilitySet::from_describe_capabilities(&response_with(&[
            "mod-events-emit-v1",
            "not-a-versioned-string",
            "trailing-v",
        ]))
        .unwrap();
        assert!(set.has("mod-events-emit"));
        assert!(!set.has("not-a-versioned-string"));
        assert!(!set.has("trailing"));
        assert_eq!(set.advertised_strings().len(), 3);
    }

    #[test]
    fn capability_set_has_is_false_for_absent_families() {
        let set =
            CapabilitySet::from_describe_capabilities(&response_with(&["mod-events-emit-v1"]))
                .unwrap();
        assert!(!set.has("audit-trail"));
        assert!(!set.has(""));
        // Wire string with suffix is not a family.
        assert!(!set.has("mod-events-emit-v1"));
    }

    #[test]
    fn capability_set_version_of_returns_advertised_version() {
        let set =
            CapabilitySet::from_describe_capabilities(&response_with(&["queue-stats-v3"])).unwrap();
        assert_eq!(set.version_of("queue-stats"), Some(CapabilityVersion(3)));
        assert_eq!(set.version_of("absent-family"), None);
    }

    #[test]
    fn capability_set_multi_version_keeps_highest() {
        let set = CapabilitySet::from_describe_capabilities(&response_with(&[
            "mod-events-emit-v1",
            "mod-events-emit-v2",
        ]))
        .unwrap();
        // Both parsed (raw keeps both); version_of returns the
        // highest per the auto-advance selection input.
        assert_eq!(set.advertised_strings().len(), 2);
        assert_eq!(
            set.version_of("mod-events-emit"),
            Some(CapabilityVersion(2))
        );
    }

    #[test]
    fn capability_set_advertised_strings_returns_raw_list() {
        let names = ["mod-events-emit-v1", "audit-trail-v1", "garbage"];
        let set = CapabilitySet::from_describe_capabilities(&response_with(&names)).unwrap();
        assert_eq!(
            set.advertised_strings(),
            names
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .as_slice()
        );
    }

    #[test]
    fn describe_capabilities_response_deserializes_aurora_wire_shape() {
        // Mirrors Aurora's serialization: camelCase keys, `value`
        // omitted when None (recon §1b).
        let wire = serde_json::json!({
            "families": {"tools.aurora.admin": ["emitEvent"]},
            "extensions": [
                {"name": "mod-events-emit-v1"},
                {"name": "runtime-settings-v1", "value": {"note": "x"}}
            ],
            "implementation": "aurora-locus",
            "version": "0.10.0"
        });
        let resp: DescribeCapabilitiesResponse = serde_json::from_value(wire).unwrap();
        assert_eq!(resp.implementation, "aurora-locus");
        assert_eq!(resp.version, "0.10.0");
        assert_eq!(resp.extensions.len(), 2);
        assert_eq!(resp.extensions[0].name, "mod-events-emit-v1");
        assert!(resp.extensions[0].value.is_none());
        assert!(resp.extensions[1].value.is_some());
    }

    // ----- PaginationCursor -----

    #[test]
    fn pagination_cursor_construction_and_display() {
        let c = PaginationCursor("eyJpZCI6NDJ9".to_string());
        assert_eq!(c.0, "eyJpZCI6NDJ9");
        assert_eq!(format!("{c}"), "eyJpZCI6NDJ9");
    }

    #[test]
    fn pagination_cursor_serde_round_trip() {
        let c = PaginationCursor("opaque".to_string());
        let json = serde_json::to_string(&c).unwrap();
        let back: PaginationCursor = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // ----- AuditTrailEntryRead / AuditTrailEntryWrite -----

    #[test]
    fn audit_trail_entry_read_construction_and_round_trip() {
        let entry = AuditTrailEntryRead {
            upstream_id: "upstream-abc".to_string(),
            upstream_seq: 17,
            timestamp_epoch_ms: 1_700_000_000_000,
            upstream_action: serde_json::json!({
                "$type": "tools.aurora.admin.emitEvent#takedownAccount",
                "did": "did:plc:abc",
            }),
            hash_chain_predecessor: Some("prev-hash-hex".to_string()),
            hash_chain_signature: "sig-bytes-hex".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: AuditTrailEntryRead = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn audit_trail_entry_read_handles_chain_head() {
        // Chain head: hash_chain_predecessor is None.
        let entry = AuditTrailEntryRead {
            upstream_id: "first".to_string(),
            upstream_seq: 0,
            timestamp_epoch_ms: 0,
            upstream_action: serde_json::Value::Null,
            hash_chain_predecessor: None,
            hash_chain_signature: "head-sig".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"hash_chain_predecessor\":null"));
        let back: AuditTrailEntryRead = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn audit_trail_entry_write_construction_and_round_trip() {
        let entry = AuditTrailEntryWrite {
            batch_id: "batch-1".to_string(),
            subjects: vec![
                serde_json::json!({"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:a"}),
                serde_json::json!({"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:b"}),
            ],
            event_payload: serde_json::json!({
                "$type": "tools.aurora.admin.emitEvent#takedownAccount",
                "comment": "spam",
            }),
            timestamp_epoch_ms: 1_700_000_000_000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: AuditTrailEntryWrite = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
        assert_eq!(entry.subjects.len(), 2);
    }

    #[test]
    fn audit_trail_entry_write_handles_empty_subjects() {
        // Server-level events have no subject; the type accepts
        // an empty Vec without ceremony.
        let entry = AuditTrailEntryWrite {
            batch_id: "no-subject-batch".to_string(),
            subjects: vec![],
            event_payload: serde_json::json!({"kind":"server-level"}),
            timestamp_epoch_ms: 0,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: AuditTrailEntryWrite = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }
}
