//! Path A independent re-verification of Aurora's audit chain
//! (v1.8.6, v2 §4).
//!
//! Reimplements Aurora-Locus's canonical hash forms so cairn-mod
//! can verify `getAuditTrail` entries byte-exact from wire data,
//! trusting nothing upstream except that Aurora served the
//! response. Two canonical forms (per Aurora `verify_entry` /
//! `verify_entry_legacy` at `audit_chain.rs:1146-1172` /
//! `:1206-1232`, both R1-verified byte-identical, chainlink #138):
//!
//! - **v0.9 form (15 keys)**: alphabetical compact JSON →
//!   SHA-256 → hex-lowercase. `previous_hash` is INSIDE the
//!   canonical object (Aurora does not use cairn-mod's own
//!   `sha256(prev ‖ canonical)` concat discipline).
//! - **legacy form (13 keys)**: the v0.9 object minus `payload`
//!   and `source` (the upstream #345 format bump). Rows sealed
//!   before the bump match this form; matching either form is
//!   consistent, matching neither is tamper.
//!
//! The three wire-to-canonical transforms (v2 §4.3, mini-recon
//! #136 — none are in Aurora's operator doc as written):
//!
//! - **T1 timestamp reparse**: stored `created_at` is chrono
//!   `to_rfc3339()` (`…+00:00` form); the wire serializes
//!   `DateTime<Utc>` with `use_z = true` (`…Z` form). Both come
//!   from the same `write_rfc3339(naive, offset, AutoSi, use_z)`
//!   with only the suffix differing, so reconstruction is a
//!   validated suffix swap (`…Z` → `…+00:00`) — byte-equivalent
//!   to v2's `parse_from_rfc3339(wire).to_rfc3339()` over the
//!   writer's entire output domain, without taking a chrono
//!   dependency (cairn-mod has none; deviation logged on
//!   chainlink #139). A wire string matching neither form is
//!   tamper-class.
//! - **T2 order/byte-preserving re-embedding**: `payload` is
//!   hashed as the *stored serialized string* embedded in the
//!   canonical object; the mirror captures the wire object as
//!   `RawValue` and re-embeds its bytes verbatim. Cascade
//!   subjects re-serialize compact with `$type` first and
//!   source-declared field order; empty array → canonical `null`
//!   (never `"[]"`); empty-string CIDs preserved verbatim.
//! - **T3 sentinel + gap rules**: rows with
//!   `current_hash == "pre-chain"` skip per-row and linkage
//!   checks but still count for sequence contiguity and set the
//!   next row's expected `previous_hash` to the literal sentinel.
//!   Missing sequences are gaps. Genesis rows carry
//!   `previous_hash: null`.
//!
//! Canonical construction detail: cairn-mod's `serde_json` ships
//! the `preserve_order` feature, so `serde_json::Map` preserves
//! insertion order. The builders below therefore assemble the
//! canonical JSON **by hand in alphabetical key order** (writing
//! directly into a `String`), which keeps the byte discipline
//! structural — immune to both map-backing drift and accidental
//! `json!`-literal reordering. The seven Section D worked
//! examples from Aurora's operator doc pin the output byte-exact
//! (see tests).

use super::audit_types::AuroraAuditEntry;
use super::read_types::ReadSubject;

/// Per-entry verdict from the two-form recompute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamEntryVerdict {
    /// Stored hash matches the current v0.9 (15-key) form.
    V09,
    /// Stored hash matches only the pre-v0.9 legacy (13-key) form
    /// — an honestly-sealed row predating the upstream format
    /// bump, NOT a failure.
    Legacy,
    /// Stored hash matches neither form (or a wire field failed
    /// its transform): tamper-class.
    Tampered,
    /// `current_hash == "pre-chain"` sentinel — pre-chain-era row
    /// whose linkage is undefined by design; skipped by both
    /// per-row and linkage checks.
    Sentinel,
}

/// Chain-walk outcome over a collected entry window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainWalkVerdict {
    /// Every entry verified (under either form), linkage held,
    /// no gaps.
    Verified {
        /// Entries matching the v0.9 form.
        v09_count: usize,
        /// Entries matching only the legacy form.
        legacy_count: usize,
        /// Sentinel rows skipped.
        sentinel_count: usize,
    },
    /// First failure encountered, walking ascending.
    Failed {
        /// Sequence at which the walk failed.
        failing_sequence: i64,
        /// Failure kind (mirrors Aurora's taxonomy).
        kind: ChainFailureKind,
    },
}

/// Failure taxonomy, mirroring Aurora's `ChainFailureKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainFailureKind {
    /// Content rehash matched neither canonical form.
    PerRowMismatch,
    /// `previous_hash` didn't equal the prior row's `current_hash`.
    LinkageMismatch,
    /// A sequence number is missing from the window.
    Gap,
}

/// The literal sentinel Aurora stores on pre-chain-era rows.
pub const PRE_CHAIN_SENTINEL: &str = "pre-chain";

/// Canonical-input fields for one entry, post-transform. All
/// values are in their **stored** (canonical-side) forms: numeric
/// ids, `+00:00`-form timestamp, JSON-encoded cascade/payload
/// strings.
#[derive(Debug, Clone, Default)]
pub struct CanonicalFields {
    /// Chain sequence (numeric in the canonical form).
    pub sequence: i64,
    /// Stored `created_at` TEXT (`+00:00` form; post-T1).
    pub timestamp: String,
    /// Deciding actor's DID.
    pub actor_did: String,
    /// Action verb.
    pub action: String,
    /// Flat subject triple per the Section C variant table.
    pub subject_did: Option<String>,
    /// Record URI (or a Blob's originating-record URI).
    pub subject_uri: Option<String>,
    /// Record/blob CID (empty string preserved verbatim for
    /// URI-level batch-cascade entries).
    pub subject_cid: Option<String>,
    /// Operator rationale.
    pub rationale: String,
    /// Snapshot id (numeric; post-T2 parse).
    pub snapshot_id: Option<i64>,
    /// Moderation event id (numeric; post-T2 parse).
    pub event_id: Option<i64>,
    /// Prior row's `current_hash` (inside the canonical object).
    pub previous_hash: Option<String>,
    /// JSON-encoded cascade array (None when empty; post-T2).
    pub cascade_subjects: Option<String>,
    /// JSON-encoded numeric-element id array (None when empty).
    pub cascade_snapshot_ids: Option<String>,
    /// Provenance discriminator (v0.9 canonical field).
    pub source: String,
    /// Stored payload serialization verbatim (v0.9 canonical
    /// field; None when the action carries none).
    pub payload: Option<String>,
}

/// Why a wire entry could not be transformed into canonical
/// fields (tamper-class before any hashing happens).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformError {
    /// Wire timestamp failed RFC3339 parsing.
    Timestamp(String),
    /// A stringified-i64 field failed integer parsing.
    NumericId {
        /// Which wire field failed.
        field: &'static str,
        /// The offending wire value.
        value: String,
    },
}

/// JSON string-escape per serde_json's writer (the subset it
/// emits: control chars, quote, backslash — no `/` escaping, no
/// non-ASCII escaping when writing UTF-8).
fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_opt_string(out: &mut String, v: Option<&str>) {
    match v {
        Some(s) => write_json_string(out, s),
        None => out.push_str("null"),
    }
}

fn write_opt_i64(out: &mut String, v: Option<i64>) {
    match v {
        Some(n) => out.push_str(&n.to_string()),
        None => out.push_str("null"),
    }
}

/// Build the v0.9 (15-key) canonical JSON string — byte-identical
/// to Aurora's `verify_entry` construction (alphabetical keys,
/// compact separators). Key list copied from
/// `audit_chain.rs:1146-1163`; do not reorder.
pub fn build_canonical_v09(f: &CanonicalFields) -> String {
    let mut o = String::with_capacity(512);
    o.push('{');
    o.push_str("\"action\":");
    write_json_string(&mut o, &f.action);
    o.push_str(",\"actor_did\":");
    write_json_string(&mut o, &f.actor_did);
    o.push_str(",\"cascade_snapshot_ids\":");
    write_opt_string(&mut o, f.cascade_snapshot_ids.as_deref());
    o.push_str(",\"cascade_subjects\":");
    write_opt_string(&mut o, f.cascade_subjects.as_deref());
    o.push_str(",\"event_id\":");
    write_opt_i64(&mut o, f.event_id);
    o.push_str(",\"payload\":");
    write_opt_string(&mut o, f.payload.as_deref());
    o.push_str(",\"previous_hash\":");
    write_opt_string(&mut o, f.previous_hash.as_deref());
    o.push_str(",\"rationale\":");
    write_json_string(&mut o, &f.rationale);
    o.push_str(",\"sequence\":");
    o.push_str(&f.sequence.to_string());
    o.push_str(",\"snapshot_id\":");
    write_opt_i64(&mut o, f.snapshot_id);
    o.push_str(",\"source\":");
    write_json_string(&mut o, &f.source);
    o.push_str(",\"subject_cid\":");
    write_opt_string(&mut o, f.subject_cid.as_deref());
    o.push_str(",\"subject_did\":");
    write_opt_string(&mut o, f.subject_did.as_deref());
    o.push_str(",\"subject_uri\":");
    write_opt_string(&mut o, f.subject_uri.as_deref());
    o.push_str(",\"timestamp\":");
    write_json_string(&mut o, &f.timestamp);
    o.push('}');
    o
}

/// Build the pre-v0.9 legacy (13-key) canonical JSON string —
/// the v0.9 object minus `payload` and `source` (key list copied
/// from `audit_chain.rs:1206-1220`).
pub fn build_canonical_legacy(f: &CanonicalFields) -> String {
    let mut o = String::with_capacity(512);
    o.push('{');
    o.push_str("\"action\":");
    write_json_string(&mut o, &f.action);
    o.push_str(",\"actor_did\":");
    write_json_string(&mut o, &f.actor_did);
    o.push_str(",\"cascade_snapshot_ids\":");
    write_opt_string(&mut o, f.cascade_snapshot_ids.as_deref());
    o.push_str(",\"cascade_subjects\":");
    write_opt_string(&mut o, f.cascade_subjects.as_deref());
    o.push_str(",\"event_id\":");
    write_opt_i64(&mut o, f.event_id);
    o.push_str(",\"previous_hash\":");
    write_opt_string(&mut o, f.previous_hash.as_deref());
    o.push_str(",\"rationale\":");
    write_json_string(&mut o, &f.rationale);
    o.push_str(",\"sequence\":");
    o.push_str(&f.sequence.to_string());
    o.push_str(",\"snapshot_id\":");
    write_opt_i64(&mut o, f.snapshot_id);
    o.push_str(",\"subject_cid\":");
    write_opt_string(&mut o, f.subject_cid.as_deref());
    o.push_str(",\"subject_did\":");
    write_opt_string(&mut o, f.subject_did.as_deref());
    o.push_str(",\"subject_uri\":");
    write_opt_string(&mut o, f.subject_uri.as_deref());
    o.push_str(",\"timestamp\":");
    write_json_string(&mut o, &f.timestamp);
    o.push('}');
    o
}

fn sha256_hex(s: &str) -> String {
    hex::encode(proto_blue_crypto::sha256(s.as_bytes()))
}

/// T1: reconstruct the stored `+00:00`-form timestamp bytes from
/// the wire's `Z`-form string.
///
/// Aurora's stored `created_at` and its wire serialization are
/// produced by the same chrono `write_rfc3339(naive, offset,
/// SecondsFormat::AutoSi, use_z)` call differing only in `use_z`
/// (`datetime/mod.rs:633-638` vs `datetime/serde.rs:45` at chrono
/// 0.4.42) — every byte before the suffix is identical, so the
/// stored form is exactly the wire form with `Z` → `+00:00`.
/// Idempotent for a `+00:00`-form input. Light structural
/// validation rejects garbage early; a suffix-valid but
/// content-corrupted timestamp still fails the hash compare
/// downstream (tamper-class either way).
fn reparse_timestamp(wire: &str) -> Result<String, TransformError> {
    fn valid_rfc3339_utc_prefix(p: &str) -> bool {
        // YYYY-MM-DDTHH:MM:SS with optional .fraction
        let b = p.as_bytes();
        if b.len() < 19 {
            return false;
        }
        let sep_ok = b[4] == b'-'
            && b[7] == b'-'
            && (b[10] == b'T' || b[10] == b't')
            && b[13] == b':'
            && b[16] == b':';
        if !sep_ok {
            return false;
        }
        let digits_ok = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|&i| b[i].is_ascii_digit());
        if !digits_ok {
            return false;
        }
        match &b[19..] {
            [] => true,
            [b'.', frac @ ..] => !frac.is_empty() && frac.iter().all(u8::is_ascii_digit),
            _ => false,
        }
    }
    if let Some(prefix) = wire.strip_suffix('Z') {
        if valid_rfc3339_utc_prefix(prefix) {
            return Ok(format!("{prefix}+00:00"));
        }
    } else if let Some(prefix) = wire.strip_suffix("+00:00")
        && valid_rfc3339_utc_prefix(prefix)
    {
        return Ok(wire.to_string());
    }
    Err(TransformError::Timestamp(wire.to_string()))
}

fn parse_wire_i64(field: &'static str, v: &str) -> Result<i64, TransformError> {
    v.parse::<i64>().map_err(|_| TransformError::NumericId {
        field,
        value: v.to_string(),
    })
}

/// T2 (subjects): serialize one wire subject into Aurora's
/// embedded-cascade form — `$type` first, then struct fields in
/// Aurora's source-declared order (Repo: `did`; Record: `uri`,
/// `cid`; Blob: `did`, `cid`, `record_uri` omitted when absent).
/// Field order pinned by the Section D fixtures; deliberately NOT
/// derived from a struct whose declaration order could drift.
fn write_cascade_subject(out: &mut String, s: &ReadSubject) {
    match s {
        ReadSubject::Account { did } => {
            out.push_str("{\"$type\":\"com.atproto.admin.defs#repoRef\",\"did\":");
            write_json_string(out, did);
            out.push('}');
        }
        ReadSubject::Record { uri, cid } => {
            out.push_str("{\"$type\":\"com.atproto.repo.strongRef\",\"uri\":");
            write_json_string(out, uri);
            out.push_str(",\"cid\":");
            write_json_string(out, cid);
            out.push('}');
        }
        ReadSubject::Blob {
            did,
            cid,
            record_uri,
        } => {
            out.push_str("{\"$type\":\"com.atproto.admin.defs#repoBlobRef\",\"did\":");
            write_json_string(out, did);
            out.push_str(",\"cid\":");
            write_json_string(out, cid);
            if let Some(uri) = record_uri {
                out.push_str(",\"record_uri\":");
                write_json_string(out, uri);
            }
            out.push('}');
        }
    }
}

/// T2 (cascade list): the canonical `cascade_subjects` value —
/// `None` when the wire array is empty (canonical `null`, never
/// `"[]"`), else the compact JSON-encoded string.
fn cascade_subjects_canonical(subjects: &[ReadSubject]) -> Option<String> {
    if subjects.is_empty() {
        return None;
    }
    let mut o = String::with_capacity(64 * subjects.len());
    o.push('[');
    for (i, s) in subjects.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        write_cascade_subject(&mut o, s);
    }
    o.push(']');
    Some(o)
}

/// T2 (cascade snapshot ids): wire stringified-i64 elements →
/// canonical numeric-i64 elements inside the encoded string;
/// empty → canonical `null`.
fn cascade_snapshot_ids_canonical(
    ids: &[Option<String>],
) -> Result<Option<String>, TransformError> {
    if ids.is_empty() {
        return Ok(None);
    }
    let mut o = String::with_capacity(8 * ids.len());
    o.push('[');
    for (i, id) in ids.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        match id {
            Some(v) => o.push_str(&parse_wire_i64("cascadeSnapshotIds", v)?.to_string()),
            None => o.push_str("null"),
        }
    }
    o.push(']');
    Ok(Some(o))
}

/// Decompose the wire `subjectRef` into the canonical flat triple
/// per the operator doc's Section C variant table (mirrors
/// Aurora's `Subject::from_columns` inverse).
fn decompose_subject(
    subject: &Option<ReadSubject>,
) -> (Option<String>, Option<String>, Option<String>) {
    match subject {
        None => (None, None, None),
        Some(ReadSubject::Account { did }) => (Some(did.clone()), None, None),
        Some(ReadSubject::Record { uri, cid }) => (None, Some(uri.clone()), Some(cid.clone())),
        Some(ReadSubject::Blob {
            did,
            cid,
            record_uri,
        }) => (Some(did.clone()), record_uri.clone(), Some(cid.clone())),
    }
}

/// Apply T1/T2 to one wire entry, producing canonical-side fields.
pub fn canonical_fields_from_wire(
    entry: &AuroraAuditEntry,
) -> Result<CanonicalFields, TransformError> {
    let (subject_did, subject_uri, subject_cid) = decompose_subject(&entry.subject_ref);
    Ok(CanonicalFields {
        sequence: entry.sequence,
        timestamp: reparse_timestamp(&entry.timestamp)?,
        actor_did: entry.actor_did.clone(),
        action: entry.action.clone(),
        subject_did,
        subject_uri,
        subject_cid,
        rationale: entry.rationale.clone(),
        snapshot_id: entry
            .snapshot_id
            .as_deref()
            .map(|v| parse_wire_i64("snapshotId", v))
            .transpose()?,
        event_id: entry
            .event_id
            .as_deref()
            .map(|v| parse_wire_i64("eventId", v))
            .transpose()?,
        previous_hash: entry.previous_hash.clone(),
        cascade_subjects: cascade_subjects_canonical(&entry.cascade_subjects),
        cascade_snapshot_ids: cascade_snapshot_ids_canonical(&entry.cascade_snapshot_ids)?,
        source: entry.source.clone(),
        payload: entry.payload.as_ref().map(|p| p.get().to_string()),
    })
}

/// Recompute one entry's hash under both forms and compare to its
/// stored `current_hash`. Sentinels short-circuit; transform
/// failures are tamper-class.
pub fn verify_upstream_entry(entry: &AuroraAuditEntry) -> UpstreamEntryVerdict {
    if entry.current_hash == PRE_CHAIN_SENTINEL {
        return UpstreamEntryVerdict::Sentinel;
    }
    let fields = match canonical_fields_from_wire(entry) {
        Ok(f) => f,
        Err(_) => return UpstreamEntryVerdict::Tampered,
    };
    if sha256_hex(&build_canonical_v09(&fields)) == entry.current_hash {
        return UpstreamEntryVerdict::V09;
    }
    if sha256_hex(&build_canonical_legacy(&fields)) == entry.current_hash {
        return UpstreamEntryVerdict::Legacy;
    }
    UpstreamEntryVerdict::Tampered
}

/// T3: walk a collected window of entries — re-sorted ascending
/// by sequence — applying per-row (two-form), linkage, and gap
/// rules per Aurora's `verify_chain_range` semantics. The caller
/// supplies whatever window it collected (typically the full
/// paginated trail); `prev_hash_before_window` seeds linkage for
/// the first row (None when the window starts at the chain head's
/// genesis).
pub fn walk_chain(
    entries: &[AuroraAuditEntry],
    prev_hash_before_window: Option<&str>,
) -> ChainWalkVerdict {
    let mut sorted: Vec<&AuroraAuditEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.sequence);

    let mut v09 = 0usize;
    let mut legacy = 0usize;
    let mut sentinels = 0usize;
    let mut prev_hash: Option<String> = prev_hash_before_window.map(str::to_string);
    let mut expected_seq: Option<i64> = None;

    for entry in sorted {
        if let Some(exp) = expected_seq
            && entry.sequence != exp
        {
            return ChainWalkVerdict::Failed {
                failing_sequence: exp,
                kind: ChainFailureKind::Gap,
            };
        }

        if entry.current_hash == PRE_CHAIN_SENTINEL {
            sentinels += 1;
            prev_hash = Some(PRE_CHAIN_SENTINEL.to_string());
            expected_seq = Some(entry.sequence + 1);
            continue;
        }

        match verify_upstream_entry(entry) {
            UpstreamEntryVerdict::V09 => v09 += 1,
            UpstreamEntryVerdict::Legacy => legacy += 1,
            UpstreamEntryVerdict::Sentinel => unreachable!("sentinel handled above"),
            UpstreamEntryVerdict::Tampered => {
                return ChainWalkVerdict::Failed {
                    failing_sequence: entry.sequence,
                    kind: ChainFailureKind::PerRowMismatch,
                };
            }
        }

        // Linkage: only checkable when we know the predecessor.
        if (expected_seq.is_some() || prev_hash_before_window.is_some())
            && entry.previous_hash.as_deref() != prev_hash.as_deref()
        {
            return ChainWalkVerdict::Failed {
                failing_sequence: entry.sequence,
                kind: ChainFailureKind::LinkageMismatch,
            };
        }

        prev_hash = Some(entry.current_hash.clone());
        expected_seq = Some(entry.sequence + 1);
    }

    ChainWalkVerdict::Verified {
        v09_count: v09,
        legacy_count: legacy,
        sentinel_count: sentinels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: single-subject repoRef cascade string (the
    /// Arc-4 single-subject chain-row shape).
    fn repo_cascade(did: &str) -> Option<String> {
        Some(format!(
            r#"[{{"$type":"com.atproto.admin.defs#repoRef","did":"{did}"}}]"#
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn fields(
        sequence: i64,
        actor: &str,
        action: &str,
        subject: (Option<&str>, Option<&str>, Option<&str>),
        rationale: &str,
        prev: Option<&str>,
        cascade: Option<String>,
        cascade_ids: Option<&str>,
        source: &str,
        payload: Option<&str>,
    ) -> CanonicalFields {
        CanonicalFields {
            sequence,
            timestamp: "2026-05-09T00:00:00Z".to_string(),
            actor_did: actor.to_string(),
            action: action.to_string(),
            subject_did: subject.0.map(String::from),
            subject_uri: subject.1.map(String::from),
            subject_cid: subject.2.map(String::from),
            rationale: rationale.to_string(),
            snapshot_id: None,
            event_id: None,
            previous_hash: prev.map(String::from),
            cascade_subjects: cascade,
            cascade_snapshot_ids: cascade_ids.map(String::from),
            source: source.to_string(),
            payload: payload.map(String::from),
        }
    }

    // ---- Section D worked examples (operator doc, all seven
    // hashes independently recomputed at R1 — chainlink #138).
    // These pin build_canonical_v09's byte discipline end-to-end.

    #[test]
    fn section_d_example_1_repo_ref_genesis() {
        let f = fields(
            1,
            "did:plc:moderator",
            "TakedownAccount",
            (Some("did:plc:test1234567890abcdef"), None, None),
            "spam",
            None,
            repo_cascade("did:plc:test1234567890abcdef"),
            None,
            "manual",
            None,
        );
        let canon = build_canonical_v09(&f);
        assert_eq!(
            canon,
            r#"{"action":"TakedownAccount","actor_did":"did:plc:moderator","cascade_snapshot_ids":null,"cascade_subjects":"[{\"$type\":\"com.atproto.admin.defs#repoRef\",\"did\":\"did:plc:test1234567890abcdef\"}]","event_id":null,"payload":null,"previous_hash":null,"rationale":"spam","sequence":1,"snapshot_id":null,"source":"manual","subject_cid":null,"subject_did":"did:plc:test1234567890abcdef","subject_uri":null,"timestamp":"2026-05-09T00:00:00Z"}"#,
            "canonical string must byte-match Section D Example 1"
        );
        assert_eq!(
            sha256_hex(&canon),
            "f51dd8d375762a1e22954eec59af4972efeea5847ff427eaeaee1aaee5ce24ca"
        );
    }

    #[test]
    fn section_d_example_2_strong_ref() {
        let f = fields(
            1,
            "did:plc:moderator",
            "TakedownRecord",
            (
                None,
                Some("at://did:plc:test1234567890abcdef/app.bsky.feed.post/1abc"),
                Some("bafyreidemorecord"),
            ),
            "off-topic",
            None,
            Some(
                r#"[{"$type":"com.atproto.repo.strongRef","uri":"at://did:plc:test1234567890abcdef/app.bsky.feed.post/1abc","cid":"bafyreidemorecord"}]"#
                    .to_string(),
            ),
            None,
            "manual",
            None,
        );
        assert_eq!(
            sha256_hex(&build_canonical_v09(&f)),
            "16555784f242d5951a46de0ab23d47f0cf061c8651b221900b8995f039e2f9ba"
        );
    }

    #[test]
    fn section_d_example_3_blob_with_record_uri() {
        let f = fields(
            1,
            "did:plc:moderator",
            "TakedownBlob",
            (
                Some("did:plc:test1234567890abcdef"),
                Some("at://did:plc:test1234567890abcdef/app.bsky.feed.post/1abc"),
                Some("bafyreidemoblob"),
            ),
            "csam",
            None,
            Some(
                r#"[{"$type":"com.atproto.admin.defs#repoBlobRef","did":"did:plc:test1234567890abcdef","cid":"bafyreidemoblob","record_uri":"at://did:plc:test1234567890abcdef/app.bsky.feed.post/1abc"}]"#
                    .to_string(),
            ),
            None,
            "manual",
            None,
        );
        assert_eq!(
            sha256_hex(&build_canonical_v09(&f)),
            "95a66f39bec9238cca0dd3554de615e222ec6470cf7753cd5068cc5c0591c54e"
        );
    }

    #[test]
    fn section_d_example_4_blob_without_record_uri() {
        let f = fields(
            1,
            "did:plc:moderator",
            "TakedownBlob",
            (Some("did:plc:test1234567890abcdef"), None, Some("bafyreidemoblob")),
            "csam-orphan-blob",
            None,
            Some(
                r#"[{"$type":"com.atproto.admin.defs#repoBlobRef","did":"did:plc:test1234567890abcdef","cid":"bafyreidemoblob"}]"#
                    .to_string(),
            ),
            None,
            "manual",
            None,
        );
        assert_eq!(
            sha256_hex(&build_canonical_v09(&f)),
            "3b9f4b0f5b0c93ba166217f19bfb46ddd1354cf4a74e85bd0810d6e88c39159a"
        );
    }

    #[test]
    fn section_d_example_5_batch_with_cascades() {
        let f = fields(
            1,
            "did:plc:moderator",
            "BatchTakedownAccounts",
            (None, None, None),
            "coordinated spam network",
            None,
            Some(
                r#"[{"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:victim1"},{"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:victim2"},{"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:victim3"}]"#
                    .to_string(),
            ),
            Some("[7,null,12]"),
            "manual",
            None,
        );
        assert_eq!(
            sha256_hex(&build_canonical_v09(&f)),
            "2f8145772ef1a1972482d1416634921edd358bb1580ca400e7da08c6ea539a3c"
        );
    }

    #[test]
    fn section_d_example_6_second_entry_chained() {
        let f = fields(
            2,
            "did:plc:moderator",
            "RestoreAccount",
            (Some("did:plc:test1234567890abcdef"), None, None),
            "appeal granted",
            Some("f51dd8d375762a1e22954eec59af4972efeea5847ff427eaeaee1aaee5ce24ca"),
            repo_cascade("did:plc:test1234567890abcdef"),
            None,
            "manual",
            None,
        );
        assert_eq!(
            sha256_hex(&build_canonical_v09(&f)),
            "95d85237bd7c8e5469d648fa854628bf3ef414c2cd651e614972332754c6b1b3"
        );
    }

    #[test]
    fn section_d_example_7_substrate_source_with_payload() {
        let f = fields(
            1,
            "did:system",
            "moderation_auto_label_applied",
            (Some("did:plc:test1234567890abcdef"), None, None),
            "auto-label rule matched report category",
            None,
            repo_cascade("did:plc:test1234567890abcdef"),
            None,
            "auto_label_rule",
            Some(r#"{"applied":true}"#),
        );
        assert_eq!(
            sha256_hex(&build_canonical_v09(&f)),
            "168054b81407fe774f080bdc2dfece49183d249f90c20c237c12006e47fb6d6b"
        );
    }

    // ---- T1: the +00:00-form fixture Section D masks. ----

    #[test]
    fn t1_reparse_reconstructs_stored_plus_zero_offset_form() {
        // Stored (writer side): to_rfc3339() => +00:00 suffix.
        let stored = "2026-05-09T00:00:00.123456+00:00";
        // Wire (serde side): use_z = true => Z suffix, same AutoSi
        // digit grouping.
        let wire = "2026-05-09T00:00:00.123456Z";
        assert_eq!(reparse_timestamp(wire).unwrap(), stored);
        // Whole-second case: no subsecond digits either side.
        assert_eq!(
            reparse_timestamp("2026-05-09T00:00:00Z").unwrap(),
            "2026-05-09T00:00:00+00:00"
        );
        // Millisecond grouping preserved (3 digits stay 3).
        assert_eq!(
            reparse_timestamp("2026-05-09T00:00:00.500Z").unwrap(),
            "2026-05-09T00:00:00.500+00:00"
        );
        // Garbage is tamper-class, not a panic.
        assert!(matches!(
            reparse_timestamp("not-a-timestamp"),
            Err(TransformError::Timestamp(_))
        ));
    }

    // ---- Legacy form + verdicts. ----

    /// A pre-v0.9 row: hash computed under the 13-key form.
    fn legacy_entry() -> AuroraAuditEntry {
        let mut f = fields(
            1,
            "did:plc:moderator",
            "TakedownAccount",
            (Some("did:plc:legacy"), None, None),
            "sealed before the format bump",
            None,
            None,
            None,
            "manual", // stored source (backfilled column default) — NOT hashed under legacy
            None,
        );
        // Stored form: what the T1 transform reconstructs from the
        // wire's Z-form string.
        f.timestamp = "2026-05-09T00:00:00+00:00".to_string();
        let legacy_hash = sha256_hex(&build_canonical_legacy(&f));
        serde_json::from_value(serde_json::json!({
            "id": "1",
            "sequence": 1,
            "timestamp": "2026-05-09T00:00:00Z",
            "actorDid": "did:plc:moderator",
            "action": "TakedownAccount",
            "subjectRef": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:legacy"},
            "rationale": "sealed before the format bump",
            "snapshotId": null,
            "eventId": null,
            "currentHash": legacy_hash,
            "previousHash": null,
            "verified": true,
            "cascadeSubjects": [],
            "cascadeSnapshotIds": [],
            "source": "manual"
        }))
        .unwrap()
    }

    #[test]
    fn legacy_row_fails_v09_passes_legacy() {
        let entry = legacy_entry();
        assert_eq!(verify_upstream_entry(&entry), UpstreamEntryVerdict::Legacy);
    }

    #[test]
    fn tampered_row_matches_neither_form() {
        let mut entry = legacy_entry();
        entry.rationale = "rewritten by attacker".to_string();
        assert_eq!(
            verify_upstream_entry(&entry),
            UpstreamEntryVerdict::Tampered
        );
    }

    // ---- Wire round-trip: entry built the way Aurora's serde
    // emits it (Z timestamp, stringified i64s, null-vs-omitted per
    // the wire-form table), verified against a stored-form hash. ----

    #[test]
    fn wire_round_trip_z_timestamp_and_stringified_ids() {
        // Stored-side truth: +00:00 timestamp, numeric ids.
        let stored = CanonicalFields {
            sequence: 3,
            timestamp: "2026-05-09T12:30:45.250+00:00".to_string(),
            actor_did: "did:plc:moderator".to_string(),
            action: "TakedownRecord".to_string(),
            subject_did: None,
            subject_uri: Some("at://did:plc:x/app.bsky.feed.post/r".to_string()),
            subject_cid: Some("bafyrec".to_string()),
            rationale: "wire round trip".to_string(),
            snapshot_id: Some(9_007_199_254_740_993),
            event_id: Some(42),
            previous_hash: Some("aaaa".to_string()),
            cascade_subjects: Some(
                r#"[{"$type":"com.atproto.repo.strongRef","uri":"at://did:plc:x/app.bsky.feed.post/r","cid":"bafyrec"}]"#
                    .to_string(),
            ),
            cascade_snapshot_ids: Some("[9007199254740993]".to_string()),
            source: "manual".to_string(),
            payload: None,
        };
        let stored_hash = sha256_hex(&build_canonical_v09(&stored));

        // Wire-side: exactly what Aurora's Serialize emits.
        let wire = serde_json::json!({
            "id": "3",
            "sequence": 3,
            "timestamp": "2026-05-09T12:30:45.250Z",
            "actorDid": "did:plc:moderator",
            "action": "TakedownRecord",
            "subjectRef": {"$type": "com.atproto.repo.strongRef",
                           "uri": "at://did:plc:x/app.bsky.feed.post/r",
                           "cid": "bafyrec"},
            "rationale": "wire round trip",
            "snapshotId": "9007199254740993",
            "eventId": "42",
            "currentHash": stored_hash,
            "previousHash": "aaaa",
            "verified": true,
            "cascadeSubjects": [{"$type": "com.atproto.repo.strongRef",
                                 "uri": "at://did:plc:x/app.bsky.feed.post/r",
                                 "cid": "bafyrec"}],
            "cascadeSnapshotIds": ["9007199254740993"],
            "source": "manual"
        });
        let entry: AuroraAuditEntry = serde_json::from_value(wire).unwrap();
        assert_eq!(verify_upstream_entry(&entry), UpstreamEntryVerdict::V09);
    }

    // ---- T3: sentinel + gap + linkage walk. ----

    fn walk_entry(sequence: i64, rationale: &str, prev: Option<&str>) -> AuroraAuditEntry {
        let mut f = fields(
            sequence,
            "did:plc:moderator",
            "TakedownAccount",
            (Some("did:plc:x"), None, None),
            rationale,
            prev,
            repo_cascade("did:plc:x"),
            None,
            "manual",
            None,
        );
        f.timestamp = "2026-05-09T00:00:00+00:00".to_string();
        let hash = sha256_hex(&build_canonical_v09(&f));
        serde_json::from_value(serde_json::json!({
            "id": sequence.to_string(),
            "sequence": sequence,
            "timestamp": "2026-05-09T00:00:00Z",
            "actorDid": "did:plc:moderator",
            "action": "TakedownAccount",
            "subjectRef": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"},
            "rationale": rationale,
            "snapshotId": null,
            "eventId": null,
            "currentHash": hash,
            "previousHash": prev,
            "verified": true,
            "cascadeSubjects": [{"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:x"}],
            "cascadeSnapshotIds": [],
            "source": "manual"
        }))
        .unwrap()
    }

    fn sentinel_entry(sequence: i64) -> AuroraAuditEntry {
        serde_json::from_value(serde_json::json!({
            "id": sequence.to_string(),
            "sequence": sequence,
            "timestamp": "2026-05-09T00:00:00Z",
            "actorDid": "did:plc:legacy",
            "action": "LegacyEvent",
            "subjectRef": null,
            "rationale": "pre-chain era",
            "snapshotId": null,
            "eventId": null,
            "currentHash": "pre-chain",
            "previousHash": null,
            "verified": false,
            "cascadeSubjects": [],
            "cascadeSnapshotIds": [],
            "source": "manual"
        }))
        .unwrap()
    }

    #[test]
    fn walk_verifies_contiguous_chain_and_reports_counts() {
        let e1 = walk_entry(1, "first", None);
        let e2 = walk_entry(2, "second", Some(&e1.current_hash.clone()));
        // Newest-first input order (as the trail serves it) — the
        // walk re-sorts ascending.
        let verdict = walk_chain(&[e2, e1], None);
        assert_eq!(
            verdict,
            ChainWalkVerdict::Verified {
                v09_count: 2,
                legacy_count: 0,
                sentinel_count: 0
            }
        );
    }

    #[test]
    fn walk_sentinel_skips_but_links_and_counts() {
        let s1 = sentinel_entry(1);
        let e2 = walk_entry(2, "first real", Some("pre-chain"));
        let verdict = walk_chain(&[s1, e2], None);
        assert_eq!(
            verdict,
            ChainWalkVerdict::Verified {
                v09_count: 1,
                legacy_count: 0,
                sentinel_count: 1
            }
        );
    }

    #[test]
    fn walk_detects_gap_and_linkage_break() {
        let e1 = walk_entry(1, "first", None);
        let e3 = walk_entry(3, "third", Some("whatever"));
        assert_eq!(
            walk_chain(&[e1.clone(), e3], None),
            ChainWalkVerdict::Failed {
                failing_sequence: 2,
                kind: ChainFailureKind::Gap
            }
        );

        let e2_bad = walk_entry(2, "second", Some("not-the-prior-hash"));
        assert_eq!(
            walk_chain(&[e1, e2_bad], None),
            ChainWalkVerdict::Failed {
                failing_sequence: 2,
                kind: ChainFailureKind::LinkageMismatch
            }
        );
    }
}
