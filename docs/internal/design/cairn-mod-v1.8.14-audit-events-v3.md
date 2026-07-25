# cairn-mod v1.8.14 audit events — design v3 (canonical)

**Status:** Draft v3. R1 + R2 folded; canonical materialization from v2 patch spec + R3 S-2 citation fix. Pending narrow R3 confirmation → fold-and-lock.

- cairn-mod HEAD: `6877c89` (`skydeval/v1.8.13-report-flow`, unpushed — post-v1.8.13 shipping)
- Aurora-Locus HEAD: `2ffeb1a` (no drift since v1.8.5)
- kryphocron: `7602abc` @ `0.3.1`; kryphocron-lexicons: `0.3.0`
- Recon: `docs/internal/recon/v1.8.14-audit-events-recon.md` (chainlink #168)
- Design chainlink: #169 (v1) → R1 #170 → R2 #171 → v3 materialization (fresh chainlink, close `--no-changelog`)

---

## §1 — Process context + memory locks

Workstream B third release. Umbrella §4.B.3 scope; recon #168 surfaced five umbrella-vs-source divergences + seven §9d decisions; Nova committed the scope in the kickoff. Opus-in-CC (crypto-adjacent — audits cairn-mod's own decode of private content). Straight to CC-adversarial after drafting (memory #15). Sourcing per memory #6 + corollaries (#26 full-file grep — audit action values, Aurora event_types, Tier variants; #27 DDL forward-trace — **no migration** per recon, re-verified §5; #29/#30 own-source + kryphocron/Aurora grep). Firewall applies.

This document is the **canonical** v1.8.14 design. It supersedes `-v1.md` (initial draft) and `-v2-folds.md` (R1 fold patch). Both remain in the design dir as history; neither is authoritative. From v3 forward on this cycle, each revision is a full materialized doc so R3's grep-verification reads a canonical artifact (R2 M-finding).

## §2 — What v1.8.14 is

A small, **cairn-mod-side, migration-free** release. After the R1 architectural collapse it has **two independent pieces plus a derived field**, all realized as tags on shipped surfaces — **zero new audit action values, zero new emission APIs**:

1. **Kryphocron-context tags on the shipped `report_resolved` audit row** — when a moderator resolves a report whose subject is a decoded kryphocron record, the existing `report_resolved` audit `reason` JSON gains two keys: `content_tier` (`"private"`/`"public"`, §5) and `decode_source` (`"aurora_server"`/`"cairn_client"`, from `reports.decode_source`, v1.8.13). Both umbrella-named variants — `RecordDecoded` and `ModerationApplied` — collapse into this one tag surface (§3). Covered by `cairn audit verify` (payload-agnostic — zero verify change). **F3: no cross-verify against Aurora.**
2. **queryEvents kryphocron vocabulary** — the 12 Aurora `kryphocron_*` `event_type`s already flow through cairn-mod's free-form `String` filter/response and render as pretty-JSON; v1.8.14 adds a `--kryphocron-only` CLI filter + pins the 12 values in tests/docs (§7).
3. **`content_tier`** — derived cairn-mod-side via the fallible `Tier::from_nsid` (Aurora provides no tier field), carried in the audit `reason` JSON (§5).

No new trait method, no new capability gate, no new decode, **no migration**, no new `BackendError`, **no new `AUDIT_ACTION_VALUES` entry** (closed set stays at 10).

### §2.1 Locked decisions (post-R1/R2 collapse)
- **Collapse (R1 LB-1/LB-2/LB-3):** `RecordDecoded` as a standalone action is **removed**. There is no §F10-clean, transactional, moderator-DID-bearing, plaintext-reading emission site for a distinct "record decoded" event — `get_report` drops the moderator DID, is non-transactional, and doesn't SELECT the decode columns; `report_dismissed` doesn't exist; `decoded_plaintext` is a write-only column with no read projection. Kryphocron context becomes a **tag** on the shipped `report_resolved` write at `resolve_report` instead (§3).
- **`ModerationApplied` (R1 HELD):** was always the tag pattern, not a new action. Folds into the same `report_resolved` tag surface as `RecordDecoded`. Two umbrella names, one tag surface, zero new actions (§3.2).
- **~~§3.1a idempotency~~ (R1 MOOT):** no per-view emission after the collapse; the tag fires once per resolution inherently. Section removed.
- **`ContentTier { Public, Private }` (LB-2):** snake_case Display, derived via the doubly-fallible `Tier::from_nsid` with `impl From<kryphocron::Tier> for ContentTier` (§5).
- **queryEvents (LB-3/LB-7, R1/R2 held):** Aurora's 12 `kryphocron_*` events already flow (free-form String) + render (pretty-JSON); add `--kryphocron-only` filter + doc/test-pin (§7).
- **Capability (LB-4, R1/R2 held):** the 12 payloads are metadata-only and already flow ungated; a new registry entry would gate currently-ungated flow for no security benefit. **Registry stays 13.** No entry added (§6).
- **No trait growth (LB-5):** audit-authoring is internal `audit_log` writes at the resolve site. Trait stays **49**.
- **No migration (LB-6):** 0014 stays highest; `content_tier` + `decode_source` live in `reason` JSON (§5.3).

### §2.2 Non-goals
- **No Aurora audit-chain ingestion / no Path A verification of kryphocron variants** (F3 — §8).
- **No new decode invocation** — the tag records a decode that already happened at v1.8.13 ingest; it reads `reports.decode_source`, does not re-decode.
- **No migration, no trait growth, no new `BackendError`, no synthetic actor, no new `AUDIT_ACTION_VALUES` entry.**
- **No wire-type mirrors** for Aurora event payloads — pretty-JSON pass-through (§7).
- **No plaintext in audit events** — decoded plaintext lives on `reports.decoded_plaintext`; audit tags carry metadata only.

### §2.3 Umbrella-vs-source scope-shape corrections
- **v1.8.14 does NOT ingest Aurora's kryphocron audits and does NOT run Path A verification against them** (F3 — Aurora's kryphocron audits live in a separate non-hash-linked `moderation_event` store). cairn-mod records only its own moderation-decision chain; no cross-verify.
- **`RecordDecoded`/`ModerationApplied` as standalone actions are an umbrella hybrid that source §F10 rejects** — the audit-worthy moment is the moderation *decision* (resolve), not an input/operational event (ingest) or a repeatable read (view). Source §F10 wins; both fold to tags. This divergence is logged to the v1.8.15 series-wrap ledger (§9e).

### §2.4 Workstream B scope split
- v1.8.12 wired the substrate; v1.8.13 first-consumed it (decode-at-ingest, `reports.decoded_plaintext`, `reports.decode_source`); **v1.8.14 (this): tag cairn-mod's own moderation decisions on decoded content + surface Aurora's kryphocron queryEvents vocabulary**; v1.8.15 wraps (§9e reconciliations + golden-vector test).

## §3 — Kryphocron-context tagging on shipped `report_resolved` audit writes

After the R1 collapse, v1.8.14's audit change is a **payload extension on one shipped audit write**, not a new event. Both umbrella-named variants fold here.

### §3.1 `RecordDecoded` folded into the `report_resolved` tag (v1 §3.1 collapsed)

Design v1 proposed `RecordDecoded` as a distinct `AUDIT_ACTION_VALUES` entry with moderator-view emission. R1 verified three load-bearing gaps at that site (LB-1/LB-2/LB-3): `get_report` discards the moderator DID and is non-transactional; `report_dismissed` doesn't exist; `decoded_plaintext` is write-only with no read projection. The fold collapses `RecordDecoded` semantics into `content_tier` + `decode_source` keys on the `reason` JSON of the shipped `report_resolved` audit write when the subject is a `kryphocron_record`.

**Emission site:** `resolve_report` at `src/writer.rs:669`, audit write at `src/writer.rs:1999-2016`. This path is §F10-clean (a moderation *decision*), carries a real moderator DID (`req.actor_did`), and is transactional (`append_in_tx` inside the resolve tx) — the three properties `RecordDecoded` needed and its v1 site lacked.

**Why resolve is the right moment:** F14 compensation queries care about "who made the moderation decision on a kryphocron-tier subject with decoded content." That is precisely the resolve moment — not the reporter-triggered ingest (§F10-excluded, per the `createReport` precedent that intentionally does not audit) and not a repeatable read.

### §3.2 `ModerationApplied` — same tag surface (R1 HELD)

v1 §3.2 read `ModerationApplied` as a `content_tier` tag on the shipped `report_resolved` write rather than a new action. R1 verdict: **HELD**. Combined with §3.1's collapse, both umbrella-named variants fold into the same tagging pattern on the same shipped action. The names `RecordDecoded` and `ModerationApplied` no longer appear as distinct design concepts — both refer to the tagged `report_resolved` audit row.

### §3.3 Data plumbing — `decode_source` into the resolve read surface (R2 S-1)

`resolve_report` already SELECTs the report row for the state UPDATE (`src/writer.rs:1926-1941`). It does **not** currently select `decode_source`. Two-file change, explicitly specified:

1. **`Report` struct** (the row type the resolve SELECT maps into) — add `decode_source: Option<String>`.
2. **Resolve SELECT** at `src/writer.rs:1926-1941` — add the `decode_source` column to the `query_as!` projection.

v1.8.13 migration 0014 shipped the column; v1.8.14 plumbs it into the resolve read surface. **Alternative rejected:** a separate query at emission time — the resolve SELECT already fetches the row, so this is one column on one existing query, no new query, matching the shipped resolve-handler shape.

### §3.4 Emission-site code (R2 S-2 fix — verified primitives)

R2 flagged that v2's illustrative code invented helper names (`subject.nsid()`, `parse_nsid_from_uri`, `from_collection`). R3 supplied the verified primitives; this section grounds them against HEAD:

- **`parse_at_uri_components(uri: &str) -> Option<(&str, &str, &str)>`** — `pub(crate)` at `src/xrpc_gateway/handlers/create_report.rs:424`. Returns `Some((repo, collection, rkey))` for a well-formed record AT-URI; **`None`** for account subjects and malformed URIs. **NOTE — the return is an `Option` of a `(repo, collection, rkey)` tuple, not a `Result` and not a struct.** The collection is tuple field `.1`. (R3's `.ok()` + `.components.collection` phrasing does not match HEAD; the correct form is `.and_then(...)` on the `Option` and destructure the tuple.) Reachable from `writer.rs` as `crate::xrpc_gateway::handlers::create_report::parse_at_uri_components` (both under the same crate; the fn is `pub(crate)`).
- **`kryphocron::Nsid::new(&str) -> Result<Nsid, _>`** — in-use at `src/pds_admin/rust/mod.rs:2088` (`kryphocron::Nsid::new(collection).map_err(...)`). `.ok()` drops the parse error.
- **`Tier::from_nsid(nsid: &proto_blue_syntax::Nsid) -> Result<Tier, UnknownNsid>`** — `pub fn` (build-script-generated `impl Tier`, `kryphocron-lexicons`), doubly fallible. `Tier` is `#[non_exhaustive] { Public, Private }` re-exported as `kryphocron::Tier`.
- **`impl From<kryphocron::Tier> for ContentTier`** — added in §5, so the derivation chain ends in `.map(ContentTier::from)`.

Derivation of `content_tier` at the emission site:

```rust
// content_tier is derived, doubly fallible, and None for account subjects
// (subject_uri is None) or unregistered NSIDs. `subject_uri` and `subject_type`
// are already on the resolved `report` row.
let content_tier: Option<ContentTier> = report
    .subject_uri
    .as_ref()
    .and_then(|uri| parse_at_uri_components(uri))       // Option<(repo, collection, rkey)>
    .and_then(|(_repo, collection, _rkey)| kryphocron::Nsid::new(collection).ok())
    .and_then(|nsid| kryphocron::Tier::from_nsid(&nsid).ok())
    .map(ContentTier::from);                             // impl From<Tier> for ContentTier (§5)

let decode_source = report.decode_source.clone();       // Option<String> from §3.3 SELECT extension
```

**Reason-JSON extension — the shipped builder returns `String`, so tags cannot be added by index-mutation.** `build_resolve_audit_reason(applied_label_val, resolution_reason) -> String` (`src/writer.rs:3549`) `.to_string()`s a `serde_json::json!` literal. R3's illustrative `extended_reason["content_tier"] = json!(...)` assumes a `serde_json::Value`; it does **not** compile against the shipped `String`. The honest realization is to have the builder produce a `Value`, apply the kryphocron tags, then stringify **once** at the call site:

```rust
// Refactor build_resolve_audit_reason to return serde_json::Value:
//   fn build_resolve_audit_reason(applied_label_val: Option<&str>,
//                                 resolution_reason: Option<&str>) -> serde_json::Value { json!({...}) }
// (The one existing caller stringifies at the call site — see below. No other
//  caller exists; grep-confirm at implementation.)

let mut reason_value = build_resolve_audit_reason(
    req.action.as_apply().map(|a| a.val.as_str()),
    req.resolution_reason.as_deref(),
);

if report.subject_type == "kryphocron_record" {
    if let Some(tier) = content_tier {
        reason_value["content_tier"] = serde_json::json!(tier.as_str()); // "public" | "private"
    }
    if let Some(source) = decode_source {
        reason_value["decode_source"] = serde_json::json!(source);       // "aurora_server" | "cairn_client"
    }
}

let audit_reason = reason_value.to_string();
// ... unchanged: append_in_tx with AuditRowForAppend { action: "report_resolved", reason: Some(audit_reason), ... }
```

For non-`kryphocron_record` subjects the two keys are **absent** (not `null`) — the reason JSON is byte-identical to the shipped v1.8.13 output, so existing `report_resolved` rows and `cairn audit verify` are unaffected. The `reason` field is opaque `Option<String>` hashed verbatim by the chain (audit_verify.rs); adding keys on the kryphocron branch is a payload change the verifier is agnostic to.

**Implementation note (builder-return refactor):** changing `build_resolve_audit_reason`'s return type from `String` to `Value` touches its **single** caller (the resolve site above). Confirm at implementation there is exactly one caller (`grep 'build_resolve_audit_reason(' src/`); if a second appears, stringify there too. This refactor is the load-bearing correction over R3's cited snippet.

### §3.5 `AUDIT_ACTION_VALUES` unchanged (closed set stays 10)

`AUDIT_ACTION_VALUES` (`src/writer.rs:167`) is **not** extended — no `record_decoded`, no `moderation_applied`. The closed set stays at 10 entries; `list_audit_log`'s hard validation (list_audit_log.rs) is unchanged. `report_resolved`'s reason schema const (`src/writer.rs:110-122`) gains documentation of the two optional kryphocron keys. `cairn audit verify` needs **zero change** (payload-agnostic).

## §4 — (removed)

v1's §4 (`DecodedRecord` `codec_id` extension) and §3.3 (`SYNTHETIC_DECODE_ACTOR_DID`) are dropped: the moderator-view/ingest emission model they supported was removed by the R1 collapse, and `DecodedRecord { plaintext, decode_source }` is unchanged from v1.8.13. `codec_id` is not carried into any audit tag (always `laquna/0.2` at Aurora v0.10, and not persisted on `reports`). No synthetic actor — the resolve path carries a real moderator DID (`req.actor_did`).

## §5 — content_tier vocabulary + derivation

### §5.1 `ContentTier` enum + snake_case

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentTier {
    Public,
    Private,
}

impl ContentTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}
```

Wire string `"public"`/`"private"` (snake_case, matching cairn-mod `audit_log` conventions; kryphocron's `Tier` has no serde).

### §5.2 Derivation via the fallible `Tier::from_nsid` + `From<Tier>`

`Tier::from_nsid(nsid: &proto_blue_syntax::Nsid) -> Result<Tier, UnknownNsid>` (kryphocron-lexicons build-script-generated `impl Tier`, re-exported `kryphocron::Tier`). Two fallibility layers precede it: `parse_at_uri_components` returns `Option` (account subjects / malformed URIs → `None`), and `kryphocron::Nsid::new` returns `Result` (unparseable collection → `Err`). The conversion into `ContentTier` is total on `Tier`'s current variants:

```rust
impl From<kryphocron::Tier> for ContentTier {
    fn from(tier: kryphocron::Tier) -> Self {
        match tier {
            kryphocron::Tier::Public => ContentTier::Public,
            kryphocron::Tier::Private => ContentTier::Private,
            // Tier is #[non_exhaustive]; a future substrate tier would
            // not compile here until this match is extended. At v1.8.14
            // the registry ships exactly Public|Private.
            _ => ContentTier::Private,
        }
    }
}
```

The full derivation chain (§3.4) yields `Option<ContentTier>`: `None` when the subject has no AT-URI (account subject), the collection won't parse, or the NSID isn't registered. At v1.8.14 the only subject reaching this path is `kryphocron_record` (= `tools.kryphocron.feed.postPrivate` → `Tier::Private`), so `content_tier` is effectively always `"private"` here; the `Public` arm + `from_nsid` plumbing is future-proofing for when non-private kryphocron subjects reach the audit path.

**Design call:** v3 keeps the full `from_nsid` derivation (correctness for future kryphocron tiers; the umbrella's "content_tier field derived, not baked into names") rather than a literal `"private"`. R1/R2 confirmed the derivation; no simplification requested.

**Cargo:** `Tier`/`Nsid`/`from_nsid` are already reachable (kryphocron dep since v1.8.12; `Nsid::new` in-use at mod.rs:2088). No feature flag gates `from_nsid` (it's in the always-compiled generated registry).

### §5.3 Storage in `reason` JSON (LB-6)

`content_tier` (and `decode_source`) live as keys in the `report_resolved` `audit_log.reason` JSON for kryphocron subjects. Not typed columns — no migration. Queryable via `reason -> 'content_tier'` JSON extraction; promotion to typed columns deferred to v1.8.15+ if operators need SQL `WHERE` on tier.

## §6 — Capability gating (LB-4)

The 12 Aurora `kryphocron_*` payloads are **metadata-only** — verified: zero `encodedContent` across `events.rs`/`aurora_moderator.rs`. They carry operational metadata (`KryphocronBindGrantedPayload`, `rebuiltCommitCount`, etc.). No content-decode consent concern.

These events **already flow** through cairn-mod's outbound `query_events` (free-form `event_type: String`) with **no capability gate today** (`query_events` is a v1.8.3 read that isn't kryphocron-gated). Adding a `("kryphocron-events", AutoAdvance)` registry entry (13 → 14) would gate currently-ungated flow — a behavior change with no security benefit (metadata-only, already visible). **v3 adds no new capability entry — registry stays 13.** (R1/R2 confirmed.)

## §7 — Aurora's 12 kryphocron_* event_type surfacing (LB-3/LB-7)

### §7.1 Verbatim enumeration (Aurora `admin/events.rs:249-262`)
`kryphocron_bind_granted`, `kryphocron_bind_denied`, `kryphocron_audience_check_denied`, `kryphocron_reborrow_failed`, `kryphocron_composite_rollback_marker`, `kryphocron_audience_updated`, `kryphocron_block_changed`, `kryphocron_mute_changed`, `kryphocron_threadgate_changed`, `kryphocron_fallback`, `kryphocron_recovery_write`, `kryphocron_system_cleanup`.

### §7.2 Already flow + already render
cairn-mod's outbound `query_events` uses free-form `event_type: String` (read_types.rs:150) — the 12 values **already deserialize and flow**. The CLI `events_query` (pds_admin_reads.rs:85) already `to_string_pretty`s the whole page — the 12 events **already render as JSON**. No new fields, no per-type formatters needed for basic surfacing.

### §7.3 CLI extension — `--kryphocron-only` filter (Sub-A)
The subcommand exists: `cairn pds-admin events query` (`PdsAdminEventsSub::Query`, main.rs:379 → `run_pds_admin_events_query`, main.rs:2380). v1.8.14 adds a **`--kryphocron-only`** flag to `PdsAdminEventsQueryArgs` (main.rs:545) that filters the rendered page to `event_type` values starting with `kryphocron_` (client-side filter on the response, since Aurora's `event_type` filter takes one exact value, not a prefix). **No per-type formatters** (pretty-JSON already renders them; 12 hand-written formatters would duplicate output and risk drift on Aurora field additions).

### §7.4 Vocabulary doc/test-pin
Pin the 12 `kryphocron_*` strings in a cairn-mod test (mirroring existing pinned-string tests in read_types.rs) + document them in the CLI help/vocabulary. This is the "filter and response vocabulary" the umbrella names — realized as documentation + a test asserting the 12 values round-trip through the free-form `event_type` field.

## §8 — Ingestion posture (F3 non-goals)
### §8.1 StreamIngestor unchanged
`ingest_event` (stream_ingest.rs:89) mirrors every upstream event into `upstream_events`, special-cases only `report_review`, and `_ => {}`-falls-through all other verbs including kryphocron. **No v1.8.14 change** — the WS stream path neither originates nor specially handles cairn-mod's local audit tags. Aurora's 12 kryphocron events, if streamed, land in `upstream_events` as mirrored rows (free-form `event_type`, no CHECK) with no special handling — unchanged, honest.
### §8.2 F3 — no cross-verify
v1.8.14 does NOT extend `verify_upstream_entry` for kryphocron variants and does NOT mirror Aurora's kryphocron audits into `upstream_audit_mirror`. Aurora's kryphocron audits live in a separate non-hash-linked store (F3); cairn-mod's chain records only cairn-mod's own moderation decisions. Explicit non-goal.

## §9 — Audit-layer tagging (internal, LB-5)
### §9.1 No new trait method; no new emission API
Audit-authoring is internal (`resolve_report` writes the `report_resolved` `audit_log` row via `append_in_tx`), not `dyn PdsAdminBackend`. Trait stays **49**. No new emission method; v1.8.14 extends the `reason` JSON payload construction at the shipped resolve site (§3.4). No Ozone stub.
### §9.2 Single call-site change
The only behavioral change is at `resolve_report` (`src/writer.rs:669`): extend the resolve SELECT with `decode_source` (§3.3), derive `content_tier` (§3.4/§5), refactor `build_resolve_audit_reason` to return `Value`, and add the two tags on the `kryphocron_record` branch before stringifying. Non-kryphocron subjects: unchanged behavior (tags absent). No changes to v1.8.13 ingest handlers (§F10 clean — ingest stays audit-free).

## §10 — Non-goals
§10.1 No Aurora audit-chain ingestion. §10.2 No Path A verification on kryphocron variants (F3). §10.3 No new decode invocation. §10.4 No trait growth (49). §10.5 No migration (0014 highest). §10.6 No new `BackendError` variants. §10.7 No wire-type mirrors for Aurora event payloads (pretty-JSON pass-through). §10.8 No synthetic actor. §10.9 No new capability registry entry (registry stays 13). §10.10 No new `AUDIT_ACTION_VALUES` entry (closed set stays 10).

## §11 — Test coverage plan
1. **Unit — `ContentTier`:** `From<Tier>` maps `Tier::Public → Public`, `Tier::Private → Private`; `as_str()` → `"private"`/`"public"`.
2. **Unit — reason-JSON extension:** resolve on a `kryphocron_record` subject produces `reason` with `content_tier` + `decode_source` keys; resolve on a non-kryphocron subject produces byte-identical output to v1.8.13 (keys absent, not `null`).
3. **Unit — derivation chain:** `parse_at_uri_components` on an account subject → `None` → `content_tier` `None`; on a `tools.kryphocron.feed.postPrivate` AT-URI → `Private`; on an unregistered NSID → `None`.
4. **Unit — `AUDIT_ACTION_VALUES` closed set:** stays at 10 entries; `report_resolved` accepted; no `record_decoded`/`moderation_applied`; pinned test unchanged from HEAD.
5. **Unit — `build_resolve_audit_reason` refactor:** returns `Value`; the base (non-kryphocron) shape matches the shipped keys `{applied_label_val, resolution_reason}`.
6. **Unit — `--kryphocron-only` filter:** renders only `kryphocron_*` event_types from a mixed page; the 12 values pinned.
7. **Integration — resolve of a kryphocron subject:** the `report_resolved` audit row carries `content_tier: "private"` + `decode_source` from `reports.decode_source`.
8. **Integration — resolve of a non-kryphocron subject:** the `report_resolved` audit row is unchanged (no kryphocron keys).
9. **Integration — `cairn audit verify` covers the tagged rows:** a chain including a tier-tagged `report_resolved` verifies clean (payload-agnostic).
10. **Integration — queryEvents CLI:** `events query --kryphocron-only` against a mock page returns only kryphocron events; pretty-JSON render intact.
11. **Regression:** full `cargo test` + fmt/clippy/`RUSTDOCFLAGS="-D warnings" cargo doc` (memory #20); trait pinned 49, registry pinned 13, migration highest 0014, `AUDIT_ACTION_VALUES` at 10 — all unchanged.

## §12 — Ready-for-implementation checklist
- [ ] Branch off `6877c89`; implementation chainlink open (Opus-in-CC).
- [ ] Re-verify at HEAD: `resolve_report` (`src/writer.rs:669`), resolve SELECT (`1926-1941`), `report_resolved` audit write (`1999-2016`), `build_resolve_audit_reason` (`3549`, single caller), `AUDIT_ACTION_VALUES` (`167`, 10 entries), `list_audit_log` validation, `AuditRowForAppend`/`append_in_tx`; `reports.decode_source` column (v1.8.13); `parse_at_uri_components` (`create_report.rs:424`, `pub(crate)`, `Option<(&str,&str,&str)>`); `subject_type == "kryphocron_record"` literal (`server/create_report.rs:369`); `events_query` render + `PdsAdminEventsSub::Query`/`PdsAdminEventsQueryArgs`; `cairn audit verify` payload-agnostic.
- [ ] Re-verify kryphocron 0.3.1: `Nsid::new(&str) -> Result` (in-use at mod.rs:2088); `Tier::from_nsid(&Nsid) -> Result<Tier, UnknownNsid>` (`pub fn`, generated); `Tier { Public, Private }` `#[non_exhaustive]`; no feature flag.
- [ ] Re-verify Aurora `2ffeb1a`: the 12 `kryphocron_*` `event_type`s (events.rs:249-262), metadata-only payloads (no `encodedContent`).
- [ ] Firewall grep on this doc: clean.

## §13 — Post-implementation checklist
- [ ] `report_resolved` reason gains `content_tier` + `decode_source` for kryphocron subjects; byte-identical to v1.8.13 for non-kryphocron subjects; ingest still audit-free (§F10 honored).
- [ ] `content_tier` derived via `parse_at_uri_components` → `Nsid::new` → `Tier::from_nsid` → `ContentTier::from`; snake_case; in reason JSON (no migration).
- [ ] `build_resolve_audit_reason` returns `Value`; single caller stringifies at site.
- [ ] `AUDIT_ACTION_VALUES` unchanged (10); `report_resolved` reason-schema const documents the two optional keys.
- [ ] `events query --kryphocron-only` filters; 12 values pinned; no per-type mirror structs.
- [ ] Trait 49, registry 13, migration 0014, no new BackendError — all unchanged.
- [ ] `cairn audit verify` green over the tagged rows. Full `cargo test` + gates green.
- [ ] CHANGELOG under `[Unreleased]`; chainlink closed `--no-changelog`.
- [ ] v1.8.15 ledger updated (§9e).

## §14 — Revision log

**v3 (this draft — canonical materialization).** Full canonical doc materializing everything surviving R1 + R2, with the R3 S-2 citation fix applied against verified HEAD primitives.

- **R1 (chainlink #170) — collapse.** Three LBs (LB-1 `get_report` cannot carry `RecordDecoded` semantics — drops moderator DID, non-transactional, omits decode columns; LB-2 `report_dismissed` doesn't exist and `AUDIT_ACTION_VALUES` is a closed set of 10; LB-3 `decoded_plaintext` is a write-only column with no read projection) collapse into a single fold: `RecordDecoded` as a standalone action is removed; kryphocron context becomes `content_tier` + `decode_source` tags on the shipped `report_resolved` write at `resolve_report`. §3.2 `ModerationApplied`-as-tag HELD. §3.1a idempotency race MOOT. M corrections: `Tier::from_nsid` is `pub fn` (not `const fn`); registry confirmed 13.
- **R2 (chainlink #171) — 0 LB, 2 S, 2 M.** Collapse verified structurally sound across four checkpoints. S-1: `decode_source` must be plumbed into the resolve read surface (§3.3). S-2: v2's illustrative code cited non-existent helpers (`subject.nsid()`, `parse_nsid_from_uri`, `from_collection`). M: v2 not materialized as canonical (fixed by this v3 doc); chainlink numbering.
- **R3 — S-2 fix applied against HEAD (this materialization).** Verified primitives: `parse_at_uri_components(&str) -> Option<(&str,&str,&str)>` (**Option of tuple**, not a `Result`/struct — corrects the R3 verdict's `.ok()`/`.components.collection` phrasing), `kryphocron::Nsid::new(&str) -> Result`, `Tier::from_nsid(&Nsid) -> Result<Tier, UnknownNsid>`, and a new `impl From<kryphocron::Tier> for ContentTier` (§5). **Additional correction over R3's cited snippet:** `build_resolve_audit_reason` returns `String`, not `serde_json::Value`, so the `extended_reason["key"] = json!(...)` index-mutation does not compile; the materialized §3.4 refactors the builder to return `Value` and stringifies once at the single call site.

**Design decisions locked at v3:**
- No new `AUDIT_ACTION_VALUES` entries. Closed set stays at 10.
- No migration. `content_tier` + `decode_source` live in `reason` JSON on shipped `report_resolved` writes.
- No trait growth (49). No new capability registry entries (13). No new `BackendError`. No synthetic actor.
- `DecodedRecord` unchanged from v1.8.13. No `AuditEvent` enum (confirmed non-existent).
- Single emission-site change: `resolve_report` at `src/writer.rs`. Ingest handlers stay audit-free (§F10).
- CLI: queryEvents `--kryphocron-only` filter. Aurora's 12 `kryphocron_*` event_types surface via free-form String pass-through + existing pretty-JSON render.

**v2 (superseded — `-v2-folds.md`).** R1 fold patch against v1. Non-canonical; retained as history.
**v1 (superseded — `-v1.md`).** Initial draft with `RecordDecoded` as standalone action + moderator-view emission. R1 collapsed. Retained as history.

Pending: narrow R3 confirmation (canonical doc exists + citations swapped + M folds applied) → fold-and-lock, then implementation kickoff.

## §9e — v1.8.15 series-wrap reconciliation ledger
Seven items carry into v1.8.15:
1. v1.8.12 codec-path text
2. v1.8.12 NSID sub-family text
3. v1.8.13 HTTP-410 mechanism
4. v1.8.13 `encodedContentGeneration` decode-input
5. v1.8.13-close golden-vector decode test
6. v1.8.14 `content_tier` derivation vocabulary (umbrella §4.B.3 reconciliation)
7. v1.8.14 standalone-`RecordDecoded`-vs-tag divergence (source §F10 wins over the umbrella hybrid; `ModerationApplied` likewise folds to a tag)

## §9f — v1.8.16+ inventory unchanged
Four items carry forward (batch-restore CLI, per-subject batch labels, stream start/stop, runtime_settings_writes auto-join). v1.8.14 touches none.
