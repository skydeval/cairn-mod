# cairn-mod v1.8.12 substrate consumption — design v2

**Status:** Draft v2. R1 folded (chainlink #162); locked pending implementation kickoff.

- cairn-mod HEAD: `d569d16` (`skydeval/v1.8.11-series-wrap`, unpushed — post-v1.8.11 shipping)
- Aurora-Locus HEAD: `2ffeb1a` (no drift since v1.8.5)
- kryphocron: `0.3.1` (`7602abc`); kryphocron-lexicons: **`0.3.0`** (`687dfad`)
- Recon: `docs/internal/recon/v1.8.12-substrate-consumption-recon.md` (chainlink #160)
- Design chainlink: #161

## §1 — Process context + memory locks

Workstream B entry point. Umbrella §4.B.1 scope: **substrate wiring + detection only, no consumption**. Recon #160 surfaced one load-bearing umbrella correction (codec path) + five §7d design calls; Nova committed the scope in the kickoff. Straight to CC-adversarial after drafting (memory #15). Sourcing per memory #6 + corollaries (#26 full-file grep for the capability/feature enumerations; #27 DDL forward-trace N/A — no migration; #29/#30 own-source + kryphocron-source grep — every claim re-verified at the pinned commits). Firewall applies (kryphocron is skydeval-owned per memory #4, so kryphocron type names are fine in the doc; cairn-mod's firewall applies to paths/identifiers).

**Four draft-time corrections to the kickoff** (source-verified, folded below):
- **C1 (LB-4 feature hygiene UNACHIEVABLE — Nova-decided):** the kickoff's decode-only-feature objective can't be met. In kryphocron 0.3.1 `Cargo.toml`, `zstd = "0.13"` is an **unconditional** dependency (not `optional`, not feature-gated; `default = []` has nothing to trim; the source comment calls it "the one non-Rust build dependency the default codec brings in"). So `kryphocron = "0.3.1"` pulls `zstd 0.13 → zstd-sys` (C libzstd) into cairn-mod's `Cargo.lock` regardless of features. **Nova decision (this session): accept `zstd-sys`, matching Aurora** (whose `Cargo.lock` already carries it). LB-4 revised (§6.2); the §9.6 negative test is dropped.
- **C2 (lexicons version):** kryphocron-lexicons is **`0.3.0`**, not `0.3.1` (kickoff provenance slip). Declared as `kryphocron-lexicons = "0.3"` (§6.1).
- **C3 (RustBackend field name):** the codec sits alongside `capabilities` (not `advertised_capabilities` as the kickoff's LB-1 states — `rust/mod.rs:199`) (§3.2).
- **C4 (`Codec::default()` is infallible):** `Codec::default() -> Self` and `Codec::new(seed_policy) -> Self` return `Self`, not `Result` (`kryphocron/src/codec/laquna/mod.rs:89-103`). So LB-3's "codec `default()` returns Err → `PdsAdminConfigError` variant" is a nonexistent failure path; **no new config error variant** for codec init (§5.3). Existing `RustBlockInvalid(String)` (`config.rs:306`) covers any kryphocron-sub-block validation failure — satisfies LB-5 cleanly.

## §2 — What v1.8.12 is

The smallest Workstream-B release: **substrate PRESENCE, not substrate USE.** Add `kryphocron` + `kryphocron-lexicons` deps, instantiate a decode-only `Codec` at boot, register three kryphocron capability strings (10 → 13), add a minimal `[pds_admin.rust.kryphocron]` config block, and surface detection through the v1.8.11 `probe()` output. **No decode invocation, no endpoint consumption, no trait growth, no dispatch primitive, no migration.**

### §2.1 Locked decisions (LB-1..5 + subsidiary)
- **LB-1:** codec instantiated at `kryphocron::codec::laquna::Codec::default()` (§3.1), field on `RustBackend` (§3.2).
- **LB-2:** three capability families — `kryphocron-read` (OperatorOptIn), `kryphocron-rotation`/`kryphocron-overrides` (AutoAdvance); registry 10 → 13 (§4).
- **LB-3:** `[pds_admin.rust.kryphocron]` minimal (`enabled: bool = false`); no speculative fields (§5).
- **LB-4 (revised, C1):** `kryphocron` + `kryphocron-lexicons` deps; `zstd-sys` C dependency **inherited-and-accepted**, matching Aurora (§6).
- **LB-5:** trait stays 48, dispatch primitives stay 3, migration stays 0013, no new `BackendError` (and no new `PdsAdminConfigError` per C4) (§8).
- **Subsidiary:** `ProbeReport` gains additive kryphocron-state fields (§7); no CLI subcommands; no Ozone stubs (no new trait methods); no exit codes; CHANGELOG under `[Unreleased]`.

### §2.2 Non-goals
- **No endpoint consumption** — none of the 13 `tools.aurora.ops.kryphocron.*` routes are called (v1.8.13+).
- **No decode invocation** — the codec is instantiated but never invoked (umbrella verbatim: "No decode operations yet at v1.8.12").
- **No trait growth** (48), **no dispatch primitive** (3), **no migration** (0013), **no encoder** (decode-only; encode is Aurora/PDS-side).
- **No `ReportSubject` variant / `subject_type` change** (v1.8.13).
- **No speculative config fields** — only `enabled`.

### §2.3 Umbrella-vs-source corrections (flagged for v1.8.15)
Two umbrella text edits, deferred to the v1.8.15 kryphocron series-wrap (v1.8.12 does not edit the umbrella):
1. **Codec path:** umbrella §4.B.1 says `laquna::Codec`; shipped is `kryphocron::codec::laquna::Codec` (vendored module; the standalone `laquna` crate — sibling repo, `0.2.0`, `publish = false` — has only free `encode`/`decode`, no `Codec`/`SeedPolicy`; kryphocron 0.3.1 vendors laquna's deps, does not depend on the crate). **This design uses the correct path (LB-1); the umbrella text fix is v1.8.15's.**
2. **NSID sub-families:** umbrella referenced `channel`/`wall`/`moderation`; shipped lexicon groupings (kryphocron-lexicons 0.3.0) are `feed`/`graph`/`policy` (8 NSIDs). The private-record `$type` is `tools.kryphocron.feed.postPrivate` (only NSID carrying `encodedContent`). v1.8.12 consumes no NSIDs, so this is series-coherence context only; the umbrella fix is v1.8.15's.

### §2.4 Workstream B scope split
- **v1.8.12 (this):** substrate wiring + detection. Deps + codec instantiation + 3 registry entries + config block + probe surfacing.
- **v1.8.13 (report-flow retrieval):** first decode; `KryphocronRecord` `ReportSubject` variant (`tools.kryphocron.feed.postPrivate`); `subject_type` rebuild-migration; `BackendError::KryphocronDecodeFailed` family; consumes `kryphocron-read` + endpoints as needed. Codec-skew check compares stored `encodedContentCodec` (`"laquna/0.2"`) against `Codec::codec_id()`.
- **v1.8.14 (kryphocron audit):** cairn-mod-side audit-chain variants; gated on v1.8.3 + v1.8.8.
- **v1.8.15 (laquna handling / series-wrap):** codec-skew semantics wrap + the two §2.3 umbrella reconciliations.
The four target different kryphocron surfaces (not incremental extensions of one). v1.8.12 is unambiguously the smallest.

## §3 — kryphocron substrate integration

### §3.1 Codec instantiation at `kryphocron::codec::laquna::Codec::default()` (LB-1)
Path verified at kryphocron 0.3.1 (`src/lib.rs:163` `pub mod codec` → `src/codec/mod.rs:14` `pub mod laquna` → `src/codec/laquna/mod.rs:53` `pub struct Codec`). `Codec::default()` (`mod.rs:89-92`) sets `SeedPolicy::DidNsidRkey` (`mod.rs:63`, the default variant); infallible (`-> Self`, C4). Decode-only usage is separable from `AtRestHooks` (recon §4.3: `Codec::decode` is directly callable; `EncodedRecord::new`/`DecodeContext::new` are host-constructible; no oracle needed for decode). v1.8.12 **instantiates but does not invoke** — the codec exists to be consumed at v1.8.13+.

Use a type alias to avoid repeating the fully-qualified path:
```rust
// in the kryphocron integration module
use kryphocron::codec::laquna::Codec as KryphocronCodec;
```

**R1 verdict on `Option<Codec>` gating**: HELD. Rationale matches v1.8.8's stream-consumer-when-disabled precedent. Downstream releases (v1.8.13+) consuming the codec accept the `Option`-unwrap or `enabled`-match idiom as the standard pattern for kryphocron consumption. Alternative (unconditional instantiation) rejected because `Codec::default()` being infallible means the `Option` cost is purely opt-in-tracking; there's no simpler-code argument once the `enabled` gate exists (v1.8.13+ still branches on `enabled` regardless of `Option` vs unconditional).

### §3.2 RustBackend field placement + boot-time construction
Add one field to `RustBackend` (`rust/mod.rs:183-211`), alongside `capabilities` (C3 — the field is `capabilities: Arc<RwLock<CapabilitySet>>` at `:199`, NOT `advertised_capabilities`):
```rust
/// Decode-only kryphocron codec (v1.8.12). Instantiated when
/// `[pds_admin.rust.kryphocron].enabled = true`; None otherwise.
/// Never invoked at v1.8.12 (wiring + detection only); consumed
/// from v1.8.13. Pure construction — no I/O.
kryphocron_codec: Option<KryphocronCodec>,
```
Instantiated in `new_with_key_source` (`rust/mod.rs:242`, the real constructor; `new` `:234` delegates), which "does NOT perform network I/O" — `Codec::default()` is pure, so it honors that contract. **`Option<Codec>` gated on `config.kryphocron.enabled`** (LB-3): `Some(Codec::default())` when enabled, `None` otherwise. (Recon §6.5 floated unconditional instantiation as simpler; the kickoff LB-3 ties instantiation to `enabled`, so v1 gates it — `Option` is the honest representation of "operator declined consumption," and it lets `probe()` distinguish "advertised but not consumed" from "advertised and codec-ready" per §7.1.)

### §3.3 Decode-only mode; encoder deferred
cairn-mod is a decode-only consumer: it decodes private-record `encodedContent` it fetches; it never encodes (encode is Aurora/PDS-side, at-rest). The `ContentCodec::encode` method exists on the type but cairn-mod calls neither `encode` nor (at v1.8.12) `decode`. Note the codec ID is `"laquna/0.2"` (recon §4.1, `mod.rs:179`) even at kryphocron 0.3.1 — recorded here for the v1.8.13 skew check, not used at v1.8.12.

## §4 — Capability registry additions

### §4.1 Three new families
Recon confirmed exactly three kryphocron capability strings advertised by Aurora (`admin.rs:711/720.../772/777`, registry `registry.rs:161/164/170`): `kryphocron-read`, `kryphocron-rotation`, `kryphocron-overrides`. Registry keys are **suffix-less family names** (the `-vN` is parsed off the wire), so the entries are `"kryphocron-read"` / `"kryphocron-rotation"` / `"kryphocron-overrides"`.

### §4.2 Classifications (LB-2) with rationale per family
```rust
("kryphocron-read",      CapabilityClassification::OperatorOptIn),
("kryphocron-rotation",  CapabilityClassification::AutoAdvance),
("kryphocron-overrides", CapabilityClassification::AutoAdvance),
```
- **`kryphocron-read` → OperatorOptIn** (fourth OperatorOptIn consumer after `batch-takedown` v1.8.7, `mod-events-stream` v1.8.8, `runtime-settings` v1.8.9). It gates decode of private content (`tools.kryphocron.feed.postPrivate` with `encodedContent`) — content access is consent territory; operators explicitly opt in via `[pds_admin.rust.pinned_versions]`. Matches the §5.4.2 opt-in posture.
- `("kryphocron-overrides", CapabilityClassification::AutoAdvance)` — AutoAdvance because the gating basis for OperatorOptIn in this family is `encodedContent` decode: `tools.kryphocron.feed.postPrivate` is the sole NSID carrying encoded content, gated by `kryphocron-read`. Endpoints under `kryphocron-overrides` (`setAccountOverride`, `getAccountOverrides`) are SuperAdmin-gated per-account policy operations at the Aurora side and are audit-chained through Aurora's own audit trail — but they do NOT return `encodedContent`. Since v1.8.12's classification framework treats decode-of-private-content as the OperatorOptIn axis (per LB-2's stated design), rotation/overrides fall on the AutoAdvance side even though they touch account-level state.
- cairn-mod does not consume these operator-facing endpoints at v1.8.12 (or in currently-scoped Workstream B releases through v1.8.15) — the classification is forward-looking gate posture for any release that eventually surfaces them.
- `("kryphocron-rotation", CapabilityClassification::AutoAdvance)` — genuinely pure-operational-visibility rationale holds. Rotation-state reads surface batch identifiers + rotation schedules, no per-account data, no `encodedContent`. R1 confirmed this classification's rationale is factually accurate.

### §4.3 Pinned test 10 → 13; canonical fixtures 10 → 13
- `CAPABILITY_CLASSIFICATIONS` (`types.rs:307`) gains three entries → **13**. The pinned test `assert_eq!(CAPABILITY_CLASSIFICATIONS.len(), 13)` (`types.rs:739`, was 10) + three new per-index tuple assertions.
- `canonical_body()` (`tests/rust_backend.rs:62`, consolidated to 10 registered families at v1.8.11) gains the three kryphocron wire strings (`kryphocron-read-v1`, `kryphocron-rotation-v1`, `kryphocron-overrides-v1`) → advertises all 13 registered + the `queue-stats-v1` tolerance probe. All three land in the **same commit** (registry + pinned test + fixture coordinate).

**Implementation note on fixture array-count**: `canonical_body()` at `tests/rust_backend.rs:62` currently carries **11 array items** at HEAD (10 registered capability families + 1 `queue-stats-v1` placeholder retained per v1.8.11's intentional unknown-extension-tolerance test — see v1.8.11 recon C2). v1.8.12 extends this to **14 array items** by adding three kryphocron family strings (`kryphocron-read-v1`, `kryphocron-rotation-v1`, `kryphocron-overrides-v1` — with `-v1` suffix on the wire, registry family key is suffix-less).

The 10 → 13 frame is correct for registered families (registry semantics). The 11 → 14 frame is correct for the fixture array cardinality (test-side implementation view). Implementer patching the fixture sees the array; both frames refer to the same additions.

### §4.4 `kryphocron-read` second-order classification note (reversibility)
Classifying `kryphocron-read` as OperatorOptIn commits the gating posture for when v1.8.13+ consumes endpoints under it. **If v1.8.13 recon finds `kryphocron-read` gates a mix of decode-required + operational-visibility endpoints** needing finer gating, split into `kryphocron-decode` (OperatorOptIn) + `kryphocron-read` (AutoAdvance) **at v1.8.13's design**, not here. Reversal is cheap (const-array edit; a config-break for operators pinning `kryphocron-read`, but not migration-shaped). Note the 13 kryphocron endpoints (recon §3.2) already show `kryphocron-read` covering both reads *and* control-POSTs like `cancelRotation` — so the v1.8.13 finer-gating question is live; v1.8.12 takes the conservative OperatorOptIn default.

## §5 — Config surface

### §5.1 `[pds_admin.rust.kryphocron]` minimal wiring block
Mirror the shipped `[pds_admin.rust.stream]` pattern (recon §6.3):
- **Raw TOML:** `#[serde(default)] pub kryphocron: Option<PdsAdminKryphocronToml>` on `PdsAdminRustToml` (`config.rs:325`; mirror the `stream` field at `:357-358`). Define `PdsAdminKryphocronToml` with `#[serde(deny_unknown_fields)]` (mirror `PdsAdminStreamToml` at `:408-409`), one field: `#[serde(default)] pub enabled: Option<bool>`.
- **Resolved:** `pub kryphocron: RustKryphocronConfig` on `RustBackendConfig` (`pds_admin/config.rs:180`; mirror `stream` at `:225`). Define `RustKryphocronConfig { pub enabled: bool }` + `Default` (`enabled: false`) (mirror `RustStreamConfig` at `:135-162`). Resolve in `validated_rust_from_toml` (mirror the stream block at `:1044-1071`): `enabled = toml.kryphocron.and_then(|k| k.enabled).unwrap_or(false)`.

### §5.2 `enabled = false` default posture
Default off (matches the v1.8.8 stream posture). An operator must explicitly set `enabled = true` for the codec to be instantiated. Rationale: Workstream-B consumption is opt-in; a cairn-mod pointed at a kryphocron-enabled Aurora shouldn't start decoding private content until the operator declares intent (the §5.4.2 posture — best-effort decode is the *default when enabled*, not a default-on behavior).

### §5.3 Boot behavior + startup failure modes
- **`enabled = false` (default):** no codec instantiated (`kryphocron_codec = None`); `probe()` reports kryphocron families (if advertised) as "advertised, not consumed"; no error.
- **`enabled = true`:** `kryphocron_codec = Some(Codec::default())` at boot (pure, infallible — C4); `probe()` reports codec-ready state; dispatch remains no-op (no endpoints at v1.8.12).
- **Startup failure modes (corrected per C4):**
  - `enabled = true` + kryphocron crate absent → **compile-time** failure (the dep is unconditional; can't be missing at runtime). Not a runtime path.
  - **No "codec `default()` returns Err" path** — `Codec::default()` is infallible (C4). The kickoff's guarded-startup-rejection mode does not exist; **no new `PdsAdminConfigError` variant** is added.
  - Malformed `[pds_admin.rust.kryphocron]` (e.g., unknown key under `deny_unknown_fields`) → serde parse error surfaced as the existing `RustBlockInvalid(String)` (`config.rs:306`) — no new variant.
  - `enabled = true` + operator pins `kryphocron-read` without upstream advertisement → the existing `require_opt_in` OperatorOptIn behavior (v1.8.7/8/9 precedent) applies — pin-without-advertisement is the standard opt-in mismatch, handled by shipped machinery, not new code.

## §6 — Cargo dependencies

### §6.1 kryphocron + kryphocron-lexicons (no standalone laquna)
```toml
kryphocron = "0.3.1"
kryphocron-lexicons = "0.3"   # resolves 0.3.0 (C2)
```
No standalone `laquna` dep (LB-1/C1 — kryphocron vendors it). Pin to `0.3.x`, matching Aurora (`aurora-locus/Cargo.toml:34-35`). cairn-mod does not lead the substrate version (umbrella §4.B.1). **Feature flags:** kryphocron 0.3.1 has `default = []` and only `test-support` / `audit-serde-json` features (neither needed at v1.8.12 — audit-serde is a v1.8.14 concern). Declare with defaults (i.e., no features); `default-features = false` is a no-op here since default is empty. `kryphocron-lexicons` likewise defaults-only.

### §6.2 zstd-sys C dependency — inherited and accepted (LB-4 revised, C1)
**The decode-only-feature-hygiene objective is unachievable and is dropped.** In kryphocron 0.3.1 `Cargo.toml`, `zstd = "0.13"` (`:54`) is an **unconditional, non-optional, non-feature-gated** dependency (source comment: "the one non-Rust build dependency the default codec brings in"); `ruzstd` (`:53`, pure-Rust decode) is *also* unconditional but does not displace `zstd`. There is no feature to disable `zstd`. Therefore adding `kryphocron` pulls `zstd 0.13 → zstd-sys` (C libzstd) into cairn-mod's `Cargo.lock` regardless of feature selection.

**Decision (Nova, this session): accept it.** cairn-mod-consuming-kryphocron inherits the identical build footprint as Aurora-consuming-kryphocron — Aurora's `Cargo.lock` already carries `zstd-sys` (verified). This is the honest cost of consuming the substrate; a no-C-toolchain build would require an upstream kryphocron change (making `zstd` optional behind an encode feature) that is out of v1.8.12's scope. If kryphocron later gates `zstd`, cairn-mod can revisit; until then, `zstd-sys` in `Cargo.lock` is expected, not a regression. **Design note for operators:** building cairn-mod at v1.8.12+ requires a C toolchain for `zstd-sys` (same as building Aurora) — documented in the CHANGELOG/deps note.

### §6.3 Version pinning to 0.3.x
`kryphocron = "0.3.1"`, `kryphocron-lexicons = "0.3"` (→ 0.3.0). Conservative tracking of Aurora's pins; cairn-mod does not lead. A `Cargo.lock` commit accompanies the manifest change (the lockfile now carries `zstd-sys` + the kryphocron tree).

## §7 — probe() extension

### §7.1 ProbeReport additive fields
`ProbeReport` (`backend.rs:543-568`: `backend_name`, `pds_url`, `detected_version`, `capabilities: Vec<String>`) gains additive kryphocron-state fields, populated only when `kryphocron_codec.is_some()` (i.e., `enabled = true`):
```rust
/// v1.8.12: present when kryphocron consumption is enabled.
/// None when [pds_admin.rust.kryphocron].enabled = false, even
/// if the upstream advertises kryphocron capabilities.
pub kryphocron: Option<KryphocronProbeState>,
```
where `KryphocronProbeState { codec_id: String /* "laquna/0.2" */, seed_policy: &'static str /* "DidNsidRkey" */, decode_ready: bool }`. `codec_id` and `seed_policy` are constants from the instantiated codec; `decode_ready` reflects "codec built, ready for v1.8.13 decode." Purely additive — existing `ProbeReport` consumers (the v1.8.11 `pds-admin probe` formatter) are unchanged; the formatter gains an optional kryphocron section rendered only when `Some`.

### §7.2 CLI presentation
No new subcommand. `cairn pds-admin probe` (v1.8.11) surfaces the kryphocron state: when enabled, an added section shows the three kryphocron families' advertised/registered match (they're now in the registry, so the v1.8.11 match report lists them automatically) plus the codec state (`codec_id`, `seed_policy`, `decode_ready`). When disabled, kryphocron families still appear in the match report as advertised-and-registered, but no codec section renders. `--json` includes the additive `kryphocron` field (null when disabled).

## §8 — Non-goals

### §8.1 No endpoint consumption (v1.8.13+)
None of the 13 `tools.aurora.ops.kryphocron.*` routes are dispatched.

### §8.2 No decode invocation (v1.8.13+)
The codec is instantiated but `decode` is never called.

### §8.3 No trait growth
Trait stays **48** (`backend.rs:639-1229`). No `probe_kryphocron_state()` or similar — kryphocron state rides `probe()`'s existing `ProbeReport` (extended additively per §7). No Ozone stubs (no new trait methods).

### §8.4 No dispatch primitive additions
Stays at three (`dispatch_moderator_read`, `dispatch_admin_post`, `dispatch_ops_read`). v1.8.12 consumes zero endpoints; a fourth primitive (if any) is a v1.8.13 question.

### §8.5 No migration
Highest stays **0013**. Detection-only, no persistence (DDL forward-trace N/A).

### §8.6 No encoder / no new error variants
Decode-only (encode is PDS-side). No new `BackendError` (no dispatch/decode this release); no new `PdsAdminConfigError` (C4 — codec init is infallible; config errors ride `RustBlockInvalid`).

## §9 — Test coverage plan

1. **Unit — codec gating (disabled):** `enabled = false` → `RustBackend.kryphocron_codec` is `None`; no codec built.
2. **Unit — codec gating (enabled):** `enabled = true` → `kryphocron_codec` is `Some`; `Codec::default()` constructs (infallible); `codec_id() == "laquna/0.2"`.
3. **Unit — registry classifications:** `CAPABILITY_CLASSIFICATIONS.len() == 13`; the three kryphocron entries present with correct classifications (`kryphocron-read` OperatorOptIn; `rotation`/`overrides` AutoAdvance). Pinned per-index assertions updated.
4. **Integration — probe() output:** enabled → `ProbeReport.kryphocron == Some` with `codec_id`/`seed_policy`/`decode_ready`; disabled → `None`. Existing `ProbeReport` fields unchanged.
5. **Integration — canonical fixtures:** `canonical_body()` advertises all 13 registered families; probe match-report shows the three kryphocron families as advertised-and-registered.
6. **~~Feature hygiene~~ (DROPPED per C1):** the `cargo tree | grep zstd-sys` negative test is removed — `zstd-sys` is expected in the tree (inherited from kryphocron, matching Aurora). Optionally, a *positive* documentation assertion that the build succeeds with the C toolchain present (or simply rely on CI building green).
7. **Config — parse:** `[pds_admin.rust.kryphocron] enabled = true` parses; unknown key under the block → `RustBlockInvalid`; absent block → `enabled` defaults false.
8. **Regression — full lib suite:** `cargo test` green; fmt + clippy + `RUSTDOCFLAGS="-D warnings" cargo doc` (memory #20/#13); trait pinned at 48, registry pinned at 13.

## §10 — Ready-for-implementation checklist
- [ ] Branch off `d569d16`; implementation chainlink open.
- [ ] kryphocron re-verified at 0.3.1: `kryphocron::codec::laquna::Codec::default()` path + infallibility; `SeedPolicy::DidNsidRkey` default; codec_id `"laquna/0.2"`; `zstd` unconditional (C1).
- [ ] kryphocron-lexicons `0.3.0` (C2); Aurora pins re-confirmed (`Cargo.toml:34-35`).
- [ ] cairn-mod re-verified at HEAD: registry 10 + pinned test at `types.rs:739`; `canonical_body()` 10-family shape (`rust_backend.rs:62`); `RustBackend` fields (`rust/mod.rs:183`, codec slots by `capabilities`); `new_with_key_source` (`:242`); `PdsAdminRustToml`/`stream` sub-block pattern (`config.rs:357-408`); `ProbeReport` (`backend.rs:543`); `RustBlockInvalid` (`config.rs:306`).
- [ ] Firewall grep on this doc: clean.

## §11 — Post-implementation checklist
- [ ] Deps added (kryphocron 0.3.1 + kryphocron-lexicons 0.3); `Cargo.lock` updated (carries `zstd-sys`, accepted per C1); build green with C toolchain.
- [ ] Codec instantiated only when `enabled = true`; `None` otherwise; never invoked.
- [ ] Registry 10 → 13; pinned test + canonical fixture updated in the same commit; classifications correct.
- [ ] `[pds_admin.rust.kryphocron] enabled` parses; default false; malformed → `RustBlockInvalid`.
- [ ] `probe()` surfaces kryphocron state additively; existing consumers unchanged; `--json` carries the optional field.
- [ ] Trait 48, dispatch primitives 3, migration 0013 — all unchanged.
- [ ] Full `cargo test` + fmt/clippy/rustdoc gates green.
- [ ] CHANGELOG under `[Unreleased]` (deps + C-toolchain note per §6.2); chainlink closed `--no-changelog`.
- [ ] Umbrella §2.3 corrections (codec path, NSID sub-families) recorded for the v1.8.15 series-wrap (NOT edited here).

## §12 — Revision log

**v2 (this draft).** Post-CC-adversarial R1 fold (chainlink #162). R1 verdict: 5-agent verification with 0 LB, 1 S, 1 M. All four drafting-time corrections C1–C4 HELD. `Option<Codec>` R1-open verdict: HELD. Scope-creep guard clean.

Ship signal per memory #12: 0 LB → fold-and-lock. Both findings folded; recommendation → straight to implementation kickoff, no R2.

**R1 S-1 fold**: §4.2's `kryphocron-overrides` classification decision (AutoAdvance) HELD — R1 confirmed no `encodedContent` on rotation/overrides endpoints; `postPrivate` is sole content carrier. Rationale rewritten: overrides are SuperAdmin-gated per-account policy operations audit-chained through Aurora's own trail, but the OperatorOptIn axis is specifically decode-of-private-content, and overrides don't return encodedContent. Classification decision survives on correct basis. `kryphocron-rotation` rationale (pure-operational-visibility) reaffirmed accurate.

**R1 M-1 fold**: §4.3 gains array-count clarifying note. Canonical fixture at HEAD is 11 items (10 registered + `queue-stats-v1` placeholder from v1.8.11 intentional retention); v1.8.12 extends to 14 items. Registered-family frame (10 → 13) is correct for registry semantics; array-cardinality frame (11 → 14) is correct for implementer's fixture-patching view.

**R1-open verdict fold**: §3.1 records `Option<Codec>` HELD with v1.8.8 precedent citation.

**Design decisions locked at v2:**
- All five LB kickoff decisions hold.
- Codec at `kryphocron::codec::laquna::Codec::default()` (LB-1).
- Registry additions: `kryphocron-read` OperatorOptIn, `kryphocron-rotation` + `kryphocron-overrides` AutoAdvance (LB-2 with corrected rationale for overrides).
- `[pds_admin.rust.kryphocron]` minimal config, `enabled: bool = false` default (LB-3).
- kryphocron + kryphocron-lexicons deps, no standalone laquna, `zstd-sys` inherited transitively matching Aurora (LB-4 per C1 accept-and-match).
- No trait growth, no dispatch primitive, no migration (LB-5).
- `Option<Codec>` gating on `enabled` (R1-open HELD).
- `probe()` additive extension for kryphocron state.
- v1.8.15 series-wrap absorbs umbrella corrections (codec path text, NSID sub-family text).

**v1 (superseded).** Initial draft. See git history if needed.

Pending: implementation kickoff.
