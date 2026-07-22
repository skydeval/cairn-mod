# cairn-mod v1.8.11 series-wrap — design v1

**Status:** Draft v2. R1 folded (chainlink #158); locked pending implementation kickoff.

- cairn-mod HEAD: `f3cf7b2` (`skydeval/v1.8.10-operator-extensions`, unpushed — post-v1.8.10 shipping)
- Aurora-Locus HEAD: `2ffeb1a` (`skydeval/v0.11-cycle`, no drift since v1.8.5)
- Recon: `docs/internal/recon/v1.8.11-series-wrap-recon.md` (chainlink #156)
- Design chainlink: #157

## §1 — Process context + memory locks

Last release of Workstream A. Umbrella §4.A.11 sets scope; recon #156 surfaced five umbrella-vs-source divergences + three ledger-scoping calls, and Nova committed the scope decisions in the kickoff so this design implements rather than re-litigates. Straight to CC-adversarial after drafting (memory #15, per-release doc). Sourcing per memory #6 + corollaries (#26 full-file grep for the removal/rename enumerations; #27 DDL forward-trace N/A — no migration; #29/#30 own-source grep — every claim re-verified at `f3cf7b2`). This is a **source-side reconciliation release**: umbrella text catches up to shipped state; code changes are removal (item 9), rename (item 10), one new CLI presentation layer (item 8/probe), and a test-fixture edit (item 5). Firewall applies.

**Four draft-time corrections to the kickoff** (source-verified, folded below):
- **C1 (LB-7 fixture delta):** the kickoff's "missing 4" list was garbled (it named six families, some already present). The true delta of registered families absent from `canonical_body()` is exactly **`moderator-activity`, `subject-context`, `subject-history`, `appeals`** (§7.1).
- **C2 (`queue-stats-v1` disposition):** not a deferred feature and not umbrella speculation — it's an intentional *unknown-extension-tolerance test probe* with test-only references (`types.rs:924-925` version-parse vector; `canonical_body()` tolerance probe). Keep it; not a v1.8.16+ inventory item (§11).
- **C3 (LB-8 "prune 3 deferred lines"):** all three inline "deferred" CHANGELOG mentions (`:149`, `:207`, `:310`) are **still-accurate** forward-looking non-goal notes (they map to live v1.8.16+ inventory items). Pruning them loses real documentation. **Keep, don't prune** — the humanization is confined to promotion + consistency (§8).
- **C4 (LB-8 dated-section/tag):** the repo tags minor-only (`v1.7.0`, no patch tags) and memory #28 says "v1.8 ships as one release," so the convention points at `## [1.8.0]` + tag `v1.8.0`, which conflicts with the kickoff's `[1.8.11]`. **Nova decision (this session): defer the final tag to the release step**; the design records the conflict + convention evidence and recommends `[1.8.0]` (§8.1).

## §2 — What v1.8.11 is

A documentation-and-cleanup wrap release. **No new upstream consumption, no new capability families, no migration, no trait-method additions.** Trait stays at 48, registry at 10, highest migration at 0013. The only additive surface is the `cairn pds-admin probe` CLI presentation layer over the already-shipped `RustBackend::probe()` (§6). Everything else is umbrella-text reconciliation (§3), a field removal (§4), a variant rename (§5.1), a fixture edit (§7), and a CHANGELOG pass (§8).

### §2.1 Locked scope inclusions

Umbrella §4.A.11 enumerates four deliverables (reconcile-per-§7, `[pds_admin.locus]` cleanup, docs incl. §5.4.1-README, required `probe` CLI). Recon confirmed 8 of Nova's 11 ledger items map to those. **Nova commits items 9, 10, 11 in** — source comments explicitly target v1.8.11 (`config.rs:1071-1080` "will be removed in v1.8.11"; `config.rs:1213` names the Inspector rename as v1.8.11-queued), and shipped source is a stronger scope commitment than umbrella silence. v1.8.11 also reconciles umbrella §4.A.11 to enumerate items 9-11 (§10).

Committed set: item 5 (fixture consolidation, §7), item 6 (locus — *keep aid*, §5.2), item 7 (§5.4.1 README, noted in §2.3/§10), item 8 (probe CLI, §6), item 9 (field removal, §4), item 10 (rename, §5.1), item 11 (CHANGELOG, §8) + five Category-A umbrella text edits (§3) + the §7/§11 slip fix (§9).

### §2.2 Non-goals

- **v1.8.10 pre-existing timing flakes** (`serve_binary` sigterm, strike/temp-suspension window) — implementation-side test hygiene per the Aurora-Locus pattern (memory #21); flagged for a future sweep, out-of-scope here.
- **Per-release CHANGELOG rewrite** — the v1.8 series is already humanized (recon §7); no per-entry rewrite, no `[1.8.0]` *aggregate* collapse (subsections preserved — §8).
- **Aggressive locus cleanup** — the deprecation aid is retained (§5.2, LB-3); removal is explicitly a non-goal so no future reader attempts it as "cleanup."
- **The three still-accurate deferred-item CHANGELOG notes** — kept, not pruned (C3, §8.2).
- New capability families, trait methods, migration, config keys, exit codes (wrap-release character).
- Workstream B surfaces; the `[pds_admin.rust.kryphocron]` config block (lands v1.8.12).

### §2.3 Umbrella-vs-source reconciliation categories

- **Category A (§3):** five umbrella *text* reconciliations (items 1-4 + 4b). No code.
- **Category B (§4):** item 9 field removal. Code + tests.
- **Category C (§5):** item 10 variant rename (§5.1) + item 6 locus retention (§5.2, text-only).
- **Category D (§6, §7):** item 8 probe CLI + item 5 fixture consolidation (coordinate — same commit).
- **Category E (§8):** item 11 CHANGELOG.
- Plus item 7 (§5.4.1 verbatim → README, a doc deliverable, §10.1) and the §7/§11 slip (§9).

### §2.4 v1.8.16+ inventory unchanged

Four items carry forward, none added or pulled in at v1.8.11: (1) `accounts batch-restore` CLI (batch-revoke writer design deferred), (2) per-subject batch labels, (3) `stream start`/`stop` subcommands (need an authenticated server-side control endpoint), (4) `runtime_settings_writes` auto-join into `cairn audit cross-verify`. These are the three CHANGELOG "deferred" notes' referents (items 1, 3) plus standing inventory — kept in the CHANGELOG as accurate non-goals (C3).

## §3 — Category A: Umbrella text reconciliations (5 items)

All five are text-only edits to `cairn-mod-v1.8-umbrella-v13.md` (→ v14, or an in-place §4.A.11/§5.2 revision per the umbrella's own revision convention — see §9 for the tracking-location fix that must land first). No cairn-mod code changes. Each aligns umbrella prose to grep-verified shipped source.

### §3.1 AdminServer scope at OAuth-namespace layer
**Umbrella (representative §4.A.N):** "Ops surface auth requires `AdminServer` scope … service DID must hold that role" — framed as an endpoint-level gate.
**Source (`2ffeb1a`):** `AdminServer` is a real gate but at the **OAuth-scope / NSID-namespace layer** — `oauth/scope.rs:831` `const TOOLS_OPS_REQUIRED: &[AtProtoScope] = &[AtProtoScope::AdminServer]` (variant `:84`). Handlers use `AdminAuthContext` (`auth.rs:293-297`, `{did,session,role}`) which resolves a `Role` and does not inspect scope; per-endpoint elevation is role-based (`auth.role.can_act_as(Role::SuperAdmin)`, e.g. `admin.rs:2382-2393`). In `admin.rs`, "AdminServer scope" appears only in comments (`:668`).
**Reconciliation:** describe AdminServer as NSID-namespace-layer OAuth enforcement (`oauth/scope.rs`), with per-endpoint access role-based. **Precision note:** this corrects *both* the umbrella ("endpoint-level gate") *and* the prior-session ledger phrasing ("no enforcement") — the accurate statement is "enforced one layer up." Consumption consequence unchanged: all eight v1.8.10 ops handlers ignore `_auth`, so cairn-mod's degradation posture stands.

### §3.2 Ops capability-model
**Umbrella (§4.A.10 "Capability families consumed"):** "ops-family strings."
**Source:** the consumed core ops block is capability-bare; the only shipped ops extension is `instance-metrics-v1` (v1.8.9) plus out-of-scope kryphocron/themes. No ops-family strings exist to bind for the visibility pool.
**Reconciliation:** align §4.A.10 to the F19 advisory posture (umbrella §5.3): the per-release-doc bound NSID list is the endpoint contract; `describeCapabilities` is advisory. (This was the v1.8.10 design's stance already; the umbrella text is the lagging artifact.)

### §3.3 Ozone stub variant taxonomy (41/2/0)
**Umbrella (§4.A.10):** stubs return `BackendError::CapabilityNotAdvertised`.
**Source (`src/pds_admin/ozone.rs`):** **41** `Unsupported` in the stub impl block; **2** `ArchitecturallyForbidden` (`apply_label` `:692`, `negate_label` `:700`, per §F4); **0** `CapabilityNotAdvertised` (reserved for the Rust backend — `audit.rs:195`).
**Reconciliation:** umbrella stub clause reads `Unsupported`, noting the two §F4 `ArchitecturallyForbidden` exceptions and that `CapabilityNotAdvertised` is Rust-backend-only.

### §3.5 Audit-divergence WARN status (item 4b — added by recon)
**Umbrella (§5.2 / `:88` / `:313`):** the `acknowledge_v1_8_1_audit_divergence` three-gate inspector "stays in force / production-quality enforcement."
**Source:** stale — Part 1 was retired to an **advisory WARN at v1.8.6** (`config.rs:1204-1215` `let _ = &rust.acknowledge_...; // reject-when-false behavior is gone`; parser WARN `:1071-1080`; pinned by `divergence_rust_missing_ack_passes_since_v1_8_6` `:2619`). Parts 2/3 (auto-mode, xrpc-gateway coexistence) remain hard-fail — unrelated to the flag.
**Reconciliation:** umbrella §5.2 describes the field as advisory-WARN-since-v1.8.6 with **removal in v1.8.11** (which item 9 delivers). After item 9 lands, the umbrella's field description is deleted entirely (the field no longer exists), leaving only a historical note.

## §4 — Category B: Item 9 removal

### §4.1 `acknowledge_v1_8_1_audit_divergence` surface enumeration
Full-crate grep at `f3cf7b2` (recon §4.1, re-verified). Removal touches:

**Struct field defs (2):**
- Runtime: `src/pds_admin/config.rs:229` `pub acknowledge_v1_8_1_audit_divergence: bool` (`RustBackendConfig`; doc `:222-228`).
- TOML: `src/config.rs:416` `pub acknowledge_v1_8_1_audit_divergence: Option<bool>` `#[serde(default)]` (`PdsAdminRustToml`; doc `:405-414`).

**Parser/validator:** `config.rs:1071-1080` (deprecation WARN + `.unwrap_or(false)`), `:1134` (struct-literal populate), `:1204-1215` (Part-1 discarded-read vestige).

**Dead error variant (delete outright):** `PdsAdminConfigError::AuditDivergenceAcknowledgmentRequired` (`config.rs:372`, doc `:361`) — **zero construction sites** (grep confirms only the def). Removes without touching call sites.

**Error-STRING edits (variants stay, text changes):** the field name is embedded in the `#[error]` strings of `PolicyAutoModeIncompatibleWithInspectorRustBackend` (`:385`) and `XrpcGatewayIncompatibleWithInspectorRustBackend` (`:397`). These two variants are *also* item 10's rename targets (§5.1) — the string edit and the rename land together (LB-4/LB-5 coordinate in one phase).

**WARN string body:** `src/pds_admin/dispatch.rs:1217` references the field name (remove/reword).

**Fn retained:** `validate_audit_divergence_acknowledgment` (`config.rs:1191`, re-export `mod.rs:54`, call `src/config.rs:1011`, comment `serve.rs:436`) survives — Parts 2/3 are live coexistence gates. Only the Part-1 vestige (`:1204-1215`) is deleted. **Optional fn rename** (e.g. `validate_rust_backend_coexistence`) is a design call; v1 recommends **keep the name** to minimize churn and preserve the call-site/re-export surface — the name is slightly stale but harmless, and renaming ripples to 8+ test sites for cosmetic gain. Flag for R1.

**Docs:** `CHANGELOG.md:256/450/489`; doc-comments `src/config.rs:232/319`, `config.rs:1165`.

### §4.2 Removal phase order
1. Delete both struct field defs (`config.rs:229`, `src/config.rs:416`) + their doc-comments.
2. Delete the dead variant `AuditDivergenceAcknowledgmentRequired` (`config.rs:372` + doc `:361`).
3. Remove the config-validator Part-1 vestige (`config.rs:1204-1215`) — the block collapses to Parts 2/3 only; **coordinate with §5.1** (same two live variants get renamed here).
4. Remove the parser WARN + populate (`config.rs:1071-1080`, `:1134`) and the dispatch WARN string (`dispatch.rs:1217`).
5. Edit the two `#[error]` strings (`:385`, `:397`) to drop the field name — done as part of the §5.1 rename (the strings also carry "InspectorRustBackend").
6. Update the 12 test sites + delete the pin test (§4.3).
7. Full-crate grep for `acknowledge_v1_8_1_audit_divergence` → zero hits (memory #26 completeness gate). Then `cargo test`.

### §4.2-a — Orphaned binding fix during Part-1 removal (S-1)

Item 9's removal deletes `config.rs:1215` (Part-1 field-existence check). This orphans the `let rust = …` binding at `config.rs:1199-1202`, since Parts 2 (auto-mode policy) and Part 3 (xrpc_gateway compatibility) use function parameters directly rather than the local binding.

**Two implementation options:**

**Option A (recommended, minimal churn)**: Keep the binding, add a `matches!(rust, PdsAdminRust { .. })` no-op or equivalent to satisfy the linter without changing behavior. This preserves the binding for future Parts 4+ additions and matches memory #8 v1.8.6 sunset lock's discipline (Parts 2/3 unchanged).

**Option B**: Delete the `rust` binding entirely; refactor Parts 2/3 to re-derive from function parameters. Larger diff, cleaner surface, but changes Parts 2/3 code that memory #8 v1.8.6 sunset lock specified as untouched.

**Recommend Option A** — memory #8 v1.8.6 sunset lock said Parts 2/3 stay live and untouched. Option B rewrites Parts 2/3 for cosmetic linter satisfaction; Option A preserves the shipped structure.

Implementer verifies `cargo clippy --all-features --all-targets -- -D warnings` passes cleanly before proceeding to Phase order step 3 (validator branch removal). If Option A's no-op satisfies clippy, proceed. If not, escalate to Option B with chainlink flag.

### §4.3 Test deletions vs updates
**12 field-reference sites across 5 files** (recon §4.2):
- `config.rs`: `:2121` (`rust_toml()`), `:2426`, `:2457`, `:2480`, `:2492`, `:2553` (`policy_rust(ack)`) — remove field from struct literals / drop the `ack` parameter from `policy_rust`.
- `rust/mod.rs`: `:1913` (`fixture_config()`).
- `tests/rust_backend.rs`: `:133` (`backend_config()`), `:305` (`rust_backend_config_json()` — feeds 5 tests).
- `tests/stream_consumer.rs`: `:227`, `:417`.

**Delete (premise removed with the field):** `divergence_rust_missing_ack_passes_since_v1_8_6` (`config.rs:2619`) — it asserts the *advisory* behavior of a field that no longer exists. **Review/adapt:** the sibling validator tests `:2626/:2632/:2640/:2648/:2661/:2681/:2693` and `tests/rust_backend.rs:350` — those exercising Parts 2/3 (`PolicyAutoMode`/`XrpcGateway`) stay but update to the renamed variants; those exercising Part 1 (the ack flag) delete. R1 verifies the keep/delete split per test.

## §5 — Category C: Item 10 rename + Item 6 locus retention

### §5.1 `InspectorRustBackend` variant renames (2 variants)
All sites in `src/pds_admin/config.rs` (recon §5). Semantic-preserving: enum derives `#[derive(Debug, thiserror::Error, PartialEq, Eq)]` (`:261`) — **no Serialize/Deserialize**, so no wire/JSON/TOML boundary; `#[error]` Display strings don't embed the variant identifier, so Display output is rename-stable; matching is structural.

- `PolicyAutoModeIncompatibleWithInspectorRustBackend` → **`PolicyAutoModeIncompatibleWithRustBackend`**: def `:387`, construct `:1227` (Part 2), test match `:2654`, **test panic-string prefix `:2657`** (`"expected PolicyAutoModeIncompatible…"` — prefix-only; a full-name replace misses it — update manually).
- `XrpcGatewayIncompatibleWithInspectorRustBackend` → **`XrpcGatewayIncompatibleWithRustBackend`**: def `:399`, construct `:1236` (Part 3), test assert `:2689`.
- Rename-tracking comment `:1213` (names the stale naming as v1.8.11-queued) — remove/update.
- The two `#[error]` strings (`:385`, `:397`) drop both "InspectorRustBackend" phrasing **and** the item-9 field name in one edit.
- Editorial prose "Inspector-only"/"inspector-era" (`config.rs:112/1205/2665`, `tests/rust_backend.rs:356`, `CHANGELOG.md:459/481`) — NOT identifiers; leave unless a light editorial pass is in scope (recommend leave; they're historically accurate descriptions of the v1.8.1 posture).

Method: grep-replace-verify on each full identifier + the two manual sites (`:2657` prefix, `:1213` comment). No test *logic* breaks — structural matches auto-update.

### §5.2 Locus deprecation aid retained (LB-3)
**Shipped state (recon §6.2):** `[pds_admin.locus]` has been hard-rejected (not aliased) since **v1.8.1** via `PdsAdminConfigError::LocusBlockRenamed` (`config.rs:400-406`), rejector `reject_unsupported_backend_subsections()` (`:1268-1271`, runs even when `enabled=false`), TOML catch-field `src/config.rs:254`, test `locus_subsection_rejects_as_renamed` (`config.rs:1685-1699`). The umbrella's "partly done, v1.8.11 completes it" (`:207`) is stale.

**Decision: KEEP the deprecation aid.** Six lines cost nothing to maintain and give operators upgrading from v1.7-era configs an actionable rejection ("`[pds_admin.locus]` was renamed to `[pds_admin.rust]` in v1.8.1; move the subsection's contents"). Removing it would let a stray `[pds_admin.locus]` fall through to the `#[serde(flatten)] other_backends` catch-all (`config.rs:262-263`) and be **silently ignored** — a worse operator experience for no meaningful codebase gain. This §5.2 documents the keep decision so future readers don't attempt removal as "cleanup."

**Umbrella item-6 text updates to:** rename shipped v1.8.1 as hard-reject via `LocusBlockRenamed`; v1.8.11 does NOT remove the aid; v1.8.11 reconciles the umbrella text to shipped state.

## §6 — Category D: Item 8 probe CLI

### §6.1 Presentation layer over shipped `RustBackend::probe()`
No new trait method, no wire additions. Backend surface already ships (recon §6.4): trait `probe()` (`backend.rs:1228` → `Result<ProbeReport, BackendError>`), `ProbeReport` (`backend.rs:543-568`: `backend_name`, `pds_url`, `detected_version`, `capabilities: Vec<String>`), RustBackend impl (`rust/mod.rs:1811`: JWT → `describeCapabilities` GET → parse → build `CapabilitySet` → required-capability check → atomic swap into `self.capabilities`), Ozone impl (`ozone.rs:1124`). v1.8.11 adds only: clap variant + dispatch + formatting.

**Probe-call posture:** the shipped `probe()` mutates internal state (swaps the capability set) as a side effect of its startup role (`pds_admin_reads.rs:67`). For a diagnostic command that mutation is harmless (the CLI process is short-lived and does one thing), so v1 **reuses `probe()` as-is** rather than inventing a read-only variant — simpler, no new backend surface. R1 to confirm no ordering hazard (probe is the only backend call in the command).

**Scaffold:** `probe` must run even when the read gate would refuse (its whole purpose is diagnosing capability mismatch). v1 uses a **lighter scaffold than `backend_for_reads`** — policy gate (is `[pds_admin]` enabled + backend resolved?) + construct, but **not** the read-capability gate (the probe IS the capability check). Ozone backend: `probe()` returns a `ProbeReport` with `backend_name="ozone"` and empty/degenerate capabilities — the command reports "probe is a RustBackend diagnostic" honestly rather than erroring. R1 to confirm the Ozone path.

### §6.2 Registry-vs-advertised match report shape
The command diffs the **10 registry entries** (`CAPABILITY_CLASSIFICATIONS`, expected) against the **advertised** set (`ProbeReport.capabilities`, actual). Human format:
- **Upstream identity:** `pds_url`, `detected_version`, `implementation`/`backend_name`.
- **Per-family match table** (10 rows): family name, classification (AutoAdvance / OperatorOptIn), advertised? (✓/✗), advertised version if present.
- **Drift callouts:**
  - Registry-known family **NOT advertised** → warn "upstream does not advertise `<family>` — this cairn-mod release expects it; upstream may predate the capability or have it disabled."
  - Advertised family **NOT in registry** → note "upstream advertises `<family>`, unknown to this cairn-mod release (newer upstream, or an extension cairn-mod doesn't consume)." This is the F19 advisory posture made operator-visible: unknown advertised extensions are tolerated, not errors (the `queue-stats-v1` tolerance case, §11).
- `--json` → raw `ProbeReport` + the computed match structure, untouched.

Never errors on mismatch — a drift report IS the successful output. The only error paths are transport/auth failures from `probe()` itself, mapped per the shipped `map_rust_backend_http_error` (404 → `Terminal` with the F19 hint, 401/403 → `Auth` degradation).

### §6.3 — Probe placement: `cairn pds-admin probe` (S-4 corrected framing)

`cairn pds-admin probe` sits as a peer to `cairn pds-admin ops <subcmd>` under the `cairn pds-admin` group. It's not a subcommand of `ops` because it's diagnostic (introspection of upstream capabilities), not dispatch. It's not under a different top-level group because state introspection commands consistently live under the group that owns the state — `cairn stream status` is under `cairn stream`, `cairn pds-admin probe` is under `cairn pds-admin`.

The v1.8.10 R1 A6 stress-test reasoning applies: dispatch commands to Aurora live under `cairn pds-admin`; state introspection can live at the top of that group rather than nested under a subcommand-specific parent. Both `cairn stream status` and `cairn pds-admin probe` follow this pattern — introspection at the group root, dispatches under domain-specific subcommands.

## §7 — Category D: Item 5 canonical fixture consolidation

### §7.1 4 missing families identified against registry (C1 — corrects kickoff)
Registry (10 families, `types.rs:307-376`): `mod-events-emit`, `moderator-activity`, `subject-context`, `subject-history`, `appeals`, `audit-trail`, `batch-takedown`, `mod-events-stream`, `instance-metrics`, `runtime-settings`.

`canonical_body()` (`tests/rust_backend.rs:62-81`) advertises 6 registered (`mod-events-emit-v1`, `audit-trail-v1`, `batch-takedown-v1`, `mod-events-stream-v1`, `instance-metrics-v1`, `runtime-settings-v1`) + `queue-stats-v1` (unregistered probe).

**Delta — the 4 registered families MISSING (all AutoAdvance):** `moderator-activity`, `subject-context`, `subject-history`, `appeals`. (The kickoff's LB-7 list named six, several already present — corrected here per grep.)

### §7.2 `canonical_body()` update + downstream verification
Add the four `-v1` wire strings — `moderator-activity-v1`, `subject-context-v1`, `subject-history-v1`, `appeals-v1` — to the `extensions` array (bringing it to 10 registered + the `queue-stats-v1` tolerance probe). **Keep `queue-stats-v1`** (C2/§11 — the deliberate unknown-extension case).

**Downstream test verification (memory #26):** grep every consumer of `canonical_body()` and every test asserting a specific advertised-set shape or a family's *absence*. Known consumers: `spawn_audit_mock` (`rust_backend.rs:1933`, reuses it) and the probe end-to-end test (§12.3). Any test asserting "family X not advertised" against `canonical_body()` breaks and updates. Secondary fixtures (`rust_backend.rs:752-760`, `:1047-1059` parameterized, `stream_consumer.rs:134-143`) are unaffected — they build their own advertisement.

**Coordination (LB-6 ↔ LB-7):** item 5 + item 8 land in the **same commit** — the probe end-to-end "all-match" scenario requires `canonical_body()` to advertise all 10 registered families, else the match report can't be tested against a fully-advertised upstream.

## §8 — Category E: CHANGELOG humanization

Narrow, recon-confirmed (recon §7): the whole v1.8 series is already humanized prose under one `## [Unreleased]` block; there is **no "Deferred" heading** (only 3 inline mentions). v1.8.11's pass is promotion + a light consistency sweep — **not** a per-entry rewrite, **not** a `[1.8.0]` aggregate collapse (subsections stay).

### §8.1 `[Unreleased]` → dated section (C4 — tag deferred)
Promote `## [Unreleased]` to a dated release section, **preserving the `### Added — v1.8.N` subsections verbatim underneath** (this satisfies the kickoff's "no aggregate restructure" — subsections are kept, not merged).

**Open decision (deferred to the release step — Nova, this session):** the dated header + git tag. Evidence points at **`## [1.8.0] - <date>` + tag `v1.8.0`**: the repo tags minor-only (`v1.7.0`, `v1.6.0`; no patch tags), and memory #28 says "v1.8 ships as one release." The kickoff's literal "[1.8.11]" conflicts with both. v1 **records the conflict + recommends `[1.8.0]`** but leaves the final header/tag to `/dev-release` at release time — the CHANGELOG content work (subsection preservation, consistency) is tag-independent and proceeds regardless.

### §8.2 The 3 "deferred" mentions — KEEP (C3 — corrects kickoff)
The kickoff's "prune 3 inline 'deferred' mentions" is corrected: all three are **still-accurate** forward-looking non-goals, not stale cruft.
- `CHANGELOG.md:149` — `stream start`/`stop` deferred (need an authenticated server-side control endpoint) → live v1.8.16+ inventory item 3. **Keep.**
- `:207` — `accounts batch-restore` / batch-revoke writer deferred → live inventory item 1. **Keep.**
- `:310` — per-method bsky-PDS-admin mappings deferred past v1.8 → accurate. **Keep.**

Pruning these would delete real non-goal documentation that maps to §2.4's carried-forward inventory. Keep-a-Changelog tolerates "not shipped / deferred" notes; they stay as-is.

### §8.3 Consistency pass exemplars
Light sweep only: verb-tense uniformity, wrap width (~62 cols), heading style, cross-ref anchor format — using the existing v1.8.9/v1.8.10 sections as exemplars (all sections are already at that level; this is polish, not rewrite).

## §9 — Umbrella §11 vs §7 revision-tracking slip

Recon caught an umbrella-internal inconsistency: §4.A.11 `:206` says umbrella revision tracking "follows **§7**"; `:445` says "Umbrella revisions are tracked in **§11 (CHANGELOG)**." §7 is the open-items/reconciliation section; §11 is the umbrella's own changelog. **Resolution: §11 wins** (the umbrella's cross-section convention records revisions in its §11 changelog; the §7 reference at `:206` is draft-era leftover). v1.8.11's umbrella edit corrects `:206` to reference §11. **This fixes the *pointer* only; the §3 Category-A reconciliations and §10 additions are themselves recorded per the corrected §11 convention.** Trivial, but it lands first so the subsequent umbrella edits have a coherent tracking home.

## §10 — v1.8.11 umbrella additions

All umbrella edits are text-only, landing as v1.8.11's documentation work. Recommend a fresh umbrella revision (v14) rather than in-place edits to the locked v13, recorded in the umbrella's §11 changelog per §9.

### §10.1 Items 9/10/11 + item 7 enumerated in §4.A.11
§4.A.11 gains explicit enumeration of items 9 (field removal), 10 (variant rename), 11 (CHANGELOG pass) alongside items 5-8, each with shipped-state/deferral history + v1.8.11 delivery. This closes the umbrella-vs-source scope drift. Also: item 7 (the §5.4.1 threat-model statement shipped **verbatim in the README**) is a committed §4.A.11 deliverable — the design notes it as a doc task (copy umbrella `:361-369` into the README's operator section; per-release docs cite §5.4.1). **Caveat:** the statement describes Workstream-B decode behavior not live until v1.8.12+ — frame it as a pre-announcement (operators encounter the threat model "before configuring Workstream B"), not as describing a live v1.8.11 code path.

### §10.2 5 text reconciliations landed
The §3 Category-A edits (AdminServer OAuth-layer, ops capability-bare/F19, Ozone 41/2/0 taxonomy, endpoint count 54, audit-divergence advisory-WARN-then-removed) land in the umbrella, each citing the grep-verified source line. Item 4b's field description is deleted post-item-9 (field gone).

## §11 — Non-goals + `queue-stats-v1` disposition

Non-goals restated: §2.2 (timing flakes, per-release rewrite, aggressive locus cleanup, deferred-note pruning) + no new families/trait/migration/config/exit-codes.

**`queue-stats-v1` disposition (C2 — resolves recon's open question):** grep shows only test-artifact references — `types.rs:924-925` uses `queue-stats-v3` as a **version-parse test vector** (`assert_eq!(set.version_of("queue-stats"), Some(CapabilityVersion(3)))`), and `canonical_body()` carries `queue-stats-v1` as a deliberate **unknown-extension-tolerance probe**. It is **not** a registered capability, **not** a trait method, **not** a deferred feature, and **not** umbrella speculation — it is an intentional test string exercising "advertised-but-unregistered extension is tolerated, not errored" (the F19 posture the probe command surfaces, §6.2). **Disposition: KEEP in `canonical_body()`; add NOT to the v1.8.16+ inventory; NO umbrella drop.** §7.2 documents the intent so it isn't "consolidated away" during the fixture edit.

## §12 — Test coverage plan

### §12.1 Item 9 removal regression
- Delete `divergence_rust_missing_ack_passes_since_v1_8_6` (`config.rs:2619`).
- Update 12 field-reference sites (§4.3); the Parts-2/3 validator tests stay (retargeted to the renamed variants).
- Full-crate grep `acknowledge_v1_8_1_audit_divergence` → 0 hits.
- New: a parse test confirming a config carrying the (now-removed) field key is **ignored** via `#[serde(deny_unknown_fields)]` absence / catch-all — i.e. an old config with the stale key still boots (the field silently drops, no hard error), preserving upgrade smoothness. (Verify the TOML struct's unknown-field posture at draft-review; if it rejects unknown keys, that's a migration hazard R1 must catch.)

### §12.2 Item 10 rename verification
- Renamed-variant construction + match tests (`config.rs:2654/2689`) pass under new names.
- `#[error]` Display strings updated (no longer contain "InspectorRustBackend" or the item-9 field name); if any test asserts on Display text, update — recon found none, verify.

### §12.3 probe CLI end-to-end (LB-6 + LB-7 coordinate)
- **All-match:** probe against `canonical_body()` (now advertising all 10) → report shows 10/10 advertised, no drift. *Requires §7 fixture consolidation — same commit.*
- **Registry-known-not-advertised:** probe against a fixture missing one registered family → drift warn for that family.
- **Advertised-not-in-registry:** probe against `canonical_body()`'s `queue-stats-v1` → "unknown to this release" note, tolerated (no error).
- **`--json`:** raw `ProbeReport` + match structure.
- **Placement:** `pds-admin probe` parses; not under `ops`.
- **Ozone:** `probe` on Ozone backend degrades honestly (no panic, no error — reports RustBackend-diagnostic nature).
- **Transport:** 404 → `Terminal` + F19 hint; 401/403 → `Auth` degradation.

### §12.4 Full lib suite regression (memory #22 close gate)
Full `cargo test` green; fmt + clippy + `RUSTDOCFLAGS="-D warnings" cargo doc` (memory #20/#13 pre-commit QA unit); registry/trait pinned tests unchanged at 10/48.

## §13 — Ready-for-implementation checklist
- [ ] Branch off `f3cf7b2`; implementation chainlink open.
- [ ] cairn-mod re-verified at HEAD: item-9 surface (2 fields, dead variant, 12 tests + 1 delete), item-10 sites (2 variants in `config.rs`, `:2657` prefix, `:1213` comment), `canonical_body()` 6+1 → target 10+1, `probe()`/`ProbeReport` shapes, `PdsAdminSub` for the `Probe` slot, TOML unknown-field posture (§12.1).
- [ ] Aurora re-verified at `2ffeb1a` for the §3 Category-A source citations (`oauth/scope.rs:831`, `admin.rs` role checks, ops route count 54, Ozone 41/2/0).
- [ ] Umbrella §11-vs-§7 slip fix scoped first (§9).
- [ ] Firewall grep on this doc: clean.

## §14 — Post-implementation checklist
- [ ] Field gone (full-crate grep 0 hits); old config with stale key still boots.
- [ ] Variants renamed; Display strings clean; Parts 2/3 gates still hard-fail.
- [ ] Locus aid retained + documented (§5.2); `[pds_admin.locus]` still hard-rejects.
- [ ] `cairn pds-admin probe` renders match report + `--json`; end-to-end tests green.
- [ ] `canonical_body()` advertises 10 + `queue-stats-v1`; downstream fixtures verified.
- [ ] CHANGELOG promoted (header/tag per release-step decision), 3 deferred notes retained, consistency pass done.
- [ ] Umbrella v14: §4.A.11 enumerates items 5-11; 5 Category-A reconciliations + §11/§7 fix landed; §5.4.1 verbatim in README.
- [ ] Full `cargo test` + fmt/clippy/rustdoc gates green.
- [ ] CHANGELOG hand-written; chainlink closed `--no-changelog`.

## §14a — R1 folds applied (S-3, §5.3, M-1..M-3)

**S-3 — CHANGELOG 3-line keep rationale, per-line:** stream start/stop and batch-revoke lines map to real v1.8.16+ inventory items (forward-looking non-goals); the per-method Ozone/bsky-PDS-mappings line (`:310`-era) does NOT map to inventory — it is an accurate historical note about shipped design. All three retained; pruning any would delete real documentation. Exact line numbers verified at implementation time.

**§5.3 — `validate_audit_divergence_acknowledgment` name: KEEP (R1-open verdict).** 18 reference sites of pure cosmetic churn against a non-misleading name (Parts 2/3 are live gates). Doc-comment at `config.rs:1159-1190` refreshed: strip the Part-1 description (`:1165`) and every `acknowledge_v1_8_1_audit_divergence` mention; retain Parts 2/3 semantics.

**M-1 — §5.1 precision:** the two `#[error]` strings (`:380-386`, `:393-397`) never contained the token `InspectorRustBackend` — their only needed edit is dropping the stale field-name sentence (item 9). The variant-identifier rename does not touch Display text.

**M-2 — item-9 site-count precision:** 10 struct-literal compile-breaks (`config.rs:2121/2426/2457/2480/2492/2553`, `rust/mod.rs:1913`, `tests/rust_backend.rs:133`, `tests/stream_consumer.rs:227/417`) + 1 non-breaking `json!`-key site (`tests/rust_backend.rs:305`, silently ignored — no `deny_unknown_fields`) + 1 pin-test deletion (`divergence_rust_missing_ack_passes_since_v1_8_6`).

**M-3 — sixth stale umbrella line (optional fold, taken):** umbrella `:89` claims Ozone's `CapabilityNotAdvertised` "gains its first producer here" — stale; Ozone has 0 such returns and the variant is Rust-backend-produced. Folded into the §3.3 reconciliation edit.

## §15 — Revision log

**v2 (this draft).** Post-CC-adversarial R1 fold (chainlink #158). R1 verdict: 5-agent verification with 0 LB, 4 S, 3 M. All four drafting-time corrections C1–C4 HELD (C3 held-with-rationale-caveat, refined per S-3). R1-open verdict on `validate_audit_divergence_acknowledgment` name: KEEP. Scope-creep guard clean.

Ship signal per memory #12: 0 LB → fold-and-lock. All S + M findings folded; no R2 required.

**R1 S-1 fold**: §4.2 gains explicit orphaned-binding fix instruction for Part-1 removal. `let rust` binding at `config.rs:1199-1202` becomes unused when `config.rs:1215` is deleted. Option A (recommended): keep binding + `matches!` no-op. Option B (escalation-only): delete binding + refactor Parts 2/3.

**R1 S-2 fold**: §3.4 endpoint count reconciliation removed. Umbrella's 55 already matches shipped source (55). Category A shrinks from 5 items to 4 (§3.1, §3.2, §3.3, §3.5).

**R1 S-3 fold**: §8.2 C3 rationale corrected. Not "all 3 map to inventory" — line Z (`:310`, per-method Ozone/bsky-PDS mappings) is accurate historical note about shipped design, not deferred work. Keep decision preserved; rationale differs per-line.

**R1 S-4 fold**: §6.3 probe placement framing corrected. "Top-level" replaced with accurate "sibling to `cairn pds-admin ops`". `cairn stream status` precedent shows introspection at group root, dispatches under domain-specific subcommands — pattern applies to `cairn pds-admin probe`.

**R1 M-1..M-3 folds**: three minor folds per R1 report's §Minor findings, transcribed at implementation-time application.

**R1-open verdict fold**: §5.3 adds `validate_audit_divergence_acknowledgment` KEEP verdict + doc-comment refresh instruction.

**Design decisions locked at v2:**
- All nine LB kickoff decisions hold.
- Category A: 4 umbrella text reconciliations (not 5 per S-2).
- Item 9 removal preserves `rust` binding via `matches!` no-op (S-1).
- CHANGELOG 3-line keep rationale is per-line (S-3).
- `cairn pds-admin probe` is sibling to `cairn pds-admin ops` (S-4).
- `validate_audit_divergence_acknowledgment` name retained; doc-comment refreshed.
- Scope-creep guard clean: trait 48, registry 10, no migration, no `Cargo.toml`, no adjacent cleanup.
- All four drafting-time corrections C1–C4 held.
- v1.8.16+ inventory unchanged.

**v1 (superseded).** Initial draft. See git history if needed.

Pending: implementation kickoff.

**M-fold transcription note:** the folds document carried M-1..M-3 as placeholders; transcribed verbatim from the R1 report §Minor findings at application time (see §14a).

