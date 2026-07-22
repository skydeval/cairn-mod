# cairn-mod v1.8.10 operator extensions — design v1

**Status:** Draft v2. R1 folded (chainlink #154); locked pending implementation kickoff.

- cairn-mod HEAD: `dec3eb0` (`skydeval/v1.8.9-ops-runtime`, unpushed)
- Aurora-Locus HEAD: `2ffeb1a` (`skydeval/v0.11-cycle`)
- Recon: `docs/internal/recon/v1.8.10-operator-extensions-recon.md` (chainlink #152)
- Design chainlink: #153

## §1 — Process context + memory locks

Umbrella §4.A.10 scope (operator extensions — outbound visibility reads), recon #152 ground truth. Straight to CC-adversarial after drafting. Sourcing per memory #6 + corollaries; the verbatim-copy discipline has exactly one object in this release (§3.3) — seven of eight upstream responses are handler-internal `json!` bodies with no struct to copy, and §3.2 documents that posture explicitly so nobody "fixes" it later. Firewall applies.

## §2 — What v1.8.10 is

Eight read-only `tools.aurora.ops.*` visibility endpoints consumed outbound (trait 40 → 48), dispatched through a new gate-less `dispatch_ops_read` primitive (the pool is capability-bare), rendered by a new `cairn pds-admin ops` CLI subgroup (nine subcommands: eight new + `metrics` migrated in). No migration, no registry change, no config change.

### §2.1 Locked decisions (kickoff LB-1..7 + subsidiary), with source-wins corrections

All seven LB decisions hold. **Three small corrections (A1–A3), flagged on #153:**

- **A1 (error mapping)**: the kickoff's "other 4xx → `Validation`" row doesn't match the shipped mapper. v1.8.10 reuses `map_rust_backend_http_error` **unchanged**: 400/422 → `Validation`; 401/403 → `Auth`; 404/409/410 → `Terminal`; 429 → `Transient` (RateLimited marker); 5xx → `Transient`; anything unclassified → `Transient`. No endpoint-specific mapping exists or is added (§8).
- **A2 (mirror home)**: `FederationStatusResponse` lives in the existing `src/pds_admin/rust/ops_types.rs` — the ops mirror module v1.8.9 placed public precisely for v1.8.10 reuse — not a new module (the kickoff's "new module" phrasing predates checking the module's charter).
- **A3 (stub arithmetic)**: eight new Ozone stubs (the kickoff's "18 total, up from 17" miscounts; the running total is bookkeeping trivia with no design impact — the commitment is simply `Unsupported` ×8 per the shipped convention).

Locked as kicked off: the eight picks with `runHealthChecks` excluded (LB-1); gate-less `dispatch_ops_read<T>` as a **sibling** of `dispatch_moderator_read`, not a merge (LB-2); `serde_json::Value` pass-through for the seven untyped responses (LB-3 — the correctness posture, same discipline as v1.8.9's key pass-through); trait 40 → 48 (LB-4); byte-verbatim `FederationStatusResponse` (LB-5); **registry stays at 10** with the cadence-break documented (LB-6); `cairn pds-admin ops` subgroup with `metrics` migrating in as a direct rename, no alias (LB-7, the v1.8.9 R1 A6 caveat activating on cue). Subsidiary: no Cargo/migration/exit-code/registry/fixture changes; F19 honesty in the CLI's unavailability message; per-endpoint human formatters with raw-JSON fallback.

### §2.2 Non-goals

- `runHealthChecks` — out of scope on **verb + primitive-scope discipline** (S-2 softened): it is POST, outside `dispatch_ops_read`'s GET scope; the handler is side-effect-free (SELECT 1 + existence probes, no writes — R1-verified), so the exclusion does NOT rest on state mutation. Future active-probe consumption would need a `dispatch_ops_probe<T>` sibling.
- Every umbrella-excluded mutating ops endpoint (list restated verbatim in §9 from §4.A.10) and the ops blob-quarantine trio.
- `ops.kryphocron.*` (Workstream B) and `ops.themes.*`.
- Inbound HTTP console API / TUI (Shape A/B — ruled out at recon §2.2).
- New capability registry entries, fixtures, migrations (LB-6; §7).
- Local enumeration of expected-available endpoints — availability is wire-discovered (F19).
- Automated cross-verify integration (no writes exist in this release).
- No push.

### §2.3 Umbrella-vs-source divergences (v1.8.11 reconciliation)

1. **Capability-bare pool**: §4.A.10's "ops-family capability strings" — 55 of 56 ops routes ship `CapsBuilder::new(Family::Ops)` with no extensions (`getInstanceMetrics` is the sole exception, consumed v1.8.9). The per-release-doc NSID list is the endpoint contract; `describeCapabilities` is advisory (the umbrella's own F19 posture, now load-bearing).
2. **Pool count**: 56 at HEAD vs the umbrella's 55 (trivia).
3. **Ozone stub variant**: umbrella says `CapabilityNotAdvertised`; the settled shipped convention (every stub v1.8.3 → v1.8.9) is `Unsupported`. Follow shipped.
4. (Standing from v1.8.9/v1.8.10 recons:) "AdminServer scope" is not a shipped gate — all eight candidate handlers take `_auth: AdminAuthContext` unused; degradation posture retained for future upstream tightening.

## §3 — Aurora surfaces consumed

### §3.1 The eight endpoints

All GET, no query params, `Family::Ops` capability-bare routes (route-block pattern verbatim in recon §4.2), handlers in Aurora `admin.rs`, **no role floor in any handler** (`_auth` unused — grep of all eight signatures, recon §4.3):

| NSID | Handler @ `admin.rs` | Response |
|---|---|---|
| `tools.aurora.ops.getSystemHealth` | `:8034` | `Value` |
| `tools.aurora.ops.getDatabaseStatus` | `:8077` | `Value` |
| `tools.aurora.ops.getResourceUsage` | `:8127` | `Value` |
| `tools.aurora.ops.getVersionInfo` | `:8312` | `Value` |
| `tools.aurora.ops.getSystemMetrics` | `:8333` | `Value` |
| `tools.aurora.ops.getBlobStatistics` | `:8447` | `Value` |
| `tools.aurora.ops.getSequencerStatus` | `:8831` | `Value` |
| `tools.aurora.ops.getFederationStatus` | `:9433` | `FederationStatusResponse` |

### §3.2 The seven `Value` responses — pass-through rationale

These handlers return `Json<serde_json::Value>` built from inline `serde_json::json!` blocks — **snake_case keys, no contract structs, no serde derives to copy** (memory #31 has no object). Observed key sets at `2ffeb1a`, for the *formatters* only (never for validation):

- `getSystemHealth`: `status`, `version`, `uptime_seconds`, `services{database, sequencer, relay, federation}`, `active_http_requests`, `active_sessions`.
- `getDatabaseStatus`: `status`, `pool{size, idle_connections, active_connections}`, `latency_ms`, `statistics{total_accounts, active_sessions}`.
- `getResourceUsage`: `memory{resident_bytes, resident_mb}`, `cpu{seconds_total}`, `file_descriptors{open}`.
- `getVersionInfo`: `version`, `service_did`, `hostname`, `port`, `rust_version`, `build_profile`, `features{federation, invites_required, rate_limiting, email}`.
- `getSystemMetrics`: `uptime_seconds`, `http{…}`, `database{…}`, `cache{hits, misses, hit_rate_percent}`, `sequencer{current_sequence, events_total, events_received}`, `accounts{total}`, `relay{connection_status}`.
- `getBlobStatistics`: per-`mime_type` `count` aggregation.
- `getSequencerStatus`: assembled dynamically (`:8831+`); rendered via the generic fallback.

**Posture (LB-3):** the trait returns the parsed `Value` verbatim. Fabricated typed mirrors would break on any upstream field tweak and would be schema fabrication, not mirroring. This is the v1.8.9 LB-5 discipline applied to response bodies: cairn-mod does not own these schemas, so it forwards them with fidelity. Formatters (§6.3) are pure functions doing field-presence checks — a missing/unknown field falls through to pretty-printed JSON, never errors.

### §3.3 `FederationStatusResponse` (LB-5) — the one typed mirror

**Fields verbatim, copied from source at `2ffeb1a`** (`admin.rs:9408-9428`; doc-comments elided per convention). **LB-1 correction: the wire is camelCase** — Aurora's struct carries `#[serde(rename_all = "camelCase")]` (v1 recorded snake_case because the recon grep started at the struct line and missed the attributes above it):

```rust
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FederationStatusResponse {
    enabled: bool,
    service_did: String,
    relay_count: usize,
    relay_connected: bool,
    discovery_enabled: bool,
    search_enabled: bool,
    known_instances: usize,
    status: String,
}
```

cairn-mod mirror (in `ops_types.rs` per A2): same field names, `#[serde(rename_all = "camelCase")]` **mandatory** (without it every field lookup fails against the real wire — `serviceDid`, `relayCount`, `relayConnected`, `discoveryEnabled`, `searchEnabled`, `knownInstances`), and the D-1 substitution `usize` → `u64` with the field-adjacent comment (`// u64 not usize: wire is width-agnostic; JSON numbers don't carry platform width`).

**Wire-form pinning**: Aurora's struct derives **`serde::Serialize` only** (server-side response type; the folds document's `#[derive(Debug, Deserialize)]` sketch was a typo — corrected against source, flagged on the implementation chainlink). cairn-mod's mirror derives both `Serialize` and `Deserialize` for module consistency with every other `ops_types.rs` mirror (Deserialize consumes the wire; Serialize powers `--json` re-emission).

### §3.4 Capability posture in the core admin ops block (S-1 narrowed) + F19

The eight endpoints v1.8.10 consumes register as `CapsBuilder::new(Family::Ops)` with no extension strings — verified in the **core admin ops block at `admin.rs:233-462`**, where all eight picks live. Across the full `tools.aurora.ops.*` namespace, 15 endpoints DO carry capability extensions (kryphocron ×13, themes, instance-metrics) — outside the picked block. The gate-less `dispatch_ops_read<T>` (LB-2) is justified for the picked-endpoint set specifically, not by a namespace-wide capability-bare claim; future consumption of gated ops endpoints routes through `dispatch_moderator_read` or extends the primitive with an optional capability parameter (not v1.8.10 scope).

No pins, no gates, no registry entries for the picked set: availability is discovered at the wire (404 → `Terminal`). `describeCapabilities` remains advisory for this block (umbrella §5.3 verbatim posture: "the actual endpoint enumeration comes from the per-release-doc bound NSID list, not from `describeCapabilities` parsing alone"). The probe still runs at CLI-scaffold startup for the *other* gated surfaces; nothing here reads its result.

## §4 — Trait additions (40 → 48)

### §4.1 Signatures

```rust
/// v1.8.10 ops visibility reads — all capability-bare upstream
/// (no gate; availability is wire-discovered per F19). Seven
/// return the upstream's ad-hoc JSON verbatim (§3.2); Ozone:
/// Unsupported.
async fn get_system_health(&self) -> Result<serde_json::Value, BackendError>;
async fn get_sequencer_status(&self) -> Result<serde_json::Value, BackendError>;
async fn get_federation_status(&self) -> Result<FederationStatusResponse, BackendError>;
async fn get_blob_statistics(&self) -> Result<serde_json::Value, BackendError>;
async fn get_database_status(&self) -> Result<serde_json::Value, BackendError>;
async fn get_resource_usage(&self) -> Result<serde_json::Value, BackendError>;
async fn get_version_info(&self) -> Result<serde_json::Value, BackendError>;
async fn get_system_metrics(&self) -> Result<serde_json::Value, BackendError>;
```

### §4.2 Dispatch
All eight bodies are one-liners over `dispatch_ops_read` (§5). Consts: eight `OPS_*_NSID` items in `rust/mod.rs` per the house pattern.

### §4.3 Ozone
Eight `Err(BackendError::Unsupported)` stubs — the shipped convention for the majority of Ozone's stubs; the two shipped exceptions (`apply_label`/`negate_label` → `ArchitecturallyForbidden` per §F4) are label-surface territory unrelated to ops reads and unchanged here (M-3). Both dispatch.rs test mocks extend with `unimplemented!` stubs.

## §5 — `dispatch_ops_read<T>` (LB-2)

### §5.1 Signature + semantics

```rust
/// Gate-less ops-namespace GET dispatch (v1.8.10 §5): the
/// tools.aurora.ops.* visibility pool is capability-bare (no
/// extension strings ship on those routes), so the
/// capability-gated read helper cannot carry it. Same JWT →
/// GET → error-map → parse pipeline as dispatch_moderator_read,
/// minus the capability check; availability is wire-discovered
/// (404 → Terminal) and describeCapabilities stays advisory (F19).
async fn dispatch_ops_read<T>(
    &self,
    nsid: &'static str,
    query: Option<&[(&str, &str)]>,
) -> Result<T, BackendError>
where
    T: serde::de::DeserializeOwned,
{ /* mint JWT → GET (+ optional query pairs) → map → parse */ }
```

`query` is `None` for all eight v1.8.10 call sites; the parameter exists so a future ops read with params doesn't fork a third primitive.

### §5.2 Error mapping
The shipped `map_rust_backend_http_error`, unchanged (A1): 401/403 → `Auth`; 400/422 → `Validation`; 404/409/410 → `Terminal`; 429 → `Transient` (RateLimited marker); 5xx/unclassified → `Transient`. The 404 → `Terminal` case is the F19 "endpoint not shipped at this upstream" signal (§6.4).

### §5.3 Coexistence (S-1 scoped)

Sibling primitives with a clear semantic split:
- `dispatch_moderator_read`: gated-family reads (capability advertisement + OperatorOptIn pinning per classification).
- `dispatch_ops_read<T>`: capability-bare reads within the core admin ops block; F19-adjacent 404-discovery for availability.

Future work may extend `dispatch_ops_read` with an optional capability parameter for the gated ops endpoints outside the core block (kryphocron, themes), unifying the two; v1.8.10 keeps them separate — sibling primitives with clear scope beat premature generalization.

## §6 — CLI subgroup (LB-7)

### §6.1 Structure

`cairn pds-admin ops <sub>` — nine subcommands, all `[--json]`:

| Subcommand | Trait method |
|---|---|
| `metrics` | `get_instance_metrics` (migrated from `cairn pds-admin metrics`) |
| `health` | `get_system_health` |
| `sequencer` | `get_sequencer_status` |
| `federation` | `get_federation_status` |
| `blobs` | `get_blob_statistics` |
| `database` | `get_database_status` |
| `resources` | `get_resource_usage` |
| `version` | `get_version_info` |
| `system-metrics` | `get_system_metrics` |

All ride the `backend_for_reads` scaffold (policy gate + construct + probe). Note `blobs` here is a *read* inside the `ops` subgroup — the existing `cairn pds-admin blobs` action group is untouched (clap disambiguates by nesting; the design accepts the name reuse as natural language, R1 may bounce to `blob-stats`).

### §6.2 `metrics` migration
`PdsAdminSub::Metrics` moves into the new `PdsAdminOpsSub` enum; the old path is **removed** (direct rename, no alias, no deprecation shim — v1.8 ships as one release with no public users). §10.7 pins both directions.

### §6.3 Formatters
Per-endpoint human renderers as pure functions over the `Value`: format known fields (the §3.2 key sets), and for anything unrecognized (or the whole body on shape surprise) fall through to `serde_json::to_string_pretty`. Never error on a missing field; never zero-fill. `federation` renders the typed mirror. `--json` always emits the raw body.

**Formatter key-set verification (M-1)**: at implementation time, capture each endpoint's observed key set against the mock bodies; `getBlobStatistics` and `getSequencerStatus` specifically need their formatter recognition aligned with observed keys (sequencer's body is dynamically assembled). Unrecognized keys fall through to pretty-JSON — correct pass-through, suboptimal presentation; implementer's discretion to expand coverage. Key sets remain formatter-only, never validation.

### §6.4 F19 unavailability message
On `Terminal` from a 404, the CLI appends: `this upstream does not ship <nsid>; endpoint availability varies by PDS version — check tools.aurora.describeCapabilities output and your Aurora release notes`. On `Auth`, the standard degradation message (role floors may appear upstream later; §2.3 item 4).

## §7 — Registry unchanged (LB-6)

### §7.1 No additions
Registry stays 10 entries; pinned test unchanged; canonical fixtures stay 7 strings; no `pinned_versions` interaction (`require_opt_in` has no object here).

### §7.2 The cadence break, documented
v1.8.6 → v1.8.9 each added registry entries; v1.8.10 adds none **because the consumed surface advertises nothing** — 55 of 56 ops routes are capability-bare. This is deliberate fidelity to source, not an oversight; the umbrella's "ops-family strings" line is the artifact to fix (v1.8.11), not this design.

## §8 — Error mapping

Single table for all eight endpoints — the shipped mapper verbatim (§5.2 / A1). No per-endpoint special cases; no new variants; no new exit codes. Auth failures degrade per-section in any future combined view; in v1.8.10's per-endpoint subcommands they surface directly.

## §9 — Non-goals

§2.2 restated with the umbrella's exclusion list verbatim: "`pauseSequencer`, `resumeSequencer`, `resetSequencerCursor`, `rebuildSequencer`, `triggerPdsDiscovery`, `cleanupNonceStores`, `runBlobGC`, federation-peer mutations, relay-URL mutations" — plus `quarantineBlob`/`restoreBlob`/`deleteBlob` (ops trio), `runHealthChecks` (POST active probe — the visibility/action boundary), kryphocron/themes sub-namespaces, Shape-A/B console forms, registry additions, and local endpoint-availability enumeration.

## §10 — Test coverage plan

1. **Unit (primitive)**: `dispatch_ops_read` happy path; 404 → `Terminal`; 401/403 → `Auth`; 429 → `Transient` with marker; 5xx → `Transient`. No capability gate exercised (none exists).
2. **Unit (mirror)**: `FederationStatusResponse` deserializes cleanly from the **camelCase** wire body (`{"serviceDid": …, "relayCount": …}`) — the positive-path pin (LB-1 inverted v1's backwards polarity); extra-field tolerant; a snake_case body must FAIL field lookup (pins the `rename_all` attribute).
3. **Unit (pass-through)**: one representative `Value` endpoint returns the body verbatim (round-trip equality).
4. **Unit (formatters)**: known-field rendering for two representative endpoints; unknown-shape body falls through to pretty JSON without error.
5. **Integration (mock Aurora)**: all eight endpoints against canned bodies (the §3.2 key sets); `federation` through the typed mirror.
6. **Integration (availability)**: one endpoint mocked 404 → `Terminal` + the F19 CLI hint text.
7. **CLI**: `pds-admin ops` parses all nine; `pds-admin metrics` (old path) no longer parses (§6.2 both directions); `--json` raw output.
8. **Regression**: full `cargo test` (memory #24); registry/fixture pinned tests unchanged at 10/7.

## §11 — Ready-for-implementation checklist

- [ ] Branch off `dec3eb0`; implementation chainlink open.
- [ ] Aurora re-verified at `2ffeb1a`: eight routes GET + capability-bare (`admin.rs:230-300`, `:340-400`), eight handler signatures with `_auth` unused (`:8034/:8077/:8127/:8312/:8333/:8447/:8831/:9433`), `FederationStatusResponse` byte-identical (`:9411-9428`), `runHealthChecks` POST (`:283`).
- [ ] cairn-mod re-verified at HEAD: trait = 40; registry = 10 + pinned test; fixtures = 7 strings; `map_rust_backend_http_error` rows; `ops_types.rs` pub with both derives; highest migration 0013; `backend_for_reads` scaffold.
- [ ] Canonical fixture reference (M-4): the 7-string advertised set lives in the mock harness `tests/rust_backend.rs` `canonical_body()` (~:62), NOT `src/pds_admin/types.rs` (which holds the registry pinned test). v1.8.10 modifies neither.
- [ ] Firewall grep on this doc: clean.

## §12 — Post-implementation checklist

- [ ] Old `pds-admin metrics` path gone; `ops metrics` renders identically.
- [ ] Full `cargo test` green; fmt/clippy/rustdoc/release gates.
- [ ] CHANGELOG hand-written; chainlink closed `--no-changelog`.
- [ ] v1.8.11 reconciliation notes filed (§2.3's four items).

## §13 — Revision log

**v2 (this draft).** Post-CC-adversarial R1 fold (chainlink #154). R1 verdict: 30+ verifications with 1 LB, 2 S, 3 M. All three source-wins corrections A1–A3 HELD. Both flagged deviations D-1 (u64 for usize) and D-2 (ops blobs naming) HELD. Ship signal per memory #12: 1 LB → fold-and-lock. All findings folded; recommendation → straight to implementation kickoff, no R2.

**R1 LB-1 fold**: `FederationStatusResponse` mirror gains `#[serde(rename_all = "camelCase")]` per Aurora source at `admin.rs:9410`. Test §10.2 polarity inverted to positive-camelCase-deserialize assertion. Wire-form pinning paragraph added. D-1's u64-for-usize substitution folds into the same struct definition.

**R1 S-1 fold**: §3.4 narrows "capability-bare pool" claim from namespace-wide to the core admin block at `admin.rs:233-462`. The gate-less `dispatch_ops_read<T>` primitive rationale still holds for the picked-endpoint set. §5.3 documents sibling-primitive coexistence with explicit scope; future work may extend for gated ops endpoints outside the core block.

**R1 S-2 fold**: §9.1's `runHealthChecks` exclusion rationale softened. Exclusion rests on POST verb + primitive-scope, not state mutation (handler confirmed side-effect-free per R1 verification). Future active-probe consumption would need `dispatch_ops_probe<T>` sibling primitive.

**R1 M-1 fold**: §6.3 addition — formatter key-set verification at implementation time for `getBlobStatistics` and `getSequencerStatus`. Recorded key sets remain formatter-only, never validation (Value pass-through discipline preserved).

**R1 M-2 fold**: `ops_types.rs` inventory references corrected from 7 to 8 types (`RuntimeSetting` was omitted). v1.8.10 addition brings total to 9.

**R1 M-3 fold**: §4.3 statement corrected — not all Ozone stubs are `Unsupported`. Two shipped exceptions (`apply_label`, `negate_label`) return `ArchitecturallyForbidden` per umbrella §F4. v1.8.10's eight new methods correctly return `Unsupported`.

**R1 M-4 fold**: §11 Ready-for-implementation checklist gains reference pointer — canonical fixture 7-string set lives at `tests/rust_backend.rs:62 canonical_body()`, not `src/pds_admin/types.rs`. Saves implementer the hunt.

**Design decisions locked at v2**:
- All seven LB kickoff decisions hold (eight endpoint picks, gate-less `dispatch_ops_read<T>` primitive, Value pass-through for seven endpoints, trait 40→48, `FederationStatusResponse` verbatim [with `rename_all = "camelCase"` correction], registry stays at 10, `cairn pds-admin ops` subgroup with `metrics` migration).
- `runHealthChecks` out of scope per verb+primitive-scope discipline (softened from "mutates state" per S-2).
- `dispatch_ops_read<T>` scope is the core admin ops block at `admin.rs:233-462`; wider namespace capability-bare claim narrowed per S-1.
- `FederationStatusResponse` carries `#[serde(rename_all = "camelCase")]` and `u64` for Aurora's `usize` fields.
- Ops CLI subgroup: nine subcommands (eight new + `metrics` migrated direct rename).
- `ops blobs` naming coexists cleanly with existing `blobs` actions group (D-2 HELD).
- All eight Ozone stubs return `Unsupported`; existing `apply_label`/`negate_label` `ArchitecturallyForbidden` exceptions are shipped-convention and not v1.8.10 scope.
- `ops_types.rs` shipping v1.8.9 has 8 types; v1.8.10 adds `FederationStatusResponse` bringing total to 9.
- Umbrella §4.A.10 divergences (capability model, endpoint count, Ozone stub variant) flagged for v1.8.11 reconciliation.

**v1 (superseded).** Initial draft. See git history if needed.

Pending: implementation kickoff.

**Fold-application correction (source wins, flagged on the implementation chainlink):** the folds document's LB-1 sketch showed Aurora's derive as `#[derive(Debug, Deserialize)]`; source at `admin.rs:9408` is `#[derive(serde::Serialize)]` (server-side response type, Serialize-only). The mirror derives both per `ops_types.rs` module convention.

