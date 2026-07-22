# cairn-mod v1.8.9 ops-and-runtime — design v1

**Status:** Draft v2. R1 folded (chainlink #150); locked pending implementation kickoff.

- cairn-mod HEAD: `deda7b1` (`skydeval/v1.8.8-realtime`, unpushed)
- Aurora-Locus HEAD: `2ffeb1a` (`skydeval/v0.11-cycle`)
- Recon: `docs/internal/recon/v1.8.9-ops-runtime-recon.md` (chainlink #148)
- Design chainlink: #149

## §1 — Process context + memory locks

Umbrella §4.A.9 scope (ops and runtime), recon #148 ground truth. Straight to CC-adversarial after drafting (memory #16). Sourcing per memory #6 + corollaries #27/#28/#29/#30/#31 — every wire block below is copied byte-verbatim from Aurora `2ffeb1a` or cairn-mod `deda7b1`; drafting-time greps cited inline. Firewall applies.

## §2 — What v1.8.9 is

Three outbound surfaces on the Rust backend — instance metrics (ops namespace), runtime-setting read/write (admin namespace, the registry's third OperatorOptIn family), and a moderator-activity presentation view over the v1.8.3-shipped actor-scoped `queryEvents` — plus a small local ledger for setting writes and the `require_opt_in` consolidation the third opt-in consumer forces.

### §2.1 Locked decisions (kickoff LB-1..7 + subsidiary), with source-wins amendments

Kickoff decisions hold except where shipped source contradicts them. **Six amendments (A1–A6), each flagged on chainlink #149:**

- **A1 (LB-1)**: registry grows 8 → **10**, not 11. `("moderator-activity", CapabilityClassification::AutoAdvance)` has been registered since v1.8.3 (drafting-time grep: entry at index 1 of the shipped slice) — no new entry, and there is no `moderator-reads-v1` family anywhere in either repo (full-file grep: zero hits); the wire gate for `queryEvents` IS `moderator-activity-v1`, enforced inside the shipped `query_events` dispatch. Consequence for LB-7: the CLI view needs **no additional gate** — the trait call it makes is already capability-gated. Two new entries only: `instance-metrics` (AutoAdvance), `runtime-settings` (OperatorOptIn). Pinned test 8 → 10; fixtures 5 → 7 strings.
- **A2 (LB-2/LB-4)**: there is no "shipped POST-JSON write dispatch helper" to reuse — `dispatch_emit_event` is emitEvent-shaped (fixed NSID/family/response) and `dispatch_batch` is hard-bound to `BATCH_TAKEDOWN_FAMILY` + `BatchOutcome`. And the kickoff's `require_opt_in` sketch references types that don't exist (`PinnedVersionsConfig`, `AdvertisedCapabilities`; `BackendError::CapabilityNotAdvertised` is a tuple variant, not struct-shaped). Fold: **one refactor delivers both** — generalize the POST path into `dispatch_admin_post<B, T>(nsid, family, wire_capability, body)` and extract the gate as a `RustBackend` method over the real types (§4.4/§7.2). v1.8.7's batch bodies and v1.8.8's stream gate retrofit onto them in the same commit; existing posture tests must pass unchanged.
- **A3 (LB-3)**: the shipped error taxonomy maps **5xx → `Transient`** (`map_rust_backend_http_error`, `500..=599 => BackendError::Transient(...)`) — not `Terminal`. And `getRuntimeSetting` has **no 404 path**: unknown keys return 200 with `source: "Default"` via the four-tier fallback (`default_for_key`; handler verbatim in recon §3.2). §8 uses the shipped mapping; exit codes are the shipped ones (Auth 5, Validation 7, Transient 4, Terminal 18) with nothing new.
- **A4 (LB-5)**: Aurora does **not** enforce non-empty `value` — `value` is arbitrary JSON (`serde_json::Value`), with per-key validators only (`moderation-mode` enum, cadence enum, bool gate, `moderation.defaults.*` shapes). Local pre-dispatch checks byte-match what Aurora enforces globally: **rationale non-empty, nothing else**. The CLI's value-parsing convention: attempt `serde_json::from_str`; on failure treat the argument as a JSON string (so `full` and `"full"` both work, and structured values are expressible).
- **A5 (LB-6)**: `audit_entry_id` is a **String on the wire** (`SetRuntimeSettingOutput`, verbatim §3.3) → the ledger column is `aurora_audit_entry_id TEXT NOT NULL UNIQUE`, not INTEGER. And the output mirror carries the full shipped shape — `key`, `previous_value`, `new_value`, `audit_entry_id` (the kickoff summary omitted the value diff).
- **A6 (CLI homes)**: every upstream dispatch surface since v1.8.3 lives under `cairn pds-admin` (events/statuses/subjects/appeals/accounts/blobs/records/reports/emails); `cairn moderator` is the **local moderator-management group** (add/list/revoke). The kickoff's `cairn ops metrics` / `cairn runtime …` / `cairn moderator activity` homes would scatter upstream reads across three new top-levels and mix an upstream view into local management. Amended homes: `cairn pds-admin metrics`, `cairn pds-admin runtime get|set`, `cairn pds-admin moderator-activity <did>`. Flagged prominently — this is a deviation from locked kickoff text, justified by house consistency; R1 can bounce it.

Everything else holds as locked: three trait methods (37 → 40, LB-2), family-level opt-in for `runtime-settings` covering read AND write (LB-1), `require_opt_in` extraction with same-commit retrofit (LB-4), pass-through key posture with no local allowlist (LB-5), Path A local ledger via unchained `runtime_settings_writes` + migration 0013 (LB-6), moderator-activity as CLI-only presentation with **no new trait method** (LB-7), Ozone `Unsupported` ×3, no new config sub-block (opt-in via `pinned_versions`), no Cargo changes, no new exit codes, recovery-mode `SettingSource::RecoveryMode` first-class.

### §2.2 Non-goals

- No mode-based enforcement: cairn-mod reads `moderation-mode` for visibility; emitEvent dispatches work regardless of Aurora's mode (umbrella F16).
- No local 37-key allowlist (LB-5) — Aurora's `KNOWN_RUNTIME_KEYS` is the authority and its rejection message enumerates it.
- No `subject_actions`/`pds_admin_audit` write for setting writes (§5.2 — the v1.8.7 A2 blockers apply identically).
- No stream-side `source='upstream'` mirroring into `runtime_settings_writes` (deferred to v1.8.11 evaluation; the v1.8.8 `upstream_audit_mirror` already captures `SetRuntimeSetting` auditEntry frames).
- No ops endpoints beyond `getInstanceMetrics` (the console starter is v1.8.10; mirrors are placed for its reuse).
- No special handling of restart-marker keys (`federation.enabled`, `service.public-url`) beyond pass-through — their side effects are Aurora's.
- No push.

### §2.3 Umbrella-vs-source divergences (v1.8.11 reconciliation)

1. "AdminServer scope" is not a shipped per-endpoint gate — enforcement is handler role floors (`getInstanceMetrics`: none, `_auth` unused; `getRuntimeSetting`: any-role for `moderation-mode`/`theme.deployment-default`, Admin+ otherwise; `setRuntimeSetting`: SuperAdmin + rationale + allowlist). Operator story survives (the service DID needs the role); the scope taxonomy doesn't.
2. Namespace split: only `getInstanceMetrics` is `tools.aurora.ops.*`; the runtime-settings pair is `tools.aurora.admin.*`.

## §3 — Aurora surfaces consumed

### §3.1 `tools.aurora.ops.getInstanceMetrics`

Route + handler semantics per recon §3.1 (route verbatim there; `CapsBuilder::new(Family::Ops).extensions(["instance-metrics-v1"])`; GET, no params; handler has NO role floor — `_auth: AdminAuthContext` unused). Response mirror, copied byte-verbatim from `admin.rs:6546-6608` (field names/attrs exact; cairn-mod's mirror derives `Deserialize` with `Option` + `#[serde(default)]` on the three optionals — Aurora omits them, and **absence is meaningful; never zero-fill**):

**Fields verbatim (doc-comments elided), copied from source at `2ffeb1a`** (`admin.rs:6546-6608`):

```rust
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OpsInstanceMetrics {
    system_health: OpsSystemHealth,
    resource_usage: OpsResourceUsage,
    account_growth: OpsAccountGrowth,
    federation_health: OpsFederationHealth,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OpsSystemHealth {
    status: &'static str,
    version: String,
    uptime_seconds: f64,
    active_http_requests: i64,
    active_sessions: i64,
    active_background_jobs: i64,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OpsResourceUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_resident_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_seconds_total: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    open_fds: Option<i64>,
    db_pool_size: u32,
    db_pool_idle_connections: u32,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OpsAccountGrowth {
    signups_last_24h: i64,
    signups_last_7d: i64,
    signups_last_30d: i64,
    total_accounts: i64,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OpsFederationHealth {
    federation_enabled: bool,
    relay_connected: bool,
    known_instances: i64,
}
```

Wire-form table (per-field none/empty behavior — second consumer of the v1.8.6 R1 S-2 convention):

| Field | Absent form | Notes |
|---|---|---|
| `resourceUsage.memoryResidentBytes` | **key omitted** | `skip_serializing_if`; absence = not instrumented |
| `resourceUsage.cpuSecondsTotal` | **key omitted** | same |
| `resourceUsage.openFds` | **key omitted** | same |
| every other field | always present | `status` is `"healthy"`/`"unhealthy"` from a live `SELECT 1`; counts may legitimately be 0 |

cairn-mod's mirror derives `Deserialize` with `Option` + `#[serde(default)]` on exactly the three omitted fields; **absence is meaningful — never zero-fill** (Aurora's stated contract).

### §3.2 `tools.aurora.admin.getRuntimeSetting`

GET with `GetRuntimeSettingParams { key: String }` query. Output + source vocabulary verbatim (recon §3.2):

```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRuntimeSettingOutput {
    pub key: String,
    pub value: serde_json::Value,
    pub source: SettingSource,
    pub last_modified: Option<String>,
    pub last_modified_by: Option<String>,
}

pub enum SettingSource {
    Runtime,
    File,
    Default,
    RecoveryMode,
}
```

Wire encoding of `source` is the bare string `"Runtime" | "File" | "Default" | "RecoveryMode"` (Aurora custom Serialize; cairn-mod mirrors with `#[derive(Deserialize)]` on unit variants — exact-string match). Four-tier resolution (recovery env → runtime row → file YAML → compiled default); **unknown keys are a 200 with `source: "Default"`, never a 404** (A3). Role floor: `moderation-mode` + `theme.deployment-default` any-role; other keys Admin+ (403 → `Auth`). **Recovery-mode is first-class**: `AURORA_RECOVERY_MODE` truthy forces `moderation-mode` reads to `value: "full"`, `source: "RecoveryMode"` — `runtime get` renders the source field verbatim so operators see the override honestly (umbrella F16).

### §3.3 `tools.aurora.admin.setRuntimeSetting`

POST JSON. Wire shapes verbatim (recon §3.2):

```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRuntimeSettingInput {
    pub key: String,
    pub value: serde_json::Value,
    pub rationale: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRuntimeSettingOutput {
    pub key: String,
    pub previous_value: serde_json::Value,
    pub new_value: serde_json::Value,
    pub audit_entry_id: String,
}
```

Handler gates (verbatim quotes in recon §3.2): SuperAdmin floor (`"setRuntimeSetting requires SuperAdmin role; caller has {:?}"` → 403), rationale non-empty, `KNOWN_RUNTIME_KEYS` allowlist (**36** keys at HEAD; rejection message enumerates them — R1 M-1 corrected the recon's 37). The exact count is 36 at HEAD `2ffeb1a` per programmatic slice length (the folds document's `2cea582` hash was a typo; corrected, source wins). This design does not copy or enumerate the list — LB-5's pass-through posture means Aurora's allowlist is authoritative at every dispatch, so any count drift surfaces cleanly through `BackendError::Validation` on 400 responses; the count is reference-only, per-key value validation (`moderation-mode must be one of: full, reduced, disabled`). Upstream side effect: one audit-chain entry (`action: "SetRuntimeSetting"`, `subject: None`, rationale `"{key} → {value_json}: {rationale}"`), **no `moderation_event`** — so no v1.8.8 event-frame echo, only an `auditEntry` frame when chain co-delivery is on (§5.2).

### §3.4 `queryEvents` actor-filter reuse (moderator-activity)

Zero new upstream surface. cairn-mod's shipped filter (verbatim, `read_types.rs:151-153`):

```rust
    /// Actor DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
```

`query_events` already gates on `moderator-activity` (AutoAdvance, registered v1.8.3). The v1.8.9 deliverable is presentation (§6.3).

## §4 — Trait additions (37 → 40)

New mirror module `src/pds_admin/rust/ops_types.rs` (public — v1.8.10's console starter imports from it): `InstanceMetrics` (+ four sub-structs, cairn-mod-named, fields byte-matching §3.1), `RuntimeSetting` (mirror of `GetRuntimeSettingOutput`), `SettingSource`, `SetRuntimeSettingOutcome` (mirror of `SetRuntimeSettingOutput`). Consts `GET_INSTANCE_METRICS_NSID` / `GET_RUNTIME_SETTING_NSID` / `SET_RUNTIME_SETTING_NSID` / `INSTANCE_METRICS_FAMILY`+`_CAPABILITY` / `RUNTIME_SETTINGS_FAMILY`+`_CAPABILITY` in `rust/mod.rs` per the house const pattern.

### §4.1–§4.3 Signatures

```rust
/// Fetch aggregated instance metrics (v1.8.9) —
/// `tools.aurora.ops.getInstanceMetrics`. Gates on the
/// `instance-metrics` family (AutoAdvance). No role floor
/// upstream beyond authentication. Absent optional fields mean
/// "not instrumented", never zero.
async fn get_instance_metrics(&self) -> Result<InstanceMetrics, BackendError>;

/// Read one runtime setting (v1.8.9) —
/// `tools.aurora.admin.getRuntimeSetting`. Gates on the
/// `runtime-settings` family (**OperatorOptIn** — family-level:
/// the read shares the write's opt-in). Unknown keys are a 200
/// with source = "Default" upstream. `moderation-mode` reads are
/// any-role; most other keys need Admin+ upstream (403 → Auth).
async fn get_runtime_setting(&self, key: &str) -> Result<RuntimeSetting, BackendError>;

/// Write one runtime setting (v1.8.9) —
/// `tools.aurora.admin.setRuntimeSetting`. Same family gate.
/// SuperAdmin upstream (403 → Auth); key allowlist + per-key
/// value validation upstream (400 → Validation). Returns the
/// value diff + the upstream audit-chain entry id (there is no
/// event id — setting writes emit no moderation event).
async fn set_runtime_setting(
    &self,
    key: &str,
    value: &serde_json::Value,
    rationale: &str,
) -> Result<SetRuntimeSettingOutcome, BackendError>;
```

(Flattened parameters rather than an input struct — house convention: every shipped write method takes flattened args; the wire body is built inside the dispatch.) Ozone: `Unsupported` ×3.

### §4.4 Dispatch reuse + the A2 refactor

- Reads: `dispatch_moderator_read(family, wire, nsid, &params, None, None)` as-is — `get_instance_metrics` passes a unit params struct (serializes to no query pairs), `get_runtime_setting` passes `Params { key }`. One wrinkle: `dispatch_moderator_read`'s gate is advertisement-only; the `runtime-settings` read must ALSO honor the opt-in pin (family-level, LB-1). Resolution: the gate call inside both new methods goes through `require_opt_in` (§7.2), which no-ops for AutoAdvance families — `get_instance_metrics` and the shipped read methods are unaffected.
- Write: `dispatch_admin_post<B: Serialize, T: DeserializeOwned>(nsid, family, wire_capability, body)` — the generalization of v1.8.7's `dispatch_batch` (same body: gate → JWT → POST → error map → parse; the family/capability/response become parameters). `dispatch_batch` becomes a thin wrapper (or its four call sites call `dispatch_admin_post` directly — implementation's call; either way batch tests must pass unchanged).

## §5 — Local persistence

### §5.1 `runtime_settings_writes` (LB-6 Path A)

Unchained observational ledger of cairn-mod-initiated setting writes — the `cross_verify_outcomes`/`upstream_events` posture (advisory, prunable, no hash chain):

```sql
CREATE TABLE runtime_settings_writes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    rationale TEXT NOT NULL,
    -- Aurora's chain-entry id (String on the wire — A5).
    aurora_audit_entry_id TEXT NOT NULL UNIQUE,
    dispatched_at TEXT NOT NULL DEFAULT (datetime('now')),
    source TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'upstream'))
) STRICT;

CREATE INDEX runtime_settings_writes_key_idx
    ON runtime_settings_writes (key, dispatched_at DESC);
```

The recon-inherited off-by-one on Aurora's allowlist count (M-1) would have been a shipped bug under any design that copied the list locally; LB-5's pass-through posture made it a footnote instead.

Written by the CLI path after a successful dispatch (best-effort: an insert failure logs ERROR and does not fail the command — the upstream chain entry is the authoritative record). `source = 'upstream'` is reserved (non-goal §2.2). Operators MAY prune.

### §5.2 Why not `subject_actions` / `pds_admin_audit`

Identical to v1.8.7 A2: `subject_actions.subject_did NOT NULL` (no subject exists), `pds_admin_audit.precipitating_action_id NOT NULL REFERENCES subject_actions(id)` + 16-verb `backend_method` CHECK + hash-chained rows. The upstream audit-chain entry (action `"SetRuntimeSetting"`) is the audit trail — reachable via v1.8.6 cross-verify (it appears as an upstream-only entry, correct for operator-config actions) and mirrored by v1.8.8 when chain co-delivery is on.

**Cross-verify does not auto-join `runtime_settings_writes` in v1.8.9 (M-3).** The shipped machinery pairs `pds_admin_audit.backend_action_id` against `AuditEntry.event_id`; ledger rows have `aurora_audit_entry_id` and no `backend_action_id`. Operator manual reconciliation (unmirrored writes):

```sql
SELECT r.key, r.value, r.dispatched_at, r.aurora_audit_entry_id
FROM runtime_settings_writes r
LEFT JOIN upstream_audit_mirror m ON m.entry_id = r.aurora_audit_entry_id
WHERE m.entry_id IS NULL;
```

(Join column on the mirror side is `entry_id` — the v1.8.8 shipped column name; the folds document sketched `m.aurora_audit_entry_id`, corrected against 0012 DDL, source wins.) Automated coverage is deferred to the v1.8.11 evaluation — either a cross-verify extension flag or a general subject-optional audit shape; v1.8.9 ships local persistence + this manual surface only.

### §5.3 Migration 0013 scope

One table + one index. Additive-only: no trigger touches, no CHECK extensions on existing tables. Forward-trace (corollary #28): live trigger bodies remain 0010 (`subject_actions`, `pds_admin_audit`) / 0001 (`audit_log`); 0012 added none; 0013 adds none. Highest shipped migration at HEAD is 0012 (drafting-time verified); 0013 is free.

## §6 — CLI extensions (homes per A6)

### §6.1 `cairn pds-admin metrics [--json]`
Calls `get_instance_metrics`; renders the four sections with absent optionals shown as `-` (never `0`). `--json` emits the mirror verbatim.

### §6.2 `cairn pds-admin runtime get <key>` / `runtime set <key> <value> --reason <R> [--yes]`
- `get`: renders value + `source` + last-modified columns verbatim (RecoveryMode surfaces as-is).
- `set`: local checks = reason non-empty (A4); value parsed as JSON with string fallback; `--yes` confirm (SuperAdmin blast radius; house `--yes` pattern from `stream cursor set`). On success prints the previous → new diff + `auditEntryId`, then best-effort ledger insert (§5.1). No local key validation (LB-5) — Aurora's 400 lists the known keys.

### §6.3 `cairn pds-admin moderator-activity <did> [--after <RFC3339>] [--before <RFC3339>] [--limit <N>] [--json]`
CLI-only (LB-7): pages `query_events(filter { actor: Some(did), after, before }, cursor, limit)` and renders (a) a per-`event_type` count summary and (b) the event rows, newest-first (upstream `ORDER BY created_at DESC, id DESC` — the v1.8.8 S-1 verified ordering). Read-only; persists nothing. Time-flag names match the shipped filter fields (`after`/`before`, inclusive) rather than the kickoff's `--since/--until` (drift-avoidance with §3.4's wire names — micro-amendment under A6).

## §7 — Capability registry + opt-in

### §7.1 Two new entries (registry 8 → 10, A1)
`("instance-metrics", AutoAdvance)` and `("runtime-settings", OperatorOptIn)` — the latter the **third** OperatorOptIn family. `moderator-activity` unchanged (shipped v1.8.3). Pinned test at `src/pds_admin/types.rs` 8 → 10.

### §7.2 `require_opt_in` extraction (LB-4, real types)

`RustBackend` method (it needs the capabilities lock + pinned map + registry):

```rust
/// Shared capability gate (v1.8.9): advertisement check plus the
/// OperatorOptIn pin requirement (v1.8.7 semantics). AutoAdvance
/// families pass on advertisement alone. Both refusals surface as
/// CapabilityNotAdvertised(wire) — "operator didn't opt in" and
/// "upstream doesn't offer it" are equally capability-unavailable
/// to the caller.
fn require_opt_in(&self, family: &str, wire: &'static str) -> Result<(), BackendError> {
    // (a) advertised — same blocking-read pattern as every gate;
    // (b) classification_for(family) == Some(OperatorOptIn)
    //     → self.pinned_versions.contains_key(family), else refuse
    //     with the config-line WARN.
}
```

**Same-commit retrofit**: `dispatch_batch` (v1.8.7) and `subscribe_mod_events` (v1.8.8) replace their inline gate blocks with this call; `dispatch_moderator_read` is NOT retrofitted (its families are all AutoAdvance today and its gate is structurally the (a) half) — the two new runtime-settings methods call `require_opt_in` explicitly before dispatch. **Retrofit tripwire tests (M-4)** — shipped names (the folds document's best-guess names corrected against HEAD, per its own verify-at-implementation instruction): `batch_dispatch_refused_when_advertised_but_unpinned`, `batch_dispatch_refused_when_pinned_but_unadvertised`, `batch_posture_b_pin_requires_required_capabilities_entry` (tests/rust_backend.rs) and `unpinned_family_parks_dormant_without_wire_traffic` (tests/stream_consumer.rs). All four must pass unchanged through the retrofit commit; any test change indicates behavior drift → chainlink flag.

### §7.3 Fixtures
Canonical mock advertisement gains `instance-metrics-v1` + `runtime-settings-v1` (5 → 7 strings); probe end-to-end assertion updates.

### §7.4 Opt-in postures
`runtime-settings = "v1"` under `[pds_admin.rust.pinned_versions]`; dual-posture semantics per v1.8.7 §8.1 verbatim (Posture A one line; Posture B adds `runtime-settings-v1` to `required_capabilities`, making it probe-required). Family-level: the pin gates read AND write (recon §7d-1).

## §8 — Error mapping (shipped taxonomy, A3)

### §8.1 `setRuntimeSetting`
403 (SuperAdmin floor) → `Auth` (exit 5); 400 (unknown key / bad value / empty rationale) → `Validation` (exit 7) with Aurora's message (which enumerates the allowlist on unknown-key); 429 → `Transient` (exit 4, `[sub_classification=RateLimited retry_after_seconds=N]` marker — shipped mapping, most plausible on metrics polling; M-2); 5xx → `Transient` (exit 4); 404/409/410 → `Terminal` (exit 18) — all via the shipped `map_rust_backend_http_error`, no new variants, no new exits.

### §8.2 Reads
`getInstanceMetrics`: 403 impossible-by-construction today (no role floor) but maps to `Auth` if Aurora tightens; 5xx → `Transient`. `getRuntimeSetting`: 403 (Admin+ keys under a Moderator DID) → `Auth`; **no 404 path** — unknown key is a 200/`Default`.

### §8.3 Recovery-mode reads
Normal 200 with `source: "RecoveryMode"` — not an error path; rendered verbatim.

## §9 — Non-goals (restated)
§2.2 list; headline: no local allowlist, no chained local persistence, no stream-side ledger mirroring (v1.8.11 evaluation), no mode-based enforcement, no ops-console endpoints (v1.8.10), no push.

## §10 — Test coverage plan

1. **Unit (mirrors)**: `InstanceMetrics` parses the full shape AND an optionals-absent body (absence ≠ zero pinned); `SettingSource` four exact strings (incl. `"RecoveryMode"`); `SetRuntimeSettingOutcome` full diff shape; extra-field tolerance throughout.
2. **Unit (dispatch wire)**: `get_runtime_setting` sends `?key=`; `set_runtime_setting` POSTs `{key, value, rationale}` camelCase; metrics GET has no params.
3. **Unit (gate)**: `require_opt_in` — AutoAdvance passes on advertisement; OperatorOptIn advertised+unpinned refuses with wire string; unadvertised refuses; **v1.8.7 batch + v1.8.8 stream posture tests pass unchanged post-retrofit** (the LB-4 drift tripwire).
4. **Unit (ledger)**: successful set → `runtime_settings_writes` row (TEXT audit id, source `local`); duplicate `aurora_audit_entry_id` ignored/errors cleanly; insert failure doesn't fail the command path.
5. **Integration (mock Aurora)**: all three endpoints happy-path; 403 SuperAdmin mapping; 400 unknown-key mapping preserving Aurora's enumerated-keys message; recovery-mode read (`"full"`/`RecoveryMode`); runtime-settings pinned vs unpinned posture fixtures (A/B per v1.8.7 precedent).
6. **Integration (CLI)**: `runtime set` JSON-vs-string value parsing; `--yes` guard; `moderator-activity` pagination + summary over a mock queryEvents page (actor filter on the wire). **Fixture requirement (M-5)**: the roundtrip test provides its own describe body advertising `moderator-activity-v1` — the canonical fixture's five strings (`mod-events-emit-v1`, `audit-trail-v1`, `batch-takedown-v1`, `mod-events-stream-v1`, `queue-stats-v1`; the folds document's differing names corrected against HEAD) do not carry it. Test-only fixture; canonical-fixture consolidation is a v1.8.11 evaluation item.
7. **Registry/fixtures**: pinned test 8 → 10; canonical fixtures 5 → 7; probe assertion.
8. **Regression**: full `cargo test` (memory #24); migration 0013 fresh + upgrade.

## §11 — Ready-for-implementation checklist

- [ ] Branch off `deda7b1`; implementation chainlink open.
- [ ] Aurora cites re-verified at `2ffeb1a`: metrics route (`admin.rs:243-249`) + handler/no-role-floor (`:6544+`), runtime-settings routes (`:685-700`), `GetRuntimeSettingParams/Output` + `SettingSource` (`aurora_admin.rs:4014-4049`), get handler four-tier + role floor (`:5210+`), `SetRuntimeSettingInput/Output` (`:5286-5299`), set handler gates (`:5301+`), `KNOWN_RUNTIME_KEYS` 37 entries (`:4211-4256`), `MODERATION_MODE_KEY = "moderation-mode"` (`:4068`), chain-entry write with no moderation_event (`:5516-5560`), advertised-list pins (`admin.rs:12311/12320`).
- [ ] cairn-mod re-verified at HEAD: trait = 37; registry = 8 with `moderator-activity` at index 1; fixtures = 5 strings; `dispatch_moderator_read`/`dispatch_batch` shapes; `QueryEventsFilter.actor`; highest migration 0012; no `moderator-reads-v1` anywhere.
- [ ] Firewall grep on this doc: clean.

## §12 — Post-implementation checklist

- [ ] Retrofit tripwire: v1.8.7/v1.8.8 posture tests unchanged.
- [ ] Absence-is-meaningful pinned (metrics optionals).
- [ ] Full `cargo test` green; fmt/clippy/rustdoc/release gates; sqlx cache if 0013 queries use macros.
- [ ] CHANGELOG hand-written; chainlink closed `--no-changelog`.
- [ ] v1.8.11 reconciliation notes filed (§2.3 + A6 home decision).

## §13 — Revision log

**v2 (this draft).** Post-CC-adversarial R1 fold (chainlink #150). R1 verdict: 28 verifications with 0 LB, 1 S, 5 M. All six drafting-time amendments A1–A6 HELD against source. A6 CLI-consolidation stress-test HELD against v1.8.8 `cairn stream` top-level precedent. Ship signal per memory #12: 0 LB → fold-and-lock. All findings folded; recommendation → straight to implementation kickoff, no R2.

**R1 S-1 fold**: `OpsInstanceMetrics` mirror inlined byte-verbatim in §3.1. v1's comment-summary form deferred the copy source to the recon, breaking the every-prior-cycle contract that the design doc contains the implementation copy source. Adds a wire-form table (second consumer after v1.8.6 R1 S-2). Formalizes design-doc-as-copy-source discipline for future cycles.

**R1 M-1 fold**: `KNOWN_RUNTIME_KEYS` corrected from 37 to 36 entries per programmatic count. Footnote demonstrates why LB-5's pass-through posture was right — the miscount would have been a shipped bug under any design copying the list locally; pass-through made it a footnote instead. §5 rationale gains an explicit sentence citing this as a live demonstration.

**R1 M-2 fold**: §8 error mapping gains 429 (rate-limit) → `Transient` (exit 6). Applies uniformly to all three v1.8.9 endpoints. `getInstanceMetrics` is the most likely trigger under monitoring-adjacent polling load.

**R1 M-3 fold**: §5 documents that cross-verify does not auto-join `runtime_settings_writes`. Manual correlation via `aurora_audit_entry_id` LEFT JOIN against `upstream_audit_mirror`; SQL example provided for operator use. Automated coverage deferred to v1.8.11 evaluation.

**R1 M-4 fold**: §7.2 names four retrofit tripwire tests explicitly (v1.8.7 batch-takedown posture A + B, v1.8.8 mod-events-stream posture A + B). All four must pass unchanged through the retrofit commit; any test change indicates behavior drift. Names are best-guess; verify at implementation and adjust to match shipped conventions.

**R1 M-5 fold**: §10.7 documents that the moderator-activity roundtrip test needs its own describe-body fixture advertising `moderator-activity-v1`. Canonical fixtures at HEAD don't carry it explicitly (v1.8.3 shipped it; fixture-list updates lagged). Test-only fixture, not a canonical-fixture reconciliation (deferred to v1.8.11 evaluation).

**Design decisions locked at v2**:
- All seven LB kickoff decisions hold (NSID + registry, trait 37→40, wire error mapping, `require_opt_in` extraction, pass-through key posture, `runtime_settings_writes` unchained table, moderator-activity CLI-only).
- Registry grows 8 → 10 (not 11; moderator-activity pre-existing per A1). Pinned test updates accordingly.
- `dispatch_admin_post<B, T>` generalization + `require_opt_in` on `RustBackend` land in same commit as retrofit of v1.8.7 batch-takedown + v1.8.8 mod-events-stream (LB-4).
- `runtime_settings_writes` migration 0013 additive: single table + single index, STRICT mode, `aurora_audit_entry_id TEXT NOT NULL UNIQUE` (A5), `source TEXT` with `'upstream'` reserved for future.
- Cross-verify does not auto-join `runtime_settings_writes` (M-3); v1.8.11 evaluation for automated coverage.
- CLI homes under `cairn pds-admin` per A6 (stress-test HELD).
- Wire error mapping includes 429 → Transient (M-2 addition).
- Pass-through key posture is the correctness posture; live-demonstrated by M-1 miscount having zero impact.
- Umbrella §4.A.9 divergences (AdminServer scope language, ops-vs-admin namespace split) flagged for v1.8.11 reconciliation.

**v1 (superseded).** Initial draft. See git history if needed.

Pending: implementation kickoff.

**Fold-application corrections (source wins, flagged on the implementation chainlink):** M-1 footnote hash corrected `2cea582` → `2ffeb1a`; M-3 SQL join column corrected to the shipped `upstream_audit_mirror.entry_id`; M-4 tripwire names replaced with the four shipped test names; M-5 canonical-fixture string names corrected to the shipped five.

