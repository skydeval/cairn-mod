# cairn-mod v1.8 — Series Umbrella Design Doc (v13)

**Status:** Locked. Recon-correction pass complete; v13 reconciles umbrella figures against the corrected recon. Per-release doc drafting begins with v1.8.1.
**Predecessor:** v1.7.0 shipped (commit `6ccec83`).
**Series scope:** 15 minor releases across two workstreams — v1.8.1 through v1.8.15.
**Ground truth:** `docs/internal/recon/v1.8-surface-recon.md` (Aurora-Locus HEAD `2ffeb1a`, v0.10.0; cairn-mod HEAD `65769dd`). Recon is source-accurate as of the recon-correction pass; umbrella cites recon figures directly.

---

## §1 — What this document is

The umbrella for the v1.8 series. It captures the cross-cutting decisions every per-release design doc inherits — the two-workstream shape, the auth model, the RustBackend trait and capability architecture, the kryphocron/laquna consumption model, the naming convention, degradation semantics, the temporal-direction rule for adjacent docs, and the ground-truth citation discipline. Each individual release (v1.8.1, v1.8.2, …) gets its own per-release design doc that binds the umbrella's decisions to that release's specific endpoint list, schema migrations, and Rust code.

The umbrella is not an implementation spec. No specific endpoint bodies, no Rust code samples beyond illustrative type sketches, no schema migrations. Those live in per-release docs.

**Rewrite note.** This is v13, following the recon-correction pass. v12 flagged that the on-disk recon carried nine pre-correction figures per §7; the correction pass verified each against source independently and returned three findings: six recon items needed correction, two were already source-accurate (endpoint count, rotation oracle), and one (`lxm`) was already correct in the recon but got a defensive note added. v13 reconciles the umbrella's §2.2 (endpoint count) and §7 (correction list) against the actual pass outcome. Web-review chain: v6 → v7 (full rewrite) → v8 (R1 fold) → v9 (R2 fold) → v10 (R3 fold, web-review convergence) → v11 (CC-adversarial R1 fold) → v12 (CC-adversarial R2 fold, locked-pending-recon-correction) → v13 (recon-correction reconciliation, locked). Per-release doc drafting begins with v1.8.1.

---

## §2 — What v1.8 is, and what it isn't

### §2.1 What v1.8 is

v1.8 ships **Rust PDS support** in cairn-mod, and — as a coequal workstream — **kryphocron-content moderation support** when the driven Rust PDS advertises kryphocron capabilities.

Two workstreams, run in parallel with a single sequencing gate:

- **Workstream A — RustBackend.** cairn-mod grows a second `PdsAdminBackend` implementation (`RustBackend`) that drives PDSes exposing the Rust-PDS admin vocabulary — a `tools.aurora.*`-shaped surface currently implemented by Aurora-Locus at v0.10. `OzoneBackend` continues to serve bsky-PDS unchanged. RustBackend is additive; it doesn't replace anything.
- **Workstream B — kryphocron/laquna consumption.** cairn-mod grows the ability to read and moderate private-tier content on kryphocron-enabled PDSes. This includes consuming the kryphocron substrate for client-side decode, handling laquna's rotation model, wiring kryphocron audit-event variants into cairn-mod's own audit chain, and surfacing kryphocron-scoped mod actions through `queryEvents`.

The two workstreams share the RustBackend foundation but scope orthogonally: A's releases are general Rust-PDS moderation parity; B's releases specifically add kryphocron-content moderation on top.

By series end, cairn-mod can drive a Rust PDS with full moderation-side parity plus a starter operator-console subset, and — when that Rust PDS advertises kryphocron — can moderate its private-tier content with the same authorization and audit discipline as public-tier content.

### §2.2 What v1.8 is not

- **Not an OzoneBackend replacement.** Operators on bsky-PDS keep using cairn-mod exactly as they always did. RustBackend and Workstream B are entirely additive.
- **Not Aurora-Locus-specific in name or interface.** Aurora-Locus is the only Rust PDS at time of writing, but cairn-mod's abstractions, config keys, log output, error messages, and operator-facing docs do not name Aurora-Locus. See §3 (naming convention).
- **Not kryphocron-specific in the RustBackend surface.** Workstream A's trait, config, error taxonomy, and capability negotiation work against any Rust PDS advertising the base vocabulary. Workstream B's kryphocron surfaces are separately gated on the kryphocron-family capability advertisements — a Rust PDS without kryphocron sees only Workstream A behavior.
- **Not sanctuary-scoped.** cairn-mod is general-purpose. It is not a component of the kryphocron suite, does not enforce single-operator constraints, does not distinguish "sanctuary-internal" from "cross-sanctuary" content, and does not implement any confidentiality gate on private records. The audience gate on kryphocron records is a **friction property**, not a confidentiality one — this shapes what Workstream B is, and §5.4 makes the implications explicit.
- **Not a total surface consumer.** Aurora-Locus at v0.10 exposes 133 `tools.aurora.*` endpoints across four namespaces (recon §1a — 129 advertised via `describeCapabilities` + 3 unadvertised `tools.aurora.lexicon.*` routes + `describeCapabilities` itself). v1.8 selects the ones that align with cairn-mod's mission as a moderation service — the 7 moderator + 25 admin endpoints in full (32), a starter 5–10 ops subset, and no superadmin at all. Total: ~37–42 of 133, roughly 28–32% — a substantial consumer of Aurora's moderation-relevant surface, but explicitly not everything Aurora exposes. §4 enumerates the selection.

### §2.3 Scope expansion: cairn-mod as a starter operator-visibility console

A consequence of Workstream A landing v1.8.10 (operator-console starter): in the v1.8 era, cairn-mod grows a **starter operator-visibility surface** for any Rust PDS exposing the `tools.aurora.ops.*` family. Per §4.A.10, that surface is visibility-only (system-health probes, sequencer status read, federation status, blob statistics, database status, resource usage) — 5–10 endpoints from a pool of 55. cairn-mod does not become a full operator console in v1.8; it becomes a moderator-adjacent instance-visibility surface, which is aligned with — not divergent from — cairn-mod's moderation-service identity. Operator visibility into instance health, sequencer state, blob quotas, and federation status is adjacent to moderation work in practice.

Whether cairn-mod ever grows into a full operator console (superadmin surfaces, mutating ops) is a post-v1.8 question. v1.8 does not commit to that trajectory; it commits only to the visibility-only starter.

The v1.8 ops-starter subset is small (5–10 endpoints from a pool of 55; specific list is v1.8.10's per-release-doc call). The remaining ~45–50 ops surfaces are deferred to post-v1.8 cycles.

Superadmin surfaces (42 endpoints at v0.10) are not in v1.8 scope at all. Superadmin operations are PDS-operator-owned by design; they don't belong in a moderation console.

---

## §3 — Naming convention

The Rust-PDS backend is named **`RustBackend`**, not `LocusBackend` or `AuroraBackend`. This applies uniformly to type names, module paths, config keys, log output, error messages, operator-facing docs, README, CHANGELOG, and CLI help text.

Rationale: the abstraction is not "specific to Aurora-Locus." It's "what any sufficiently-capable Rust PDS can offer." Aurora-Locus is currently the only Rust PDS, so it's currently the only consumer of `RustBackend`, but the trait shape isn't bound to Locus. Naming the backend `LocusBackend` would over-commit; naming it `AuroraBackend` would over-commit differently. `RustBackend` names the abstraction honestly.

`OzoneBackend` stays as-is — Ozone is Bluesky's actual product name, and the bsky-PDS + Ozone pairing is the canonical Ozone reference deployment. Naming that backend after the product is honest, not coupling.

Kryphocron consumption in Workstream B does name kryphocron directly — kryphocron is the substrate's actual name, `kryphocron` is the crate name, and the lexicon family is `tools.kryphocron.*`. Nothing to abstract; the substrate is the substrate.

**Enforcement.** Code review during v1.8.1 per-release-doc drafting; no linting infrastructure. If an operator-facing string escapes with a product name in it, it gets fixed before ship.

---

## §4 — Series phasing

Two workstreams; workstream banners; releases within each workstream sequenced by their own dependencies. §4A covers Workstream A; §4B covers Workstream B. The one cross-workstream gate — Workstream B depends on Workstream A's v1.8.1 foundation — is stated once here and again at §4B's top.

Per-release capability strings are cited against the recon's §1b (the 19 strings Aurora advertises at v0.10). Where the umbrella references a capability family that maps to a specific advertised string, the string is given verbatim.

### §4A — Workstream A: RustBackend

Eleven releases, v1.8.1 through v1.8.11. Each one lands a capability family (or in v1.8.1's case, the foundation the rest of the workstream inherits).

#### §4.A.1 v1.8.1 — Foundation

**What ships.**

- `RustBackend` skeleton implementing `PdsAdminBackend` — the same trait `OzoneBackend` implements, so both backends are interchangeable at the dispatch layer.
- The ES256K service-auth JWT signing module. cairn-mod grows a `k256`-based secp256k1 signer (or equivalent), a config surface for the service DID and private key, and a per-call JWT-minting function. See §5.1.
- The capability-type surface goes live. `CapabilityVersion`, `CapabilityClassification`, `parse_capability_string`, and `classification_for` all exist as-shipped (recon §3c) — with `CAPABILITY_CLASSIFICATIONS` currently empty. `parse_capability_string` **has a production consumer** at `src/pds_admin/config.rs:854` in `validated_rust_from_toml`, which validates operator-supplied `pinned_versions` entries at config-parse time. What v1.8.1 adds is an *additional* runtime consumer — the `describeCapabilities` probe against Aurora that invokes `parse_capability_string` on each advertised string. So v1.8.1 doesn't wire the "first" consumer; it wires a *second, runtime-path* consumer alongside the existing config-parse-time consumer. v1.8.1 also populates `CAPABILITY_CLASSIFICATIONS` with the initial entries. `Capability` and `CapabilitySet` are **created** here — recon §3c confirms neither type exists at v1.7. The `describeCapabilities` parser at cairn-mod's side is created here — recon §3c confirms no cairn-mod-side probe-path parser exists.
- The `describeCapabilities` probe against `GET /xrpc/tools.aurora.describeCapabilities` (recon §1b). Response type binds to Aurora's actual response shape — `{families, extensions, implementation, version}` — and to Aurora's actual capability-string scheme: flat kebab-`vN`, no family prefix in the string itself (F7).
- The initial `CAPABILITY_CLASSIFICATIONS` registry entries covering `aurora-describe-capabilities` and the v1.8.2 protocol-parity classifications.
- `RustBackendConfig` rewritten: out with `client_id`/`client_secret`/`scopes` (the OAuth-model residue from v1.7-era scaffolding); in with `service_did`, `service_signing_key_env`, `service_did_document_url`, `target_service_did`. `capability_refresh_interval` is **retained** but its semantics change (see §5.2). `verification_persist` is **retained** as-shipped — the field parses and stores per validated_rust_from_toml; its consumer is not yet wired and lands in v1.8.6 alongside audit-trail work (per-release doc details the wiring). `acknowledge_v1_8_1_audit_divergence` shipped at v1.8.1 with the three-gate `validate_audit_divergence_acknowledgment` boot-time inspector in force; *(v1.8.11 reconciliation)* Part 1 (the flag check) was retired to an advisory parse-time WARN at v1.8.6 once `cairn audit cross-verify` closed the divergence, and the field itself is removed at v1.8.11 — Parts 2 (no auto-mode policy rules) and 3 (no xrpc_gateway coexistence) remain live gates. Migration path from the pre-v1.8.1 config is documented; the pre-v1.8.1 OAuth-shaped fields never shipped to any live deployment so the break is safe. See §5.1 and §5.2.
- The `BackendError::CapabilityNotAdvertised` variant, previously reserved (recon §3a), gains its first producers here — the **RustBackend's** inspector-mode dispatch refusals (and, from v1.8.7, the OperatorOptIn pin gate). *(v1.8.11 reconciliation)* Ozone never produces this variant; its stubs are `Unsupported` (plus the two §F4 `ArchitecturallyForbidden` label methods).
- A prepared but not-yet-populated slot in the `Nsid` allowlist and the projection `$type` constants for the `tools.aurora.*`-shaped surfaces the subsequent releases will consume. This resolves F6 (inbound gateway hardwired to `tools.ozone.moderation.*`) at the foundation level so subsequent releases can slot their NSIDs in as pure additions.
- No mutating operations against Aurora yet. v1.8.1 ships a working authenticated `describeCapabilities` probe and the substrate for everything else.

**Capability family consumed:** `aurora-describe-capabilities` (auto-advance).

#### §4.A.2 v1.8.2 — Protocol parity

**What ships.**

- RustBackend implementations of the v1.7 Ozone-matched action surface: takedown-account, suspend-account, restore-account, apply-label, negate-label. Same trait methods as `OzoneBackend`, driven against Aurora's `tools.aurora.admin.emitEvent` (recon §1a) instead of `com.atproto.admin.updateSubjectStatus`.
- `emitEvent` variant handling for the five actions above. cairn-mod's outbound RustBackend translates its own action verbs into the appropriate action-variant type (specific type name — Aurora exposes it as an action enum, exact type name is per-release-doc territory; the umbrella commits to the pattern, not the identifier); the umbrella-level `emitEvent` unification pattern is committed here and inherited by subsequent releases. See §5.5.
- The `AuroraJson` extractor pattern is noted as an inbound-side concern for Aurora-Locus; cairn-mod's outbound side uses standard `serde_json` and matches the wire shape. Cited as F7-adjacent.
- Label methods continue to hard-refuse with `ArchitecturallyForbidden(LABEL_BRIDGE_INVARIANT_REASON)` at the trait level (recon §3b) — the label-distribution invariant is trait-level, not backend-level, and does not change with backend. **Constant rename note:** recon §3b and §3a refer to this as `F4_INVARIANT_REASON` — a legacy reference to a prior document's F4 designation. This umbrella renames the constant to `LABEL_BRIDGE_INVARIANT_REASON` to disambiguate from the recon's current-F4 (the private-record decode / HTTP-200-with-encoded-blob finding). Implementation applies the rename during v1.8.2 code work; all downstream references (backend.rs constant, ozone.rs return, per-release doc citations) track the rename.

**Capability family consumed:** the v1.8.2 per-release doc verifies which of Aurora's 19 advertised strings map here — expected candidates include `mod-events-emit-v1` (auto-advance) plus subject-status-related strings. Verification is v1.8.2's job.

#### §4.A.3 v1.8.3 — Read basics

**What ships.**

- `queryEvents` and `queryStatuses` outbound implementations. Trait grows new outbound-read methods (v1.7's `PdsAdminBackend` trait is action-verb-shaped — mutations plus `probe`, no cursor-paginated read surfaces per recon §3a); the trait extension is additive per §5.7.
- Cursor semantics against Aurora's cursor shape.
- Response shape parsing against Aurora's `PaginatedResponse<EventWithContext>` and `PaginatedResponse<StatusWithContext>`.
- `EventPayload` discriminator type — the umbrella-committed shape for representing Aurora's `emitEvent` variants as read-back — lands here, since v1.8.3 is the first consumer that has to render them from `queryEvents` output. v1.8.5 (write side) and v1.8.7 (batch) inherit this shape under §5.7's additive-only rule.

**Capability families consumed:** `moderator-activity-v1` (queryEvents, auto-advance). queryStatuses maps to a moderator-namespace read; specific string bound at per-release-doc time.

#### §4.A.4 v1.8.4 — Rich context

**What ships.**

- `getSubjectContext` (with the `include` opt-in joins), `getSubjectHistory`. These are the two rich-context endpoints Aurora actually exposes at v0.10 — F7 flagged that the umbrella's v6 assumed a three-way split (subject-context, subject-history, reporter-context) but v0.10 has no separate `getReporterContext` endpoint. v7 reflects this: v1.8.4 ships the two endpoints that exist.
- If reporter-pattern analysis is wanted, it's constructed cairn-mod-side from `queryEvents` and `queryStatuses` scoped by reporter, not from a dedicated Aurora endpoint.

**Umbrella-level directive on `include` vocabulary.** `getSubjectContext`'s `include` parameter is **closed-set as of v1.8.4** and explicitly excludes any value that would overlap with v1.8.3's `queryEvents` response shape, v1.8.5's `emitEvent` request/response shapes, or v1.8.6's `getAuditTrail` response shape. Rich context stays for hierarchical context; discriminated data lives in its own dedicated query.

**Capability families consumed:** `subject-context-v1`, `subject-history-v1` (both auto-advance).

#### §4.A.5 v1.8.5 — Action surface enrichment

**What ships.**

- Full `emitEvent` variant coverage beyond the five actions from v1.8.2. Aurora's `emitEvent` has 16 action variants at v0.10 (v9-corrected count against recon §1d's own enumeration; recon text says "17" but enumerates 16 — noted in §7 as a recon-side correction). The 16 variants: takedown/suspend/restore/**delete** account (4), apply/remove label (2), takedown record (1), quarantine/restore/delete blob (3), resolve/dismiss report (2), resolve/escalate appeal (2), send email (1), update subject status (1). v1.8.2 already lands the first three listed account-action verbs (takedown/suspend/restore account) plus apply/remove label at trait level; v1.8.5 lands the remaining 12 variants including the Admin-gated ones.
- `resolveAppeal` semantics — but not as its own trait method. F7 flagged that the v6 umbrella treated `resolveAppeal` as a distinct endpoint; recon confirmed it's an `emitEvent` action variant (`ResolveAppeal` / `EscalateAppeal`). v9 folds appeal resolution into cairn-mod's trait as an appeal-context method that dispatches through `emitEvent` internally.
- **Per-action role gating.** Aurora's `check_role` (`src/api/aurora_admin.rs:379-401`) gates two `emitEvent` variants at Admin+: `DeleteAccount` and `SendEmail`. All other variants — including `DeleteBlob` — permit Moderator+ per the namespace default. RustBackend surfaces role-insufficient dispatches through `BackendError::Auth` for the Admin-gated variants when cairn-mod's service DID holds only Moderator role. Per-release doc for v1.8.5 encodes this role matrix explicitly rather than assuming "all delete-shaped actions are Admin-gated."
- Cascading-actions handling: Aurora's emitEvent response includes a `cascadingActions` field on the wire (Rust type per recon §1a; exact struct name is per-release-doc territory). cairn-mod's action-response type surfaces cascades so operators see the full effect of a single dispatched action.
- **Blob-quarantine action** is included here as one of the 16 emitEvent variants — this is the *moderation surface* for blob quarantine, dispatched via `emitEvent`. Ops-endpoint-based blob quarantine (`tools.aurora.ops.quarantineBlob`, `restoreBlob`, `deleteBlob`) is a separate PDS-operator surface and is not consumed by v1.8; see §4.A.10 for the deferral.
- Per-release Ozone stub-add: `OzoneBackend` gains stubs returning `BackendError::CapabilityNotAdvertised` for every trait method added in v1.8.5 (per §5.7).

**Scope-honest sizing note.** v1.8.5 is the largest workstream-A release after v1.8.1. It ships 12 new trait methods (or 12 emitEvent action variants folded into a smaller number of trait methods with variant dispatch — the per-release doc picks the internal shape) plus per-action role handling plus cascading-actions surfacing. This is fine; scope-per-version is inviolable and v1.8.5's committed scope lands in v1.8.5. See §5.7 for the series-level trait sizing context in which v1.8.5's 12 methods sit. Naming the size honestly so future reviewers understand what the release contains.

**Capability families consumed:** the remaining `emitEvent`-related strings from Aurora's 19. Classification: opt-in for variants where semantic-break risk is highest (per-release-doc call).

#### §4.A.6 v1.8.6 — Audit verification

**What ships.**

- `getAuditTrail` outbound. Response shape binds to Aurora's `GetAuditTrailOutput` — `items`, `cursor`, plus the three chain-verify fields `chainVerified`, `chainVerifiedThrough`, `chainLegacyCount` (recon §1g).
- Hash-chain verification cairn-mod-side. Aurora's `getAuditTrail` folds verification inline (there is no standalone verify endpoint, recon §1g); cairn-mod consumes those inline results and additionally implements its own re-verification pass on the returned entries. The re-verification implements both the current v0.9-format canonical hash and the pre-v0.9 legacy fallback (F18) so cairn-mod can verify across the format bump.
- `getAuditEntry` outbound for single-entry lookup.
- The cross-chain-verify **claim is scoped**. F3 established that Aurora's kryphocron audit events live in a separate, non-hash-linked `moderation_event` store — invisible to `getAuditTrail`/verify. v1.8.6 verifies Aurora's mod-event audit chain; kryphocron events are explicitly out of scope for v1.8.6's cross-chain-verify, and v1.8.14's Workstream B design accommodates this.

**Capability family consumed:** `audit-trail-v1` (opt-in).

#### §4.A.7 v1.8.7 — Batch

**What ships.**

- Batch outbound support for the actions Aurora exposes as batch endpoints. F7 flagged that the v6 umbrella assumed a single `batchEmitEvents` endpoint; recon confirmed Aurora exposes six discrete batch endpoints (`batchTakedown/Suspend/Restore Accounts`, `batchTakedownRecords`, `batchApply/RemoveLabel`) plus multi-subject `emitEvent`. v7 reflects this: cairn-mod's batch surface dispatches to the appropriate Aurora batch endpoint per action type, and falls back to multi-subject `emitEvent` where no dedicated batch endpoint exists.
- Batch atomicity model: **whole-transaction, all-or-nothing** (recon §1f). F9 flagged that Aurora's v0.2 partial-success contract was removed — no `failures[]` returned; a single-subject failure aborts the whole batch. cairn-mod's batch trait surfaces this: no per-subject success/failure map, one whole-batch outcome, error carries the failing index + identifier.
- Aurora enforces a 50-item batch cap on the legacy batch family (recon §1f; specific constant name is per-release-doc territory as it's implementation-side). Batches larger than 50 are split cairn-mod-side into 50-item chunks.
- Per-action size limits for `emitEvent` batches: `DeleteAccount = 10`, `DeleteBlob = 25`, others 50 (recon §1f).
- `BackendActionId::PerBatch` gains its first producer here (recon §3d — the variant existed but no code path constructed it).

**Capability families consumed:** `batch-takedown-v1` and related batch-family strings (all opt-in).

#### §4.A.8 v1.8.8 — Realtime

**What ships.**

- `subscribeModEvents` WebSocket consumption. cairn-mod grows a WS client that subscribes to Aurora's event stream and surfaces events into cairn-mod's internal moderation surfaces.
- Cursor persistence. F10 flagged that Aurora's subscription is **at-most-once**, not at-least-once — a mid-stream disconnect drops the in-flight row permanently. cairn-mod's cursor design accommodates this: cursors are persisted before the next poll, not after ack. Missed events are recovered via `queryEvents` reconciliation.
- Reconnect and outdated-cursor handling. When Aurora emits `outdatedCursor`, cairn-mod re-bootstraps via `queryEvents` from a cairn-mod-side high-water mark and resubscribes.
- Heartbeat handling (30-second interval per Aurora).
- Optional `includeAuditChain` support — Aurora's stream can co-deliver audit-chain entries. cairn-mod's default is off (audit chain is v1.8.6's territory); operator can opt in.

**Capability family consumed:** `mod-events-stream-v1` (opt-in).

#### §4.A.9 v1.8.9 — Ops and runtime

**What ships.**

- `getInstanceMetrics` outbound. F7 flagged that Aurora exposes this under `tools.aurora.ops.*`, not `tools.aurora.admin.*` as the v6 umbrella assumed. v7 reflects this — the endpoint is dispatched against the ops namespace and requires the appropriate scope.
- Moderator-activity views built on `queryEvents` scoped by actor DID (Aurora exposes `moderator-activity-v1` as a capability but the underlying endpoint is queryEvents-shaped, recon §3j).
- `getRuntimeSetting` and `setRuntimeSetting` outbound. F7 flagged that these require **`AdminServer`** scope (not `AdminModeration`) and SuperAdmin for writes (recon §1a, §1h). *(v1.8.11 reconciliation:* shipped enforcement is the OAuth-namespace-layer scope gate — Aurora `oauth/scope.rs:831` `TOOLS_OPS_REQUIRED = [AdminServer]` consumed by the namespace middleware — plus per-handler role floors; there is no per-endpoint scope check, and service-auth JWT callers are gated by role floors alone.)* v10 acknowledges: cairn-mod's Rust-backend service DID must hold the corresponding role for read/write, and setRuntimeSetting will 403 unless the role is SuperAdmin. cairn-mod surfaces this as `BackendError::Auth`.
- The runtime-setting surface cairn-mod cares about most: `moderation-mode`. F16 flagged that Aurora's Mode-3 disable is partial — `reduced` and `disabled` are indistinguishable to the substrate, and `AURORA_RECOVERY_MODE=true` can silently force mode back to `full`. cairn-mod reads the setting for operator visibility but doesn't assume mode-based enforcement; cairn-mod's outbound dispatches through Aurora's `emitEvent` work regardless of Aurora's mode (recon §1d).

**Capability families consumed:** `instance-metrics-v1`, `moderator-activity-v1` (both auto-advance), `runtime-settings-v1` (opt-in).

#### §4.A.10 v1.8.10 — Operator extensions

**What ships.**

- Starter subset of `tools.aurora.ops.*` — 5–10 endpoints from the pool of 55 (F1). Specific list is v1.8.10's per-release doc call; the umbrella commits to a shape rather than an enumeration.
- **Umbrella-level shape directive.** The starter subset targets the "operator visibility" subcategory, not the "operator action" subcategory. Concretely: system-health probes, sequencer status (read-only), federation status, blob statistics, database status, resource usage, plus `getInstanceMetrics` (already consumed by v1.8.9's `instance-metrics-v1`) and `getRuntimeSetting` (already consumed by v1.8.9's `runtime-settings-v1`) which are implicitly committed by the earlier release's consumption. Excluded from v1.8.10 scope: any endpoint that mutates PDS state (`pauseSequencer`, `resumeSequencer`, `resetSequencerCursor`, `rebuildSequencer`, `triggerPdsDiscovery`, `cleanupNonceStores`, `runBlobGC`, federation-peer mutations, relay-URL mutations).
- **Blob-quarantine ops endpoints deferred.** `tools.aurora.ops.quarantineBlob`, `restoreBlob`, and `deleteBlob` (recon §1a) are not consumed by v1.8.10. Blob-quarantine as a *moderation action* is dispatched through `emitEvent` per §4.A.5 (v1.8.5); the ops endpoints are the *PDS-operator surface* for the same underlying capability, targeting operational blob-lifecycle management outside the moderation context. Cairn-mod's moderation-service identity aligns with the emitEvent path; the ops path is deferred post-v1.8 alongside other operator-action endpoints.
- Ops surface auth: the `AdminServer` scope requirement is enforced at the OAuth-namespace layer (see the §4.A.9 reconciliation note); the shipped visibility handlers carry no per-endpoint role floors at v0.11, so a service-auth (role-granted) DID reads them today. cairn-mod's degradation posture stands for any future upstream tightening. If cairn-mod's DID only has Moderator or Admin roles, the ops probes return `BackendError::Auth` and cairn-mod's console surfaces degrade gracefully.
- `describeCapabilities` collapse behavior (F19). Aurora's advertised method names for `ops.kryphocron.*` and `ops.themes.*` sub-namespaces collapse to bare leaf names (recon §1b). cairn-mod's capability-discovery layer treats the advertised list as advisory, not authoritative — the actual endpoint enumeration comes from the per-release-doc bound NSID list, not from `describeCapabilities` parsing alone.
- Per-release Ozone stub-add: `OzoneBackend` gains stubs returning `BackendError::Unsupported` for every trait method added in v1.8.10 (per §5.7). *(v1.8.11 reconciliation:* `Unsupported` is the settled shipped convention across the trait; taxonomy at series close is 41 `Unsupported` / 2 `ArchitecturallyForbidden` (§F4 label methods) / 0 `CapabilityNotAdvertised`.)*

**Capability families consumed:** none new — *(v1.8.11 reconciliation)* the core admin ops block ships capability-bare (`CapsBuilder::new(Family::Ops)`, no extension strings; `instance-metrics-v1` is the single exception, consumed at v1.8.9). The endpoint contract is the per-release-doc bound NSID list per §5.3/F19; v1.8.10 added zero registry entries by fidelity to source.

#### §4.A.11 v1.8.11 — Series wrap

**What ships.**

- Reconciliation of any per-release-doc findings that surfaced umbrella-level revision needs. Umbrella revision tracking follows §11.
- `[pds_admin.locus]` disposition *(v1.8.11 reconciliation)*: the rename to `[pds_admin.rust]` shipped **fully** at v1.8.1 (not "partly done") — the `LocusBlockRenamed` migration error is a fully-shipped deprecation aid, and v1.8.11 **retains** it (removing the aid would replace a precise operator-facing rename error with a silent ignore).
- Documentation: `RustBackend` operator-facing docs, config reference, capability-family reference, migration notes for operators moving from OzoneBackend to RustBackend against a Rust PDS. **Operator-facing kryphocron threat-model section required, ships §5.4.1's canonical statement verbatim in the README.** The technical claim lives in §5.4 and §5.4.2; the operator-facing statement in §5.4.1 is what appears in the shipped README so operators encounter it before configuring Workstream B. Per-release docs cite §5.4.1 rather than re-explaining.
- Required: a compatibility-check CLI subcommand (`cairn pds-admin probe`) that runs `describeCapabilities` against a configured Rust PDS and reports the capability-family match to cairn-mod's expected registry. Given §5.3's advisory-not-authoritative position and `describeCapabilities`'s load-bearing role in gating Workstream B, this CLI is the operator's only tool for verifying their PDS advertises the capability strings cairn-mod expects. Ships as part of series wrap so it can enumerate every registered capability from all v1.8 releases.

- *(scope inclusion, v1.8.11)* Item 9: removal of the deprecated `acknowledge_v1_8_1_audit_divergence` field (WARN-deprecated since v1.8.6; the v1.8.6 sunset lock named v1.8.11). Item 10: rename of the two stale `…IncompatibleWithInspectorRustBackend` error variants to `…IncompatibleWithRustBackend` (the inspector posture ended at v1.8.2; Parts 2/3 remain live). Item 11: CHANGELOG humanization — the `[Unreleased]` block becomes the dated `[1.8.0]` section with per-release subsections retained.

**Capability families consumed:** none new. This is documentation and cleanup.

### §4B — Workstream B: kryphocron and laquna consumption

Four releases, v1.8.12 through v1.8.15. All four are gated on Workstream A's v1.8.1 landing first — Workstream B builds on RustBackend's foundation (`describeCapabilities` parsing, ES256K service-auth, capability-family plumbing). Additional Workstream A prerequisites specific to individual Workstream B releases: **v1.8.14 depends on v1.8.3 (`queryEvents` outbound) and v1.8.8 (`subscribeModEvents` WS stream)** because v1.8.14's `queryEvents` surface additions and content-tier discriminator on WS events extend both surfaces, and both surfaces must exist before extension. Scope-per-version is inviolable: v1.8.14 does not partial-ship, does not split into v1.8.14a/b, does not defer any of its five committed items to a later release. It ships when v1.8.1 + v1.8.3 + v1.8.8 are all landed. This is a real gate on scope, not a coupling artifact — items 1–3 (cairn-mod-side audit-chain variants, F3 scope-honor, F14 scoped-partial framing) could technically ship without v1.8.3 or v1.8.8, but the release's committed scope includes items 4–5 (`queryEvents` surface additions, content-tier discriminator) which cannot. Other Workstream B releases have no additional Workstream A dependencies beyond the v1.8.1 foundation. Beyond these documented gates, Workstream B releases can interleave with Workstream A per per-release-doc scheduling.

**Threat-model note baked into every Workstream B release.** F5 established that laquna is not encryption: the encoded content on kryphocron records can be decoded client-side with a stock `laquna/0.2` substrate over fully public inputs (`seed = did||nsid||rkey`, rotation slug self-stamped on the record). The audience gate is a **friction property, not confidentiality.** cairn-mod being able to decode reported private content is what makes moderation possible; that this decoding does not require Aurora's permission is a substrate-level property, not a cairn-mod capability we invent. Every Workstream B release respects this in its scope, error semantics, and documentation.

The threat model is also honest about what cairn-mod is not: cairn-mod does not enforce "who *should* read what." That's the operator's deployment concern. cairn-mod exposes what it can decode, and the operator decides whether the deployment topology (whose PDS it points at, which DIDs are granted `admin_roles`) makes those decodings legitimate.

#### §4.B.1 v1.8.12 — Substrate consumption

**What ships.**

- kryphocron added as a cairn-mod dependency, pinned to the same major that Aurora-Locus consumes (currently `kryphocron = "0.3.1"`, `kryphocron-lexicons = "0.3"` per recon §2a). Version pinning updates track Aurora's pinning conservatively; cairn-mod does not lead the substrate version.
- Substrate initialization at cairn-mod startup. Because cairn-mod is not a PDS and does not persist records at rest, the standard `AtRestHooks` install site does not apply. cairn-mod instantiates a `laquna::Codec` directly with default `SeedPolicy::DidNsidRkey` (recon §2f) for decode-only use.
- `describeCapabilities`-based kryphocron detection. Aurora advertises **three** kryphocron-family capability strings at v0.10 (recon §1b): `kryphocron-rotation-v1`, `kryphocron-read-v1`, `kryphocron-overrides-v1`. All three are added to cairn-mod's `CAPABILITY_CLASSIFICATIONS` registry; RustBackend queries for their presence on probe. Kryphocron detection gates Workstream B behavior on `kryphocron-read-v1` specifically (the read capability is the load-bearing one for cairn-mod's decode path); the other two surface operator-visibility controls.
- **Absence of audience/audit-specific capability strings.** Aurora advertises no `kryphocron-audience-v1`, no `kryphocron-audit-v1`, no `kryphocron-decode-audit-v1`. This is aligned with the substrate's actual v0.10 shape (recon §2b, §2e — no audience-query API, no decode-audit event). cairn-mod's audience-inference (via response-shape at getRecord, per §5.4) and audit-recording (via cairn-mod's own chain at v1.8.14) are therefore **not** capability-gated — they operate whenever `kryphocron-read-v1` is advertised, regardless of any finer-grained kryphocron capability advertisement.
- No decode operations yet at v1.8.12. This release just wires the substrate and the detection.
- Config surface. The `[pds_admin.rust.kryphocron]` subsection surfaces operator controls: whether to enable kryphocron consumption if capabilities are advertised, the **client-side decode scope per §5.4.2** (best-effort default vs server-side-only opt-in), and (for future-cycle use) whether to record kryphocron audit events into cairn-mod's chain.

**Capability family consumed:** the three kryphocron-family strings noted above; detection only, no consumption yet.

#### §4.B.2 v1.8.13 — Report-flow private-record retrieval

**What ships.**

- Third `ReportSubject` variant added to cairn-mod's report intake (recon §3h). The current two variants — `RepoRef` and `StrongRef` — extend with a **`KryphocronRecord`** variant that carries the AT-URI, CID, and the kryphocron-family lexicon NSID. Per §3, kryphocron is named directly in cairn-mod's kryphocron-consumption surfaces; the variant name is not hedged. The `subject_type` column gains a `kryphocron_record` discriminator. **Migration shape:** the `subject_type` column is CHECK-constrained to `('account', 'record')` in the current schema, so adding `kryphocron_record` requires a constraint-migration table rebuild (drop-and-recreate the `reports` table with the extended CHECK, copy data, swap) — not a plain `ALTER TABLE ADD` or a data-only insert. v1.8.13's per-release doc details the migration; the umbrella just names the shape so per-release drafting knows to plan for a rebuild-shaped migration rather than an additive one.
- Report-open handler grows a kryphocron branch. When a report's subject is a `tools.kryphocron.feed.postPrivate` record (the only kryphocron-family record NSID Aurora exposes at v0.10 per recon §2d; if future kryphocron cycles add more, cairn-mod's per-release doc handles enumeration):
  - cairn-mod issues `com.atproto.repo.getRecord` against the PDS. **Auth model:** ES256K service-auth JWT per §5.1, with `lxm = com.atproto.repo.getRecord` — set per §5.1's convention (`lxm` binds the token's `exp` cap to 1 hour; Aurora does not enforce lxm-vs-endpoint matching). The JWT authenticates cairn-mod's service DID; Aurora's audience check runs against that DID per recon §2b/§2h. If cairn-mod's service DID happens to be in the record's audience (unlikely but possible for same-operator deployments), Aurora returns `text` (server-side decoded); otherwise Aurora returns `encodedContent` (HTTP 200 either way — no denial signal, per recon-F4).
  - If Aurora returns the record with `text` populated, cairn-mod uses that plaintext directly.
  - If Aurora returns the record with `encodedContent`, cairn-mod attempts client-side decode with its stock `laquna/0.2` substrate. The substrate's decode function takes the record's `encodedContentGeneration` (slug self-stamped) and the record coordinates (`did`, `nsid`, `rkey`) as inputs; seed derivation is internal to laquna, not something cairn-mod computes (recon §2f, §2h). No hidden inputs; all values come from the record and its AT-URI.
  - Either path yields plaintext; cairn-mod stores the decoded plaintext in the report queue, with a `decode_source` field indicating whether it came from Aurora's server-side decode or cairn-mod's client-side decode.
- `BackendError` gains `KryphocronDecodeFailed { codec_id_unknown | codec_error }`. Previously-drafted `rotation_slug_recovery_failed` and `seed_derivation_failed` variants dropped: laquna's decode entry point takes raw record coordinates and returns either the plaintext or a structural decode error (there is no separate slug-recovery or seed-derivation error path exposed to callers). Slug parsing from `encodedContentGeneration` is a string-format check that either succeeds or produces a codec-level failure; seed derivation happens inside laquna over raw inputs and can't produce a distinct caller-visible error. The two failure modes surfaced are (a) codec ID unknown to cairn-mod's installed substrate, (b) laquna's decode call returns an error for any other structural reason. F4 established that Aurora's unauthorized read returns HTTP 200 with encoded content — not an error — so cairn-mod treats that path as a normal encoded-response, not an error.
- `KryphocronCodecUnavailable` mapping. Aurora returns HTTP 410 with this error when authorized decode hits codec skew (recon §2d). cairn-mod maps this to `KryphocronDecodeFailed::codec_id_unknown` and can attempt its own decode if the stored `encodedContentCodec` matches its installed codec.
- Report queue UI surfacing. Decoded content is surfaced to moderators as normal report content, with an indication that the content was originally private and was decoded by cairn-mod.

**Capability family consumed:** `kryphocron-read-v1` (opt-in — private-content decode is a deliberate operator choice).

#### §4.B.3 v1.8.14 — Kryphocron audit-chain events

**What ships.**

- cairn-mod's own audit chain gains kryphocron-scoped event variants. These are **greenfield event types** — cairn-mod's audit chain at v1.7 has no analogous decode-tracking or content-tiered event variants, so v1.8.14 defines the shape rather than inheriting an existing pattern. **Naming convention:** the tier is encoded as a `content_tier` field on generic variants, not baked into variant names as `Private*`. Concretely: `RecordDecoded { moderator, subject, report_id, codec_id, decode_source, content_tier }` and `ModerationApplied { moderator, subject, action_type, content_tier }`. Where `content_tier: private` for kryphocron-encoded content and other values (`public`, or future kryphocron tiers if kryphocron adds them) as appropriate. Design rationale: this aligns with §5.5's emitEvent-unification pattern (verbs are enum variants, discriminators are fields) and avoids the redundancy of both `Private*` prefix and `content_tier` on the same event. These entries participate in cairn-mod's own hash chain and are covered by `cairn audit verify`. Per-release doc for v1.8.14 details the schema-migration shape (append-only additions, no CHECK constraint update needed on the audit tables per recon §3g).
- F3's scope constraint honored. Aurora's kryphocron audit events live in a separate, non-hash-linked `moderation_event` store (recon §1g, §2e). v1.8.14 **does not** attempt cross-chain-verify of kryphocron events against Aurora's hash chain — the two chains cover disjoint subject matter. cairn-mod's chain covers cairn-mod's actions; Aurora's chain covers Aurora's mod-event actions; kryphocron events on Aurora's side are queryable via `queryEvents` and the WS stream (v1.8.8) but are not tamper-evident on Aurora's side.
- F14's gap noted but not filled. Aurora records no persisted decode-read event of its own; only in-memory counters and a `tracing::debug` line (recon §2e). cairn-mod recording its own decode events is **scope-partial compensation**: complete within cairn-mod's own consumption (cairn-mod's chain shows what cairn-mod decoded and when), silent about other Aurora consumers who don't record their own reads. The substrate-level gap remains — an operator still has no PDS-side accounting of read-time decodes by any consumer. §7 flags this as a substrate-level concern to raise with kryphocron upstream, not a cairn-mod v1.8 fix.
- `queryEvents` surface additions. Kryphocron mod events flow through Aurora's `queryEvents` in the `moderation_event` store, so cairn-mod's outbound `queryEvents` gains support for the kryphocron event variants in its filter and response vocabulary. The gateway inbound `queryEvents` (cairn-mod's own read surface) grows corresponding projections.
- Content-tier discriminator. Events touching private content carry a `content_tier: private` flag so moderator UIs can render kryphocron-scoped mod actions with appropriate visual distinction.

**Capability family consumed:** `kryphocron-read-v1` (already added at v1.8.13); the v1.8.14-specific additions are cairn-mod-side.

#### §4.B.4 v1.8.15 — Laquna-specific handling

**What ships.**

- Codec-version handling. Records carry `encodedContentCodec` (currently `laquna/0.2`, recon §2g). cairn-mod's decode path pattern-matches on the codec ID and dispatches to the appropriate substrate version. For a future `laquna/0.3` cutover, cairn-mod's forward-compat surface accommodates the new codec without breaking on `laquna/0.2` records.
- Rotation-slug recovery from record. F confirmed the slug is self-stamped in `encodedContentGeneration` in the form `laquna/{unix_secs:020}/{hex64_slug}` (recon §2c). cairn-mod's decode path parses this format and hands the slug to the substrate. No rotation-oracle call needed for read-side decode; Aurora's rotation-oracle admin endpoints (`getRotationStatus` etc.) are for operator visibility, not for cairn-mod's read path.
- Codec-skew error semantics. If the stored `encodedContentCodec` is a codec cairn-mod doesn't have installed, cairn-mod surfaces `BackendError::KryphocronDecodeFailed::codec_id_unknown` (defined at v1.8.13). The report can still be filed; the private content is just not decoded — the report shows the encoded blob metadata (codec ID, generation) so the moderator knows why decode failed.
- Rotation cadence awareness. Aurora's rotation cadence is operator-controlled (recon §2c); cairn-mod does not assume any cadence, does not track rotation timing, and does not participate in Aurora's rotation lifecycle. cairn-mod's decode is per-record; each record carries its own generation mark.

**Capability family consumed:** `kryphocron-rotation-v1` for operator-visibility reads of Aurora's rotation state, if desired; the core decode-time slug recovery uses no admin capability at all (the slug is on the record).

---

## §5 — Cross-cutting decisions

### §5.1 Authentication model

**RustBackend authenticates via ATProto ES256K service-auth JWTs.** No OAuth, no client-credentials flow, no admin OAuth loopback. Per-call JWT signed with cairn-mod's secp256k1 private key.

Justification against F2. Recon §1c established that Aurora-Locus's auth ladder for external services terminates at layer 4 (`verify_service_jwt`) — the ES256K path. Aurora's admin OAuth (Phases 1–3) is a browser-loopback operator-login ceremony that doesn't apply to service consumers. cairn-mod's v1.7-era config committed to OAuth 2.1 client-credentials, but Aurora exposes no such surface. Rather than requesting Aurora grow a machine-to-machine OAuth surface (evaluated: no meaningful benefit over service-auth; second auth path to maintain; documentation confusion; scope-enforcement upgrade needed), cairn-mod adopts the shipped ES256K path.

**cairn-mod's obligations under this model.**

- A published DID document with an `#atproto` verification method (secp256k1 public key). The DID doc URL is in cairn-mod's config; how cairn-mod's operator publishes and serves the DID doc is deployment-topology-specific (may be via `did:web` on the operator's domain, `did:plc` via the PLC registry, or another resolvable DID method).
- A secp256k1 private key held in an env var or file-referenced-by-env-var, per the same shape as v1.7's `AdminPassword` newtype (recon §3e). cairn-mod does not persist the key across restarts unless the operator explicitly configures a persistent store; env-var-and-reload is the default.
- A per-call JWT-minting function: `iss` = cairn-mod's service DID, `aud` = the target PDS's service DID (retrieved from PDS config or discovery), `alg` = `ES256K`, `exp` ≤ 1 hour, `lxm` = the target NSID for the call. Fresh JWT per call; no caching, no refresh. **Note on `lxm` semantics:** cairn-mod includes `lxm` in every service-auth JWT per ATProto convention, which ties the token's `exp` binding to the method being called (a token with `lxm` present is capped at 1 hour; a token without `lxm` is capped at 1 minute per Aurora's `verify_service_jwt`). Aurora does not enforce that `lxm` matches the endpoint being called — the `lxm`-vs-endpoint match is a caller-side convention, not a server-verified constraint. cairn-mod includes `lxm` per convention and for the 1-hour `exp` binding; it does not rely on Aurora rejecting mismatched `lxm`.

**cairn-mod's Rust-backend service DID must hold a role in Aurora's `admin_roles` table** — `Moderator`, `Admin`, or `SuperAdmin` per the operation. This grant is issued out-of-band (via Aurora's `superadmin.grantRole`); cairn-mod does not self-provision. Cairn-mod's operator documentation covers the grant procedure.

**Aurora's scope-vs-role split.** Recon §1c noted that scope checks (`atproto:admin.moderation`, etc.) are enforced only on OAuth-authenticated requests; service-auth callers pass the scope layer and are gated solely by `admin_roles`. cairn-mod's Rust-backend design treats the role as authoritative for authorization; scope references in comments and config are informational only.

**DPoP not required.** Aurora's DPoP proof-of-possession is enforced only for OAuth-bound tokens (recon §1c). Service-auth JWTs skip DPoP entirely.

**Step-up and TOTP not applicable.** Step-up auth (recent `authenticated_at` window) and TOTP are session-machinery for Aurora's own operator sessions (recon §1c). Service-auth callers have no session in Aurora's session table, and the endpoints cairn-mod calls (`emitEvent`, query/read surfaces, batch endpoints, audit-trail surfaces) are not step-up-gated.

### §5.2 Config model

`[pds_admin]` selector and backend blocks per v1.7 shape (recon §3f); RustBackend's block is `[pds_admin.rust]`.

`RustBackendConfig` v7 shape:

- `pds_url: Url` — the target Rust PDS base URL.
- `service_did: String` — cairn-mod's service DID (the `iss` used in JWT minting). Literal DID string; no env indirection (a DID is not secret material).
- `service_signing_key_env: String` — env-var name holding the secp256k1 private key. The `_env` indirection mirrors v1.7's `AdminPassword` pattern for secret material (recon §3e).
- `service_did_document_url: Option<Url>` — where cairn-mod's DID doc is resolvable, if not derivable from the DID method. Required for `did:web`, optional for `did:plc` (resolvable via PLC directory).
- `target_service_did: String` — the target PDS's service DID (used as `aud`). **Mandatory operator-configured field.** The recon documents no discovery endpoint on Aurora for retrieving a PDS's service DID at runtime; rather than invent one, cairn-mod requires operators to configure the target DID explicitly alongside the target PDS URL. Operators deploying cairn-mod against a specific PDS already know that PDS's URL; also knowing its service DID is a minor additional lift.
- `request_timeout: Duration` — same shape as `OzoneBackend`.
- `capability_refresh_interval: Duration` — how often to re-probe `describeCapabilities`. **Semantics (v9-corrected):** the re-probe detects version advances and disappearances **within capability families cairn-mod's registry already knows about**. Unknown newly-advertised families are ignored for consumption but fire a **structured operator-visible warning** in cairn-mod's logs. The warning is standardized across the series: `WARN cairn_mod::pds_admin::rust::capability: PDS advertises capability family "<family-vN>" not in cairn-mod's registry; consider upgrading cairn-mod to consume it` (exact string subject to per-release-doc refinement; the shape — warning-level, source `pds_admin::rust::capability`, family name in quotes, upgrade suggestion — is series-locked). Per-release docs use this exact log shape when documenting capability-registry additions so operators see a consistent warning pattern. This is not "unchanged from v1.7"; v1.7 had no producing consumer for the field (recon §3c, F11), so any semantics are net-new — v9 states them explicitly rather than inherit them.
- `required_capabilities: Vec<String>` — capability strings the operator declares this backend depends on; startup fails if not advertised.
- `pinned_versions: BTreeMap<String, String>` — opt-in version pinning per capability family (see §5.3).
- `verification_persist: bool` — retained from the v7-superseded config as parse+store (the field validates and persists per `validated_rust_from_toml`, no consumer wired yet). Consumer lands in v1.8.6 alongside audit-trail work — v1.8.6's per-release doc details the wiring. This is not "production-quality enforcement" at v1.8.1; it's a config surface reserved for a future consumer.
- `acknowledge_v1_8_1_audit_divergence: bool` — shipped at v1.8.1 with the three-gate boot inspector in force; *(v1.8.11 reconciliation)* advisory-WARN only since v1.8.6, field removed at v1.8.11 (Parts 2/3 of `validate_audit_divergence_acknowledgment` remain).
- `[pds_admin.rust.kryphocron]` sub-block — added at v1.8.12 for Workstream B controls.

The v7 fields **replace** v1.7's OAuth-model residue (`client_id`, `client_secret`, `scopes`). Fields not listed as replaced are retained. Since the OAuth-shaped RustBackend never shipped to any live deployment, the field-replacement break is safe.

### §5.3 Capability model

**Capabilities are wire strings advertised by the PDS in `describeCapabilities`.** Aurora's scheme is flat kebab-`vN` (recon §1b, F7). cairn-mod's `Capability` type stores the string as-received; version parsing splits on the last `-v` and yields a `CapabilityVersion(u32)`.

**Version selection.** For each capability family cairn-mod's RustBackend supports:

1. If the PDS advertises `-v1` and `-v2` and RustBackend supports both, RustBackend uses `-v2` (auto-advance) unless operator has pinned.
2. If the PDS advertises only `-v2` and RustBackend supports `-v2`, RustBackend uses `-v2` without operator intervention.
3. If the PDS advertises only `-v2` and RustBackend supports only `-v1`, this is a cairn-mod-side gap; §5.6 degradation applies.
4. If the PDS advertises only `-v1` and RustBackend supports both, RustBackend uses `-v1`.
5. If neither version is advertised, the capability is absent and §5.6 degradation applies.

**Classification.** Each capability family is either `AutoAdvance` (default; `-v2` takes priority over `-v1`) or `OperatorOptIn` (operator must pin to advance). Classification lives in a const registry (`CAPABILITY_CLASSIFICATIONS`, recon §3c). v1.8.1 populates the registry from the empty scaffold; subsequent releases add entries.

**Advertisement authoritativeness.** Aurora's `describeCapabilities` is not a full endpoint enumeration (F19 — sub-namespace paths collapse; `lexicon.*` endpoints are unadvertised). cairn-mod's discovery layer treats the advertised list as a capability-detection signal, not an endpoint index. Per-release docs bind NSIDs from cairn-mod's own registry, not from `describeCapabilities` parsing alone.

**Practical impact.** cairn-mod maintains its own NSID registry compiled into the build. cairn-mod knows about, e.g., `tools.aurora.ops.kryphocron.getOracleActivity` because that NSID is in the registry, not because Aurora advertises `getOracleActivity` under a `kryphocron` sub-family. Every new Aurora endpoint cairn-mod wants to consume requires either a fresh Aurora surface recon that identifies the endpoint or a compile-time addition to cairn-mod's registry — Aurora advertising a new capability string alone is not sufficient. This is the correct trade-off for cairn-mod's use case (a moderation service consuming a stable, versioned admin surface) but it does mean Aurora's advertising system and cairn-mod's registry evolve in lockstep, not independently.

**Expected release cadence coupling.** Aurora minor releases that add capability strings cairn-mod cares about require a cairn-mod release cutting to consume them. Aurora minor releases with no such additions require no cairn-mod work. Realistic cadence: cairn-mod releases lag Aurora minors by approximately 1 cycle on the auto-advance path — Aurora ships v0.N with new capabilities, cairn-mod's next release consumes them. Operators running cairn-mod against an Aurora that's advertising capabilities cairn-mod hasn't consumed yet see operator-visible warnings (per §5.2's `capability_refresh_interval` semantics) but the mismatch is otherwise silent and non-blocking — cairn-mod continues to operate against the capabilities it does know about.

**cairn-mod-side capability families.** The umbrella commits to using capability strings only when Aurora advertises them for a family cairn-mod cares about. When cairn-mod adds behavior that has no corresponding Aurora capability advertisement (e.g. cairn-mod's own kryphocron audit-event variants at v1.8.14), that behavior is not capability-gated on Aurora's side; it's gated on cairn-mod's own config.

### §5.4 Kryphocron consumption model

**cairn-mod consumes kryphocron as a client-side substrate for decode.** Not as a PDS-side substrate for storage; cairn-mod is not a PDS.

**Decode is best-effort at the PDS boundary.** When cairn-mod fetches a `tools.kryphocron.feed.postPrivate` record via `getRecord`:

- If the PDS returns `text` (server-side decoded for an authorized reader), cairn-mod uses `text` directly. No substrate work needed.
- If the PDS returns `encodedContent`, cairn-mod attempts client-side decode with its own substrate — **subject to §5.4.2's decode-scope operator policy.** Decode succeeds when the codec ID matches cairn-mod's installed codec (currently `laquna/0.2` — see F5, §2h).

**The audience gate is a friction property, not confidentiality.** F5 established this at the substrate level. cairn-mod's design honors it: cairn-mod can decode what it can fetch, whether or not the operator's DID is in the record's audience. Whether cairn-mod *should* decode a given record is the deployment operator's concern, not cairn-mod's.

**cairn-mod does not enforce federation-topology-based decode gates.** F5 and cairn-mod's general-purpose scope both preclude "refuse to decode if cross-operator." cairn-mod does not know what "cross-operator" means in any deployment; that concern belongs to the deployment operator, not to cairn-mod's design.

**cairn-mod does not participate in kryphocron's write path.** cairn-mod does not encode records, does not participate in Aurora's rotation cadence, does not implement `AtRestHooks`. cairn-mod is decode-only.

**Kryphocron authorization surface.** F13 flagged that Aurora exposes no request-time authorization query API — the only signal is issuing `getRecord` and inspecting whether `text` or `encodedContent` came back. cairn-mod's design uses this signal: the decode branch checks response-shape (presence of `text` vs `encodedContent`), not any separate authorization endpoint.

### §5.4.1 Operator-facing threat-model statement (canonical)

This is the canonical wording cairn-mod's operator-facing documentation (README, per-release docs, deployment guides) inherits when discussing kryphocron consumption. Per-release docs cite this section rather than re-explaining. v1.8.11's series-wrap documentation ships this language verbatim in the README.

> **On decoding private content: what cairn-mod can and does read.**
>
> When paired with a kryphocron-enabled PDS, cairn-mod can decode private-tier content it can fetch, regardless of whether the operator DID is in the record's audience list on the PDS side. This is a substrate property, not a cairn-mod design decision: kryphocron's default codec (laquna) is a friction-encoding scheme, not encryption. Its decoder is publicly available, its seed derives from the record's public metadata (`did || nsid || rkey`), and the rotation slug is embedded in the record itself. Any consumer holding the encoded bytes plus a stock laquna substrate can reconstruct the plaintext.
>
> Whether cairn-mod *should* decode any given record is the deployment operator's concern. cairn-mod does not enforce federation-topology-based decode gates, does not distinguish "internal" from "cross-operator" content, and does not implement confidentiality guarantees on private-tier content it processes.
>
> Operators wanting cairn-mod to only work on content the PDS has explicitly authorized can enable server-side-only mode per §5.4.2 — this constrains cairn-mod to consume only the plaintext Aurora returns as `text`, refusing to client-side-decode any `encodedContent` the PDS returned. Server-side-only mode is a coherent posture for operators whose service DID has been added to record audiences on the PDS side.
>
> Operators wanting substrate-level confidentiality on private-tier content need a different substrate. laquna does not provide it and cairn-mod does not simulate it.

### §5.4.2 Client-side decode scope: operator policy

cairn-mod supports two operator postures on client-side decode:

- **Best-effort (default).** cairn-mod attempts client-side decode when the PDS returns `encodedContent`. This is the default because it makes moderation possible on private-tier content the operator is legitimately responsible for. Recognizes that PDS-side authorization is a friction property (§5.4.1) and treats the encoded blob as decodable given the substrate.

- **Server-side-only.** cairn-mod refuses to client-side-decode; only content Aurora returns as `text` reaches the report queue as plaintext. When the PDS returns `encodedContent`, cairn-mod stores the encoded blob metadata (codec ID, generation) in the report queue without decoding. Reports on private content the moderator's DID isn't authorized to read on the PDS side become unactionable-until-authorized, which is what some operator postures want.

The posture is set at the `[pds_admin.rust.kryphocron]` config layer (v1.8.12 wires it). Default is best-effort; server-side-only is opt-in. The choice does not affect PDS-side behavior — Aurora's audience gate is unchanged either way.

Operators running server-side-only against a PDS whose audience oracle doesn't include the cairn-mod moderator DID will see many reports arrive without decoded content. That is the intended behavior for that posture; the operator's remediation is either to have the PDS grant audience membership to the moderator DID (bringing PDS-side authorization in line with the moderation service's scope) or to accept partial coverage.

**When each posture applies (descriptive, not prescriptive).** The operator chooses posture based on deployment topology, not on any cairn-mod-side preference:

- Best-effort is coherent for deployments where cairn-mod's service DID has been granted audience membership on the records it needs to moderate (typical same-operator deployment: cairn-mod's operator also operates the PDS, so cairn-mod's DID is in the PDS's audience-management policy). In this posture, cairn-mod's client-side decode capability is redundant with PDS-side authorization — Aurora returns `text` for the DID's authorized reads, and the client-side path only fires on the rare unauthorized-but-fetchable case. The redundancy is defensive, not load-bearing.

- Server-side-only is coherent for deployments where the operator wants cairn-mod's decode scope to strictly track PDS-side authorization — cross-operator moderation deployments, deployments where cairn-mod's service DID is not on record audiences by policy, or deployments where the operator wants an operational tripwire when the two go out of sync. In this posture, unauthorized-but-fetchable content shows up as encoded blobs in the report queue rather than as plaintext, and the operator can decide per-report whether to escalate (grant the DID audience membership and re-fetch) or defer.

Neither posture is more correct in the abstract. Best-effort is the default because it aligns with what most operators want in practice (moderate what you can access); server-side-only is the opt-in for operators whose policy explicitly prefers the tripwire.

### §5.5 emitEvent unification

**All action-shaped operations dispatch through `emitEvent`.** Aurora's admin surface unifies mod actions into `tools.aurora.admin.emitEvent` with 16 action variants (recon §1d — v9-corrected count against the recon's own enumeration; see §7). cairn-mod's RustBackend trait keeps its discrete action-verb methods (`takedown_account`, `apply_label`, etc.) as the public API — operators and internal callers see the verbs they're used to — but internally, the RustBackend translates each verb into the appropriate action-variant (specific type name — per-release-doc concern) and dispatches through `emitEvent`.

**Consequences.**

- v1.8.2 lands the first five action verbs on this dispatch path (takedown/suspend/restore-account, apply/negate-label).
- v1.8.5 extends the dispatch to cover all 16 emitEvent variants.
- Appeal resolution (F7) is an emitEvent variant, not a separate endpoint; cairn-mod's appeal-related trait methods dispatch through emitEvent.
- Batch operations (v1.8.7) either dispatch through Aurora's dedicated batch endpoints (six of them) or through multi-subject emitEvent for actions where no dedicated batch endpoint exists.
- Cascading actions from a single emitEvent dispatch (recon §1d) are surfaced back through the response shape.

### §5.6 Degradation

When a capability is not advertised (or not advertised at a version cairn-mod supports):

- **Hide-in-UI capabilities.** The affected surface is hidden from cairn-mod's moderator UI. Attempting to invoke it via CLI returns `BackendError::CapabilityNotAdvertised`.
- **Fall-back capabilities.** The affected surface degrades to a v1.7-era equivalent if one exists. E.g., if `queryEvents` capability is not advertised, cairn-mod's read surface falls back to whatever's available from a general-purpose Rust PDS lacking full moderation vocabulary.
- **Operator-required capabilities.** If declared in `required_capabilities` at startup, non-advertisement is a fatal config error at cairn-mod boot.

Per-capability degradation categorization is set by per-release docs, not by the umbrella. The umbrella commits to the three-category vocabulary and the `required_capabilities` mechanism.

### §5.7 Trait additivity

**The `PdsAdminBackend` trait grows monotonically across the v1.8 series.** New methods are added; existing methods are not removed or breaking-changed. Backends that don't implement a new method's underlying capability return `BackendError::CapabilityNotAdvertised` for that method (v1.7's `OzoneBackend` returns this for any new method it doesn't implement).

This is the only model compatible with parallel maintenance of two backend implementations during the v1.8 series. Alternatives (returning enums over versions, generic-parameterized methods, breaking signatures) all either violate ergonomic simplicity or break OzoneBackend's stable contract.

**Trait sizing across v1.8 (honest estimate).** The v1.8 series adds a substantial number of trait methods on top of v1.7's six existing methods. Per-release counts: ~5 (v1.8.2 protocol parity, action verbs mapped through emitEvent) + 2 (v1.8.3 read basics: queryEvents, queryStatuses) + 2 (v1.8.4 rich context: getSubjectContext, getSubjectHistory) + ~12 (v1.8.5 emitEvent variants beyond the 5 in v1.8.2 — see §4.A.5 for the 16-variant enumeration) + 2 (v1.8.6 audit trail: getAuditTrail, getAuditEntry) + up to 6 (v1.8.7 batch: six dedicated batch endpoint methods per recon §1f) + 1 (v1.8.8 realtime subscribe) + 2–3 (v1.8.9 ops/runtime: getInstanceMetrics, getRuntimeSetting, setRuntimeSetting) + 5–10 (v1.8.10 ops-starter subset selection) + kryphocron-scoped methods (v1.8.13+). Realistic total: ~30–40 new methods over 11 Workstream-A releases. This is real growth, not hypothetical.

**Per-release Ozone stub-add commitment.** Every per-release doc that adds a trait method commits to adding the corresponding `OzoneBackend` stub returning `BackendError::CapabilityNotAdvertised` in the same release. Stubs are one-line implementations; the per-release doc's shipping-list explicitly names the stub-add so it's not accidentally omitted. This keeps `OzoneBackend` compilable and functional through the entire series without any code deferral — Ozone-only deployments continue to work identically after every v1.8.x release.

**Mitigation surface for post-v1.8.** The growing trait is a real maintenance burden, but the burden is bounded (each stub is trivial) and doesn't gate the series. Post-v1.8 candidates in §7 include splitting the trait into `PdsAdminBackendCore` (v1.7 shape, both backends implement) and `PdsAdminBackendRust` (RustBackend-only extension trait) — this would eliminate the stub-add churn on Ozone. The split is deferred to post-v1.8 because splitting mid-series would require every already-shipped v1.8.x per-release doc to reconcile against the new trait shape; it's cleaner to complete the series against the additive-only trait and then split as a post-v1.8 refactor.

**Trade-off:** the trait surface grows across the series. Mitigation is the per-release Ozone stub-add commitment (during v1.8) and the post-v1.8 trait split (after v1.8 completes). Any method with no consumer for two consecutive minor releases becomes a candidate for `#[deprecated]` marking; actual removal is a future-major concern.

### §5.8 Audit chain

**cairn-mod's own audit chain covers cairn-mod's own actions.** cairn-mod's chain, defined in `pds_admin_audit` + `audit_log` (recon §3g), records every backend action cairn-mod dispatches. This is unchanged from v1.7.

**Aurora's audit chain covers Aurora's mod-event actions.** cairn-mod consumes Aurora's chain via `getAuditTrail` at v1.8.6 and can verify it inline + cairn-mod-side. This does not merge the two chains; they cover disjoint subject matter.

**Kryphocron audit events are not in Aurora's hash chain.** F3 established this. cairn-mod's v1.8.14 kryphocron variants live in cairn-mod's own chain. Aurora's kryphocron events remain queryable via `queryEvents` but are not tamper-evident on Aurora's side.

### §5.9 Inbound XRPC gateway

**The gateway grows a `tools.aurora.*` dialect alongside its existing `tools.ozone.moderation.*` dialect.** F6 established that v1.7's gateway is Ozone-hardwired. v1.8.1 lays the foundation for extensibility (Nsid allowlist becomes dual-dialect; projection `$type` constants gain per-dialect variants). Subsequent releases populate the `tools.aurora.*` side as they consume the corresponding Aurora endpoints.

The gateway remains service-auth JWT authenticated per v1.7 (recon §3e); the inbound authentication model does not change. What changes is the vocabulary of NSIDs the gateway recognizes.

### §5.10 Temporal direction

Throughout the v1.8 series, the umbrella and per-release docs are the leading artifacts. `cairn-design.md`'s existing content is a lagging artifact; v1.8.11 reconciles.

**Per-release docs surface any need for umbrella revision back to the umbrella.** Umbrella revisions are tracked in §11 (CHANGELOG). Each revision names the release that motivated it.

Adversarial reviewers of per-release docs should not flag "design doc says X but umbrella says Y" as a per-release bug — that's a v1.8.11 reconciliation item.

---

## §6 — Non-goals

Explicit non-goals for the v1.8 series, so the per-release docs don't drift.

- **Superadmin surfaces.** Aurora exposes 42 `tools.aurora.superadmin.*` endpoints (recon §1a). cairn-mod does not consume any of them in v1.8. Superadmin is PDS-operator-owned; not moderation scope.
- **PDS-mutating ops.** Ops endpoints that mutate PDS state (sequencer control, blob GC, federation-peer mutations, etc. — enumerated in §4.A.10) are not in v1.8.10 scope.
- **Aurora's internal moderation UI.** cairn-mod does not consume, mirror, or coordinate with Aurora's own admin-UI moderation surfaces. When Aurora operates in Mode 3 (`moderation-mode = disabled`), cairn-mod is the moderation surface; when Aurora operates in `full` mode, both surfaces are active independently.
- **kryphocron write path.** cairn-mod does not encode records, does not create private posts, does not participate in the audience-oracle or rotation-oracle write-side. Decode-only.
- **Confidentiality guarantee on decoded kryphocron content.** cairn-mod does not offer, imply, or enforce any confidentiality property on private-tier content it decodes. Per §5.4 and F5, the audience gate is a friction property, not confidentiality; cairn-mod's ability to decode is not a security failure and cairn-mod's inability to prevent decoding is not a security responsibility. Operators wanting confidentiality on private-tier content need a different substrate; laquna does not provide it and cairn-mod does not simulate it.
- **Cross-chain kryphocron audit verify.** F3-constrained; v1.8.6 does not attempt to verify kryphocron events against Aurora's hash chain because Aurora's kryphocron events are not in that chain.
- **Federation-of-reports semantics.** If cairn-mod is deployed against a PDS the cairn-mod operator does not own, cross-operator report federation is not a cairn-mod concern. Reports are cairn-mod-instance-local unless the operator wires up their own report forwarding.
- **Multi-PDS backend dispatch.** cairn-mod's `PdsAdminBackend` is one-backend-per-instance in v1.7 and remains so in v1.8. Multi-PDS orchestration is a post-v1.8 concern.

---

## §7 — Open items surfaced for downstream tracking

Items the umbrella surfaces for future tracking but does not resolve in the v1.8 series.

**Recon-correction pass — applied history.** v12 §7 listed nine recon-side corrections to run against the on-disk recon. The correction pass verified each independently against source and applied the ones that needed correction:

Applied (6):
- **C1.** Recon §1d "17 action variants" corrected to 16. Source `ModEventAction` enum in Aurora at `src/api/aurora_admin.rs:238-282` has 16 variants.
- **C3.** Recon §1c "five-layer auth ladder" corrected to four. Source labels exactly four `// Layer` markers in `admin_auth_from_token_with_ip`; the previously-called "layer 5" was role-finalization (authorization, not an auth layer).
- **C5.** Recon §3i F6 Nsid descriptor corrected to "3 `tools.ozone.moderation.*` variants + `com.atproto.moderation.createReport`" (not "four `tools.ozone.moderation.*` variants").
- **C7/C9.** Recon §3c `parse_capability_string` "no consumer" corrected. Source shows a production consumer at `src/pds_admin/config.rs:854` in `validated_rust_from_toml` (validating operator-supplied `pinned_versions` at config-parse time). What's absent is a *runtime-negotiation* consumer; v1.8.1 adds that.
- **C8.** Recon §1c role gate corrected. Aurora's `check_role` at `src/api/aurora_admin.rs:379-401` gates only `DeleteAccount` and `SendEmail` at Admin+; all other variants including `DeleteBlob` permit Moderator+ per namespace default.
- **C4 (defensive note).** Recon §1c was already correct that `verify_service_jwt` does not enforce `lxm`-vs-endpoint matching; correction pass added a defensive note to prevent re-introduction of the earlier misreading.

Verified already-correct (2):
- **C2.** Recon §1a's "133 endpoints" figure was source-truth all along (129 advertised via `describeCapabilities` + 3 unadvertised `tools.aurora.lexicon.*` routes + `describeCapabilities` itself). CC R1's earlier "~130" recount had excluded the 3 unadvertised lexicon routes; the recon's methodology was correct. Umbrella §2.2 v12-was-"~130" now reconciles to 133 (v13).
- **C6.** Recon §2a already named `AuroraLocusStandardRotationOracle` and correctly contrasted it with `DefaultRotationOracle` (the substrate's default that Aurora doesn't use). No correction needed.

Umbrella-side reconciliation applied in v13: §2.2 endpoint count updated from ~130 to 133; §7 recon-corrections list converted from queue to applied-history.

**F14 as a substrate-level concern.** Aurora records no persisted audit event for who decodes private content (recon §2e, F14). cairn-mod's own audit chain provides **scope-partial compensation** — complete within cairn-mod's own consumption, silent about other consumers. The substrate-level gap (a PDS-side accounting of read-time decodes by any consumer) remains. Flagged as a kryphocron substrate concern (not a cairn-mod v1.8 concern) so it doesn't get lost.

**Aurora service-DID discovery route.** Recon documents no `.well-known` or XRPC endpoint for retrieving a PDS's service DID at v0.10; operators configure it out-of-band per §5.2. Flag to Aurora upstream as an ergonomic gap. Post-v1.8 cairn-mod could consume such a route if Aurora adds one, but until then `target_service_did` stays mandatory operator-configured. Parallel treatment to F14 (both are Aurora-side gaps cairn-mod works around locally while flagging upstream).

**F17 as informational.** Aurora's scope/family/type inconsistencies (four `admin.*` NSIDs require `AdminServer` not `AdminModeration`, `ops.themes.listInstalled` diverges family, `tools.aurora.lexicon.*` unadvertised) are Aurora-side concerns. cairn-mod's per-release docs handle them at the point of consumption; no umbrella action.

**F20.** `moderation-mode-redirect-url` has no server-side consumer in Aurora. If cairn-mod ever wants to advertise itself as a redirect target on Aurora's Mode-3 UI, that's a client-side coordination, not something Aurora enforces. Not in v1.8 scope.

**Post-v1.8 candidates.** Multi-PDS dispatch, remaining ops surfaces beyond the v1.8.10 starter, superadmin subset for delegated deployments, deprecation policy for the trait's grown surface, `PdsAdminBackend` trait split into Core + RustBackend-only (per §5.7 — deferred to post-v1.8 rather than pursued in-series), and any surfaces Aurora adds in v0.11+ that align with cairn-mod's mission.

---

## §8 — Ground-truth citation discipline

Every design decision in v7 cites the recon it's grounded in. Per-release docs inherit this discipline: no design assumption goes into a per-release doc that isn't either (a) grounded in the v0.10 recon at `docs/internal/recon/v1.8-surface-recon.md`, (b) grounded in a fresh recon that supersedes v0.10 (as Aurora advances), or (c) explicitly flagged as a cairn-mod-side design commitment with no external grounding.

When Aurora advances beyond v0.10, per-release docs may need a fresh Aurora recon before drafting. The v0.10 recon is the baseline; the next recon documents the delta.

**Prior docs conflict.** When recon and prior cairn-mod docs conflict, recon wins. F8 established that the referenced v0.2 baseline `AURORA_LOCUS_FINDINGS.md` never existed; the v0.10 recon is now the baseline. Any v6-umbrella references, historical planning docs, or prior recon docs are superseded when they conflict with v0.10 recon.

---

## §9 — Document trail

The umbrella and per-release docs live in `docs/internal/design/`.

- `cairn-mod-v1.8-umbrella-v13.md` — this doc. Locked. Umbrella figures reconciled against corrected recon; per-release doc drafting begins with v1.8.1.
- `cairn-mod-v1.8-umbrella-v12.md` — recon-correction-superseded predecessor. Retained for reference.
- `cairn-mod-v1.8-umbrella-v11.md` — CC-adversarial-R2-superseded predecessor. Retained for reference.
- `cairn-mod-v1.8-umbrella-v10.md` — CC-adversarial-R1-superseded predecessor. Was web-review-locked at R3. Retained for reference.
- `cairn-mod-v1.8-umbrella-v9.md` — R3-superseded predecessor. Retained for reference.
- `cairn-mod-v1.8-umbrella-v8.md` — R2-superseded predecessor. Retained for reference.
- `cairn-mod-v1.8-umbrella-v7.md` — R1-superseded predecessor. Retained for reference.
- `cairn-mod-v1.8-umbrella-v6-locked.md` — historical pre-recon predecessor. The `-locked` suffix indicates the doc was locked-and-shipped before the v0.10 recon existed; it's retained as historical record and is not edited.
- Per-release docs (drafted in workstream order, sequenced by dependencies):
  - `cairn-mod-v1.8.1-foundation.md` (drafted alongside this umbrella; see companion file)
  - `cairn-mod-v1.8.2-protocol-parity.md` (post-v1.8.1)
  - `cairn-mod-v1.8.3-read-basics.md` (post-v1.8.2)
  - `cairn-mod-v1.8.4-rich-context.md` (post-v1.8.3)
  - `cairn-mod-v1.8.5-action-enrichment.md` (post-v1.8.4)
  - `cairn-mod-v1.8.6-audit-verification.md` (post-v1.8.5)
  - `cairn-mod-v1.8.7-batch.md` (post-v1.8.6)
  - `cairn-mod-v1.8.8-realtime.md` (post-v1.8.5)
  - `cairn-mod-v1.8.9-ops-runtime.md` (post-v1.8.5)
  - `cairn-mod-v1.8.10-operator-extensions.md` (post-v1.8.5)
  - `cairn-mod-v1.8.11-series-wrap.md` (last of Workstream A)
  - `cairn-mod-v1.8.12-substrate-consumption.md` (post-v1.8.1)
  - `cairn-mod-v1.8.13-report-flow-retrieval.md` (post-v1.8.12)
  - `cairn-mod-v1.8.14-kryphocron-audit.md` (post-v1.8.13; also depends on v1.8.3 for `queryEvents` surface and v1.8.8 for WS stream)
  - `cairn-mod-v1.8.15-laquna-handling.md` (post-v1.8.13)

Per-release docs may interleave A and B; the umbrella does not commit the specific interleaving order beyond the noted dependencies.

Ground-truth recon: `docs/internal/recon/v1.8-surface-recon.md`.

---

## §10 — Known tensions surfaced for adversarial review

Tensions the drafter surfaces for adversarial review to attack. Numbered.

**Note on CC-adversarial R2 outcomes.** CC R2 verified R1-fold quality against source at both repos' HEAD (unchanged since R1). Returned 1 load-bearing (F1 role-matrix error in §4.A.5), 2 substantial (R1-fold overreach on `parse_capability_string` recharacterization + matching §7 correction wording), 6 minor precision items, 2 new recon-side corrections. Under the ≤2-load-bearing rule, v12 folded and locked pending recon correction. Both R1-fold-overreach findings caught the same failure mode: v11 misread R1's original correct characterization and re-introduced imprecision R1 had already fixed. Umbrella-side lesson: when folding an adversarial finding, preserve the reviewer's exact characterization; don't paraphrase in a way that reintroduces the original error.

**Note on recon-correction pass outcomes.** The correction pass ran with independent source verification and returned three items where the umbrella-side "correction" was itself wrong: C2 (endpoint count), C6 (rotation oracle), and C4 (`lxm`). All three were already source-accurate in the recon; the umbrella had misread the recon or CC R1 had produced imprecise recount figures. v13 §2.2 reconciles endpoint count from ~130 to 133 (recon's source-truth figure); §7 converts the corrections-queue to applied-history with the three self-corrections explicitly noted. Second lesson from this: even when correction items look uncontroversial, verify independently against source — the reviewer-of-the-reviewer catches mistakes the first reviewer missed.

**Umbrella locked at v13.** Per-release doc drafting begins with v1.8.1 against v13's ground truth. Per-release docs follow the same review discipline as the umbrella: web-review to convergence, then CC-adversarial as the last-check before implementation. Where per-release-doc content touches kryphocron/laquna surfaces (v1.8.12–15), those releases stay Opus-implementation-only; Fable-facing derivatives are produced from Opus-locked designs before any Fable implementation is assigned.

**Substrate-side follow-ups tracked in §7.** F14 (Aurora records no persisted decode-audit event), service-DID discovery route, F17 (Aurora scope/family/type inconsistencies), F20 (`moderation-mode-redirect-url` unconsumed) all remain post-v1.8 concerns to raise upstream when appropriate.

---

## §11 — Umbrella revision log

**v13.1 (v1.8.11 series-wrap reconciliation; filename retained).** Category-A text alignments against shipped source: §4.A.9/§4.A.10 AdminServer-scope language (enforcement is the OAuth-namespace-layer gate + per-handler role floors, not per-endpoint scope checks); §4.A.10 ops capability model (core admin block capability-bare; endpoint contract = per-release NSID list per §5.3/F19); §4.A.10 Ozone stub variant (`Unsupported`, taxonomy 41/2/0); §4.A.1/§5.2 audit-divergence flag lifecycle (WARN since v1.8.6, removed v1.8.11, Parts 2/3 live); §4.A.1 `CapabilityNotAdvertised` first-producer locus (Rust-backend, never Ozone). §4.A.11: locus rename recorded as fully-shipped-at-v1.8.1 with the deprecation aid retained; revision-tracking pointer corrected §7 → §11; items 9/10/11 enumerated into scope. Endpoint-count NOT changed (55 already matches source).

Revisions to the umbrella are tracked here. Each revision names the release that motivated it and the affected sections.

**v13 (this draft — locked).** Recon-correction reconciliation. The correction pass ran with independent source verification and returned three items where the umbrella-side "correction" was itself wrong (C2 endpoint count, C6 rotation oracle, C4 `lxm`); the recon was already source-accurate on those points. v13 reconciles umbrella to match.

Reconciliation edits:
- §2.2 endpoint count: `~130` → `133 (129 advertised + 3 unadvertised lexicon + describeCapabilities)`. Recon's 133 was source-truth; CC R1's earlier ~130 recount excluded the 3 unadvertised `tools.aurora.lexicon.*` routes.
- §7 converted from correction-queue to applied-history. Now records the 6 corrections applied against the recon, the 2 verified-already-correct items, and the 1 defensive-note addition. Header note explains what the correction pass returned vs. what v12 §7 had queued.
- §7 self-corrected items explicitly named — future readers see where the umbrella misread the recon (C2, C6) and where CC R1 produced imprecise recount figures (C2 ~130).
- §10 tensions block updated: recon-correction pass complete; umbrella locked; per-release doc drafting begins with v1.8.1. Reframed second lesson from the v11→v12 paraphrase-during-fold problem to the more general "verify independently against source even when a correction item looks uncontroversial" lesson from this pass.

Umbrella-side process lesson from v12 → v13: even when a correction item seems uncontroversial and reflects a reviewer's careful work, verify independently before applying. Three of nine v12-queued corrections would have introduced errors if applied verbatim; the recon-correction pass catching them was the ground-truth-first discipline working correctly. Same lesson at higher fidelity: never paraphrase a source claim during fold; always re-verify.

**v12.** CC-adversarial R2 fold. Under the ≤2-load-bearing rule, v12 locked pending recon correction.

Load-bearing (from CC R2):
- §4.A.5 role-matrix corrected. Aurora's `check_role` at `src/api/aurora_admin.rs:379-401` gates `DeleteAccount` and `SendEmail` at Admin+ — not `DeleteAccount` and `DeleteBlob`. `DeleteBlob` permits Moderator+ per namespace default. Per-release doc for v1.8.5 encodes the corrected matrix explicitly.

Substantial (from CC R2):
- §4.A.1 `parse_capability_string` recharacterization corrected. v11 mistakenly reintroduced imprecision R1 had already fixed — described the existing consumer as "a test consumer" when it's a production consumer at `src/pds_admin/config.rs:854` (`validated_rust_from_toml` validating operator-supplied `pinned_versions` at config-parse time). v12 restores R1's correct read: production consumer exists; v1.8.1 adds a *second, runtime-path* consumer alongside the existing one.
- §7 correction-#7 wording corrected to match the above.

Minor (from CC R2):
- §4.B.2 decode-input description tightened — laquna's decode entry point takes raw record coordinates; seed derivation is internal to laquna, not something cairn-mod computes.
- §4.B.3 `KryphocronDecodeFailed` variant-drop reasoning clarified.
- §4.B.3 kryphocron audit-event shape explicitly noted as greenfield (no v1.7 cairn-mod pattern to inherit).
- §4.A.7 `MAX_BATCH_SIZE = 50` softened to "50-item batch cap" — specific constant name is per-release-doc territory.
- §4.A.5 `EmitEventOutput` reference softened — wire field name (`cascadingActions`) noted separately from Rust type.
- Two new recon-side corrections added to §7: per-action Admin gate (`check_role` gates `DeleteAccount` + `SendEmail`, not `DeleteAccount` + `DeleteBlob`); refined correction-#7 wording.

Umbrella-side process lesson from v11 → v12: when folding an adversarial finding, preserve the reviewer's exact characterization; don't paraphrase in a way that reintroduces the original error. v11 F2/F7 were exactly this failure mode — R1 had characterized `parse_capability_string`'s consumer correctly, but v11's paraphrase during fold reintroduced imprecision R2 then caught.

**v11.** CC-adversarial R1 fold. CC verified every umbrella claim against source in cairn-mod, Aurora-Locus, and pinned kryphocron 0.3.1 (with laquna vendored inside). Result: 0 load-bearing, 3 substantial, 8 minor, 7 recon-side corrections. All folded.

Substantial (from CC R1):
- §5.1 and §4.B.2 `lxm` semantics rewritten. Previous rationale claimed "Aurora enforces `lxm` matching per recon §1c"; CC verified against `verify_service_jwt` source and found Aurora does not enforce `lxm`-vs-endpoint matching. `lxm` binds the token's `exp` cap (1 hour with `lxm`, 1 minute without) — that binding is the actual reason cairn-mod includes `lxm`. Per-call-JWT design unchanged; only the rationale corrected.
- §5.2 `verification_persist` and `acknowledge_v1_8_1_audit_divergence` disambiguated. Previous framing lumped both as "production-quality enforcement"; CC found `verification_persist` is parse+store only with no consumer wired (consumer lands in v1.8.6 alongside audit-trail work). `acknowledge_v1_8_1_audit_divergence`'s three-gate boot-time inspector is genuinely production-quality; §5.2 now describes each field separately per what actually holds.
- §4.B.2 `subject_type` CHECK-constraint migration shape named. Previous framing described the column as gaining a "`kryphocron_record` discriminator" without noting the current CHECK constraint on `subject_type` limits it to `('account', 'record')`. CC found the migration requires a table rebuild (drop-and-recreate with extended CHECK, copy data, swap), not a plain additive migration. Named the shape in the umbrella so per-release doc drafts know to plan for a rebuild-shaped migration.

Minor (from CC R1):
- §4.A.3 v1.7 trait-descriptor corrected: "mutating-only" → "action-verb-shaped, no cursor-paginated read surfaces" (v1.7 has `probe` which is not mutating).
- §2.2 endpoint count: 133 → approximately 130 per CC's actual recount; specific figure queued in §7 as recon-side correction.
- §4.A.1 `parse_capability_string` characterization corrected: exists with a test consumer pinning parser behavior; v1.8.1 wires the first runtime consumer (the `describeCapabilities` probe path).
- §4.B.3 `KryphocronDecodeFailed` variant list corrected: dropped `rotation_slug_recovery_failed` and `seed_derivation_failed` as unreachable (deterministic string parse, deterministic seed derivation from record coordinates); kept `codec_id_unknown` and `codec_error`.
- §4.A.2 and §5.5 `EmitEventInput` reference softened: specific type name is per-release-doc concern; umbrella commits to the pattern (action-verb → emitEvent action-variant → dispatch), not the identifier.
- Custom rotation oracle (Aurora uses `AuroraLocusStandardRotationOracle`, not substrate default) — no umbrella claim requires the default; queued in §7 as recon-side clarification only.
- §7 recon-side corrections list expanded to seven items (see §7).

Recon-side corrections queued for targeted correction pass (v12 expanded this list to nine items — see §7 for full list):
- 17 vs 16 emitEvent variants (previously flagged in R2 fold)
- 133 vs approximately 130 total `tools.aurora.*` endpoints
- Five-layer vs four-layer `admin_auth_from_token_with_ip` ladder
- `lxm` enforcement claim
- `Nsid` allowlist "four" vs 3 ozone + createReport
- `DefaultRotationOracle` vs `AuroraLocusStandardRotationOracle`
- `parse_capability_string` "no producer" vs "has production consumer at `config.rs:854` in `validated_rust_from_toml`; v1.8.1 adds a runtime-path consumer alongside the existing one"
- Per-action Admin role gate (v12-added): `check_role` gates `DeleteAccount` + `SendEmail`, not `DeleteAccount` + `DeleteBlob`
- Refined correction-#7 wording (v12-added, matches the parse_capability_string clarification above)

**v10.** R3 adversarial-review fold. R3 returned 0 load-bearing findings, signaling web-review convergence. Substantial: §2.3 tightened from "initial-and-eventual operator console" to "starter operator-visibility console"; §5.4.2 gains "when each posture applies" descriptive paragraph. Minor: §5.7 sizing precision, §4.A.5 cross-reference to §5.7, §5.2 warning-shape lock, small stale-version reference fix.

**v9.** R2 adversarial-review fold. Load-bearing: §5.4.1 canonical operator-facing threat-model statement promoted; §5.4.2 client-side decode scope operator policy added; §5.2 `capability_refresh_interval` semantics narrowed; §7 gains target-service-DID discovery route parallel to F14. Substantial: §5.7 trait growth honestly sized; §4.A.5 emitEvent variant count corrected 17→16; §4.B.3 kryphocron audit variants renamed with `content_tier` field discriminator; §4.A.10 defers ops-side blob-mutation endpoints; §5.3 gains expected release cadence coupling. Minor: §2.2 percentage precision; §4.A.9 phrasing fix; §9 `-locked` suffix explained; §7 F14 "partly compensates" reworded as "scope-partial compensation"; §11 restructured into load-bearing/substantial/minor blocks. Scope-decision fold: v1.8.14 dependency stays as v8 stated; no split, no partial ship.

**v8.** R1 adversarial-review fold. Load-bearing corrections: §5.2 config-shape corrected; §4.A.1 capability-types framing corrected (`Capability` and `CapabilitySet` are greenfield); §4.B.1 kryphocron capability strings corrected (three, not four; named exactly); label-bridge invariant constant renamed to disambiguate from recon-current-F4. Substantial: §4B sequencing gate promoted (v1.8.14 depends on v1.8.3 + v1.8.8); §4.B.2 `getRecord` auth model stated; §4.B.2 `KryphocronRecord` variant name committed; §6 gains confidentiality-guarantee non-goal; §4.A.11 gains required operator-facing threat-model documentation. Minor: §5.3 practical-impact of advisory-`describeCapabilities` stated; §6 OAuth-non-goal removed as redundant; §4.A.11 compat-check CLI promoted from optional to required.

**v7.** Full rewrite of v6 against the v0.10 Aurora-Locus surface recon. Grounds every §4 release citation against the recon; commits ES256K service-auth (F2); commits kryphocron-as-friction threat model (F5); reflects Aurora's actual endpoint layout (F1, F7); acknowledges F3's audit-chain split; F6's Ozone-hardwired gateway needing dual-dialect extension. Predecessor v6 superseded in full.

- v6 and earlier revisions are recorded in v6's own §11 CHANGELOG; not repeated here.

---

## Notes on the cycle structure

The v1.8 series covers 15 minor releases across two workstreams sharing a foundation. Sizing is bounded by:

- 15 per-release docs of varying size (v1.8.1 the largest; v1.8.15 among the smallest).
- Each per-release doc's own adversarial-review discipline.
- Per-release Phase B verification skydeval runs against live Aurora-Locus + a live cairn-mod.

Scope is honest: cairn-mod ends the series as a full RustBackend implementation against Aurora-Locus v0.10+, a starter operator-visibility surface for any Rust PDS, and a kryphocron-content moderation service for kryphocron-enabled PDSes.

The series is bounded by the surfaces above; extensions (multi-PDS dispatch, deprecation policy, superadmin subset for delegated deployments, remaining ops surfaces, any surfaces Aurora adds in v0.11+) are post-v1.8 concerns.
