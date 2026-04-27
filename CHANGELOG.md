# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

### Security

## [1.5.1] — 2026-04-27

> Documentation reorganization for clearer audience separation —
> no behavior changes.

### Changed

- Split README.md into focused documents covering distinct
  audiences. README.md retains discovery-tier content (project
  pitch, status, trust-chain disclosures, architecture summary)
  and slims to ~150 lines. New SETUP.md covers first-deployment
  setup (install, signing key, configuration, bootstrap, service-
  record verify). New OPERATIONS.md covers day-2 operator content
  (production checklist, monitoring, dependency security scanning,
  single-instance enforcement). New docs/moderator-cli.md is the
  moderator CLI reference (membership management, login, report
  workflow, audit log queries). Existing files (CHANGELOG,
  CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, MAINTAINERS, LICENSE-*,
  cairn-design.md) stay at root per their conventions. (#68)

## [1.5.0] - 2026-04-27

> v1.5 "Label emission" closes the v1.4 loop: every recorded
> action now translates into ATProto labels that consumer AppViews
> honor, and revocation atomically negates whatever was emitted.
> Operators declare the action-to-label mapping in
> `[label_emission]` — defaults ship out of the box, override
> knobs cover val / severity / blurs / locales per action type,
> and notes never emit (defense-in-depth at the resolver). Reason
> labels emit as `reason-<code>` alongside their action label,
> sharing its expiry on temp_suspension. Revocation reads the
> stored val from the linkage table (not the current policy)
> so operator policy edits between emission and revocation can't
> desynchronize negation. Subjects can introspect their own active
> labels via `tools.cairn.public.getMyStrikeState`'s new
> `activeLabels` field; operators query the same surface via
> `cairn moderator labels <subject>`. The new §4.2 disclosure 5
> makes the trust-chain framing explicit: internal moderation
> state and protocol-visible labels are different surfaces, both
> observable.

### Added
- Label-emission schema migration: `subject_actions.emitted_label_uri` column (the action label's val — the column name predates the realization that ATProto labels lack canonical URIs; locked) and `subject_action_reason_labels` linkage table with composite PK `(action_id, reason_code)`. Trigger update permits the single NULL→non-NULL transition for `emitted_label_uri`, mirroring the revocation columns' exception from #46. Linkage rows preserved across revocation as forensic record per [§F21.7](cairn-design.md#f217-schema-linkage-and-audit-log-integration) (#57)
- `[label_emission]` config block + `LabelEmissionPolicy` runtime loader. Operator surfaces: `enabled` master toggle, `warning_emits_label` opt-in, `emit_reason_labels` reason gate, `reason_label_prefix` (default `"reason-"`, empty permitted with startup warning), `[label_emission.action_label_overrides.<type>]` for per-action val/severity/blurs/locales, `[label_emission.severity_overrides]` for severity-only overrides. Cross-action `val` uniqueness enforced at config load — labels need to discriminate by val for revocation routing per [§F21.1](cairn-design.md#f211-action-to-label-mapping) (#58)
- Action-to-label translation core: `resolve_action_labels` and `resolve_reason_labels` pure functions translate an `ActionForEmission` plus the resolved policy into unsigned `LabelDraft`s. Same shape as the v1.4 calculators (#49 strike, #50 decay, #51 window) — no I/O, no async, no signing, no DB. Notes never emit (hard gate); warnings gated on `warning_emits_label`; reason labels share the warning's suppression gate (reasons-without-context confuses consumers, recovery path is asymmetric). TempSuspension propagates `expires_at` to both action label and reason labels per [§F21.2](cairn-design.md#f212-reason-labels) (#59)
- Recorder integration: `handle_record_action` now signs and persists the configured ATProto labels in the same transaction as the `subject_actions` INSERT, the `subject_strike_state` cache UPSERT, and the audit_log row. Atomic — failure rolls back action + audit + labels together so the audit chain never claims emission that didn't happen. Audit reason JSON gains `emitted_labels: [{val, uri}, ...]` capturing every label this action produced; hash chain (#39) extends to lock the (action, labels) bundle per [§F21.7](cairn-design.md#f217-schema-linkage-and-audit-log-integration) (#60)
- Revocation negation: `handle_revoke_action` now atomically emits negation labels (neg=true) for every label the original action emitted, targeting the same `(src, uri, val)` tuple. Val read from `subject_actions.emitted_label_uri` and `subject_action_reason_labels` rows, NOT from current policy resolution — operator policy edits between emission and revocation cannot desynchronize negation. Negations carry `exp = None` (negations are permanent statements that supersede the original; expiring them would resurrect the original in consumer caches). Negation is unconditional regardless of current policy state — prior emissions exist on the wire and must be negated even when emission has been disabled since recording. Audit reason JSON gains `negated_labels: [{val, uri}, ...]` mirroring emission's `emitted_labels` shape per [§F21.3](cairn-design.md#f213-negation-on-revocation) (#62)
- Idempotency guards: defense-in-depth `should_skip_action_label_emission` and `should_skip_reason_emission` helpers gate the emission loops on the row's pre-emission state. v1.5's normal flow always finds the gates' queries returning empty/NULL (the INSERT just landed inside the same transaction), so the guards are structurally a no-op in production; they exist to protect against future paths (backfill migrations, retry helpers) where a row might already carry emission state. The `subject_action_reason_labels` PK on `(action_id, reason_code)` is the SQL-level safety net per [§F21.5](cairn-design.md#f215-idempotency) (#64)
- Public XRPC `subjectStrikeState.activeLabels`: `tools.cairn.public.getMyStrikeState` and `tools.cairn.admin.getSubjectStrikes` now return the labels cairn-mod is currently emitting against the subject. One entry per non-revoked, non-negated action with `val`, `actionId`, `actionType`, `reasonCodes`, optional `expiresAt`. Most-recent-action-first ordering. Cache-bypass invariant from [§F20.9](cairn-design.md#f209-cache-management) extends here — always recomputed from `labels` + `subject_actions` source-of-truth. Exp-passed labels are INCLUDED (cairn-mod surfaces emitted state; AppView-side honor of `exp` is the consumer's responsibility per [§F7](cairn-design.md#f7-label-expiry-schema-only-enforcement-deferred)) per [§F21.8](cairn-design.md#f218-public-introspection-and-operator-cli) (#65)
- Operator CLI: `cairn moderator labels <subject>` HTTP-routes via admin `getSubjectStrikes` and renders `activeLabels` as the primary output. Default tabular human format (one row per emitted label — action label plus one per reason code, all sharing action context columns); `--json` emits just the `activeLabels` array, not the full strikes envelope per [§F21.8](cairn-design.md#f218-public-introspection-and-operator-cli) (#66)
- Test pinning: warning/note emission policy contract (the `warning_emits_label` gate at all relevant configurations + the Note hard gate at every code path) (#61); temp_suspension exp-field semantics (validation rejection paths + label-exp propagation including ms-precision RFC-3339 ↔ epoch-ms parity) (#63)

### Changed
- [`cairn-design.md`](cairn-design.md) gains [§F21](cairn-design.md#f21-label-emission-against-moderation-state-v15) (label emission against moderation state), nine subsections covering action-to-label mapping, reason labels, negation on revocation, temp suspension expiry via ATProto's native `exp` field, idempotency, customization for deployments, schema linkage and audit-log integration, public introspection and operator CLI, and deferred future work. [§4.2](cairn-design.md#42-operator-trust-trust-chain-readme-audience) trust-chain disclosure 5 documents that internal moderation state and protocol-visible labels are different surfaces, both observable: operators declare the translation rules in `[label_emission]`, subscribers compare config + emitted streams to verify policy variation. [§F20.10](cairn-design.md#f2010-deferred-to-future-releases) reordered: label emission marked shipped; remaining items reordered for v1.6+. [§18](cairn-design.md#18-future-roadmap) roadmap marks v1.5 shipped, adds v1.6 (policy automation) and v1.7+ (PDS administrative actions, default-disabled when `[pds_admin]` is absent), notes the continued v1.x trajectory toward Ozone parity, and contemplates cairn-mod-enterprise as eventual platform-tier sibling project (open scope; no version commitment) (#67)

### Fixed

### Removed

### Security

## [1.4.0] - 2026-04-26

> v1.4 "Account moderation state model" turns moderation into
> first-class records: every action against a subject (warning,
> note, suspension, takedown) writes a structured row with a
> strike value resolved at action time and frozen for forensic
> durability. Strikes accumulate, dampen for first-time offenders,
> and decay over time per operator-configurable rules. Read
> endpoints — admin and a new user-facing `tools.cairn.public.*`
> namespace — recompute strike state through a pure decay
> calculator on every fetch, so cached values can never produce a
> misleading answer. Operators declare reason vocabularies and
> strike policy in `[moderation_reasons]` and `[strike_policy]`
> config blocks; the new §4.2 disclosure 4 makes the trade-off
> explicit: cairn-mod's contribution is making policy declarable
> and observable, not adjudicating what the policy should be.

### Added
- Account moderation state model: `subject_actions` table records every moderation action (warning, note, temp_suspension, indef_suspension, takedown) with structured reason metadata, duration, notes, and links to source reports. `subject_strike_state` cache table tracks current strike counts per subject_did. Append-only schema; revocation transitions are the only allowed UPDATE per the trigger contract from [§F20.6](cairn-design.md#f20-account-moderation-state-model-v14) (#46)
- Reason vocabulary system: operators declare moderation reasons in `[moderation_reasons]` config block with `base_weight`, `severe` flag, and `description`. Cairn-mod ships eight default reasons aligned with ATProto's `reasonType` (hate-speech, harassment, threats-of-violence, csam, spam, misinformation, nsfw, other). Operator-declared blocks replace defaults entirely (no merging) per [§F20.2](cairn-design.md#f20-account-moderation-state-model-v14) (#47)
- Strike policy system: `[strike_policy]` config block declares `good_standing_threshold` (default 3), `dampening_curve` (default `[1, 2]`), `decay_function` (linear or exponential), `decay_window_days` (default 90), `suspension_freezes_decay` (default `true`), and `cache_freshness_window_seconds` (default 3600). Per-field defaults let operators declare partial blocks per [§F20.3](cairn-design.md#f20-account-moderation-state-model-v14) (#48, #55)
- Strike calculator: pure function applies dampening at action time. Users in good standing get curve-position values; users out of good standing get full `base_weight`; severe reasons bypass dampening. The `was_dampened` flag and `strikes_at_time_of_action` are frozen on the row for forensic auditability per [§F20.3](cairn-design.md#f20-account-moderation-state-model-v14) (#49)
- Decay calculator: time-based decay computed on read, not stored. Linear decay reaches 0 at `decay_window_days`; exponential decay reaches ~1% at the same boundary (half-life = window / log₂(100)). Suspension freezes decay (v1.4 simplification: only the most recent unrevoked suspension affects calculation) per [§F20.4](cairn-design.md#f20-account-moderation-state-model-v14) (#50)
- Recorder + revoker: `WriteCommand::RecordAction` and `WriteCommand::RevokeAction` route action writes through the writer task. Single-transaction atomicity across `subject_actions` row, `subject_strike_state` cache update, and hash-chained `audit_log` row via #39's pathway. Predict-then-verify pattern on the `subject_actions.id` ensures `audit_log_id` linkage stays correct even under sequence-allocation edge cases (#51)
- Position-in-window calculator: pure function counts in-good-standing offenses within the current decay window. Uses each prior action's `was_dampened` flag as the "in good standing at its time" predicate so position counting is stable across policy edits (#51)
- Multi-reason resolver: when an action carries multiple reason codes, the strike calculation uses the dominant reason — severe wins regardless of `base_weight`; ties on `base_weight` resolve to first-listed deterministically (#51)
- Admin XRPC: `tools.cairn.admin.recordAction`, `tools.cairn.admin.revokeAction` (writes); `tools.cairn.admin.getSubjectHistory`, `tools.cairn.admin.getSubjectStrikes` (reads). All Mod-or-Admin authorization. The shared [`src/server/strike_state.rs`](src/server/strike_state.rs) module factors the projection logic used by both admin and public read endpoints (#51, #52, #53)
- Public XRPC: `tools.cairn.public.getMyStrikeState`. First endpoint in the `tools.cairn.public.*` namespace. Service-auth gated; the verified `iss` must equal the subject_did. CORS allows browser-side callers (the namespace is designed for downstream consumers like future accessory bots or Web UIs). Cross-references admin's `subjectStrikeState` type to avoid type drift (#54)
- Operator CLIs: `cairn moderator action` / `warn` / `note` / `revoke` / `history` / `strikes` — moderator-tier, HTTP-routed via admin XRPC, cursor-paginated history, structured strikes display with decay trajectory. The `decayWindowRemainingDays` field is omitted at zero strikes since trajectory is meaningless without strikes to project (#51, #52)
- Subject-strike-state cache management: `cache_is_fresh` predicate and `get_or_recompute_strike_count` entry point. Cache bypass is the v1.4 read-endpoint invariant; the cache exists for v1.5+ consumers needing O(1) "is this user in good standing?" reads. Best-effort cache writes during recompute (write failure logs but doesn't fail the read) per [§F20.9](cairn-design.md#f20-account-moderation-state-model-v14) (#55)

### Changed
- [`cairn-design.md`](cairn-design.md) gains [§F20](cairn-design.md#f20-account-moderation-state-model-v14) (account moderation state model), ten subsections covering action types, reasons, strike calculation, decay, revocation, schema, XRPC surface, operator CLIs, cache management, and deferred future work. [§4.2](cairn-design.md#42-operator-trust-trust-chain-readme-audience) trust-chain disclosure 4 documents that operators set their own moderation policy and that policy declarability is cairn-mod's contribution rather than a fixed moderation philosophy. [§18](cairn-design.md#18-future-roadmap) roadmap updated to mark v1.4 as shipped and surface the deferred-to-future-releases items from §F20.10 (#56)
- [`cairn-design.md`](cairn-design.md#f10-audit-log) §F10 audit-log action vocabulary gained `subject_action_recorded` and `subject_action_revoked` entries (lexicon `defs.json` `knownValues` + `AUDIT_ACTION_VALUES` + design-doc prose). Update landed with #51's commit since the recorder writes those actions (#51)

### Fixed

### Removed

### Security

## [1.3.0] - 2026-04-26

> v1.3 "Audit integrity" makes audit-log tampering cryptographically
> detectable. Every audit row now carries a SHA-256 hash chained to
> the previous row's hash; operators verify chain integrity via
> `cairn audit verify`, backfill pre-v1.3 rows via `cairn audit-rebuild`,
> and inspect individual hashes via the extended `cairn audit show`
> output. The release also reconciles the design doc against four
> releases of drift — §11/§14/§16.1/§18 reflect what shipped, §19's
> release runbook documents the manual flow that v1.1/v1.2/v1.3
> actually used, and the unused GitHub Actions release workflow is
> marked deprecated.

### Added
- Hash-chained audit log: every `audit_log` row carries `prev_hash` and `row_hash` columns (SHA-256 over DAG-CBOR canonical encoding of the row's content). Tampering with any row's content or stored hash produces a recomputation mismatch detectable via `cairn audit verify`. `WriteCommand::AppendAudit` routes audit-row writes through the writer task; cross-process callers (`cairn publish-service-record` / `cairn unpublish-service-record`) use a parallel `append_via_pool` path that shares the same `compute_audit_row_hash` function — single canonical hash implementation, no risk of drift between paths (#39)
- `cairn audit-rebuild` CLI subcommand. One-shot operator command that walks `audit_log` in id order and fills `prev_hash` + `row_hash` for every row using the canonical hash function. Idempotent — re-running on an already-rebuilt log is a no-op success. Acquires the writer's `server_instance_lease` for the duration of the rebuild; lease conflict surfaces as exit 11 `LEASE_CONFLICT` so the operator stops `cairn serve` first. The §F10 `audit_log_no_update` trigger is dropped + recreated inside a single `BEGIN IMMEDIATE` transaction so partial-failure ROLLBACK restores the trigger atomically (#40)
- `cairn audit verify` CLI subcommand. Read-only operator command that walks the chain, recomputes each attested row's hash from its stored content + the running prev_hash, and compares against the stored `row_hash`. Reports the first divergence (row id, expected hex hash, actual hex hash, count of rows verified before divergence) and exits with the new exit code 15 `AUDIT_DIVERGENCE`. Pre-attestation rows (NULL `row_hash`, predating `cairn audit-rebuild` on a legacy install) are skipped with a horizon notice rather than flagged as errors. Safe to run while `cairn serve` is live — read-only, no lease (#41)
- `cairn audit show <id>` output gains `row_hash` and `prev_hash` fields in both human and JSON output. Pre-attestation rows display the `(pre-attestation)` sentinel; the genesis row's `prev_hash` displays as the all-zeros 64-char hex string. `tools.cairn.admin.defs#auditEntry` gains optional `prevHash` and `rowHash` fields; `tools.cairn.admin.listAuditLog` also exposes them on the wire (the human-table formatter stays terse), so `cairn audit list --json | jq` surfaces hashes for free (#42)

### Changed
- [`cairn-design.md`](cairn-design.md) §11/§14/§16.1/§18 reconciled to reflect what shipped through v1.0/v1.1/v1.2/v1.3 versus what's still aspirational. §18 renamed from "v1.1 Roadmap" to "Future Roadmap" (anchor moves from `#18-v11-roadmap` to `#18-future-roadmap`). Cross-platform binary commitments (Windows + multi-target) dropped from §14 and §16.1 — cairn-mod is server software designed for Linux deployment behind a reverse proxy, and `cargo install cairn-mod` is the canonical install path (#43)
- [`cairn-design.md`](cairn-design.md) §19 release runbook rewritten to match the manual flow that v1.1, v1.2, and v1.3 have actually used: a 13-step procedure across three phases (Readiness, Manual end-to-end verification, Release ceremony). Cadence-bound framings ("1 week before target date," "Week-1 post-release") replaced with cadence-agnostic language; §19.4 now defers to §20.2's existing monitoring SLA rather than duplicating it (#44)
- [`.github/workflows/release.yml`](.github/workflows/release.yml) marked deprecated via header comment. The workflow has never been used successfully — three v1.0 `workflow_dispatch` attempts failed on 2026-04-24, and v1.1/v1.2/v1.3 all shipped via the manual flow now documented in §19.2. The file is preserved (not deleted) as historical record of the v1.0 release-automation design intent (#45)

### Fixed

### Removed

### Security

## [1.2.0] - 2026-04-26

> v1.2 "Trust-chain transparency" makes the labeler's trust posture
> auditable. Operators and external auditors can now read the full
> signing-key history, maintainer roster (with HTTP-attested vs CLI-
> inserted provenance), service record content hash, and instance
> metadata via a single admin endpoint. The audit log gains a per-id
> detail view to complement the existing list query, and the service-
> record lifecycle gains its inverse — `cairn unpublish-service-record`
> — closing a documented friction point in the operator workflow.

### Added
- `tools.cairn.admin.getTrustChain` admin XRPC endpoint and `cairn trust-chain show` CLI subcommand. Read-only, admin-role-only summary of instance trust posture: signing-key history (active + rotated, with `validFrom`/`validTo`), maintainer roster with `provenanceAttested` flag distinguishing HTTP-attested adds from CLI/SQL inserts, published service-record content hash + declared label values, and instance metadata (build version, service endpoint). The envelope reuses the `tools.cairn.admin.defs` shared types so the CLI and any other consumer agree on wire shape (#35, #36, #37)
- `tools.cairn.admin.getAuditLog` admin XRPC endpoint and `cairn audit show <id>` CLI subcommand. Per-id detail view complementing `cairn audit list` (the v1.1 list query). Admin-role-only; returns the bare `auditEntry` shape with the full `reason` payload. `AuditEntryNotFound` 404 on unknown id mirrors `getReport`'s posture (#26)
- `cairn unpublish-service-record` CLI subcommand. Removes the `app.bsky.labeler.service` record from the operator's PDS via `com.atproto.repo.deleteRecord` (with `swapRecord` for race detection), clears `service_record_*` `labeler_config` state, and writes a `service_record_unpublished` audit row in one transaction. Idempotent — running on an unpublished labeler is a no-op success that still audits. Subsequent `cairn serve` startup verify (§F19) fail-starts with the existing exit 13 `SERVICE_RECORD_ABSENT` until republish; no new exit code needed (#34)

### Changed
- `ReportStatus` and `ResolutionAction` extracted from string fields to typed Rust enums. Wire shape unchanged; the change is internal type safety + central enumeration of allowed values (#27)
- `acquire_service_auth` and `truncate` factored from per-CLI-module copies into shared [`src/cli/auth.rs`](src/cli/auth.rs) and [`src/cli/output.rs`](src/cli/output.rs). No behavior change; the factor-out triggered when `cli/trust_chain.rs` brought the duplicated `acquire_service_auth` to eight identical copies across four modules (#28)
- F10 audit-log actions list in [cairn-design.md](cairn-design.md#f10-audit-log) updated to include `service_record_unpublished` (#34)

### Fixed
- `tests/wellknown.rs::ALL_LEXICONS` now exercises every lexicon served at `.well-known/lexicons/*` — `getTrustChain`, `retentionSweep`, and `getAuditLog` were previously missing from the per-NSID serving test (coverage gap, not a correctness gap; the underlying handlers and routes were always tested) (#38)

### Removed

### Security

## [1.1.0] - 2026-04-25

> v1.1 "Pleasant to operate" focuses on operational comfort for
> self-hosters. The release adds orchestrator-friendly health
> probes, supply-chain security scanning in CI, the full admin
> CLI surface (moderator / report / audit / retention), startup-
> time service-record drift detection, and a 41% trim of the
> published crates.io tarball. The housekeeping pass deflakes
> three timing-sensitive cache tests, validates `contrib/`
> deployment configs in CI, and ships a quickstart rot-check
> that exercises the README's operator workflow against a mock
> PDS — silent doc drift now fails CI.
>
> Also: this release reconciled a tracker numbering migration
> mid-development (chainlink replaced an earlier crosslink
> instance), and removed a stale auto-generated hook system that
> was emitting misleading reminders. See
> [docs/tracker-history.md](docs/tracker-history.md) for the
> migration record.

### Added
- `/health` and `/ready` orchestrator probe endpoints (unauthenticated, per-check rationale in [§F14](cairn-design.md#f14-health-and-readiness-probe-endpoints-v11)) (#23)
- CI security scanning: `cargo-audit` + `cargo-deny` on push/PR plus a scheduled daily audit that opens an issue on new advisories; hard-fail posture with a dated-review-comment escape hatch in [`deny.toml`](deny.toml) (policy in [§F15](cairn-design.md#f15-dependency-security-scanning-in-ci-v11)) (#13)
- `cairn moderator {add, remove, list}` CLI subcommands for managing the `moderators` table directly; one-shot, no lease conflict with running `cairn serve` (contract in [§F16](cairn-design.md#f16-moderator-management-cli-v11)) (#24)
- `cairn report {list, view, resolve, flag, unflag}` admin CLI subcommands wrapping the `tools.cairn.admin.*` HTTP endpoints; audit attribution preserved via JWT iss (contract in [§F17](cairn-design.md#f17-report-management-cli-v11)) (#7)
- `cairn audit list` admin-only CLI subcommand wrapping `tools.cairn.admin.listAuditLog` with actor / action / outcome / time-window filters and `--cursor` pagination (contract in [§F18](cairn-design.md#f18-audit-log-cli-v11)) (#6)
- `cairn serve` startup verify-only check against the published service record on the operator's PDS; drift / absent / unreachable each fail-start with a distinct exit code (12/13/14); reconciliation via `cairn publish-service-record` (contract in [§F19](cairn-design.md#f19-service-record-verify-on-startup-v11)) (#8)
- subscribeLabels retention sweep — daily writer-task batched DELETEs against `labels` older than `[subscribe].retention_days` (default 180); operator-initiated runs via `tools.cairn.admin.retentionSweep` (admin-only, audited per call) and `cairn retention sweep`; new `[retention]` config block. Full contract in [§F4](cairn-design.md#f4-comatprotolabelsubscribelabels-endpoint) (#12)
- E2E quickstart rot-check: new [`tests/e2e/quickstart.sh`](tests/e2e/quickstart.sh) walks the README's operator workflow end-to-end (signing-key generation → config → `publish-service-record` → `serve` → `curl /.well-known/did.json`) against a [mock PDS binary](examples/mock_pds.rs). New `e2e-quickstart` CI job — silent README drift now fails CI (#10)
- contrib syntax smoke check: prototype `contrib-smoke` CI job was developed during v1.1 but removed before release after four CI iterations surfaced a fundamental fragility — the validators (`caddy validate` / `caddy adapt`, `nginx -t`, `systemd-analyze verify`) are version- and environment-sensitive runtime tools rather than pure syntax checkers, making the job test "does CI's specific environment accept this template" rather than "is the template syntactically valid for operators." A cleaner replacement (likely pure syntax validation, not invoking runtime tools) is tracked as chainlink #33; the docker-compose end-to-end alternative tracks as chainlink #32. Side-effect of the removal: `contrib/nginx/cairn.conf` ships with rate-limiting as operator-add (matches the Caddyfile pattern) — the inline `rate=10r/h` was one of the four failures that drove this deferral and stays out as the v1.2 design conversation hasn't picked an approach (#9)

### Changed
- crates.io tarball trimmed from 287 files to 168 via [`Cargo.toml`](Cargo.toml) `[package].exclude` rules — drops `.chainlink/`, `.claude/`, `.github/`, internal docs (`cairn-design.md`, `RETROSPECTIVE.md`, `MAINTAINERS.md`, `CODE_OF_CONDUCT.md`, `docs/`), and `tests/` (which alone account for ~70 files including the ~40-file signature corpus). The `.sqlx/` offline cache (~95 entries) is a hard floor required for downstream `SQLX_OFFLINE=true` builds without sqlx-cli; further reduction would require splitting the cache into lib-only vs all-targets variants and is deferred (#22)
- §20.4 of [cairn-design.md](cairn-design.md) replaced its three-paragraph "named handoff target TBD" narrative (stale post-v1.0) with a brief two-sentence pointer to [MAINTAINERS.md](MAINTAINERS.md) as the durable source of truth for the archive-on-silence policy. Single-source-of-truth — no policy duplication (#17)

### Fixed
- Three timing-sensitive auth-cache tests (`doc_cache_returns_cached_then_expires`, `doc_cache_negative_has_shorter_ttl`, `jti_cache_expiry_permits_reuse`) deflaked by routing wall-clock reads through a new `Clock` trait. Production wires `SystemClock`; tests substitute `MockClock` with explicit `advance(Duration)` calls. Zero `thread::sleep` in cache tests; deterministic regardless of CI scheduler jitter. Verified correctness power before commit by intentionally breaking `DidDocCache::get` and `JtiCache::check_and_record` and confirming the relevant tests panic (#21)

### Removed

### Security

## [1.0.0] - 2026-04-24

### Added

### Changed
- Design-doc drift sweep: crate name, security contact, tracker references, CHANGELOG phrasing (#5)
- Release workflow: manual workflow_dispatch triggers crates.io publish + GitHub Release, with non-blocking post-publish smoke test (#4)
- CI hardening: rustdoc + MSRV gates, rust-cache; MSRV bumped 1.85→1.88 (#3)
- Complete rustdoc sweep for tier 3 items deferred from #22 (#11)

### Fixed
- `cairn publish-service-record` audit trail: skip path now audits (was silent), publish path records `content_changed=true` (was inverted on first publish), and `labeler_config` upsert + audit row share one transaction (#20)
- `cairn serve` exited ~30 seconds after startup with no signal received; the drain timeout now bounds only the post-shutdown drain phase (#19)
- Clippy 1.95 `collapsible_if` on five nested if-let sites (#14)

### Removed

### Security
