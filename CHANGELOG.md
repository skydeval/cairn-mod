# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.8.0] - 2026-07-22

The v1.8 series ships as one release: the Rust-PDS backend, from
the service-auth foundation (v1.8.1) through protocol parity,
reads, writes, audit verification, batch, realtime,
ops-and-runtime, operator extensions, series wrap (v1.8.11), and
kryphocron consumption (v1.8.12–v1.8.15). Per-release subsections
below preserve the development attribution.

### Added — v1.8.15 kryphocron handling guide
- New operator guide (`docs/laquna-operator-guide.md`) for working with kryphocron-encoded private records: diagnosing a codec the deployment can't read, inspecting an un-decodable record, reading rotation cadence, and codec-version forward compatibility. Documentation only; closes the kryphocron consumption workstream.

### Added — v1.8.14 kryphocron context on resolved reports
- Resolving a report about a decoded private record now records the content tier and decode source on the resolution's audit entry, so the audit trail shows which moderation decisions touched decoded private content.
- New `cairn pds-admin events query --kryphocron-only` flag filters a page of moderation events down to kryphocron events.

### Added — v1.8.13 private-record retrieval on report intake
- When a report's subject is a private record cairn-mod can decode, the plaintext is retrieved at report intake and stored on the report, so opening the report stays a plain read; opt-in via the `kryphocron-read` capability, and a record whose codec isn't installed is left un-decoded with the report still filed.

### Added — v1.8.12 kryphocron capability wiring
- cairn-mod can now consume kryphocron, the private-record capability a Rust PDS may advertise; this release wires and detects it only, and nothing happens unless the operator enables it (default off).
- `cairn pds-admin probe` reports kryphocron state when enabled — the installed codec, its seed policy, and decode readiness.
- Building from source now needs a C toolchain (the kryphocron dependency pulls in C libzstd).

### Added — v1.8.11 series wrap
- New `cairn pds-admin probe` compatibility check runs `describeCapabilities` against the configured Rust PDS and reports which capabilities line up, so operators can verify a PDS before enabling gated surfaces (`--json` for a structured report).
- The deprecated `acknowledge_v1_8_1_audit_divergence` config field is removed; configs still carrying it are ignored.

### Added — v1.8.10 operator extensions
- New `cairn pds-admin ops` subcommands surface eight read-only instance-visibility views from the PDS — health, sequencer, federation, blobs, database, resources, version, and system metrics — each with `--json`.
- Availability is discovered at the wire; a view the PDS doesn't offer surfaces a clear operator hint rather than a hard failure.

### Added — v1.8.9 ops and runtime
- Operators can read the PDS's instance metrics and get/set the PDS's runtime settings via `cairn pds-admin`; runtime writes require operator opt-in (`runtime-settings = "v1"`) and a SuperAdmin-granted service identity on the PDS.
- New `cairn pds-admin moderator-activity <did>` view summarizes a single moderator's activity.

### Added — v1.8.8 realtime stream consumption
- cairn-mod can now consume the PDS's realtime moderation event stream when the operator opts in (`mod-events-stream = "v1"`), reconnecting automatically and surviving restarts.
- Upstream report resolutions annotate matching local reports; the operator's own local report status stays operator-owned.
- Optionally re-verifies the PDS's streamed audit-chain entries against cairn-mod's own recompute, recording both verdicts so any disagreement is visible.
- New `cairn stream` CLI inspects and, when needed, overrides the stream cursor.

### Added — v1.8.7 batch endpoints + multi-subject dispatch
- New batch endpoints for account takedown, suspension, restore, and record takedown, plus multi-subject variants of the existing action verbs — all requiring operator opt-in (`batch-takedown = "v1"`).
- New `cairn pds-admin` subcommands for each: batch account actions, multi-subject blob and record actions, and multi-subject status updates.

### Added — v1.8.6 audit verification
- New `cairn audit cross-verify` command independently re-verifies the PDS's hash-chained audit trail against cairn-mod's own records and reports any divergence with a distinct exit code; `--history` lists past outcomes.
- Operators can read the PDS's audit trail and fetch individual audit entries via `cairn pds-admin`.

### Added — v1.8.5 action surface enrichment
- `cairn pds-admin` gains ten moderation actions against a Rust PDS: delete account; quarantine/restore/delete blob; resolve/dismiss report; resolve/escalate appeal; send email; and update subject status. Each shows the full outcome, with `--summary` for a one-liner.
- The appeals surface is now complete end-to-end: list and inspect appeals (v1.8.4), then resolve or escalate them.
- `[pds_admin.action_map]` must now map the ten new action types (or `"skip"` them).

### Added — v1.8.4 moderator read surface completion
- cairn-mod now covers every moderator read endpoint on a Rust PDS: fetch an event, a subject's context and history, and list and inspect appeals.
- New `cairn pds-admin` subcommands expose all of them: `events get`, `subjects context`, `subjects history`, `appeals list`, `appeals get`.

### Added — v1.8.3 read-side foundation + CID plumbing
- cairn-mod can now read a Rust PDS's moderation surface — the event stream and per-subject status rows — via new `cairn pds-admin events query` and `statuses query` subcommands that print a page as JSON.
- Record-targeted actions can now carry the record CID, so a fully record-shaped action targets that record rather than escalating to an account-level takedown.

### Added — v1.8.2 protocol parity
- cairn-mod can now execute account takedowns, suspensions, restorations, and record takedowns against a Rust PDS, in lockstep with label emission and the existing audit chain.
- Record takedowns require the record's full coordinates (AT-URI and CID); a partially-shaped record target is rejected rather than dispatched.

### Changed — v1.8.2
- A takedown recorded against a record no longer escalates to a whole-account takedown at the PDS; without a record CID it is recorded locally and not dispatched, rather than silently widening into an account action. Account-targeted actions are unaffected.

### Added — v1.8.1
- New `[pds_admin].backend` selector chooses the active PDS backend (`"ozone"` or `"rust"`); with one backend block declared it auto-detects, and an ambiguous or dangling selection is rejected at startup with a clear error.
- New `[pds_admin.rust]` config block declares a Rust-PDS backend (URL, service identity, signing-key env var, and target PDS identity), authenticated per-call with short-lived ES256K service-auth tokens — no OAuth, no token cache.
- The Rust-PDS backend (`backend = "rust"`) now boots. v1.8.1 is inspector-only: it probes the PDS's advertised capabilities at startup and refuses enforcement actions until protocol parity lands in v1.8.2, so standing it up against a Rust PDS in v1.8.1 requires an explicit acknowledgement.
- The early-design `[pds_admin.locus]` block name is rejected at config load with a message pointing at the new `[pds_admin.rust]` name, so a stale config surfaces immediately.
- Backend failures now carry a structured operator-facing category in the audit trail and structured logs; operators parsing failure logs by category should note the new value set.

### Changed — v1.8.1
- The `apply_label` / `negate_label` methods on the Ozone backend now report as architecturally forbidden rather than merely unsupported — behavior is unchanged (cairn-mod has always forbidden them), the distinction is clearer operator semantics.

### Fixed

### Deprecated

### Removed

### Security

## [1.7.0] - 2026-04-30

> v1.7 "PDS-side enforcement bridge & inbound XRPC gateway" closes the
> loop between cairn-mod and the operator's PDS. Outbound, cairn-mod
> propagates account-state changes to the configured PDS in lockstep
> with label emission; inbound, an XRPC gateway lets cairn-mod stand in
> for Ozone on a bsky-PDS. Both halves are opt-in and disabled by
> default, so upgrading from v1.6 changes no behavior until an operator
> turns them on.

### Added

- Outbound PDS-side enforcement: when enabled, cairn-mod propagates
  account takedowns, suspensions, and restorations to the operator's
  configured PDS in the same pipeline that emits labels, declared via a
  new `[pds_admin]` config block (bsky-PDS supported this release).
- Inbound XRPC gateway: when enabled, cairn-mod accepts proxied
  `tools.ozone.moderation.*` calls (emitEvent, queryStatuses,
  queryEvents) and PDS-forwarded `com.atproto.moderation.createReport`,
  making it a drop-in Ozone replacement for operators on bsky-PDS.
- Trust tables for the gateway: operators manage which moderator DIDs
  and which upstream PDSes cairn-mod accepts inbound calls from, with
  new `cairn xrpc-callers` and `cairn xrpc-pdses` CLI commands.
- New `cairn pds-admin {takedown, suspend, restore}` commands — a
  manual escape hatch for the enforcement bridge that still records
  strikes and audits like any other action.
- New `cairn moderator events` view over the full audit-log vocabulary,
  with `--ozone-only` to show just the Ozone-eligible subset.
- Every outbound backend call and every inbound mutation stays on
  cairn-mod's hash-chained audit trail, and `cairn audit verify` now
  walks it.

### Changed

### Fixed
- `getSubjectHistory` returned null for the `actorKind` and
  `triggeredByPolicyRule` fields — the v1.6 columns existed but the
  read side never surfaced them; now populated across the API and the
  `cairn moderator history` output (which gains an ACTOR column).
- Enabling the XRPC gateway no longer panics at startup on a duplicate
  createReport route; the user-direct and PDS-forwarded report paths
  now share one route.

### Removed

### Security

## [1.6.0] - 2026-04-27

> v1.6 "Policy automation" lets operators declare strike-threshold
> rules that fire inside every recordAction: auto-mode rules take the
> consequent action immediately, flag-mode rules queue a pending row
> for moderator review. Pending state is moderator-tier only — the
> public surface still shows what cairn-mod has done, not what it
> might do.

### Added

- Policy automation: operators declare strike-threshold rules in a new
  `[policy_automation]` config block, and cairn-mod evaluates them
  inside every recordAction — auto-mode rules record the consequent
  action in the same transaction, flag-mode rules queue it for review.
- Moderator review queue: pending policy actions can be listed,
  inspected, confirmed (materializing a real action the moderator owns,
  with the originating rule preserved for provenance), or dismissed,
  via `tools.cairn.admin.*` endpoints and `cairn moderator pending
  {list, view, confirm, dismiss}`.
- Taking down a subject auto-dismisses that subject's unresolved
  pendings in the same transaction, whatever path the takedown came
  from.
- Every policy event — rule firings, pending creation, confirmation,
  dismissal, and cascade — is recorded on the audit chain with enough
  discrimination for consumers to tell moderator-driven from
  policy-driven actions apart.

### Changed

- Pending policy actions are moderator-tier visibility only; the public
  strike-state surface is unchanged. Subscribers see what cairn-mod has
  done, not what it might do.

### Fixed

## [1.5.2] — 2026-04-27

> Closes a v1.5 documentation gap.

### Changed

- Documented the `cairn moderator labels` subcommand (shipped in v1.5)
  in the moderator CLI reference.

## [1.5.1] — 2026-04-27

> Documentation reorganization for clearer audience separation — no
> behavior changes.

### Changed

- Split the README into audience-focused documents: the README keeps
  the project pitch, status, and architecture summary; new SETUP and
  OPERATIONS guides cover first deployment and day-2 operation; and a
  moderator CLI reference collects the moderator commands.

## [1.5.0] - 2026-04-27

> v1.5 "Label emission" turns every recorded action into ATProto labels
> that consumer AppViews honor, and negates them atomically on
> revocation. Operators declare the action-to-label mapping; subjects
> can see their own active labels, and operators can query the same.

### Added
- Recorded actions now emit ATProto labels, signed and persisted in the
  same transaction as the action so the audit trail never claims an
  emission that didn't happen. Operators declare the mapping — including
  per-action value, severity, blurs, and locales — in a new
  `[label_emission]` config block, with sensible defaults out of the box.
- Reason labels emit as `reason-<code>` alongside their action label
  and share its expiry on temp suspensions.
- Revoking an action atomically negates every label it emitted, reading
  the stored values (not current policy) so a policy edit between
  emission and revocation can't desynchronize the negation.
- Subjects can introspect their own active labels via
  `tools.cairn.public.getMyStrikeState`, and operators can query the
  same subject via `cairn moderator labels <subject>`.

### Changed

### Fixed

### Removed

### Security

## [1.4.0] - 2026-04-26

> v1.4 "Account moderation state model" makes moderation first-class:
> every action against a subject writes a structured record with a
> strike value frozen at action time. Strikes accumulate, dampen for
> first-time offenders, and decay over time per operator-configurable
> rules. Read endpoints recompute strike state on every fetch, so a
> stale cache can never give a misleading answer.

### Added
- Account moderation state model: every action (warning, note, temp or
  indefinite suspension, takedown) is recorded as a structured,
  append-only row with reason metadata, duration, notes, and links to
  the source report.
- Operators declare their moderation vocabulary and strike policy in
  new `[moderation_reasons]` and `[strike_policy]` config blocks —
  reason weights and severity, good-standing threshold, dampening, and
  decay function/window. cairn-mod ships eight default reasons aligned
  with ATProto's `reasonType`.
- Strikes are resolved at action time (dampened for users in good
  standing, full weight otherwise, severe reasons bypassing dampening)
  and frozen on the row; current strike state is recomputed through a
  decay calculator on every read.
- Admin XRPC to record and revoke actions and to read a subject's
  history and strike state, plus a new `tools.cairn.public.*` namespace
  with `getMyStrikeState` for subjects to check their own standing.
- New `cairn moderator {action, warn, note, revoke, history, strikes}`
  commands for recording and reviewing moderation from the CLI.

### Changed

### Fixed

### Removed

### Security

## [1.3.0] - 2026-04-26

> v1.3 "Audit integrity" makes audit-log tampering cryptographically
> detectable: every audit row carries a SHA-256 hash chained to the
> previous row, and operators verify, backfill, and inspect those
> hashes from the CLI.

### Added
- Hash-chained audit log: every audit row carries a hash chained to the
  previous row, so tampering with any row's content or stored hash is
  detectable.
- New `cairn audit verify` walks the chain and reports the first
  divergence (safe to run against a live server); `cairn audit-rebuild`
  backfills hashes onto pre-v1.3 rows.
- `cairn audit show <id>` and the audit-log API now surface each row's
  hash and its predecessor's.

### Changed

### Fixed

### Removed

### Security

## [1.2.0] - 2026-04-26

> v1.2 "Trust-chain transparency" makes the labeler's trust posture
> auditable, adds a per-entry audit-log view, and gives the
> service-record lifecycle its inverse.

### Added
- New `tools.cairn.admin.getTrustChain` endpoint and `cairn trust-chain
  show` command: a read-only summary of the instance's trust posture —
  signing-key history, maintainer roster (noting HTTP-attested vs
  CLI-inserted entries), the published service-record hash and declared
  label values, and instance metadata.
- Per-entry audit-log lookup via `cairn audit show <id>`, complementing
  the existing list query.
- New `cairn unpublish-service-record` command removes the labeler's
  service record from the operator's PDS and audits the removal;
  idempotent, and startup verify then flags the absent record until it
  is republished.

### Changed

### Fixed

### Removed

### Security

## [1.1.0] - 2026-04-25

> v1.1 "Pleasant to operate" focuses on operational comfort for
> self-hosters: health probes, supply-chain scanning in CI, the full
> admin CLI surface, startup-time service-record drift detection, and a
> slimmer published package.

### Added
- Unauthenticated `/health` and `/ready` probe endpoints for
  orchestrators.
- Supply-chain scanning in CI: `cargo-audit` and `cargo-deny` on every
  push and PR, plus a daily scheduled audit that opens an issue on new
  advisories.
- The full admin CLI surface: `cairn moderator {add, remove, list}` for
  membership, `cairn report {list, view, resolve, flag, unflag}` for
  the report workflow, and `cairn audit list` for filtered, paginated
  audit-log queries.
- `cairn serve` verifies the published service record on the operator's
  PDS at startup and fail-starts on drift, absence, or an unreachable
  PDS, each with a distinct exit code.
- subscribeLabels retention sweep: a daily batched delete of labels past
  the configured retention window, plus operator-initiated runs via
  `tools.cairn.admin.retentionSweep` and `cairn retention sweep`, under
  a new `[retention]` config block.

### Changed
- The published crates.io package is trimmed from 287 files to 168,
  dropping internal docs, CI config, and the test corpus that
  `cargo install` doesn't need.

### Fixed
- Three timing-sensitive auth-cache tests deflaked by routing
  wall-clock reads through an injectable clock; they no longer depend
  on CI scheduler timing.

### Removed

### Security

## [1.0.0] - 2026-04-24

### Added

### Changed
- Release workflow: a manual dispatch publishes to crates.io and cuts a
  GitHub Release, with a non-blocking post-publish smoke test.
- CI hardening: rustdoc and MSRV gates plus build caching; MSRV raised
  to 1.88.

### Fixed
- `cairn publish-service-record` now audits the skip path (previously
  silent), records the change flag correctly on first publish, and
  writes its config update and audit row in one transaction.
- `cairn serve` no longer exits about 30 seconds after startup when no
  shutdown signal was received; the drain timeout now bounds only the
  post-shutdown phase.

### Removed

### Security
