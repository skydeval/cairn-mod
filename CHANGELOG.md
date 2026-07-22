# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v1.8.10 operator extensions
- Eight new read-only instance-visibility endpoints consumed from
  the upstream PDS's ops namespace (trait 40 → 48, all Unsupported
  on Ozone): system health, sequencer status, federation status,
  blob statistics, database status, resource usage, version info,
  and system metrics. All are **capability-bare upstream** — no
  advertisement strings exist for them, so there is no capability
  gate and no operator pin: availability is discovered at the
  wire, and a 404 surfaces with an operator hint pointing at the
  upstream's `describeCapabilities` output and release notes
  (endpoint availability varies by PDS version; the advertised
  list is advisory for this surface).
- Seven of the eight return the upstream's JSON verbatim — the
  upstream builds those bodies ad hoc with no contract types, so
  cairn-mod deliberately ships **no fabricated mirrors**: the raw
  body passes through, human rendering formats known headline
  fields when present and falls back to pretty JSON otherwise,
  and `--json` always emits the body untouched. Federation status
  is the one typed response (camelCase wire).
- New `cairn pds-admin ops` subcommand group: `metrics` (moved
  from `cairn pds-admin metrics` — direct rename, old path
  removed), `health`, `sequencer`, `federation`, `blobs`,
  `database`, `resources`, `version`, `system-metrics`; all take
  `--json`. The existing `blobs` *action* group is unaffected by
  the same-named read inside `ops`.
- No new capability registry entries, no migration, no config
  changes — deliberately: the consumed surface advertises
  nothing, persists nothing, and configures nothing. The
  registry-additions cadence of v1.8.6–v1.8.9 breaks here by
  fidelity to source, not oversight.

### Added — v1.8.9 ops and runtime
- Three new backend methods (trait 37 → 40), all Unsupported on
  Ozone: `get_instance_metrics` (aggregated instance health /
  resource / growth / federation metrics from the upstream PDS's
  ops namespace — absent counters mean "not instrumented" and are
  rendered as such, never zero-filled), `get_runtime_setting`, and
  `set_runtime_setting` (the upstream's two-tier runtime
  configuration surface).
- **Operator opt-in required for the runtime-settings pair** —
  `runtime-settings` is the registry's third `OperatorOptIn`
  family, and the pin gates read AND write (family-level):
  `runtime-settings = "v1"` under `[pds_admin.rust.pinned_versions]`
  (dual-posture rules identical to the batch and stream opt-ins).
  `instance-metrics` is AutoAdvance. Registry 8 → 10.
- Runtime-setting reads surface the upstream's four-tier
  resolution verbatim (`Runtime` / `File` / `Default` /
  `RecoveryMode`) — including the recovery-mode override that
  forces `moderation-mode` reads to `"full"`, so operators see
  the override honestly. Unknown keys are a normal answer with
  `source: Default`, not an error. cairn-mod reads
  `moderation-mode` for visibility only; its moderation dispatches
  work regardless of the upstream's mode.
- Writes require a SuperAdmin-granted service DID upstream
  (403 → `Auth`); the upstream's key allowlist and per-key value
  validation are authoritative — **cairn-mod deliberately copies
  no key list** (unknown keys are rejected upstream with the
  known-keys enumeration), and its only local checks are a
  non-empty `--reason` and a `--yes` confirm. Successful writes
  return the value diff plus the upstream audit-chain entry id
  (setting writes are audit-chained upstream and emit no
  moderation event — they appear on the v1.8.8 stream only as
  audit-entry frames).
- New local ledger `runtime_settings_writes` (migration `0013`,
  additive-only, unchained): what this cairn-mod changed, when,
  and under which upstream chain entry. Best-effort (the upstream
  chain entry is the authoritative record); not auto-joined by
  `cairn audit cross-verify` — correlate via the stored entry id;
  operators MAY prune.
- Shared capability-gate helper extracted (`require_opt_in`) and
  the batch POST dispatch generalized — the v1.8.7 batch and
  v1.8.8 stream gates now use the same implementation, with their
  shipped posture tests passing unchanged.
- New CLI, all under `cairn pds-admin`: `metrics [--json]`,
  `runtime get <key>`, `runtime set <key> <value> --reason … --yes`,
  and `moderator-activity <did> [--after/--before/--limit]` — a
  per-moderator activity view (summary counts + rows) over the
  actor-scoped event query shipped in v1.8.3; read-only, no new
  wire surface.

### Added — v1.8.8 realtime stream consumption
- cairn-mod now consumes the upstream PDS's realtime moderation
  event stream (`subscribeModEvents` WebSocket): a long-lived
  consumer task with a reconnect state machine, spawned by
  `cairn serve` when `[pds_admin.rust.stream].enabled = true`.
  The stream is JSON text frames (hello / event / auditEntry /
  heartbeat / outdatedCursor / error); delivery is near-realtime
  (the upstream polls on a 5-second tick over a retention-bounded
  channel, 7-day default).
- **Operator opt-in required** — `mod-events-stream` is the
  capability registry's second `OperatorOptIn` family: the
  consumer connects only when the upstream advertises
  `mod-events-stream-v1` AND the operator pins
  `mod-events-stream = "v1"` under
  `[pds_admin.rust.pinned_versions]` (same dual-posture rules as
  v1.8.7's batch opt-in). Unpinned or unadvertised, the task
  parks dormant and re-evaluates with backoff.
- One new backend method, `subscribe_mod_events` (trait 36 → 37)
  — the trait's first stream-returning method. Ozone:
  Unsupported. Reconciliation deliberately adds NO second method:
  it reuses v1.8.3's `query_events` in a consumer-side page loop.
- **At-most-once ingestion (F10), realized cairn-mod-side**: two
  independent cursors (event stream + audit chain) persist to the
  new `stream_cursors` table BEFORE each frame is processed. A
  frame whose ingestion fails is lost by design (logged with full
  context); nothing is ever re-delivered into side effects.
  Heartbeats never advance cursors; a cursor-less connect seeds
  from the server's hello.
- **Echo suppression**: events whose id matches a recent local
  dispatch (`pds_admin_audit.backend_action_id`, PerEvent and
  PerBatch alike) are acknowledged but not mirrored — cairn-mod's
  own actions are already first-class locally. Cascade reversals
  of cairn-mod-approved appeals are ingested by design
  (identifiable via `details.cascadeOf` + the service DID);
  check failures fail open to ingestion.
- Genuinely-upstream events land in the new unchained
  `upstream_events` table (verbatim payload; UNIQUE event id =
  reconciliation dedup; operators MAY prune). Upstream
  `report_review` resolutions annotate matching pending local
  reports via the new write-once `reports.upstream_resolution`
  column (`resolved`/`dismissed`; matched by subject coordinates
  — report ids do not ride the wire; local `status` stays
  operator-owned).
- Optional `include_audit_chain`: streamed audit-chain entries
  are independently re-verified through v1.8.6's Path A pipeline
  and mirrored to the new `upstream_audit_mirror` table with BOTH
  verdicts (`verified_upstream` = the upstream's own recompute,
  `verified_local` = cairn-mod's) — disagreement is itself
  signal. Tampered entries are mirrored as evidence, not dropped;
  `cairn audit cross-verify` remains the authoritative exit-15
  surface.
- On `outdatedCursor` (client fell behind the retention window):
  automatic reconciliation backfills the gap from the unpruned
  historical aggregate via `query_events`, then resubscribes
  live; overlap is absorbed by the dedup key.
- New `cairn stream` CLI: `status` (durable cursor +
  observational-table state), `cursor get`, and the confirmed
  overrides `cursor set` / `cursor reset` (at-most-once escape
  hatches; replay is idempotent). `stream start`/`stop`
  subcommands are deferred — they need an authenticated
  server-side control endpoint (its own small design); the
  v1.8.8 mechanism is the `enabled` toggle + restart, which also
  clears an auth HardStop.
- Migration `0012` (additive-only): `stream_cursors`,
  `upstream_events`, `upstream_audit_mirror`,
  `reports.upstream_resolution`, and the previously-missing
  index on `pds_admin_audit.backend_action_id`.
- Config: `[pds_admin.rust.stream]` — `enabled` (default false),
  `include_audit_chain` (default false), `reconnect_max_backoff`
  (default 60s), `silence_timeout` (default 35s; must exceed the
  upstream's 30-second heartbeat), `reconnect_on_normal_close`
  (default false).

### Added — v1.8.7 batch endpoints + multi-subject dispatch
- Ten new backend methods (trait 26 → 36). Four dedicated batch
  methods consume the upstream PDS's atomic batch endpoints —
  `batch_takedown_accounts`, `batch_suspend_accounts`
  (indefinite-only by wire contract), `batch_restore_accounts`,
  and `batch_takedown_records` (**URI-level**: bare AT-URIs, all
  versions at each URI). Six `..._many` methods extend the v1.8.5
  verbs to multi-subject dispatch in one `emitEvent`:
  `delete_account_many`, `quarantine_blob_many`,
  `restore_blob_many`, `delete_blob_many`, `takedown_record_many`
  (**CID-level**: every subject requires a non-empty CID;
  URI-level batches belong to `batch_takedown_records`), and
  `update_subject_status_many`. All are Unsupported on Ozone.
- Batch dispatch is **whole-batch atomic** upstream: partial
  success is not an observable state. A per-subject failure aborts
  the entire batch and surfaces the failing index and subject id
  in the error message.
- **Operator opt-in required** for the four dedicated batch
  methods — the new `batch-takedown` capability family is the
  registry's first `OperatorOptIn` entry, and advertisement alone
  does not activate it. With an empty `required_capabilities`
  (permissive baseline), opting in is one line:

  ```toml
  [pds_admin.rust.pinned_versions]
  batch-takedown = "v1"
  ```

  With a non-empty `required_capabilities` (strict baseline), the
  existing pin cross-check applies — add `batch-takedown-v1` to
  `required_capabilities` as well, which also makes the capability
  probe-required at startup. Unpinned (or unadvertised) dispatch
  refuses with `CapabilityNotAdvertised("batch-takedown-v1")`.
  The six `..._many` methods ride their verbs' existing
  capability gates unchanged.
- Nine new CLI subcommands, all through the recordAction writer:
  `accounts batch-takedown|batch-suspend|delete-many`,
  `blobs quarantine-many|restore-many|delete-many` (blob refs as
  `<did>@<cid>`), the new `records` group with `batch-takedown`
  (bare AT-URIs) and `takedown-many` (`<at-uri>#<cid>`, CID
  fragment required), and `subjects update-status-many`.
  `accounts batch-restore` is intentionally NOT shipped:
  `batch_restore_accounts` is trait-only this release — cairn-mod's
  restore semantics ride the single-target revoke flow, and a
  batch-revoke writer design is deferred.
- One `subject_actions` intent row per batch: `action_type` reuses
  the singular verb's value, the first subject's DID occupies the
  flat `subject_did` column, and the authoritative subjects list
  rides `action_detail` with a `batch: true` marker. **Batch rows
  are strike-exempt** (`strike_value_base/applied = 0`) — the
  one-subject-one-strike semantic doesn't compose with N-subject
  aggregation; per-subject singular rows remain the strike surface.
- One `pds_admin_audit` row per batch, stamped with the new
  `PerBatch` action-id variant (first production construction; the
  stored TEXT payload is unchanged in shape, so
  `cairn audit cross-verify` joins batch rows to their upstream
  chain entries with zero changes). Dedicated-batch outputs store
  `cascading_actions_json` as NULL (no cascade channel), distinct
  from the emitEvent responses' `"[]"`.
- Batch size caps mirror the upstream constants and are validated
  client-side before any wire call (at-cap passes): 50 for the
  dedicated batch endpoints and multi-subject default, 10 for
  `delete_account_many`, 25 for `delete_blob_many`. Upstream
  re-validates; the upstream values remain authoritative.
- No migration: v1.8.7 rides the v1.8.5/v1.8.6 schema unchanged.

### Added — v1.8.6 audit verification
- New `cairn audit cross-verify` command: verifies cairn-mod's own
  four-table hash chain, fetches the upstream PDS's hash-chained
  audit trail, **independently re-verifies every upstream entry
  byte-for-byte** (both the current 15-field canonical form and the
  pre-v0.9 legacy form, including the wire-to-canonical timestamp,
  payload, and subject transforms and the pre-chain sentinel rules),
  and joins local dispatch rows to their upstream chain entries via
  the response ids recorded since v1.8.5. Any divergence exits 15
  with a JSON `outcome` discriminator (`divergence-local` /
  `divergence-cross` / `divergence-join-mismatch`); pre-v1.8.5 rows
  without join keys are reported as unjoinable, never as divergent.
- Two new backend read methods behind the new `audit-trail`
  capability family: `get_audit_trail` (paged, with the upstream's
  own whole-chain verdict) and `get_audit_entry` (by id or by
  hash). Unsupported on Ozone.
- `verification_persist` (accepted since v1.8.1) gains its
  consumer: cross-verify outcomes persist to the new
  `cross_verify_outcomes` table (migration `0011`, additive-only)
  and are listable via `cairn audit cross-verify --history`.
  Setting it `false` runs the verification without recording.
- cairn-mod's own `pds_admin_audit` row hash now covers the v1.8.5
  response columns (12-field preimage). Migration `0011` captures a
  per-deployment format boundary; `cairn audit verify` checks
  pre-boundary rows under the v1.7 form and post-boundary rows
  under the new form (with a counted, non-failing fallback for
  mid-upgrade writes, surfaced as `legacy_form_rows`).
- `acknowledge_v1_8_1_audit_divergence` is deprecated: the
  divergence it acknowledged is closed by cross-verification. The
  field now draws a warning and is ignored; it will be removed in
  the v1.8.11 series wrap. The auto-mode-rules and xrpc-gateway
  coexistence gates are unchanged.
- Docs: `cairn audit verify`'s module notes now describe the
  four-table walk it has actually performed since the xrpc
  membership tables joined the chain (the stale two-table wording
  misled this cycle's recon).

### Added — v1.8.5 action surface enrichment
- RustBackend now dispatches 14 of Aurora's 16 `emitEvent` action
  variants: added delete-account, quarantine/restore/delete-blob,
  resolve/dismiss-report, resolve/escalate-appeal, send-email, and
  update-subject-status handlers on top of v1.8.2's four. Label
  operations remain architecturally forbidden (cairn-mod's
  `subscribeLabels` is the canonical label surface), which caps the
  dispatched set at 14 by design.
- New response type `ActionResponse` surfaces Aurora's `eventId`,
  `auditEntryId`, `snapshots`, and `cascadingActions` (bare event
  ids — resolve details via `events query`/`events get`). Appeal
  approvals surface the cascaded reversal's event id. The v1.8.2
  emit dispatch helper now parses the full response; the v1.8.2
  methods are unchanged on the surface.
- Per-action role handling: delete-account and send-email surface
  Admin-role-insufficient failures as auth errors (exit 5) — those
  two are Admin-gated upstream; the blob verbs are Moderator-tier.
- Migration `0010` extends `subject_actions.action_type` and
  `pds_admin_audit.backend_method` with the ten new values, adds
  `subject_actions.action_detail` (variant data: report/appeal ids,
  decisions, email fields, status values), and adds upstream
  response persistence to `pds_admin_audit`
  (`upstream_audit_entry_id`, `cascading_actions_json`,
  `snapshots_json` — the existing `backend_action_id` column keeps
  the root event id). Both tables are rebuilt with their append-only
  triggers preserved; the two other tables referencing
  `subject_actions` are re-created unchanged as part of the rebuild.
- Ten new `cairn pds-admin` subcommands, all routing through the
  recordAction writer (writer-owned dispatch + audit): `accounts
  delete`, `blobs quarantine|restore|delete`, `reports
  resolve|dismiss`, `appeals resolve|escalate`, `emails send`,
  `subjects update-status`. Report and appeal subcommands take the
  target's full subject coordinates (`--uri`/`--cid`) because the
  upstream validates the embedded id against the subject by variant
  and identifier. Default output is the full JSON outcome including
  cascading actions; `--summary` prints a one-liner.
- **Config note:** `[pds_admin.action_map]` must now cover the ten
  new action types (map each to its same-named method, or `"skip"`).
  The coverage rule is unchanged in spirit — every action type is
  mapped explicitly — the set just grew.
- Appeals surface is now complete end-to-end: list and inspect
  appeals (v1.8.4), then resolve or escalate them (v1.8.5).
- OzoneBackend returns `Unsupported` (exit 17) for all ten new
  methods; per-method real bsky-PDS-admin mappings were considered
  and deferred past v1.8.
- Policy automation cannot propose the new verbs — they are
  operator commands; `pending_policy_actions` keeps its
  five-value vocabulary. The new verbs never emit labels and never
  carry strikes.


### Added — v1.8.4 moderator read surface completion
- RustBackend now covers every read endpoint under
  `tools.aurora.moderator.*`. New methods: `get_event`,
  `get_subject_context`, `get_subject_history`, `list_appeals`,
  `get_appeal`. Subject context/history are account-scoped (plain
  DID parameter); history rows are action rows (the same shape
  `query_statuses` returns), and `get_appeal` returns the list-view
  fields plus a lifecycle timeline.
- New CLI subcommands: `cairn pds-admin events get`,
  `subjects context`, `subjects history`, `appeals list`,
  `appeals get`. Appeal status filters take snake_case wire values
  (`pending`, `under_review`, `approved`, `denied`, `escalated`).
- Three new capability families in the registry: `subject-context`,
  `subject-history`, `appeals` (advertised as `subject-context-v1`,
  `subject-history-v1`, `appeals-v1`; `getAppeal` shares the
  `appeals` gate with `listAppeals`). `getEvent` shares v1.8.3's
  `moderator-activity` family, which now gates exactly three
  endpoints: `queryEvents`, `queryStatuses`, `getEvent`. Each family
  gates independently — a PDS advertising `moderator-activity-v1`
  without `subject-context-v1` keeps event/status reads working
  while subject-context reads report the missing capability.
- OzoneBackend returns `Unsupported` for all five new methods;
  Ozone's read surface still requires distinct service configuration
  (out of v1.8 scope).
- The umbrella plan's `getReporterContext` reference is reconciled
  as a `queryEvents` actor-filter derivation — no distinct endpoint
  exists upstream, so no new method was added for it.

### Added — v1.8.3 read-side foundation + CID plumbing
- RustBackend can now read the upstream PDS's moderation surface:
  `query_events` (moderation event stream) and `query_statuses`
  (per-DID status rows) via `tools.aurora.moderator.queryEvents` /
  `queryStatuses`. Both gate on the shared `moderator-activity`
  capability. OzoneBackend returns `Unsupported` for both (the Ozone
  read surface is not colocated with bsky-PDS).
- New CLI subcommands: `cairn pds-admin events query` and
  `cairn pds-admin statuses query` — query the configured backend
  directly and print the page as JSON. Filters map 1:1 onto the
  upstream parameters (`--event-type` takes snake_case values like
  `account_takedown`; `--subject-type` takes `account`/`record`/`blob`).
  New exit codes: 16 (capability not advertised), 17 (backend
  unsupported), 18 (terminal backend error). The v1.8.3 design draft
  assigned 14/15 but those were already taken by
  `SERVICE_RECORD_UNREACHABLE`/`AUDIT_DIVERGENCE`.
- Added `subject_cid` column to `subject_actions` (migration `0009`;
  the append-only trigger is rebuilt to guard the new column, all
  existing clauses preserved). Record-targeted actions can now carry
  the record CID: supply it on `recordAction` (`cid` field), or let
  the writer derive it from a referenced report about the same record
  (`reports.subject_cid` join, URI-matched). Fully record-shaped rows
  (URI + CID) now auto-elevate to `takedown_record` at dispatch;
  legacy rows without a CID continue to reject with a `validation`
  outcome rather than escalating to account-level takedown.

### Added — v1.8.2 protocol parity
- RustBackend can now execute account takedowns, suspensions, restorations,
  and record takedowns against Rust PDSes (Aurora-Locus and compatible) via
  `tools.aurora.admin.emitEvent`. Suspension duration is transmitted as
  `metadata.durationDays`; omitted duration means indefinite. Moderator
  `notes` are retained in cairn-mod's audit chain but are not transmitted
  to the PDS (the emitEvent wire has no notes field; `rationale` carries
  the first `reason_codes` entry).
- Added `takedown_record` to the `PdsAdminBackend` trait. Ozone implements
  it via `com.atproto.admin.updateSubjectStatus` with a `strongRef`
  subject; RustBackend dispatches it via `emitEvent` with a record
  subject. Both require the record's AT-URI **and** CID; a
  partially-shaped subject is rejected with a `validation` outcome.
- Subject-shape-aware dispatch routing: a takedown mapped to
  `takedown_account` whose underlying action row targets a record (URI +
  CID both present) auto-elevates to `takedown_record`. `takedown_record`
  is also directly mappable in `[pds_admin.action_map]`.
- Extended the audit chain's `backend_method` column to accept
  `takedown_record` (migration `0008`; automatic, no operator action
  needed).
- Dispatching with empty `reason_codes` now logs a WARN naming the
  misconfigured action row (the upstream moderator view would show no
  reason); the dispatch still proceeds.

### Changed — v1.8.2
- **Record-targeted moderation actions no longer escalate to
  whole-account takedowns at the PDS.** Previously, a takedown recorded
  against a record subject (AT-URI) dispatched an account-level takedown
  of the parent DID. Because cairn-mod's action rows do not carry a
  record CID (which both backends' record-takedown wire shapes require),
  such dispatches now record a `validation`-outcome audit row and do not
  reach the PDS, rather than silently widening a record action into an
  account action. Account-targeted actions are unaffected. A future
  release adds CID plumbing to make record-targeted rows dispatchable
  end-to-end.
- Renamed `F4_INVARIANT_REASON` to `LABEL_BRIDGE_INVARIANT_REASON`. If
  you were importing the old name from `cairn_mod::pds_admin::backend`,
  update your import. Value and label-bridge posture unchanged.

### Added
- `BackendError` taxonomy split (foundation for v1.8 series). The seven-variant
  shape — `Transient` / `Validation` / `Terminal` / `Auth` /
  `CapabilityNotAdvertised` / `Unsupported` / `ArchitecturallyForbidden` —
  is the operator-facing dashboard contract going forward; structured-log
  parsers keying on the variant name need updating (see "Changed" below).
- `BackendFailureLog` structured-log shape (nine fields: `scope` / `backend` /
  `method` / `error_category` / `error_message` / `retry_after_seconds` /
  `error_code` / `timestamp_epoch_ms` / `correlation_id`). Emitted via the
  `log_backend_failure` helper. Operators querying structured logs pivot on
  `error_category` (low-cardinality, exactly seven values).
- `[sub_classification=Name ...]` marker convention in `error_message`
  strings. Carries previously-structured side-channel data (rate-limit
  retry hints, wire-level error codes, state-conflict markers) across
  the variant migration without expanding the variant set. Operators can
  query for sub-classifications via substring match in `error_message`,
  e.g. `WHERE error_message LIKE '%[sub_classification=RateLimited%'`.
  The `BackendError::retry_after_seconds()` and `BackendError::error_code()`
  accessors parse the markers programmatically.
- New `outcome` value `'terminal'` reserved for upstream-state failures
  (HTTP 404 / 410) distinct from request-shape failures and from the
  previously-named state-conflict cases. **Not yet writeable** — the SQL
  CHECK constraint relaxation lands in a later v1.8.1 migration step
  alongside the new `error_category` column.
- `[pds_admin].backend` selector — explicit string `"ozone"` or
  `"rust"` selects the active PDS-admin backend. When omitted (the
  v1.7-compatible shape) and exactly one backend subsection is
  declared, the selector auto-detects. When both are declared and
  no selector is set, the configuration is rejected as ambiguous.
  When the selector points at a subsection that isn't declared, the
  configuration is rejected with a specific `selector requires
  block` error.
- `[pds_admin.rust]` configuration block — declares a Rust-PDS
  backend (Aurora-Locus or another ATProto Rust PDS). Required
  keys: `url`, `service_did`, `service_signing_key_env`,
  `target_service_did`. Optional keys: `service_did_document_url`,
  `request_timeout` (default `"30s"`, bounds 1s..=5m),
  `capability_refresh_interval` (default `"1h"`, lower-bound
  `"10s"`), `required_capabilities`, `pinned_versions`,
  `verification_persist` (default `true`),
  `acknowledge_v1_8_1_audit_divergence`. The env var named by
  `service_signing_key_env` must hold a hex-encoded 32-byte
  secp256k1 private key and be set at startup. (An earlier
  unreleased draft of this block used OAuth-shaped keys —
  `client_id_env` / `client_secret_env` / `scopes`; those keys
  were removed before release and now produce a boot-time
  migration error naming the replacement fields.)
- `RustBackend` — the second `PdsAdminBackend` implementation
  (`backend = "rust"` now boots instead of hard-erroring).
  **Inspector-only in v1.8.1**: the only live upstream call is the
  `tools.aurora.describeCapabilities` probe; every enforcement
  method returns `CapabilityNotAdvertised` (audit `outcome =
  'validation'`) until v1.8.2's protocol-parity work, and label
  methods hard-refuse per the label-bridge invariant, same as the
  Ozone backend. Dispatches that hit the capability gap emit an
  operator-visible WARN on the
  `cairn_mod::pds_admin::rust::capability` log target.
- ES256K service-auth JWT signing for Rust-PDS calls. Per-call
  short-lived tokens (`iss` = cairn-mod's service DID, `aud` = the
  target PDS's service DID, `lxm` = the called NSID, 1-hour
  expiry), signed with cairn-mod's secp256k1 key and DER-encoded
  to match Aurora-Locus's verifier. No OAuth, no token cache. The
  operator publishes cairn-mod's DID document and grants the
  Aurora-side `admin_roles` role out-of-band.
- Capability detection goes live: the `describeCapabilities` probe
  runs at startup and every `capability_refresh_interval`,
  verifies operator-declared `required_capabilities` against the
  advertised set, and warns about advertised capability families
  cairn-mod's registry doesn't know. The capability registry gains
  its first entry (`mod-events-emit`, auto-advance — consumed by
  v1.8.2's action verbs).
- **Inspector-only audit-divergence enforcement when `[pds_admin]`
  is enabled with `backend = "rust"`.** v1.8.1's RustBackend is
  inspector-only — every dispatch produces a `BackendError`
  audit-trail row at runtime because protocol parity with the
  upstream ATProto admin surface lands at v1.8.2. Operators who
  want to stand up the bridge against a Rust PDS in v1.8.1 must
  acknowledge this explicitly via three independent
  configuration constraints, all enforced at startup:
  1. `[pds_admin.rust].acknowledge_v1_8_1_audit_divergence = true`
     must be set on the selected block. Operators reading the
     v1.8.1 release notes own this flag. The flag is
     self-removing across the v1.8 series — required in v1.8.1,
     deprecated in v1.8.2, removed in v1.8.3.
  2. No `[policy_automation.rules.*]` may have `mode = "auto"`.
     Auto-mode rules dispatch to the backend without operator
     confirmation; in v1.8.1's inspector-only posture they would
     silently produce audit-failure rows on every fire. Use
     `mode = "flag"` on every rule until v1.8.2 ships.
  3. `[xrpc_gateway].enabled` must not be `true`. The inbound
     XRPC gateway dispatches into the recordAction path that
     calls the configured backend; with the inspector-only Rust
     backend this would produce continuous audit-failure rows
     for every inbound request.

  All three error messages include a v1.8.2-lifts-the-restriction
  pointer so operators see the upgrade path. Configurations that
  set `enabled = true` with `backend = "ozone"` are unaffected.
- `[pds_admin.locus]` (the early-design name for `[pds_admin.rust]`)
  is rejected at config-load with a clear "renamed to
  `[pds_admin.rust]` in v1.8.1" message. Operators with
  v1.7-staged `[pds_admin.locus]` configs see the renaming error
  immediately rather than silently losing the subsection.
- v1.8.1 cross-release type-system foundation (partial). Foundation
  types consumed by later v1.8.x releases that have v1.8.1 as their
  shape ground-truth:
  - `BackendActionId` migrated from a wrapper-string newtype to an
    enum with `PerEvent(String)` and `PerBatch(String)` variants. The
    `pds_admin_audit.backend_action_id` wire format is unchanged
    (variant tag is Rust-only; serialization round-trips the inner
    string only). v1.7-shaped call sites continue to use
    `BackendActionId::new(..)`, which produces `PerEvent`. The
    `PerBatch` variant is reserved for v1.8.5+ batch-action consumers.
  - `CapabilityVersion(u32)` newtype with `parse_suffix("vN")` and
    free-function `parse_capability_string("family-vN")`. No
    operator impact yet — Aurora-Locus capability-gated trait
    surface ships in later v1.8.x releases.
  - `CapabilityClassification` (`AutoAdvance` / `OperatorOptIn`) +
    empty `CAPABILITY_CLASSIFICATIONS` registry + `classification_for`
    lookup helper. Registry populates as later v1.8.x releases
    introduce capability-gated trait methods.
  - `PaginationCursor(String)` opaque-string newtype. cairn-mod
    treats the cursor as opaque round-trip data; first paginated
    consumer ships in v1.8.3.
  - `AuditTrailEntryRead` and `AuditTrailEntryWrite` upstream-audit
    record types. `subjects` and `event_payload` carry
    `serde_json::Value` placeholders pending the polymorphic
    `Subject` and `EventPayload` types' first-consumer landings;
    no v1.8.1 code path constructs these yet.

### Changed
- `apply_label` and `negate_label` on `OzoneBackend` now return
  `BackendError::ArchitecturallyForbidden` (carrying the §F4 invariant
  reason text) instead of `BackendError::Unsupported`. **Behavior is
  unchanged** — cairn-mod has always forbidden these methods on
  `OzoneBackend` per the §F4 architectural invariant in `cairn-design.md`,
  and continues to do so. The new variant name carries clearer operator
  semantics: `Unsupported` now means "switch backends if you need this,"
  while `ArchitecturallyForbidden` means "no backend will ever do this;
  cairn-mod's design forbids it." If you parse cairn-mod's structured
  failure logs by variant name, update your parsers.
- HTTP error mapping in `OzoneBackend` migrated to the new variant set:
  network/timeout/HTTP 5xx → `Transient`; HTTP 401/403 → `Auth`;
  HTTP 400/422 → `Validation`; HTTP 404/409/410 → `Terminal`; HTTP 429 →
  `Transient` with `[sub_classification=RateLimited retry_after_seconds=N]`.
  Operator dashboards keying on the existing `outcome` column values
  (`network` / `auth` / `validation` / `rate_limited` / `conflict` /
  `remote_error` / `unsupported`) continue to see the same row sets they
  did in v1.7 — the v1.8.1 audit-writer preserves v1.7 outcome semantics
  via the marker convention until the schema migration lands.

### Fixed

### Deprecated

### Removed

### Security

## [1.7.0] - 2026-04-30

> v1.7 "PDS-side enforcement bridge & inbound XRPC gateway" closes
> the loop between cairn-mod and the operator's PDS in two halves.
> Outbound: a `[pds_admin]` config block declares operator-trusted
> PDS credentials and an action-type-to-backend-method mapping;
> cairn-mod's existing recordAction pipeline now propagates
> account-state changes (takedown / temp suspension / restore) to
> the configured PDS in lockstep with label emission. Inbound: a new
> `xrpc_gateway` accepts proxied `tools.ozone.moderation.*` calls
> and PDS-forwarded `com.atproto.moderation.createReport` — making
> cairn-mod a usable Ozone replacement for operators on bsky-PDS.
> Both halves preserve cairn-mod's audit-chain discipline (every
> backend call hash-chains into the existing audit log; every
> inbound mutation lands via the canonical recordAction path).
> v1.7 ships bsky-PDS support; the `PdsAdminBackend` trait
> abstraction accommodates v1.8's Aurora-Locus backend without API
> changes. Disabled by default — operators upgrading from v1.6 see
> no behavior change unless they opt in.

### Added

### Changed
- [pds_admin] config block: parsing, validation, schema (#83)
- [pds_admin] `PdsAdminBackend` trait + `BackendError` + `BackendActionId` + `Subject` types (#84)
- [pds_admin] `pds_admin_audit` table + unified hash chain spanning `audit_log` (#85)
- [pds_admin] `OzoneBackend` skeleton: ctor + Basic-auth + xrpc-url helpers (#86)
- [pds_admin] `OzoneBackend::takedown_account` body via `com.atproto.admin.updateSubjectStatus` + recordAction dispatch (#87)
- [audit] `cairn audit verify` extended to walk the unified chain across `audit_log` and `pds_admin_audit` (#88)
- [pds_admin] `OzoneBackend::suspend_account` + `restore_account` bodies; ISO-duration → days plumbing; revoke-action dispatch path (#89)
- [pds_admin] `probe()` trait method + `OzoneBackend::probe` (`describeServer`) + serve.rs startup wiring (#90)
- [xrpc_gateway] `[xrpc_gateway]` config block + module skeleton + 501 catch-all router (#91)
- [xrpc_gateway] NSID allowlist enum + per-handler dispatch stubs + XRPC-shape 405 envelope (#92)
- [xrpc_gateway] `XrpcAuthService` + tower middleware: ATProto service-auth JWT verification (ES256K, claim validation; replay deferred to #94) (#93)
- [xrpc_gateway] Replay cache + `xrpc_known_callers` / `xrpc_trusted_pdses` membership tables + middleware composition + CLI subcommands; audit-verify extended to walk 4 tables (#94)
- [xrpc_gateway] `tools.ozone.moderation.emitEvent` handler body: dispatches `modEventLabel` / `modEventTakedown` / `modEventReverseTakedown` / `modEventComment` into the canonical `record_action` / `revoke_action` pipeline (§A14). Enforces `createdBy == claims.iss` per §A8.1 defense-in-depth. Reserved `xrpc-gateway-default` reason code documented for events without natural `reason_codes` (operators must declare in `[moderation_reasons]`). Unsupported `$type` values (Ozone has many beyond cairn-mod's four) return 400 `InvalidRequest` naming the unsupported type. (#95)
- [xrpc_gateway] `com.atproto.moderation.createReport` handler body: PDS-signed inbound flow (§A10). Upstream PDSes forward user-filed reports; cairn-mod inserts into the existing `reports` table for the §F11/§F12/§F17 resolution surface to handle unchanged. The lexicon's `reasonType` is stored verbatim (cairn-mod's `reports.reason_type` already uses lexicon strings — no translation table). The user identity comes from the body's `reportedBy` field (the PDS asserts it on behalf of the user); operators express trust in upstream PDSes by adding them to `xrpc_trusted_pdses`. Threat-model §4 entry 9 documents the transitive-trust expansion. (#96)
- [xrpc_gateway] `tools.ozone.moderation.queryStatuses` handler body: paginated read endpoint that folds cairn-mod's action history (`subject_actions` + `labels` + `reports`) into Ozone's `subjectStatusView` shape. New `handlers/projections/` submodule houses the field-by-field translation (the design-heavy piece) — pure functions, fully unit-tested. v1.7 supports `subject` / `limit` / `cursor` / `sortDirection` / `takendown` / `tags` / `appealed` filters; unsupported filters return 400 `InvalidRequest` naming the field rather than silently ignoring. `appealed=true` returns empty (cairn-mod has no appeal flow); `reviewState` is constant `#reviewClosed`. Cursor: base64url(JSON) of `(updated_at_ms, subject_did, subject_uri)` lex-comparable with the page query's sort key. `XrpcGatewayState` extended with `service_did` for the `labels.src` filter. (#97)
- [xrpc_gateway] `tools.ozone.moderation.queryEvents` handler body: paginated read endpoint that projects cairn-mod's `audit_log` (joined with `subject_actions`) into Ozone's `modEventView` shape. **cairn-mod-internal audit entries are filtered out** — the Ozone surface only sees `subject_action_recorded` / `subject_action_revoked` projected to `modEventLabel` / `modEventTakedown` / `modEventComment` / `modEventReverseTakedown`; `pending_*`, `report_resolved`, `reporter_*`, `retention_sweep`, `service_record_*`, `label_applied` / `label_negated` are operator-tier and surface only via the CLI + `cairn audit verify`. Revocations of warnings/notes are also filtered (Ozone has no "reverse comment" event). v1.7 supported filters: `subject` / `types` / `createdBy` / `sortDirection` / `createdAfter` / `createdBefore` / `limit` / `cursor` / `includeAllUserRecords`; others → 400 `InvalidRequest`. Cursor: base64url(JSON) of a single `audit_log.id` (simpler than #97's tuple cursor since the column is monotonic AUTOINCREMENT). Closes Phase D's inbound NSID surface for v1.7. (#98)
- [xrpc_gateway] Retired the `build_routes_only` test fixture: post-#98, every handler requires `Extension<XrpcGatewayState>`, so the no-middleware variant is no longer testable in isolation. The router's structural shape tests (unknown-NSID fallback, case mismatch, wrong-method 405, two-field envelope) are migrated to the layered router via `spawn_authed`. (#98)
- [cli] `cairn pds-admin {takedown,suspend,restore}`: manual escape hatch for the PDS-admin bridge (#87 / §F23 / §A13). HTTP-routed via the canonical recordAction / revokeAction admin XRPC; the writer's post-commit dispatch fires the configured backend automatically. **Does not bypass strike accounting.** Pre-flights `[pds_admin].enabled` and surfaces the `pds_admin_audit` outcome in the response. Reserved reason code `pds-admin-cli` for manual escalations (operators must declare in `[moderation_reasons]`). (#99)
- [cli] `cairn moderator add --with-xrpc-callers`: convenience flag that adds the moderator DID to `xrpc_known_callers` in the same invocation, with `--by` recording the operator running the command. Idempotent at the application layer (pre-checks `is_known_caller` to skip the duplicate add). Plain `cairn moderator add` is unchanged. (#99)
- [cli] `cairn moderator events`: operator-tier audit-events view that mirrors `tools.ozone.moderation.queryEvents` (#98) but exposes the FULL cairn-mod audit_log vocabulary (including `pending_*`, `retention_sweep`, `xrpc_*` collaboration events, `report_resolved`, etc.). Default mode renders Ozone-eligible rows in their projected modEventView shape and cairn-mod-internal rows in a generic shape, intermixed in chronological order. `--ozone-only` applies #98's filter-out policy; output is identical to what queryEvents would return for the same filters. Reuses the `audit_event::project_audit_event` projection from #98. Direct-DB; supports `--subject` / `--actor` / `--type` / `--from` / `--to` / `--limit` / `--cursor`. (#99)
- [docs] §F23 design-doc chapter — operator-facing reference for v1.7's PDS-side enforcement bridge and inbound XRPC gateway. 12 numbered subsections covering compatibility framing, outbound `pds_admin` (trait surface, OzoneBackend, audit-chain integration, startup probe), inbound `xrpc_gateway` (NSID allowlist, 501/405 envelopes), `XrpcAuthService` (verification rules + replay cache), trust tables (`xrpc_known_callers` vs `xrpc_trusted_pdses` + threat-model §4.9 cross-ref), inbound action integration + projection policy (subjectStatusView + modEventView field-by-field tables, filter-out policy, lexicon non-conformance notes), operator config blocks, operator-tier CLI surface (the five v1.7 commands), reserved reason codes (`policy-threshold` / `xrpc-gateway-default` / `pds-admin-cli`), operator-facing invariants (audit chain ordering, strict-monotonic timestamps, suspension duration encoding, strongRef.cid omission, replay cache scope, queryEvents filter-out), patterns established for v1.8+, and cross-references. (#100)
- [docs] §18 roadmap update + §19.5 v1.7 deployment runbook. §18 collapses the v1.7+ foreshadowing bullet to a one-line shipped pointer to §F23 and refreshes the v1.x trajectory along two axes (backend coverage / Ozone parity floor); v1.8 = LocusBackend + retry policy + gateway refinements; v1.9 = review queue + extended event types + source management; v2.0 = web UI; future cycle = XRPC management of collaboration tables, `tools.ozone.communication.*` / `tools.ozone.team.*`, action-time CIDs; enterprise-tier = multi-instance replay coordination + Postgres + multi-node. New §19.5 walks operators through enabling `[pds_admin]` (action_map decision, env var, reserved reason code, restart, probe verification, manual-takedown verification), enabling `[xrpc_gateway]` (service DID publication, bsky-PDS env var coordination, reserved reason code, seeding `xrpc_known_callers` + `xrpc_trusted_pdses`, probe call), the verification dance (`cairn audit verify`, `cairn moderator events --ozone-only`, end-to-end test), and the rollback path (disable + restart; rows preserved for re-enable). v1.7 doc-complete; release ceremony per §19.2 happens outside chainlink scope. (#101)

### Fixed
- `rustfmt` drift in `admin_subject_actions.rs` (7a7628f).
- `DEFAULT_POLICY_REASON_CODE` renamed from `policy_threshold` to
  `policy-threshold` so the default substitution path produces a
  valid reason identifier under the `[a-z0-9-]` reason-id validator
  (b51a940; caught during Phase B verification).
- §F22.1 TOML example used `repeated_violation` (underscore);
  renamed to `repeated-violation` so the documented operator
  example produces a valid reason identifier (78edd9b).
- `getSubjectHistory` wire shape was missing `actorKind` and
  `triggeredByPolicyRule` fields. v1.6 added these columns to
  `subject_actions` (writer persists correctly per #73), but the
  read-side projection, SELECT, lexicon def, and CLI formatter were
  never extended — so the API returned `null` for both, defeating
  forensic traceability of policy-recorded vs moderator-recorded
  actions. Fixed across all four layers + `cairn moderator history`
  tabular output gains an ACTOR column (a1c71cb; caught during Phase
  B verification).
- Startup panic on `[xrpc_gateway].enabled = true`: both
  `src/server/create_report.rs` and `src/xrpc_gateway/router.rs`
  registered `POST /xrpc/com.atproto.moderation.createReport`, and
  `axum::Router::merge` panicked on the duplicate route at
  `serve.rs:257`. Fix: gateway router no longer mounts createReport;
  the user-direct `create_report_router` is the single mount point
  and dispatches to the gateway path's logic when the JWT issuer is
  in `xrpc_trusted_pdses` (PDS-forwarded reports skip pre-gates +
  take `reportedBy` from the body); other reports continue through
  the user-direct path with pre-gates intact. §F23.5 + §19.5.3
  updated to reflect the dispatch-not-mount architecture. v1.6 → v1.7
  with `[xrpc_gateway].enabled = false` is unchanged. (#102; caught
  during Phase B verification)

### Removed

### Security

## [1.6.0] - 2026-04-27

> v1.6 "Policy automation" closes the v1.5 loop: operators
> declare strike-threshold rules in `[policy_automation]`, and
> the recorder evaluates those rules inside every recordAction
> transaction. Auto-mode rules record consequent actions in the
> same transaction; flag-mode rules queue pending rows for
> moderator review. Conservative idempotency, severity-ordered
> rule selection, takedown-cascade auto-dismissal of pendings,
> and a forensic audit chain that extends across all policy
> events. Pending state is moderator-tier visibility only — the
> public surface still shows what cairn-mod has *done*, not what
> it *might* do.

### Added

- Policy automation engine: `[policy_automation]` config block,
  `PolicyAutomationPolicy` config loader, pure-function policy
  evaluator with crossing detection + idempotency + severity
  ordering, recorder integration evaluating rules inside the
  recordAction transaction. (#70, #71, #72, #73)
- Pending action confirm flow: `tools.cairn.admin.confirmPendingAction`
  XRPC + `WriteCommand::ConfirmPendingAction` writer command.
  Confirmed pendings materialize as `subject_actions` rows with
  `actor_kind='moderator'` (the moderator takes responsibility)
  and `triggered_by_policy_rule` preserved as forensic
  provenance; full label emission via the v1.5 path. (#74)
- Pending action dismiss flow: `tools.cairn.admin.dismissPendingAction`
  XRPC + `WriteCommand::DismissPendingAction` writer command.
  Audit-only rationale storage (the pending table itself has no
  `resolved_reason` column; rationale lives in the audit row's
  `moderator_reason` field). (#75)
- Takedown-cascade auto-dismissal: every unresolved pending for
  a subject auto-dismisses inside the same transaction as a
  takedown row INSERT, regardless of takedown path (moderator-
  recorded, policy-auto-recorded, or confirmed-pending-promoted).
  Cascade audit rows reuse the `pending_policy_action_dismissed`
  audit_log.action and discriminate via reason JSON's
  `triggered_by` field (`takedown_terminal` vs `moderator_dismissed`),
  cross-referencing the triggering takedown via `takedown_action_id`.
  (#76)
- Pending action read XRPC: `tools.cairn.admin.listPendingActions`
  (paginated, `subject` + `resolution` filters, opaque id-cursor)
  and `tools.cairn.admin.getPendingAction` (single row). Mod-or-
  Admin role; direct sqlx queries against the pool (no writer
  task involvement). (#77)
- Operator CLI: `cairn moderator pending {list, view, confirm,
  dismiss}`, HTTP-routed via the admin XRPC, tabular human output
  by default, `--json` for tooling. (#78)
- New error variants: `PendingActionNotFound`,
  `PendingAlreadyResolved`, `SubjectTakendown` (defensive race-
  closer on confirm).
- New audit_log.action vocabulary: `pending_policy_action_confirmed`,
  `pending_policy_action_dismissed`. Pending creation rides the
  precipitating action's `subject_action_recorded` audit row's
  `policy_consequence` field (no separate `pending_policy_action_created`
  audit kind).
- Migration `0005_policy_automation.sql`: extends `subject_actions`
  with `actor_kind` (CHECK in 'moderator' | 'policy', defaulting
  to 'moderator' for backfill) and `triggered_by_policy_rule`
  (NULL for moderator-recorded actions); new `pending_policy_actions`
  table with write-once-on-resolution trigger; partial indexes
  on the active subset for the moderator review queue.
- Comprehensive integration test coverage: idempotency contracts
  through the writer task (#80) and end-to-end lifecycle
  scenarios composing all v1.6 surfaces (#81).
- Design doc §F22 (policy automation; 11 subsections covering
  rule shape, threshold-crossing semantics, severity ordering,
  auto-vs-flag mode, pending resolution, takedown cascade, schema
  + audit linkage, synthetic policy actor DID, public-tier non-
  visibility, operator surfaces, deferred capabilities). New §4.2
  disclosure 6 (pending visibility is moderator-tier only). §F21.9
  + §18 roadmap updates. (#82)

### Changed

- Pending policy actions are moderator-tier visibility only — not
  exposed via public XRPC (`tools.cairn.public.getMyStrikeState`
  is unchanged from v1.5). Subscribers see what cairn-mod has
  *done*, not what cairn-mod *might* do. See §4.2 disclosure 6.
- `subject_actions` audit row's reason JSON gains an `actor_kind`
  discriminator (`'moderator'` vs `'policy'`) and an optional
  `triggered_by_policy_rule` field. The precipitating action's
  audit row also gains an optional `policy_consequence` field
  (`{rule_fired, mode, auto_action_id | pending_action_id}`)
  cross-referencing the consequence when a rule fires.
- `pending_policy_action_dismissed` audit reason JSON carries a
  `triggered_by` discriminator (`'moderator_dismissed'` for #75,
  `'takedown_terminal'` for #76) so audit consumers can filter
  the two shapes via `json_extract`.
- `MAINTAINERS.md` adds a "Development pattern" section disclosing
  the AI-assisted development approach used to ship cairn-mod.

### Fixed

- rustfmt drift in `tests/admin_subject_actions.rs` from #76's
  test rewrites — two `let` bindings that were left in unwrapped
  two-line form. Pure formatting fix; no logic change. (7a7628f)

### Internal

- chainlink #79 closed as duplicate of #73; the
  `PolicyAutomationPolicy` plumbing through writer-state landed
  as part of #73's recorder integration per that session's
  "subsume #79" decision.

## [1.5.2] — 2026-04-27

> Closes the v1.5 documentation gap: `cairn moderator labels` is
> now in the moderator CLI reference.

### Changed

- Added documentation for the `cairn moderator labels` subcommand
  to docs/moderator-cli.md as a new "Active label inspection"
  section. The subcommand shipped in v1.5 (#66) but was never
  added to README.md before v1.5.1's documentation split
  preserved existing content verbatim. (#69)

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
