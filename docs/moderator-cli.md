# Moderator CLI reference

This document is the operator-facing CLI reference for cairn-mod's
moderator workflow: managing moderator membership, logging in,
recording graduated-action moderation events, reviewing pending
policy-engine flags, working with reports, querying the audit
log, and inspecting transparency surfaces. For initial
deployment, see [../SETUP.md](../SETUP.md) (at the repo root). For
day-2 operational concerns, see [../OPERATIONS.md](../OPERATIONS.md)
(at the repo root).

## Moderator management

Manage moderator membership via the `cairn moderator` CLI. All
three subcommands operate on the same SQLite DB the labeler runs
against and load config the same way `cairn serve` does
(`--config <path>` or `CAIRN_CONFIG`).

```
# Add a moderator with the standard role:
cairn moderator add did:plc:example --role mod --config /etc/cairn/cairn.toml

# Add an admin (gets the elevated `tools.cairn.admin.listAuditLog`
# permission per §F12):
cairn moderator add did:plc:example --role admin --config /etc/cairn/cairn.toml

# Change an existing moderator's role (errors without --update-role
# if the DID is already a moderator):
cairn moderator add did:plc:example --role admin --update-role --config /etc/cairn/cairn.toml

# Remove a moderator:
cairn moderator remove did:plc:example --config /etc/cairn/cairn.toml

# Removing the last admin is blocked unless --force:
cairn moderator remove did:plc:example --force --config /etc/cairn/cairn.toml

# List all moderators (tabular):
cairn moderator list --config /etc/cairn/cairn.toml

# Filter to a single role, or emit JSON for scripts:
cairn moderator list --role admin --json --config /etc/cairn/cairn.toml

# Add a moderator AND grant XRPC-call access in one invocation
# (#99 / §F23.7). Convenience for the common case: granting
# moderator status implies the moderator should also be able to
# call cairn-mod via proxied XRPC. --by is required and is
# recorded as added_by_moderator on the new xrpc_known_callers row.
cairn moderator add did:plc:example \
  --role mod \
  --with-xrpc-callers --by did:plc:operator \
  --config /etc/cairn/cairn.toml
```

The CLI runs as a one-shot — no server startup, no
single-instance lease acquisition; it is safe to invoke while
`cairn serve` is running against the same DB.

**`--with-xrpc-callers` idempotency.** Plain `cairn moderator add`
is unchanged; the flag is opt-in. Under the hood the convenience
flag is two operations against two independent tables
(`moderators` and `xrpc_known_callers`); the composite is
idempotent at the application layer rather than transactional.
The CLI pre-checks `is_known_caller` and skips the second add
when the DID is already an active caller, so re-running on a
half-applied state — moderator-add succeeded but xrpc-callers-add
failed — completes cleanly without surfacing a UNIQUE-constraint
error. For a separate-table grant (a DID allowed to call cairn-mod
via proxied XRPC without being a moderator), reach for
[`cairn xrpc-callers add`](#manage-known-xrpc-callers-f234) directly.

**`added_by` semantics:** CLI-initiated inserts leave the
`moderators.added_by` column NULL — the CLI has no attested
caller identity (no JWT `iss`, no signed request). It is
populated only for HTTP-admin attribution via the moderator who
made the change. Operators auditing membership history should
read NULL as "added via CLI / direct DB write," not "unknown."

**For emergencies when the CLI isn't available** (e.g., bootstrapping
the first admin before any binary is installed, or recovering from
a corrupted invocation), the `moderators` table can be manipulated
directly — the schema is in [the initial migration](../migrations/0001_init.sql)
and the design contract is [§F12](../cairn-design.md#f12-tools-cairn-admin-xrpc-endpoints):

```sql
INSERT INTO moderators (did, role, added_at)
VALUES ('did:plc:example', 'admin', strftime('%s','now') * 1000);
```

Direct SQL skips the last-admin guard and the role-change
prompts; reach for it only when the CLI path isn't an option.

## Moderator authentication

Admin and moderator CLI subcommands (`cairn report ...`,
`cairn audit list`, `cairn retention sweep`) require a logged-in
moderator session. Authenticate once per machine:

```
cairn login \
    --cairn-server https://labeler.example \
    --pds https://bsky.social \
    --handle moderator.example.bsky.social
```

Prompts for the moderator's PDS app password — separate from the
operator's app password (different identity, different credentials
in production deployments). Caches a session file at
`~/.config/cairn/session.json` (mode `0600`, owned by the running
user — same §5.3 invariants as the operator session). The
resolved DID must have a corresponding row in the `moderators`
table on the target cairn-mod instance — see Moderator management
above for adding rows.

To revoke: `cairn logout`.

## Recording moderation events ([§F20](../cairn-design.md#f20-account-moderation-state-model-v14))

Record graduated-action moderation events via `cairn moderator
action`, with `warn` and `note` shorthands for the two most common
action types. All three subcommands wrap
`tools.cairn.admin.recordAction`, so they require a logged-in
session and a moderator-or-admin role row in `moderators` on the
target instance.

```
# Record a takedown against an account.
cairn moderator action did:plc:offender \
  --type takedown --reason hate-speech

# Record a temp_suspension against a record (subject is the AT-URI).
# --duration is required for temp_suspension; rejected for other types.
cairn moderator action at://did:plc:offender/app.bsky.feed.post/abc \
  --type temp_suspension --duration P7D --reason spam

# Multi-reason action: severe wins for strike calculation; otherwise
# highest base_weight wins. Repeat --reason once per code.
cairn moderator action did:plc:offender \
  --type indef_suspension --reason hate-speech --reason harassment

# Cite the report rows that motivated this action; repeat --report.
cairn moderator action did:plc:offender \
  --type warning --reason spam --report 42 --report 43

# Optional moderator-facing note stored on subject_actions.notes.
cairn moderator action did:plc:offender \
  --type takedown --reason hate-speech \
  --note "third strike; no response to prior warnings"

# Shorthand: warn (always --type=warning; same flag set as `action`).
cairn moderator warn did:plc:offender --reason spam

# Shorthand: note (positional <text> becomes the note; no --reason
# required — notes don't carry strikes or emit labels).
cairn moderator note did:plc:offender "subject reported by N users for spam"
```

The five action types — `warning`, `note`, `temp_suspension`,
`indef_suspension`, `takedown` — are the v1.4 graduated set.
`note` and `warning` carry zero strikes by default; the
strike-bearing types (`temp_suspension`, `indef_suspension`,
`takedown`) compute the strike value at action time per
`[strike_policy]` and freeze it on the row for forensic
durability. Action labels emit per `[label_emission]` mapping
in the same transaction; revocation atomically negates them
(see `revoke` below).

**Output:** a one-line confirmation by default
(`Recorded action 42 (+4 strikes)`) or, with `--json`, the
full wire envelope including `actionId`, `strikeValueBase`,
`strikeValueApplied`, `wasDampened`, and `strikesAtTimeOfAction`.

## Revoking actions

Roll back a previously-recorded `subject_actions` row via
`cairn moderator revoke <ACTION_ID>`. The row's `revoked_at` /
`revoked_by_did` / `revoked_reason` columns transition NULL →
non-NULL atomically with negation labels (every label the
original action emitted gets negated against the same
`(src, uri, val)` tuple); strike state recomputes; an audit row
records the revocation.

```
# Revoke action id 42.
cairn moderator revoke 42

# With rationale stored on subject_actions.revoked_reason.
cairn moderator revoke 42 --reason "false positive"

# JSON for scripting.
cairn moderator revoke 42 --reason "false positive" --json
```

Revocation is one-shot: the schema's no-update-except-revoke
trigger permits this NULL → non-NULL transition exactly once
and aborts re-revocation. The CLI catches it pre-UPDATE and
surfaces `ActionAlreadyRevoked` for a clean error.

Revoking a policy-recorded action (`actor_kind = 'policy'` from
§F22) does NOT change `actor_kind` — the row stays attributed
to the policy engine forensically; only `revoked_at` and
friends populate. Subsequent reads via `cairn moderator
history` show the row with `ACTOR = policy` AND
`REVOKED = yes`.

## Subject moderation history

Read-only history of moderation actions against a subject via
`cairn moderator history <SUBJECT>`. Newest-first, opaque
cursor pagination, mod-or-admin role required.

```
# Account-level history.
cairn moderator history did:plc:offender

# Narrow to record-level actions on a specific URI.
cairn moderator history did:plc:offender \
  --subject-uri at://did:plc:offender/app.bsky.feed.post/abc

# Hide revoked rows (default: included).
cairn moderator history did:plc:offender --no-include-revoked

# Time-window scan via RFC-3339 lower bound on effective_at.
cairn moderator history did:plc:offender --since 2026-04-01T00:00:00Z

# Pagination.
cairn moderator history did:plc:offender --limit 25
cairn moderator history did:plc:offender --limit 25 --cursor <c>

# JSON for scripts; carries the full wire shape including
# actorKind and triggeredByPolicyRule (§F22).
cairn moderator history did:plc:offender --json
```

The tabular default columns are
`ID | EFFECTIVE_AT | TYPE | ACTOR | REASONS | APPLIED | DAMPENED | REVOKED`.
The **ACTOR column** (added in v1.6) shows `moderator` for
moderator-recorded actions and confirmed-pending materializations,
or `policy` for actions the policy engine recorded directly via
mode=auto rule firings. Operators reviewing automation activity
scan ACTOR to distinguish manual decisions from automatic ones at
a glance; `--json` additionally surfaces `triggeredByPolicyRule`
on rows where a rule was involved (auto-recorded firings AND
moderator-confirmed pendings — see §F22.5 for the dual-attribution
shape).

## Subject strike state

Read-only current strike state for a subject via
`cairn moderator strikes <SUBJECT>`. Always recomputed from
source-of-truth (the cache is bypassed); a stale row never
produces a misleading answer.

```
# Multi-line human summary.
cairn moderator strikes did:plc:offender

# Full envelope for scripting (includes activeLabels per §F21).
cairn moderator strikes did:plc:offender --json
```

The human output shows: current count, good-standing flag, raw
total (lifetime sum, ignoring decay/revoke), decayed count,
revoked count, active suspension (if any, with effective and
expires timestamps), last action timestamp, and "returns to
good standing in N days" trajectory hint. Operators who want
just the active labels should reach for `cairn moderator
labels` instead.

## Audit-events view ([§F23.7](../cairn-design.md#f237-operator-tier-cli-surface))

Operator-tier audit-events view via `cairn moderator events`.
Direct-DB scan of `audit_log` (joined with `subject_actions` for
the recordAction surface) — no HTTP, no moderator session, same
operator-tier posture as `cairn audit list` and `cairn audit
verify`. The default surfaces ALL audit_log rows including
cairn-mod-internal events (`pending_*`, `retention_sweep`,
`xrpc_*` collaboration changes, `service_record_*`, etc.);
`--ozone-only` applies the same filter-out policy as
`tools.ozone.moderation.queryEvents` ([§F23.5](../cairn-design.md#f235-inbound-action-integration--projection-policy))
and surfaces only the Ozone-eligible subset.

```
# Newest 50 events across all subjects.
cairn moderator events --config /etc/cairn/cairn.toml

# Narrow to one subject (DID for account-level, AT-URI for
# record-level; the AT-URI form is parsed and applied as a
# subject_did + subject_uri filter pair).
cairn moderator events \
  --subject did:plc:offender \
  --config /etc/cairn/cairn.toml

# Filter by actor / action / time-window.
cairn moderator events --actor did:plc:moderator --config /etc/cairn/cairn.toml
cairn moderator events --type retention_sweep --config /etc/cairn/cairn.toml
cairn moderator events \
  --from 2026-04-01T00:00:00Z --to 2026-05-01T00:00:00Z \
  --config /etc/cairn/cairn.toml

# Pagination (server caps at 250; default 50).
cairn moderator events --limit 25 --config /etc/cairn/cairn.toml
cairn moderator events --limit 25 --cursor <c> --config /etc/cairn/cairn.toml

# JSON for downstream tooling.
cairn moderator events --json --config /etc/cairn/cairn.toml

# Apply the gateway endpoint's filter-out policy. Output matches
# what an external Ozone client would see through
# tools.ozone.moderation.queryEvents.
cairn moderator events --ozone-only --config /etc/cairn/cairn.toml
```

The default tabular output emits one line per event, prefixed by
shape — `ozone\t<id>\t<created_at>\t<$type>\t<subject>\tby=<actor>`
for Ozone-eligible rows or `internal\t<id>\t<created_at>\t<action>\t<target>\tby=<actor>\toutcome=<outcome>`
for cairn-mod-internal rows. The two shapes interleave in
chronological order so a routine `cairn moderator events | grep
<did>` surfaces both moderator-facing events and operator-internal
noise on the same subject. JSON output discriminates on the
`shape` field (`"ozone"` vs `"internal"`).

**Operator-tier vs Ozone-tier.** `--ozone-only` is the canonical
bridge between the two views. Without the flag, operators see
the full cairn-mod audit chain (the operator-tier view); with the
flag, the projection matches what an external moderator hitting
`queryEvents` over the gateway sees (the Ozone-tier view).
Operators verifying "what does this look like through Ozone?"
pass `--ozone-only` and compare against the unfiltered output.

The projection is shared with the gateway endpoint via
`audit_event::project_audit_event`, so the two surfaces stay
in lockstep — adding a new Ozone-eligible action type updates
both views in the same change.

Worked example. The same subject under each mode:

```
# Default (full): includes the cairn-mod-internal pending row.
$ cairn moderator events --subject did:plc:offender --config /etc/cairn/cairn.toml
ozone     42  2026-04-29T12:00:00.000Z  ...modEventLabel  did:plc:offender  by=did:plc:mod
internal  41  2026-04-29T11:50:00.000Z  pending_policy_action_dismissed  19  by=did:plc:mod  outcome=success

# --ozone-only: the internal row is filtered out.
$ cairn moderator events --subject did:plc:offender --ozone-only --config /etc/cairn/cairn.toml
ozone     42  2026-04-29T12:00:00.000Z  ...modEventLabel  did:plc:offender  by=did:plc:mod
```

Cross-references:
[§F23.5](../cairn-design.md#f235-inbound-action-integration--projection-policy)
(projection policy and the filter-out list);
[§F23.7](../cairn-design.md#f237-operator-tier-cli-surface)
(operator-tier vs Ozone-tier split);
[§F23.10](../cairn-design.md#f2310-patterns-established-for-v18)
(the projection-submodule pattern v1.8+ inherits).

## PDS-admin bridge ([§F23.1](../cairn-design.md#f231-outbound-pds_admin-bridge))

Manual escape hatch for the PDS-admin bridge via `cairn pds-admin
{takedown, suspend, restore}`. The **production path** is policy
automation + label emission firing the bridge automatically —
operators rarely need this surface in steady-state. The CLI
exists for two cases: (a) testing the bridge during Phase B
verification (per [§19.5](../cairn-design.md#195-operator-deployment-runbook-for-v17-pds-bridge--xrpc-gateway)),
and (b) operator one-off escalations that bypass the policy
engine for a specific subject. v1.7's vocabulary; v1.8's
LocusBackend documentation reuses it.

The CLI wraps `tools.cairn.admin.{recordAction, revokeAction}`
HTTP-routed through the running `cairn serve`, so it requires a
logged-in moderator session and a moderator-or-admin role row in
`moderators`. The writer's post-commit dispatch fires the
configured backend's `takedown_account` / `suspend_account` /
`restore_account` call automatically; the CLI then looks up the
resulting `pds_admin_audit` row and surfaces the bridge outcome
in the same response.

**Manual takedowns do NOT bypass strike accounting.** Per
[§F23.7](../cairn-design.md#f237-operator-tier-cli-surface)
(and the §A14 invariant: one canonical action-recording path),
the action lands in `subject_actions` like any other and updates
strike state per `[strike_policy]`. Operators wanting a
no-strike test path should use a dedicated test subject DID
rather than reaching for the bridge against a real moderator
target.

```
# Manual takedown. --reason defaults to the reserved
# `pds-admin-cli` reason code if unset; operators must declare
# that code in [moderation_reasons] for the default to work
# (per §F23.8).
cairn pds-admin takedown did:plc:offender \
  --reason hate-speech \
  --config /etc/cairn/cairn.toml

# Manual indef_suspension (omit --duration).
cairn pds-admin suspend did:plc:offender \
  --reason harassment \
  --config /etc/cairn/cairn.toml

# Manual temp_suspension (set --duration; ISO-8601).
cairn pds-admin suspend did:plc:offender \
  --reason spam --duration P7D \
  --config /etc/cairn/cairn.toml

# Optional moderator-facing notes recorded on the
# subject_actions row.
cairn pds-admin takedown did:plc:offender \
  --reason hate-speech \
  --notes "manual escalation; pattern matches recent harassment" \
  --config /etc/cairn/cairn.toml

# Restore: revokes the most-recent unrevoked
# takedown / temp_suspension / indef_suspension for the subject.
# For a specific action_id, reach for `cairn moderator revoke`
# instead — `pds-admin restore` is the convenience case.
cairn pds-admin restore did:plc:offender \
  --reason "false positive" \
  --config /etc/cairn/cairn.toml

# JSON output for tooling (carries the recordAction envelope and
# the pds_admin_audit row in one structure).
cairn pds-admin takedown did:plc:offender \
  --reason hate-speech --json \
  --config /etc/cairn/cairn.toml
```

**`--config` is required**; the CLI loads the operator config to
(1) pre-flight `[pds_admin].enabled = true` so a misconfigured
operator gets a precise error pointing at the config block
rather than a successful recordAction with a silently-no-op
bridge, and (2) read the DB path for the post-call
`pds_admin_audit` lookup. The `--config` operator points must
match the same config the running `cairn serve` is using;
otherwise the pre-flight check is meaningless. v1.7 doesn't
enforce this — operator responsibility.

**Reserved reason code.** Manual escalations default to the
reserved `pds-admin-cli` reason code (per
[§F23.8](../cairn-design.md#f238-reserved-reason-codes)).
Operators must declare it in `[moderation_reasons]` (or pass
`--reason <other-code>` explicitly) for `cairn pds-admin` to
succeed; otherwise the writer surfaces `ReasonNotFound` and
the CLI prints the underlying error.

The output format. The happy-path two-line output for
`takedown` / `suspend`:

```
Recorded action 42 (subject taken down)
bridge: success via takedown_account (id=ozone:8c3f...)
```

When the bridge dispatch hadn't surfaced a `pds_admin_audit` row
by the time the CLI looked (the writer's post-commit hook is
async vs. the HTTP response — most often this means the bridge
is enabled but the dispatch is still in flight, less commonly
that the bridge is disabled or the configured backend method is
`"skip"`):

```
Recorded action 42 (subject taken down)
bridge: dispatch pending — check `cairn moderator events` shortly
```

Operators following up on a "dispatch pending" line should run
`cairn moderator events --subject <did> --type pds_admin_audit`
(or refresh the operator's audit chain via `cairn audit verify`)
to confirm the bridge did fire.

When the bridge dispatched but the backend returned an error
(authentication failure, network error, rate-limited), the
output surfaces the error verbatim:

```
Recorded action 42 (subject taken down)
bridge: auth via takedown_account (id=-)
error: invalid app password
```

The cairn-mod-side action is still committed — the recordAction
landed; the bridge call is what failed. Per
[§F23.1](../cairn-design.md#f231-outbound-pds_admin-bridge)'s
fail-loud-and-audit posture, the operator reconciles manually
(typically: fix the underlying issue and re-run the appropriate
`cairn pds-admin` call, or revoke the action).

**`restore` semantics.** cairn-mod has no first-class "restore"
action_type. `cairn pds-admin restore <did>` resolves the most-
recent unrevoked takedown / temp_suspension / indef_suspension
row for the subject (direct DB lookup) and revokes it via
`tools.cairn.admin.revokeAction`; the writer's post-commit
dispatch fires `OzoneBackend::restore_account`. For revocation
of a specific action_id (rather than "most recent"), use `cairn
moderator revoke <action_id>` directly — `pds-admin restore` is
the convenience case for the common pattern.

Cross-references:
[§F23.1](../cairn-design.md#f231-outbound-pds_admin-bridge)
(the bridge's design + the `PdsAdminBackend` trait);
[§F23.7](../cairn-design.md#f237-operator-tier-cli-surface)
(operator-tier CLI surface);
[§F23.8](../cairn-design.md#f238-reserved-reason-codes)
(the `pds-admin-cli` reserved reason code);
§A13 (audit-chain integration — `pds_admin_audit` rows
hash-chain into the unified chain alongside `audit_log`);
§A14 (one canonical action-recording path — manual bridge
calls land in the same pipeline as policy-driven and
moderator-direct actions).

## Pending policy actions ([§F22](../cairn-design.md#f22-policy-automation-v16))

When operator config declares `[policy_automation]` rules in
mode=flag, threshold-crossing events queue
`pending_policy_actions` rows for moderator review. The
`cairn moderator pending` subcommand family is the moderator's
review-queue surface.

```
# List unresolved pendings, newest-first across all subjects.
cairn moderator pending list

# Narrow to one subject. Returns SubjectNotFound (404) if the
# subject has never had a pending row.
cairn moderator pending list --subject did:plc:offender

# Pagination (server caps at 250; default 50).
cairn moderator pending list --limit 25
cairn moderator pending list --limit 25 --cursor <c>

# JSON for scripts.
cairn moderator pending list --json

# Full context for one pending — proposed action, originating
# rule, triggering action, resolution state.
cairn moderator pending view 17

# Confirm a pending: promote to a real subject_actions row.
# --reason becomes the materialized action's notes column.
cairn moderator pending confirm 17 \
  --reason "agreed; pattern matches recent harassment"

# Dismiss: mark resolved without creating an action.
# --reason lands in the audit row's moderator_reason field
# (the pending table itself has no resolved_reason column).
cairn moderator pending dismiss 17 --reason "false positive"
```

The list output is tabular by default:
`ID | SUBJECT | ACTION_TYPE | RULE | TRIGGERED_AT | DAYS`.
The DAYS column shows days-since-triggered against the CLI's
local wall-clock — useful for spotting stale pendings the
review queue hasn't caught up to.

**Confirm preserves rule provenance.** A confirmed pending
materializes a `subject_actions` row with
`actor_kind = 'moderator'` (the moderator takes responsibility
by confirming), `actor_did = <moderator DID>`, AND
`triggered_by_policy_rule = <rule>` for forensic provenance.
The materialized row shows up in `cairn moderator history`
with `ACTOR = moderator`; the rule attribution stays in the
row's `triggered_by_policy_rule` column and the audit chain
(`--json` surfaces `triggeredByPolicyRule`).

**Dismiss leaves the pending forensic.** A dismissed pending
row stays in `pending_policy_actions` with `resolution =
'dismissed'`; cascading takedowns (§F22.6) auto-dismiss
unresolved pendings and their cascade audit rows attribute to
the synthetic policy DID `did:internal:policy` rather than to
any moderator.

The CLI does NOT expose a `--resolution` filter on `list` —
the review queue is the unresolved set; confirmed/dismissed
pendings remain reachable via the admin XRPC
(`tools.cairn.admin.listPendingActions?resolution=confirmed`)
when needed.

## Report management ([§F17](../cairn-design.md#f17-report-management-cli-v11))

Admin-side report workflow via `cairn report {list, view, resolve,
flag, unflag}`. All five subcommands wrap the
`tools.cairn.admin.*` HTTP endpoints, so they require a logged-in
session (`cairn login`) and a moderator-or-admin role row in the
`moderators` table on the target cairn-mod instance.

```
# List pending reports.
cairn report list --status pending

# Filter by reporter; emit JSON for piping through jq.
cairn report list --reported-by did:plc:reporter --json

# Page through results via the cursor a previous response emitted.
cairn report list --cursor <c-from-prior-response>

# Inspect one report (full body included; admin-authenticated).
cairn report view 42

# Resolve a report without applying a label (the "dismiss" workflow).
cairn report resolve 42 --reason "not actionable"

# Resolve AND apply a label in one transaction.
cairn report resolve 42 \
  --apply-label-val spam \
  --apply-label-uri did:plc:offender \
  --reason "definitely spam"

# Suppress future reports from a noisy reporter; reverse with unflag.
cairn report flag did:plc:noisyreporter --reason "false reports"
cairn report unflag did:plc:noisyreporter
```

**Audit attribution.** Every mutating action (`resolve`, `flag`,
`unflag`) is recorded in `audit_log` with the moderator's DID as
the actor — taken from the JWT `iss` cairn-mod's session-auth
produces. The CLI is HTTP-wrapped (not a direct DB tool)
specifically so this attribution is correct; bypassing the HTTP
path would write `actor_did = NULL` rows, corrupting the audit
trail for exactly the events operators most want to reconstruct.

**Pagination.** Auto-pagination is intentionally out of scope.
`--cursor <c>` is the operator's mechanism for chaining calls.
JSON output includes a top-level `cursor` field when more results
are available; human output appends a trailing `next cursor: ...`
line.

## Audit log queries ([§F18](../cairn-design.md#f18-audit-log-cli-v11))

Read-only audit log inspection via `cairn audit list` and
`cairn audit show <id>`.

```
# Newest 50 entries.
cairn audit list

# Filter by actor / action / outcome.
cairn audit list --actor did:plc:moderator --action label_applied
cairn audit list --outcome failure

# Time-window scan (RFC-3339 inclusive bounds).
cairn audit list --since 2026-04-01T00:00:00Z --until 2026-05-01T00:00:00Z

# Page through; emit JSON for downstream tooling.
cairn audit list --limit 250 --cursor <c-from-prior-response> --json

# Fetch one entry by id.
cairn audit show 42
cairn audit show 42 --json | jq .reason
```

**Admin role required.** Moderators querying the audit log
receive 403. The audit log records the moderator's own actions;
read access to the full set is reserved for admins to avoid the
"moderators silently auditing one another" pattern.

**Read-only contract.** The `audit_log` table has SQL triggers
that abort UPDATE and DELETE; the CLI matches by exposing only
read operations.

## Active label inspection

Read-only label-state inspection via `cairn moderator labels
<subject>`. Surfaces what labels cairn-mod is currently emitting
against a subject — the action label per non-revoked action plus
any reason labels emitted alongside.

```
# Inspect active labels for a subject (tabular output).
cairn moderator labels did:plc:offender --cairn-server https://labeler.example

# JSON output for piping through jq.
cairn moderator labels did:plc:offender --cairn-server https://labeler.example --json
```

The tabular output groups by action: each row shows the label
value, the action that emitted it, the action type, the reason
codes attached to the action, and the label's expiry if any.
Multiple labels per action (action label + reason labels) all
share the same action context fields. Ordering: most-recent-action
first, with reason codes alphabetical within each action's reason
list.

```
Active labels for did:plc:offender
  LABEL_VAL           ACTION_ID  ACTION_TYPE       REASONS           EXPIRES_AT
  !takedown           42         takedown          hate-speech,spam  -
  reason-hate-speech  42         takedown          hate-speech,spam  -
  reason-spam         42         takedown          hate-speech,spam  -
  !hide               38         temp_suspension   harassment        2026-05-04T12:00:00.000Z
  reason-harassment   38         temp_suspension   harassment        2026-05-04T12:00:00.000Z
```

Empty state: `No active labels for <subject>` when no actions
are active or all emitted labels have been negated by revocation.

**`--json` output emits only the activeLabels array.** Operators
wanting the full strike state envelope (current count, decay
trajectory, suspension state, plus activeLabels) should use
`cairn moderator strikes --json` instead. This subcommand's job
is "show me the labels"; the JSON output reflects that scope.

**Authentication.** Wraps the same admin XRPC endpoint as
`cairn moderator strikes` (single HTTP path internally; output
diverges at the formatter layer), so it requires a logged-in
session via `cairn login` and a moderator-or-admin role row in
the `moderators` table on the target cairn-mod instance.

The label emission system this subcommand surfaces is documented
in [cairn-design.md §F21](../cairn-design.md#f21-label-emission-against-moderation-state-v15).

<a id="manage-known-xrpc-callers-f234"></a>

## Manage known XRPC callers ([§F23.4](../cairn-design.md#f234-trust-tables-known-callers-vs-trusted-pdses))

Manage the inbound gateway's `xrpc_known_callers` table —
moderator DIDs whose **proxied `tools.ozone.moderation.*` calls
through their upstream PDS** cairn-mod accepts. Direct DB; no
HTTP, no moderator session. CLI-only management for v1.7 per
§A12 (XRPC management of these tables is deferred — bootstrap
problem: the admin XRPC surface is itself authenticated by
service-auth, the same path being extended; granting the first
caller via XRPC is circular).

```
# Add a known caller. --by is required and is recorded as
# added_by_moderator on the new row. --note is optional
# free-text (operator's own annotation, not surfaced anywhere).
cairn xrpc-callers add did:plc:moderator \
  --by did:plc:operator \
  --note "added during v1.7 onboarding" \
  --config /etc/cairn/cairn.toml

# List active rows (default).
cairn xrpc-callers list --config /etc/cairn/cairn.toml

# Include revoked rows so operators can audit removal history.
cairn xrpc-callers list --include-revoked --config /etc/cairn/cairn.toml

# Revoke. --by records the operator running the command.
cairn xrpc-callers revoke did:plc:moderator \
  --by did:plc:operator \
  --config /etc/cairn/cairn.toml
```

The list output is one line per row in the form
`<did> <status> added@<ms> by <added_by_moderator> note=<note-or-->`,
where `<status>` is `active` or `revoked@<ms>`.

**Revocation is row-level irreversible.** A `revoke` flips the
row's `revoked_at` and that flip stays — re-adding the same DID
writes a *new* `xrpc_known_callers` row rather than reactivating
the old one. The chain audits both events. Double-revoke against
an already-revoked DID surfaces an error.

**Distinct from `moderators`.** `moderators` controls direct
service-auth calls to cairn-mod (the existing CLI / admin XRPC
path); `xrpc_known_callers` controls **proxied** calls from
upstream PDSes. The two tables overlap heavily in practice — a
moderator who uses bsky.app routes through bsky-PDS proxy and
needs both rows; the same moderator using `cairn moderator
action` only needs the `moderators` row. The
[`cairn moderator add --with-xrpc-callers`](#moderator-management)
convenience flag handles the both-tables case in one CLI
invocation.

Worked example. Add → list → revoke → list:

```
$ cairn xrpc-callers add did:plc:moderator --by did:plc:operator --config /etc/cairn/cairn.toml
added xrpc_known_caller: did:plc:moderator (by did:plc:operator)

$ cairn xrpc-callers list --config /etc/cairn/cairn.toml
did:plc:moderator active added@1714435200000 by did:plc:operator note=-

$ cairn xrpc-callers revoke did:plc:moderator --by did:plc:operator --config /etc/cairn/cairn.toml
revoked xrpc_known_caller: did:plc:moderator (by did:plc:operator)

$ cairn xrpc-callers list --include-revoked --config /etc/cairn/cairn.toml
did:plc:moderator revoked@1714438800000 added@1714435200000 by did:plc:operator note=-
```

Cross-references:
[§F23.4](../cairn-design.md#f234-trust-tables-known-callers-vs-trusted-pdses)
(the two-table trust model: known callers vs trusted PDSes);
§A12 (CLI-only management for v1.7; XRPC management deferred);
[§F23.8](../cairn-design.md#f238-reserved-reason-codes)
(the membership table substitutes for pre-INSERT gates per
#102's createReport dispatch).

## Manage trusted PDSes ([§F23.4](../cairn-design.md#f234-trust-tables-known-callers-vs-trusted-pdses))

Manage the inbound gateway's `xrpc_trusted_pdses` table —
**PDS DIDs** whose **forwarded `com.atproto.moderation.createReport`
calls** cairn-mod accepts. Same shape and posture as
`cairn xrpc-callers`; the semantic distinction is which
authorization question the table answers.

The cryptographic distinction:

- `xrpc_known_callers` is *moderator DIDs whose proxied
  `tools.ozone.moderation.*` calls are accepted*. The verifying
  signature is the moderator's own `#atproto` key (the user
  signs the JWT; bsky-PDS proxies the request).
- `xrpc_trusted_pdses` is *PDS DIDs whose forwarded
  `com.atproto.moderation.createReport` calls are accepted*. The
  verifying signature is the PDS's own service signing key (the
  PDS itself signs the JWT, asserting on behalf of the user
  whose DID appears in the request body's `reportedBy` field).

A DID is typically only in one table or the other.

```
# Add a trusted PDS. --by is required.
cairn xrpc-pdses add did:web:pds.example \
  --by did:plc:operator \
  --note "primary upstream PDS" \
  --config /etc/cairn/cairn.toml

# List active rows.
cairn xrpc-pdses list --config /etc/cairn/cairn.toml

# Include revoked rows.
cairn xrpc-pdses list --include-revoked --config /etc/cairn/cairn.toml

# Revoke.
cairn xrpc-pdses revoke did:web:pds.example \
  --by did:plc:operator \
  --config /etc/cairn/cairn.toml
```

**Trust-boundary expansion.** Adding a PDS to
`xrpc_trusted_pdses` is a meaningful trust gesture. Per the §4.9
threat-model entry, cairn-mod transitively trusts the listed PDS
to assert truthfully which user originated each forwarded report
(the body's `reportedBy` field). cairn-mod cannot cryptographically
verify that assertion — the JWT is signed by the PDS, not by the
reporting user. A compromised or malicious upstream PDS could
submit reports under arbitrary user DIDs, including DIDs that
have never interacted with that PDS.

Mitigation: only add upstream PDSes whose operation the operator
trusts. Removing a PDS from this table immediately stops
accepting forwarded reports from it (the membership check runs
per request) — there is no cache or grace period. Reports from
issuers outside `xrpc_trusted_pdses` continue through the
user-direct path (per
[§F23.5](../cairn-design.md#f235-inbound-action-integration--projection-policy)
/ #102: there is only one route registration for createReport
across the router stack, and the trusted-PDS branch is dispatched
*within* that handler based on `is_trusted_pds(claims.iss)`).

Cross-references:
[§F23.4](../cairn-design.md#f234-trust-tables-known-callers-vs-trusted-pdses)
(the two-table trust model);
§A12 (CLI-only management for v1.7);
[§F23.5](../cairn-design.md#f235-inbound-action-integration--projection-policy)
(the membership-dispatch shape per #102; trust-table membership
substitutes for the user-direct path's pre-INSERT gates).

## Trust-chain inspection

Read-only transparency surface via `cairn trust-chain show`.
Returns the labeler's declared signing keys, maintainer roster,
service-record summary, and instance metadata in one envelope.
**Admin role required.**

```
# Sectioned human output.
cairn trust-chain show

# JSON for scripting / external transparency-log mirroring.
cairn trust-chain show --json
```

The endpoint is read-only and writes no audit_log row — it
reflects current state, not an event. Subscribers comparing
two cairn-mod-hosted labelers can use this to observe declared
keys and label-value taxonomies before subscribing.

## Ancillary operator commands

A handful of operator-tier commands sit outside the
`cairn moderator` surface. They generally don't require a
moderator session — they're operator-tier and run as one-shots
against the SQLite DB or the operator's PDS directly.

### `cairn unpublish-service-record`

Remove the published `app.bsky.labeler.service` record from
the operator's PDS. Idempotent — running when nothing is
published is a no-op success, not an error. Clears the local
`labeler_config` state on a real delete; the next
`cairn serve` startup verify ([§F19](../cairn-design.md#f19-startup-verify-v12))
will then exit 13 SERVICE_RECORD_ABSENT until a fresh
`cairn publish-service-record` runs.

```
cairn unpublish-service-record --config /etc/cairn/cairn.toml
```

Requires the operator session — the command writes to the
operator's PDS, not to cairn-mod's HTTP surface.

### `cairn audit-rebuild`

Backfill `prev_hash` + `row_hash` on pre-v1.3 audit_log rows so
[`cairn audit verify`](#audit-log-queries-f18)'s hash-chain
walk has unbroken coverage from genesis. One-shot operator
command — direct DB, no HTTP, no moderator session. Acquires
the writer lease for the duration of the rebuild; refuses to
run while `cairn serve` is up. Idempotent — re-running on an
already-rebuilt log is a no-op success.

```
cairn audit-rebuild --config /etc/cairn/cairn.toml

# JSON outcome.
cairn audit-rebuild --config /etc/cairn/cairn.toml --json
```

The hash-chain walk is documented in
[cairn-design.md §F10](../cairn-design.md#f10-audit-log).
Rebuild is needed only on instances that ran cairn-mod ≤ v1.2
before upgrading; v1.3+ always writes the chain alongside
audit rows in the same transaction.
