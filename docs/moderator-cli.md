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
```

The CLI runs as a one-shot — no server startup, no
single-instance lease acquisition; it is safe to invoke while
`cairn serve` is running against the same DB.

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
