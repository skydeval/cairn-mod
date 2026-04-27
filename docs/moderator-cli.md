# Moderator CLI reference

This document is the operator-facing CLI reference for cairn-mod's
moderator workflow: managing moderator membership, logging in,
working with reports, and querying the audit log. For initial
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

## Active label inspection ([§F21](../cairn-design.md#f21-label-emission-against-moderation-state-v15))

Read-only operator view of what ATProto labels cairn-mod is
currently emitting against a subject. `cairn moderator labels
<subject>` HTTP-routes through the same admin XRPC envelope as
`cairn moderator strikes` ([§F21.8](../cairn-design.md#f218-public-introspection-and-operator-cli)),
but renders only the `activeLabels` field — one row per emitted
label, with the action context replicated across rows so each
line is fully self-describing.

```
# Show all currently-active labels emitted against a subject.
cairn moderator labels did:plc:offender

# Override the session's stored cairn-server URL for a one-off
# query against a different deployment.
cairn moderator labels did:plc:offender --cairn-server https://staging.labeler.example

# Emit just the activeLabels array as JSON for piping through jq.
cairn moderator labels did:plc:offender --json | jq '.[] | .val'
```

**Output shape.** Default human output is a two-pass-rendered
table with five columns:

- `LABEL_VAL` — the label's `val` as emitted on the wire (e.g.,
  `!takedown`, `reason-spam`).
- `ACTION_ID` — `subject_actions.id` of the action that emitted
  this label set. Repeats across every row belonging to the
  same action.
- `ACTION_TYPE` — `subject_actions.action_type` (one of
  `takedown`, `temp_suspension`, `indef_suspension`, `warning`).
  `note` never appears — notes don't emit labels per
  [§F21.1](../cairn-design.md#f211-action-to-label-mapping).
- `REASONS` — comma-joined operator-vocabulary reason codes;
  `-` when the action emitted with `emit_reason_labels=false`
  at recording time.
- `EXPIRES_AT` — RFC-3339 wall-clock for `temp_suspension`
  emissions; `-` for non-expiring action types.

Each `subject_actions` row that emitted labels expands into one
action-label row plus one row per `reason_code`, with the action
context (id, type, reasons, expiry) repeating so a forensic
reader can trace any individual label without correlating across
rows. Reason-label rows reconstruct their `val` by prefixing each
reason code with the default `reason-` prefix; deployments that
configure a non-default `[label_emission].reason_label_prefix`
will see drift here (tracked as a future follow-up).

**Empty state.** When the subject has no active emitted labels —
either because they have no actions, every action was a note,
every action's emission was suppressed at recording time, or
every emitted action has been revoked — the human output is a
single line: `No active labels for <subject>`. The `--json`
output is `[]`.

**Ordering.** Most-recent-action-first (descending by
`subject_actions.id`), inherited from the wire-level ordering
[§F21.8](../cairn-design.md#f218-public-introspection-and-operator-cli)
declares for `subjectStrikeState.activeLabels`. Reason-label
rows within each action are alphabetical by reason code, matching
the `subject_action_reason_labels` linkage table's stored
ordering.

**`--json` output stance.** Emits just the `activeLabels` array
from the underlying `tools.cairn.admin.getSubjectStrikes`
response — not the full `subjectStrikeState` envelope. The
subcommand's job is "show me labels"; JSON output reflects that.
Operators wanting the full state (current strike count, decay
trajectory, active suspension, etc. alongside the labels) use
`cairn moderator strikes --json`.

**Auth + role.** The subcommand wraps the same admin XRPC call
as `cairn moderator strikes` — single HTTP path, divergence is
at the formatter layer only. It requires a logged-in moderator
session (`cairn login`) and a moderator-or-admin role row in
the `moderators` table on the target instance, same as the
report and audit subcommands above.

**Read-only.** Like `strikes` and `audit list`, this subcommand
is read-only — it does not record audit rows or mutate any
state. Useful for spot-checking emission outcomes after a
recordAction or revokeAction without touching the writer task.
