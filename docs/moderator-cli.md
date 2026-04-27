# Moderator CLI Reference

CLI workflows for moderators and admins running against a live
cairn-mod instance. Covers moderator membership management, the
session-auth flow, the report management workflow, and audit log
queries.

For first-deployment setup (install, configure, bootstrap), see
[../SETUP.md](../SETUP.md). For day-2 operations (production
checklist, monitoring, secrets hygiene), see
[../OPERATIONS.md](../OPERATIONS.md). For trust-chain disclosures
and architecture overview, see [../README.md](../README.md).

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
