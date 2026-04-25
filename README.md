# Cairn

A lightweight, Rust-native [ATProto](https://atproto.com) labeler —
single binary, SQLite-backed, designed for small and mid-scale
community moderation.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV: 1.88](https://img.shields.io/badge/MSRV-1.88-informational.svg)](Cargo.toml)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

<!-- TODO (#27 CI hardening): GitHub Actions badge once workflows exist. -->
<!-- TODO (#28 release workflow): crates.io + docs.rs badges once published. -->

> **Latest stable release:** [v1.0.0](https://github.com/skydeval/cairn-mod/releases/tag/v1.0.0) · install with `cargo install cairn-mod`
>
> The `main` branch contains active development toward the next release. For production deployments, pin to a released version.

## What is Cairn?

Cairn is a standalone ATProto labeler server. It publishes a
[`app.bsky.labeler.service`](https://atproto.com/lexicons/app-bsky-labeler)
record, signs labels per the ATProto spec, accepts user reports, and
exposes an admin XRPC surface for moderators to act on them. It
exists because the ecosystem has Ozone (heavy, TypeScript,
Postgres-backed, opinionated web UI) and Skyware's labeler library
(minimal, no report intake, no audit trail), with a gap between them
for operators who want something compact but production-grade. Cairn
is deliberately smaller than Ozone and deliberately more complete
than Skyware; it does not try to be either.

## Status

**v1.0.0 is the current stable release.** Install with `cargo install cairn-mod` or pin to the [v1.0.0 tag](https://github.com/skydeval/cairn-mod/releases/tag/v1.0.0). The technical surface of v1.0 is code-complete; remaining items are tracked in the [issue tracker](https://github.com/skydeval/cairn-mod/issues).

**v1.1 is in active development on `main`.** Scope includes `/health` and `/ready` endpoints, a moderator management CLI, CI security scanning, and subscribeLabels retention.

Production deployments should pin to the stable release, not the `main` branch.

## Quickstart

Target: a running `cairn serve` behind a reverse proxy, published
service record, responding to `GET /.well-known/did.json`.

### Prerequisites

- **Rust 1.88+** — install via [rustup](https://rustup.rs).
- **A DID for the labeler** — either `did:web:your.host` or
  `did:plc:...`. How to obtain one is out of scope; the design doc
  §5.1 has the context.
- **A PDS account for the labeler** — the labeler DID must have a
  live repo on a PDS (self-hosted or bsky.social). Publishing the
  service record writes to that repo.
- **A TLS-terminating reverse proxy** — nginx or Caddy, see
  [`contrib/`](contrib/) for templates.

### 1. Install

```
cargo install cairn-mod
```

Produces a binary named `cairn`. On cargo's default install prefix,
that ends up at `~/.cargo/bin/cairn`; operators typically copy it to
`/usr/local/bin/cairn` for systemd deployment (see
[`contrib/README.md`](contrib/README.md)).

### 2. Generate a signing key

Cairn expects a 64-hex-char file containing a secp256k1 private key.
Either of these produces one:

```
# Python (simplest):
python3 -c 'import secrets; print(secrets.token_hex(32))' > signing-key.hex

# Or openssl:
openssl ecparam -name secp256k1 -genkey -noout \
  | openssl ec -text -noout 2>/dev/null \
  | awk '/priv:/{flag=1;next} /pub:/{flag=0} flag' \
  | tr -d ': \n' > signing-key.hex
```

Then lock down permissions — §5.1 requires mode `0600` owned by the
running user, and `cairn serve` refuses to start otherwise:

```
chmod 600 signing-key.hex
sudo chown cairn:cairn signing-key.hex       # if running under systemd
sudo mv signing-key.hex /var/lib/cairn/signing-key.hex
```

Publish the matching public key in the labeler's DID document at
verification method `#atproto_label`. Consumers verifying Cairn's
labels resolve the DID and extract this key.

### 3. Configure

Minimal `cairn.toml`:

```toml
# Labeler identity (§5.1). The DID must resolve to a document
# containing your signing key at verification method #atproto_label.
service_did      = "did:web:labeler.example"
# Public HTTPS URL consumers use to reach this labeler. Emitted in
# /.well-known/did.json as the AtprotoLabeler serviceEndpoint.
service_endpoint = "https://labeler.example"
# SQLite file. Created on first run; parent dir must exist.
db_path          = "/var/lib/cairn/cairn.db"
# Hex-encoded 32-byte secp256k1 key. Must be mode 0600 owned by
# the running user — Cairn refuses to start otherwise.
signing_key_path = "/var/lib/cairn/signing-key.hex"
# bind_addr defaults to "127.0.0.1:3000"; override if running
# without a reverse proxy on the same host.

# The app.bsky.labeler.service record `cairn publish-service-record`
# emits to your PDS. Lists what labels you declare and how consumers
# should render them.
[labeler]
label_values = ["spam"]

[[labeler.label_value_definitions]]
identifier      = "spam"
severity        = "alert"            # inform | alert | none
blurs           = "none"             # content | media | none
default_setting = "warn"             # ignore | warn | hide
locales         = [
  { lang = "en", name = "Spam", description = "Unsolicited promotional content." },
]

# Where the operator (= the labeler DID) authenticates to publish the
# service record. Separate from moderators authenticating to Cairn
# (§5.3) — different identity, different file.
[operator]
pds_url      = "https://bsky.social"
session_path = "/var/lib/cairn/operator-session.json"
```

See [`contrib/`](contrib/) for the systemd + Caddy + nginx templates
that plug into these paths.

### 4. Bootstrap (one-time per deployment)

Authenticate to the operator's PDS and publish the service record:

```
cairn operator-login --handle labeler.example.com --config /etc/cairn/cairn.toml
cairn publish-service-record --config /etc/cairn/cairn.toml
```

The publish step is idempotent — re-running with unchanged config is
a no-op.

### 5. Run

```
# Foreground:
cairn serve --config /etc/cairn/cairn.toml

# Or via systemd (contrib/):
sudo systemctl enable --now cairn
```

### 6. Verify

```
curl -sSL https://labeler.example/.well-known/did.json | jq '.verificationMethod[].id'
```

Should return `"did:web:labeler.example#atproto_label"` (or the
suffixed forms during v1.1 key rotation).

## Production Checklist

Walk through this before pointing real subscribers at the instance.
Each item links the relevant design-doc section for deeper context.

### Transport ([§F13](cairn-design.md#f13-single-binary--sqlite-deployment))

- [ ] **TLS terminates at the reverse proxy**, not Cairn. `cairn
  serve` binds HTTP only (default `127.0.0.1:3000`) and assumes a
  TLS-terminating proxy fronts it. See
  [`contrib/`](contrib/) for Caddy and nginx templates.
- [ ] **HSTS header** on responses (`Strict-Transport-Security:
  max-age=31536000; includeSubDomains`). Set at the proxy; the
  contrib templates ship it.

### Rate limits ([§F13](cairn-design.md#f13-single-binary--sqlite-deployment) numbers, enforced at reverse proxy)

- [ ] **`createReport`** per-IP: burst 3, rate 10 per hour. Enforced
  by `contrib/nginx/cairn.conf` out of the box; Caddy requires the
  `caddy-ratelimit` third-party module — see
  [`contrib/caddy/Caddyfile`](contrib/caddy/Caddyfile) for the
  commented stanza and install pointer.
- [ ] **`subscribeLabels`** per-IP: 8 concurrent connections.
  Enforced alongside the createReport limit in the same contrib
  configs.

### Secrets ([§5.1](cairn-design.md#51-labeler-service-identity), [§5.3](cairn-design.md#53-cli-ergonomics))

- [ ] **Signing key file** at mode `0600`, owned by the running
  user. Cairn's `credential_file::check_mode_and_owner` refuses
  wider permissions or foreign ownership at startup.
- [ ] **Signing key file NEVER committed to version control.** A
  signing key in git history is a compromise even after deletion.
- [ ] **Signing key material NOT delivered via env var.** The
  `CAIRN_SIGNING_KEY` env var is explicitly rejected by the
  loader (`SIGNING_KEY_ENV_REJECTED` constant) — the guardrail
  exists to prevent an "ergonomics" PR later adding a parallel
  unsafe path.
- [ ] **Operator session file** (written by `cairn operator-login`)
  at `0600` owned by the running user. Treat it as equivalent to
  your PDS app password — anyone with read access can push records
  to the labeler's PDS repo until the session expires.

### Key lifecycle ([§4.1.6](cairn-design.md#41-out-of-scope-threats), [§12](cairn-design.md#12-security-considerations))

- [ ] **Signing key is permanent for v1.** Rotation is v1.1
  scope. Plan the host, permissions, and backup accordingly — a
  v1 key lives as long as the labeler identity.
- [ ] **Do NOT remove the labeler signing key from the DID
  document.** Every historical label Cairn has signed stops
  verifying at consumers. Catastrophic and not undoable.

### Backup

- [ ] **SQLite database** (`db_path`) — contains labels, reports,
  audit log, moderators, single-instance lease state. Regular
  backups via `sqlite3 .backup` or filesystem snapshot.
- [ ] **Signing key file** (`signing_key_path`) — losing it means
  losing the labeler identity. Back up encrypted, store offline.
- [ ] **Session files are NOT backup-worthy.** Operator and
  moderator sessions are re-created by running `cairn
  operator-login` / `cairn login`.

### Moderator management

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
directly — the schema is in [the initial migration](migrations/0001_init.sql)
and the design contract is [§F12](cairn-design.md#f12-tools-cairn-admin-xrpc-endpoints):

```sql
INSERT INTO moderators (did, role, added_at)
VALUES ('did:plc:example', 'admin', strftime('%s','now') * 1000);
```

Direct SQL skips the last-admin guard and the role-change
prompts; reach for it only when the CLI path isn't an option.

### Report management ([§F17](cairn-design.md#f17-report-management-cli-v11))

Admin-side report workflow via `cairn report {list, view, resolve,
flag, unflag}`. All five subcommands wrap the
`tools.cairn.admin.*` HTTP endpoints, so they require a logged-in
session (`cairn login`) and a moderator-or-admin role row in the
`moderators` table on the target Cairn instance.

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
the actor — taken from the JWT `iss` Cairn's session-auth
produces. The CLI is HTTP-wrapped (not a direct DB tool)
specifically so this attribution is correct; bypassing the HTTP
path would write `actor_did = NULL` rows, corrupting the audit
trail for exactly the events operators most want to reconstruct.

**Pagination.** Auto-pagination is intentionally out of scope.
`--cursor <c>` is the operator's mechanism for chaining calls.
JSON output includes a top-level `cursor` field when more results
are available; human output appends a trailing `next cursor: ...`
line.

### Audit log queries ([§F18](cairn-design.md#f18-audit-log-cli-v11))

Read-only audit log inspection via `cairn audit list`.

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
```

**Admin role required.** Moderators querying the audit log
receive 403. The audit log records the moderator's own actions;
read access to the full set is reserved for admins to avoid the
"moderators silently auditing one another" pattern.

**Read-only contract.** The `audit_log` table has SQL triggers
that abort UPDATE and DELETE; the CLI matches by exposing only
read operations. There is no `cairn audit show <id>` subcommand
in v1.1 — the corresponding `getAuditLog` HTTP endpoint hasn't
been written yet (tracked separately).

### Single instance per DID ([§F5](cairn-design.md#f5-label-persistence-with-monotonic-sequence))

- [ ] **Only one `cairn serve` against a given DID at a time.**
  Cairn enforces this with a SQLite-backed lease; the loser of a
  startup race exits with `LEASE_CONFLICT` (exit code 11). The
  contrib systemd unit sets `RestartPreventExitStatus=11` so
  systemd doesn't restart-loop.
- [ ] **Even with the lease disabled, two instances against the
  same DB would corrupt the sequence space.** Don't attempt it.

### Monitoring (v1 surface is minimal)

- [ ] **systemd status + journalctl** — errors and panics land
  here. The contrib unit sets `StandardOutput=journal`.
- [ ] **Disk usage on the `db_path` partition** — Cairn has an
  app-level disk guard for the report path, but OS-level
  monitoring catches everything.
- [ ] **TLS certificate expiry at the reverse proxy** — Caddy
  auto-renews via ACME; nginx + certbot needs its own cron check.

### Health probes ([§F14](cairn-design.md#f14-health-and-readiness-probe-endpoints-v11))

Cairn exposes two unauthenticated endpoints for orchestrators:

- [ ] **`GET /health`** — liveness probe. Always returns 200 with
  `{"status": "ok", "version": "..."}` while the process can
  answer a request. No dependencies checked. Failure = restart
  the pod.
- [ ] **`GET /ready`** — readiness probe. Returns 200 on all-ok,
  503 on any check failure. Body is identical in both cases and
  names the individual checks (`database`, `signing_key`,
  `label_stream`). Failure = stop routing new traffic.
- [ ] **Verify both endpoints respond correctly against a running
  instance** before first release. `curl -s http://127.0.0.1:3000/health`
  should return 200; `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/ready`
  should return 200 when healthy and 503 when any check is
  intentionally failed (e.g., stop the writer, or point at an
  unreachable DB).

### Dependency security scanning ([§F15](cairn-design.md#f15-dependency-security-scanning-in-ci-v11))

- [ ] **Most recent CI security scan on `main` is green.** `cargo-audit`
  and `cargo-deny` both run on push to `main` and every PR; a scheduled
  daily `cargo-audit` opens a tracking issue when advisories land
  out-of-band. Before pointing real subscribers at the instance, verify
  the latest run on the version you're deploying passed.
- [ ] **No advisories ignored without dated rationale and review date.**
  Open `deny.toml` and inspect `[[advisories.ignore]]`. Each entry must
  carry a `reason` naming why the risk is accepted, and a
  `Review: YYYY-MM-DD` comment ≤ 180 days out. `grep -n 'Review:' deny.toml`
  is the one-command audit. Entries without a review date, or with
  dates in the past, are a hygiene failure — either renew the review
  or remove the ignore.

## Trust-chain disclosures

Operators AND subscribers should understand what Cairn's protocol
guarantees and what it doesn't. These are v1 properties, documented
in [§4.2](cairn-design.md#42-operator-trust-trust-chain-readme-audience)
of the design doc and summarized here per §14's "prominently
placed" directive.

1. **Label trust is operator trust.** A subscriber to this
   labeler's DID is implicitly trusting the current and past
   judgment of whoever controls that DID. If the operator
   silently swaps intent (becomes malicious, sells the DID, is
   compromised) there is no protocol-level mechanism for
   subscribers to detect this.

2. **Historical labels are forgeable by a malicious operator with
   DB access.** v1's audit log records who/when/why at the
   application layer but isn't cryptographically linked to the
   labels table. An operator with direct SQLite access can
   rewrite history. v1.1's hash-chained audit log is a
   prerequisite (but not sufficient) for historical-label
   integrity.

3. **Single operator per instance is a single point of
   compromise.** Operators concerned about unilateral
   label-history tampering should evaluate this limitation
   against their threat model. Mitigations (transparency logs,
   hash-chained audit) are tracked for future versions; specific
   mechanics are not yet finalized.

## Architecture

- **Single-writer task** (§F5) owns all write operations through an
  mpsc channel — sequence monotonicity, cts clamping, and signing
  all happen in one place.
- **Signed labels** per §6.2 — DAG-CBOR canonical encoding,
  ES256K with RFC 6979 deterministic nonces, low-S enforced at
  emission. Parity with `@atproto/api` is pinned by a fixture
  corpus in `tests/`.
- **Single-instance lease** (§F5) prevents two Cairn processes from
  signing labels against the same DID. Second `cairn serve` exits
  with a dedicated `LEASE_CONFLICT` code so systemd doesn't
  restart-loop.
- **Admin XRPC** lives under `tools.cairn.admin.*` — the custom
  lexicons are embedded in the binary and served at
  `/.well-known/lexicons/tools/cairn/admin/`.

Everything deeper is in the [design doc](cairn-design.md) —
threats, cryptographic details, schema migration policy, v1.1
roadmap.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build + test + PR
workflow. Participation is governed by the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## Security

Vulnerabilities go to the private channel in
[SECURITY.md](SECURITY.md) — **not** public issues.

## License

Dual-licensed under [MIT](LICENSE-MIT) or
[Apache 2.0](LICENSE-APACHE) at your option. Contributions are
accepted under the same terms.
