# Setting up cairn-mod

This guide walks through deploying a fresh cairn-mod instance from
`cargo install` to verified service-record publishing. For day-2
operational concerns once you're running, see
[OPERATIONS.md](OPERATIONS.md). For the moderator CLI reference,
see [docs/moderator-cli.md](docs/moderator-cli.md).

Target: a running `cairn serve` behind a reverse proxy, published
service record, responding to `GET /.well-known/did.json`.

## Prerequisites

- **Rust 1.88+** — install via [rustup](https://rustup.rs).
- **A DID for the labeler** — either `did:web:your.host` or
  `did:plc:...`. How to obtain one is out of scope; the design doc
  §5.1 has the context.
- **A PDS account for the labeler** — the labeler DID must have a
  live repo on a PDS (self-hosted or bsky.social). Publishing the
  service record writes to that repo.
- **A TLS-terminating reverse proxy** — nginx or Caddy, see
  [`contrib/`](contrib/) for templates.

## 1. Install

```
cargo install cairn-mod
```

Produces a binary named `cairn`. On cargo's default install prefix,
that ends up at `~/.cargo/bin/cairn`; operators typically copy it to
`/usr/local/bin/cairn` for systemd deployment (see
[`contrib/README.md`](contrib/README.md)).

## 2. Generate a signing key

cairn-mod expects a 64-hex-char file containing a secp256k1 private key.
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
verification method `#atproto_label`. Consumers verifying cairn-mod's
labels resolve the DID and extract this key.

## 3. Configure

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
# the running user — cairn-mod refuses to start otherwise.
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
# service record. Separate from moderators authenticating to cairn-mod
# (§5.3) — different identity, different file.
[operator]
pds_url      = "https://bsky.social"
session_path = "/var/lib/cairn/operator-session.json"
```

See [`contrib/`](contrib/) for the systemd + Caddy + nginx templates
that plug into these paths.

## 4. Bootstrap (one-time per deployment)

Authenticate to the operator's PDS and publish the service record:

```
cairn operator-login --handle labeler.example.com --config /etc/cairn/cairn.toml
cairn publish-service-record --config /etc/cairn/cairn.toml
```

The publish step is idempotent — re-running with unchanged config is
a no-op.

To remove the published record (e.g., decommissioning a test
deployment), run the inverse:

```
cairn unpublish-service-record --config /etc/cairn/cairn.toml
```

Idempotent — running it when nothing is published is also a no-op.
The next `cairn serve` after an unpublish will fail-start with exit
13 SERVICE_RECORD_ABSENT until you republish.

## 5. Run

```
# Foreground:
cairn serve --config /etc/cairn/cairn.toml

# Or via systemd (contrib/):
sudo systemctl enable --now cairn
```

## 6. Verify

```
curl -sSL https://labeler.example/.well-known/did.json | jq '.verificationMethod[].id'
```

Should return `"did:web:labeler.example#atproto_label"` (or the
suffixed forms during v1.1 key rotation).

## Service record verify on startup ([§F19](cairn-design.md#f19-service-record-verify-on-startup-v11))

`cairn serve` performs a **verify-only** check at startup before
binding the HTTP listener: the local `[labeler]` config is
rendered into an `app.bsky.labeler.service` record, and its
content-hash is compared against the published record at
`<operator.pds_url>/<service_did>`. Drift, absent, or
unreachable each fail-start with a distinct exit code so
orchestrators (and operators) can branch.

- [ ] **Configs without a `[labeler]` block skip verify.** If
  you're running a cairn-mod deployment that does NOT publish a
  service record (test harnesses, embedders, custom workflows),
  this gate doesn't apply and `cairn serve` starts normally.
  Operator-facing deployments always have `[labeler]`.

- [ ] **Configs with `[labeler]` MUST also have `[operator]`.**
  Verify needs `operator.pds_url` to know where to fetch the
  published record from. `[labeler]` declared without
  `[operator]` fail-starts as a USAGE-coded config error
  (real misconfig signal, not a drift gate).

**Failure modes and exit codes:**

| Code | Variant | Meaning | Operator action |
|---|---|---|---|
| 12 | `SERVICE_RECORD_DRIFT` | Local config differs from PDS record | Run `cairn publish-service-record` to update the PDS |
| 13 | `SERVICE_RECORD_ABSENT` | No record published yet | Run `cairn publish-service-record` to publish for the first time |
| 14 | `SERVICE_RECORD_UNREACHABLE` | Could not reach PDS | Transient infra issue; retry. If persistent, check `operator.pds_url` |

The drift exit's stderr message names the fields that differ
(label values, definition count, reason types, subject types).
When all four match but content hashes differ, the message
points at per-definition contents (severity / blurs / locales)
as the drift surface to inspect.

**Reconciliation flow.** When verify fails with drift or
absent, the operator runs `cairn publish-service-record` on the
host that has operator credentials configured (see
[§5.3](cairn-design.md#53-cli-ergonomics)). After successful
publish, restart `cairn serve`; verify passes on the next
startup.

**Lease handling.** Verify happens AFTER the single-instance
lease is acquired (so a verify failure doesn't waste a PDS
fetch when another instance already holds the slot). On
verify failure, the lease is released before serve exits, so a
subsequent startup attempt isn't blocked.

**No opt-out flag.** v1.1 has no `--skip-verify` or equivalent.
The whole point of the gate is to catch drift; a flag would
re-introduce the drift class via forgetfulness. If a real
emergency case surfaces post-launch, the project will weigh
adding one as its own tracker entry.
