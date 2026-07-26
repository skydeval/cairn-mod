# Setting up cairn-mod

This guide walks through deploying a fresh cairn-mod instance up to
verified service-record publishing. For day-2 operational concerns
once you're running, see [OPERATIONS.md](OPERATIONS.md).

Target: a running `cairn serve` behind TLS termination, published
service record, responding to `GET /.well-known/did.json`.

## Prerequisites

- **A DID for the labeler** — either `did:web:your.host` or
  `did:plc:...`. How to obtain one is out of scope.
- **A PDS account for the labeler** — the labeler DID must have a
  live repo on a PDS (self-hosted or bsky.social). Publishing the
  service record writes to that repo.

Form-specific prerequisites (Rust toolchain, Docker, reverse proxy)
are listed in each deployment form below.

## Choose your deployment form

cairn-mod deploys three ways. Same binary, same config file, same
security posture in all three — the signing key stays a file with
strict permissions in every form.

| Form | What it is | Pick it when |
|---|---|---|
| [A. Installed binary](#a-installed-binary) | `cargo install` + systemd + your reverse proxy | You run a traditional host and want systemd's exit-code discipline |
| [B. docker-compose](#b-docker-compose-recommended-for-docker) | Turnkey two-container stack: cairn-mod + Caddy with automatic TLS | You want the fastest path from clone to running labeler |
| [C. docker run](#c-docker-run) | The same image, driven by hand | You already operate a reverse proxy or an orchestrator that supersedes compose |

All three forks converge on the same shared steps: generate a signing
key, configure, bootstrap, verify.

## A. Installed binary

Prerequisites: **Rust 1.88+** ([rustup](https://rustup.rs)) and a
**TLS-terminating reverse proxy** — nginx or Caddy, see
[`contrib/`](contrib/) for templates.

```
cargo install cairn-mod
```

Produces a binary named `cairn`. On cargo's default install prefix,
that ends up at `~/.cargo/bin/cairn`; operators typically copy it to
`/usr/local/bin/cairn` for systemd deployment (see
[`contrib/README.md`](contrib/README.md)).

Then walk the shared steps in order — [generate a signing
key](#shared-generate-a-signing-key) (ownership: `chown cairn:cairn`),
[configure](#shared-configure), [bootstrap](#shared-bootstrap-one-time-per-deployment)
(run the commands directly on the host) — and run:

```
# Foreground:
cairn serve --config /etc/cairn/cairn.toml

# Or via systemd (contrib/):
sudo systemctl enable --now cairn
```

Continue at [Verify](#shared-verify).

## B. docker-compose (recommended for Docker)

Prerequisites: **Docker with the compose plugin**, ports 80 + 443
open. No Rust toolchain, no separate reverse proxy — the bundled
Caddy sidecar terminates TLS with an automatic Let's Encrypt
certificate.

```
git clone https://github.com/skydeval/cairn-mod && cd cairn-mod

# Deploy-varying scalars (your domain + DID) live in .env:
cp .env.example .env         # then edit
# Nested config (label taxonomy, [operator]) lives in cairn.toml:
cp cairn.toml.example cairn.toml   # then edit
```

Generate the signing key per [the shared
step](#shared-generate-a-signing-key), in the compose directory. The
container runs as fixed UID 1000 (image API) and refuses the key
otherwise — mode must be exactly `0600`, owner must be UID 1000:

```
chmod 600 signing-key.hex
sudo chown 1000 signing-key.hex   # no-op if your account is UID 1000
```

(On a multi-user host, note that host UID 1000 — whoever that is —
can read the bind-mounted key. Shared-host operators should ensure
host UID 1000 is trusted, or use the installed form.)

Bootstrap **in-container** (the session file must be written by the
container UID on the container's volume — a host-side login would
write a file the serving container never sees):

```
docker compose run --rm cairn operator-login --handle labeler.example.com
docker compose run --rm cairn publish-service-record
```

Then start the stack:

```
docker compose up -d
```

`docker compose ps` shows `cairn` reaching `healthy` (the healthcheck
curls `/ready`). Continue at [Verify](#shared-verify).

Note: bootstrap order matters — `docker compose up` before the
service record is published fail-starts with exit 13 and
`restart: unless-stopped` will loop it. See
[OPERATIONS.md](OPERATIONS.md) §Docker deployments for how a
restart-looping container reads.

## C. docker run

For operators who want the container without compose — an existing
host reverse proxy (the [`contrib/`](contrib/) nginx/Caddy templates
work unchanged, upstream `127.0.0.1:3000`), or an orchestrator of
your own. Everything — image, volumes, env, key rule — is identical
to the compose form by construction, so switching later is
mechanical.

```
docker build -t cairn-mod .

docker volume create cairn-data

# Bootstrap (one-time; interactive login prompt):
docker run -it --rm \
  -v cairn-data:/var/lib/cairn \
  -v ./cairn.toml:/etc/cairn/cairn.toml:ro \
  -v ./signing-key.hex:/var/lib/cairn/signing-key.hex:ro \
  -e CAIRN_SERVICE_DID=did:web:labeler.example.com \
  -e CAIRN_SERVICE_ENDPOINT=https://labeler.example.com \
  cairn-mod operator-login --handle labeler.example.com
docker run -i --rm \
  -v cairn-data:/var/lib/cairn \
  -v ./cairn.toml:/etc/cairn/cairn.toml:ro \
  -v ./signing-key.hex:/var/lib/cairn/signing-key.hex:ro \
  -e CAIRN_SERVICE_DID=did:web:labeler.example.com \
  -e CAIRN_SERVICE_ENDPOINT=https://labeler.example.com \
  cairn-mod publish-service-record

# Serve:
docker run -d --name cairn --restart unless-stopped \
  -p 127.0.0.1:3000:3000 \
  -v cairn-data:/var/lib/cairn \
  -v ./cairn.toml:/etc/cairn/cairn.toml:ro \
  -v ./signing-key.hex:/var/lib/cairn/signing-key.hex:ro \
  -e CAIRN_SERVICE_DID=did:web:labeler.example.com \
  -e CAIRN_SERVICE_ENDPOINT=https://labeler.example.com \
  cairn-mod
```

Notes:

- The image's `ENTRYPOINT ["cairn"]` is what makes
  `docker run … cairn-mod operator-login` work verbatim — arguments
  after the image name are `cairn` subcommands.
- The port publishes to **loopback only** (`127.0.0.1:3000:3000`) —
  the host reverse proxy terminates TLS; the labeler is never
  directly exposed. This is the containerized twin of the installed
  form's default bind posture.
- Same key ownership rule as compose: `chmod 600 signing-key.hex`,
  `sudo chown 1000 signing-key.hex`.
- `cairn.toml` is the same file as the compose form
  ([`cairn.toml.example`](cairn.toml.example)).
- Plain `docker run` wires no healthcheck — add
  `--health-cmd 'curl -fsS http://localhost:3000/ready'` (+ interval
  flags) if you want engine-level health. Optional.

Continue at [Verify](#shared-verify).

## Shared: Generate a signing key

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
running user, and `cairn serve` refuses to start otherwise. The
"running user" differs per form:

```
chmod 600 signing-key.hex

# Installed form (systemd):
sudo chown cairn:cairn signing-key.hex
sudo mv signing-key.hex /var/lib/cairn/signing-key.hex

# Docker forms (B and C): the key stays next to your compose files
# and is bind-mounted; the container's fixed UID owns it:
sudo chown 1000 signing-key.hex
```

Signing key material is **never** delivered via environment variable
in any form — `CAIRN_SIGNING_KEY` presence is a startup rejection by
design.

Publish the matching public key in the labeler's DID document at
verification method `#atproto_label`. Consumers verifying cairn-mod's
labels resolve the DID and extract this key.

## Shared: Configure

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

**Docker forms carry the config split differently.** The scalars at
the top (identity, paths, bind address) arrive via environment —
`.env` in compose, `-e` flags in docker-run, container-topology
defaults baked into the image — and the environment **overrides** the
file. The mounted `cairn.toml` carries only what env cannot: the
nested tables (`[labeler]`, `[operator]`, and any advanced tables),
which are file-only under the `CAIRN_` env prefix. That is exactly
what [`cairn.toml.example`](cairn.toml.example) templates; in the
Docker forms `session_path` must stay a container path on the data
volume (`/var/lib/cairn/operator-session.json`).

## Shared: Bootstrap (one-time per deployment)

Authenticate to the operator's PDS and publish the service record:

```
cairn operator-login --handle labeler.example.com --config /etc/cairn/cairn.toml
cairn publish-service-record --config /etc/cairn/cairn.toml
```

In the Docker forms the same two commands run **in-container** —
`docker compose run --rm cairn operator-login --handle …` /
`docker compose run --rm cairn publish-service-record` (compose
`run` allocates a TTY for the interactive login prompt), or the
`docker run -it --rm … cairn-mod operator-login …` form in
[section C](#c-docker-run). No `--config` flag needed there: the
config mounts at the compiled default path `/etc/cairn/cairn.toml`.

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

## Shared: Verify

```
curl -sSL https://labeler.example/.well-known/did.json | jq '.verificationMethod[].id'
```

Should return `"did:web:labeler.example#atproto_label"` (or the
suffixed forms during v1.1 key rotation). Identical in all three
forms — the public surface doesn't know how the labeler is deployed.

## Service record verify on startup

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

In the Docker forms a fail-start shows as a **restart loop** (docker
restart policies cannot discriminate exit codes the way systemd's
`RestartPreventExitStatus` does) — see
[OPERATIONS.md](OPERATIONS.md) §Docker deployments for the diagnosis
flow.

**Reconciliation flow.** When verify fails with drift or
absent, the operator runs `cairn publish-service-record` on the
host that has operator credentials configured. After successful
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
