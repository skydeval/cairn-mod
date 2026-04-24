# Cairn

A lightweight, Rust-native [ATProto](https://atproto.com) labeler —
single binary, SQLite-backed, designed for small and mid-scale
community moderation.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

<!-- TODO (#27 CI hardening): GitHub Actions badge once workflows exist. -->
<!-- TODO (#28 release workflow): crates.io + docs.rs badges once published. -->

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

**v1 is in development.** The technical surface is code-complete —
see the [tracker](https://github.com/skydeval/cairn-mod/issues) for
remaining docs + release work. v1.1 plans (review queue, richer
admin API, key rotation) live in the design doc's §18 roadmap.

## Quickstart

Target: a running `cairn serve` behind a reverse proxy, published
service record, responding to `GET /.well-known/did.json`.

### Prerequisites

- **Rust 1.85+** — install via [rustup](https://rustup.rs).
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
