# cairn-mod

A lightweight, Rust-native [ATProto](https://atproto.com) labeler —
single binary, SQLite-backed, designed for small and mid-scale
community moderation.

[![CI](https://github.com/skydeval/cairn-mod/actions/workflows/ci.yml/badge.svg)](https://github.com/skydeval/cairn-mod/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/cairn-mod.svg)](https://crates.io/crates/cairn-mod)
[![docs.rs](https://img.shields.io/docsrs/cairn-mod)](https://docs.rs/cairn-mod)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV: 1.88](https://img.shields.io/badge/MSRV-1.88-informational.svg)](Cargo.toml)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

> **Latest stable release:** [v1.5.0](https://github.com/skydeval/cairn-mod/releases/tag/v1.5.0) · install with `cargo install cairn-mod`
>
> The `main` branch contains active development toward the next release. For production deployments, pin to a released version.

## What is cairn-mod?

cairn-mod is a standalone ATProto labeler server. It publishes a
[`app.bsky.labeler.service`](https://atproto.com/lexicons/app-bsky-labeler)
record, signs labels per the ATProto spec, accepts user reports, and
exposes an admin XRPC surface for moderators to act on them. It
exists because the ecosystem has Ozone (heavy, TypeScript,
Postgres-backed, opinionated web UI) and Skyware's labeler library
(minimal, no report intake, no audit trail), with a gap between them
for operators who want something compact but production-grade. cairn-mod
is deliberately smaller than Ozone and deliberately more complete
than Skyware; it does not try to be either.

## Status

**v1.5.0 is the current stable release.** Install with `cargo install cairn-mod` or pin to the [v1.5.0 tag](https://github.com/skydeval/cairn-mod/releases/tag/v1.5.0). v1.5's "label emission" theme closes the v1.4 loop: every recorded action now translates into ATProto labels that consumer AppViews honor, and revocation atomically negates whatever was emitted — all inside the same SQLite transaction as the action insert and audit row. Operators declare the action-to-label mapping in `[label_emission]` (defaults ship out of the box; per-action `val` / `severity` / `blurs` / `locales` overrides cover deployment-specific surfaces; notes never emit by hard-rule defense-in-depth). Reason labels emit as `reason-<code>` alongside their action label, sharing its expiry on `temp_suspension`. The new `tools.cairn.public.getMyStrikeState`'s `activeLabels` field lets subjects introspect what cairn-mod is currently emitting against them; `cairn moderator labels <subject>` is the operator-facing tabular equivalent. The model is documented in cairn-design.md [§F21](cairn-design.md#f21-label-emission-against-moderation-state-v15) with a new [§4.2](cairn-design.md#42-operator-trust-trust-chain-readme-audience) trust-chain disclosure 5 on the internal-state-vs-protocol-visible-labels distinction. Items deferred to v1.6 and beyond are tracked in the [issue tracker](https://github.com/skydeval/cairn-mod/issues).

**v1.6 is in active development on `main`.** The next release theme is policy automation per design doc [§18](cairn-design.md#18-future-roadmap): auto-action recording when subjects cross operator-configured strike thresholds, with operator choice between auto-execution and flag-for-review per rule. v1.7+ adds operator-config-gated PDS administrative actions (default-disabled when `[pds_admin]` is absent — the existing labels-only surface remains the unchanged baseline for community-tier deployments). Subsequent v1.x releases continue toward Ozone parity with full parity expected around v1.10 (review queue, source management, webhook signal intake, team management refinement).

Production deployments should pin to the stable release, not the `main` branch.

## Install

```
cargo install cairn-mod
```

Produces a binary named `cairn`. For full first-deployment instructions
(generating a signing key, configuring, bootstrapping, running, and
the startup-time service-record verify gate), see
[SETUP.md](SETUP.md).

## Documentation

cairn-mod's docs are split by audience:

- **[SETUP.md](SETUP.md)** — first-deployment guide. Prerequisites,
  install, signing-key generation, configuration, bootstrap, run,
  verify, and the service-record verify-on-startup gate.
- **[OPERATIONS.md](OPERATIONS.md)** — day-2 operator content.
  Production checklist (transport, rate limits, secrets, key
  lifecycle, backup, monitoring, health probes, dependency
  scanning, single-instance enforcement).
- **[docs/moderator-cli.md](docs/moderator-cli.md)** — CLI reference.
  Moderator membership management, session-auth flow, report
  management workflow, and audit log queries.
- **[cairn-design.md](cairn-design.md)** — the full design doc.
  Threats, cryptographic details, schema, XRPC surface, audit log
  hash chain, account moderation state model (§F20), label emission
  system (§F21), v1.x roadmap.

## Trust-chain disclosures

Operators AND subscribers should understand what cairn-mod's protocol
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
- **Single-instance lease** (§F5) prevents two cairn-mod processes from
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
