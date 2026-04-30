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

> **Latest stable release:** [v1.7.0](https://github.com/skydeval/cairn-mod/releases/tag/v1.7.0) · install with `cargo install cairn-mod`
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

**v1.7.0 is the current stable release.** Install with `cargo install cairn-mod` or pin to the [v1.7.0 tag](https://github.com/skydeval/cairn-mod/releases/tag/v1.7.0). v1.7's "PDS-side enforcement bridge & inbound XRPC gateway" theme closes the loop between cairn-mod and the operator's PDS in two halves. Outbound: a `[pds_admin]` config block declares operator-trusted PDS credentials and an action-type-to-backend-method mapping; cairn-mod's existing recordAction pipeline now propagates account-state changes (takedown / temp suspension / restore) to the configured PDS in lockstep with label emission. Inbound: a new `xrpc_gateway` accepts proxied `tools.ozone.moderation.*` calls (`emitEvent`, `queryStatuses`, `queryEvents`) and PDS-forwarded `com.atproto.moderation.createReport` — making cairn-mod a usable Ozone replacement for operators on bsky-PDS. Both halves preserve cairn-mod's audit-chain discipline (every backend call hash-chains into the existing audit log; every inbound mutation lands via the canonical recordAction path). v1.7 ships bsky-PDS support; the `PdsAdminBackend` trait abstraction accommodates Aurora-Locus and other Rust-PDS backends in subsequent releases without API changes. **Disabled by default** — operators upgrading from v1.6 see no behavior change unless they opt in by setting `[pds_admin].enabled = true` and/or `[xrpc_gateway].enabled = true`. The model is documented in cairn-design.md [§F23](cairn-design.md#f23-pds-side-enforcement-bridge--inbound-xrpc-gateway-v17), with operator runbook in [§19.5](cairn-design.md#195-operator-deployment-runbook-for-v17-pds-bridge--xrpc-gateway) and a new [§4](cairn-design.md#4-threat-model) entry 9 on the trust-boundary expansion for upstream PDSes asserting `reportedBy` on forwarded reports. Items deferred to v1.8 and beyond are tracked in the [issue tracker](https://github.com/skydeval/cairn-mod/issues).

**v1.8 is in active development on `main`.** The next release theme is Aurora-Locus backend support and retry policy per design doc [§18](cairn-design.md#18-future-roadmap): a `LocusBackend` implementation of the v1.7 `PdsAdminBackend` trait (snake_case admin-surface adapter, JWT-with-scope auth, Locus's accumulating-label model), plus the explicit `backend = "ozone" | "locus"` selector in `[pds_admin]`. v1.8 also introduces operator-configurable retry with backoff for failed bridge calls — v1.7 fails loud and audits, leaving the retry-policy decision to v1.8 once real operator feedback grounds the design. Gateway refinements (per-PDS rate limiting on the `createReport` path, bulk-fetching optimization for `queryStatuses`'s N+1 lookups) ship alongside. Subsequent v1.x releases continue toward Ozone parity: review queue + extended event types in v1.9, web UI in v2.0.

Production deployments should pin to the stable release, not the `main` branch.

## Quickstart

Install:

```
cargo install cairn-mod
```

This produces a binary named `cairn`. For full deployment guidance
(signing key generation, configuration, service-record publishing,
service verify on startup), see [SETUP.md](SETUP.md).

For day-2 operational concerns (production checklist, monitoring,
security hygiene), see [OPERATIONS.md](OPERATIONS.md).

For the moderator CLI reference, see
[docs/moderator-cli.md](docs/moderator-cli.md).

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
