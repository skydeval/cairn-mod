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

> **Latest stable release:** [v1.6.0](https://github.com/skydeval/cairn-mod/releases/tag/v1.6.0) · install with `cargo install cairn-mod`
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

**v1.6.0 is the current stable release.** Install with `cargo install cairn-mod` or pin to the [v1.6.0 tag](https://github.com/skydeval/cairn-mod/releases/tag/v1.6.0). v1.6's "policy automation" theme closes the v1.5 loop: operators now declare strike-threshold rules in `[policy_automation]`, and the recorder evaluates those rules inside every recordAction transaction. Auto-mode rules record the consequent action in the same transaction as the precipitating action and emit labels through the v1.5 path; flag-mode rules queue a `pending_policy_actions` row for moderator review, with a confirm/dismiss surface (`tools.cairn.admin.{confirmPendingAction, dismissPendingAction}` and the `cairn moderator pending {list, view, confirm, dismiss}` CLI) that promotes pendings to real actions or resolves them without materializing one. Conservative idempotency holds — a rule fires once per subject until the firing is explicitly resolved (revoked, dismissed, or confirmed-then-revoked) — so operators don't get surprised by automated re-firing as decay timing approaches a crossing. Takedown is terminal and cascades: every unresolved pending for a takendown subject auto-dismisses inside the takedown's transaction, and the cascade audit rows discriminate from manual dismissals via the `triggered_by` field in the reason JSON. Pending state is moderator-tier visibility only — `tools.cairn.public.getMyStrikeState` is unchanged from v1.5; subscribers see what cairn-mod has *done*, not what it *might* do. The model is documented in cairn-design.md [§F22](cairn-design.md#f22-policy-automation-v16) with a new [§4.2](cairn-design.md#42-operator-trust-trust-chain-readme-audience) trust-chain disclosure 6 on the moderator-tier-only nature of pending visibility. Items deferred to v1.7 and beyond are tracked in the [issue tracker](https://github.com/skydeval/cairn-mod/issues).

**v1.7 is in active development on `main`.** The next release theme is operator-config-gated PDS administrative actions per design doc [§18](cairn-design.md#18-future-roadmap): a bridge that translates emitted labels (and the v1.6 auto-recorded actions layered on top) into PDS-level account state changes by calling `com.atproto.admin.*` on operator-controlled PDSes. **Default is labeler-only when `[pds_admin]` is absent or disabled** — the existing labels-only surface remains the unchanged baseline for community-tier deployments. Operators who run a PDS for their community (e.g., Hideaway with Prism credentials, or any deployment with admin access to its members' PDSes) opt in by declaring credentials and the per-action-type mapping; cairn-mod calls the admin endpoints in lockstep with label emission. v1.7+ also picks up decay-and-recross re-firing and mode-applies-forward configuration mutation per §F22.11. Subsequent v1.x releases continue toward Ozone parity with full parity expected around v1.10 (review queue, source management, webhook signal intake, team management refinement).

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
