# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security report.** Email
**security@mod.cairn.tools** with details.

If you don't get an acknowledgment within 48 hours, please follow
up — mail forwarding is best-effort and delivery glitches happen.

## Timeline

- **Acknowledgment:** within 48 hours of your initial report.
- **Coordinated disclosure:** 90 days by default, negotiable in
  either direction depending on severity and fix complexity. Report
  in good faith; we'll respond the same way.
- **Fix cadence:** in the next patch release. If severity warrants,
  the affected versions are yanked from crates.io and a GitHub
  security advisory is published.

## What's in scope

The design doc's threat model ([`cairn-design.md`](cairn-design.md) §4)
and security considerations (§12) are the authoritative source. In
practice the categories we especially want to hear about:

- **Signing-key handling** — anything that exposes the labeler's
  private key material, bypasses the §5.1 file-only load path, or
  would allow an unauthorized process to sign labels.
- **Auth verification paths** — JWT algorithm confusion, replay
  beyond the documented window, DID-resolution cache poisoning,
  role-check bypass.
- **Label integrity** — signature bypass, monotonicity-clamp
  regressions, sequence-number gaps or duplicates, anything that
  would let a tampered label verify against a real labeler DID.
- **DoS vectors that affect operators** — memory exhaustion paths,
  unbounded-growth data structures, subscription-layer resource
  exhaustion.
- **Report-content leaks** — any path where the body of a reporter's
  submission reaches an unauthorized caller, a log line, or a
  response a non-admin can observe.
- **Default configurations that make misconfiguration easy** — if
  Cairn ships a default that sets an operator up to fail in a way
  that compromises one of the above categories, that's in scope
  even if the operator technically "could have" overridden it.
  Safe defaults are a security property.

## What's out of scope

- **Bugs in our dependencies.** Report upstream; we'll pick up the
  fix when a patched version is published. If the upstream
  maintainer is unresponsive and the issue materially affects
  Cairn, include that in your report and we'll coordinate.
- **Issues reachable only via operator negligence** — host
  compromise, a leaked config file, an operator running Cairn as a
  privileged user on a public host with no firewall. The threat
  model in §4 makes the operator-trust boundary explicit.
- **Known v1 limitations** documented in the design doc. The
  honest-scope statements in §4.1 and §4.2 are not security bugs.

## No bug bounty

There's no monetary bounty for reports. Credits in the release
notes + advisory are the only reward offered; we'll honor a
requested handle or a requested anonymity.

## Questions

For non-security questions, use the issue tracker with the
`question` template. This mailbox is for vulnerability reports
only.
