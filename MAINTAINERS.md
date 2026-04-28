# Maintainers

This file names the people currently responsible for `cairn-mod`.

## Primary maintainer

- [@skydeval](https://github.com/skydeval)

## Development pattern

cairn-mod is developed by @skydeval with substantial implementation
assistance from [Claude](https://claude.ai) (Anthropic). The pattern
is collaborative, not AI-autonomous: architecture, design choices,
scope discipline, and judgment calls are human; the majority of
source code is AI-generated. Every commit passes the full quality
gate (`cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
full test suite, `RUSTDOCFLAGS="-D warnings" cargo doc`) before push,
and every release passes end-to-end verification against a real
ATProto PDS.

This pattern is what makes the release cadence possible at solo-
developer scale. It is not a quality compromise — the project's
test density, hash-chained audit log (cairn-design.md §F10), and
trust-chain disclosures (cairn-design.md §4.2) speak to the bar
each release is held to.

If this development pattern affects your evaluation of cairn-mod
for your deployment, that's worth knowing upfront.

## Adding maintainers

When a second maintainer is added, they get their own entry below
with the same shape:

```
- Name — [@ghhandle](https://github.com/ghhandle) — areas of focus (optional)
```

"Areas of focus" is optional and unenforced. It's a signal about
who's likely to review what, not a permissions boundary. Everyone
listed has full repo rights.

## Contact

For general questions: file an issue using the
[question template](.github/ISSUE_TEMPLATE/question.md).

For security reports: email **security@mod.cairn.tools** — see
[SECURITY.md](SECURITY.md) for the full disclosure process.

Do not DM maintainers about security issues on public social media.

## Handoff

cairn-mod is maintained solely by @skydeval. If the maintainer becomes
unresponsive for ~6 months, the repo will be archived. Users should
fork if long-term continuity matters. This policy may change in
future versions.

## Updating this file

Maintainer changes — additions, removals, handoff-target updates
— land as standalone PRs with a one-line commit message. No
deeper ceremony.
