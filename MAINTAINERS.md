# Maintainers

This file names the people currently responsible for `cairn-mod`.

## Primary maintainer

- [@skydeval](https://github.com/skydeval)

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

## Handoff policy

If `cairn-mod` receives no commits and no issue responses for six
consecutive months, the project is considered unmaintained. At that
point the preferred handoff path is transfer of ownership to a
named party, listed below. This is strictly better than silent
abandonment.

### Designated handoff target

**TBD — to be named before the v1.0 release.** The design doc
(§20.4) commits to naming a specific fallback (ideally a Guild or
ATProto-Rust community member who has accepted the role) before
v1.0 ships. Until then, this section is a live placeholder; a PR
filling it in is one of the v1.0 release gates.

If the project is unmaintained AND no handoff target has been
named, treat the repo as archived — fork freely under the
dual-license terms, but there is no authoritative upstream.

## Updating this file

Maintainer changes — additions, removals, handoff-target updates
— land as standalone PRs with a one-line commit message. No
deeper ceremony.
