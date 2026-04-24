---
name: Bug report
about: Something in Cairn isn't behaving the way the docs or design suggest it should.
title: ""
labels: bug
assignees: ""
---

## What happened

A clear and concise description of the actual behavior.

## What you expected

What should have happened instead, and where in the docs / design
that expectation comes from if you can cite it.

## Reproduction

Minimal steps to reproduce. Config snippets welcome — redact any
secrets before pasting (signing keys, PDS app passwords, session
tokens).

## Environment

- Cairn version (from `cairn --version` or commit hash if built from
  source):
- Rust toolchain (`rustc --version`):
- OS and version:
- Relevant dependencies that might matter (reverse proxy, systemd /
  launchd / other supervisor):

## Additional context

Logs, stack traces, or anything else that helps. If the issue is
intermittent, note the frequency.

## Security

If this bug has a security impact, do NOT file it here. See
[SECURITY.md](../../SECURITY.md) for the private disclosure channel.
