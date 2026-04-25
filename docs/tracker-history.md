# Tracker history

## Background

`chainlink` is the active issue tracker for this project. `.crosslink.archive/`
on disk is a frozen snapshot from the pre-migration tracker. This doc records
the migration so the two-tracker disk state doesn't confuse readers (or future
agents) who notice both directories.

## Migration timeline

- **2026-04-22** — initial commit; project scaffolded with crosslink + Claude
  Code hooks (commit `9d3a771`).
- **2026-04-23** — migrated from crosslink to chainlink (commit `b3079ba`).
  Rationale, paraphrased from that commit message: chainlink is what the
  Guild's Doll uses; local-first by design (no remote-push noise); simpler
  surface (no agent keys, no hub cache, no hydration refs). Migration path
  was a fresh init, not export/import.
- **2026-04-24** — `.gitignore` tightened post-migration (commit `4810cf9`);
  `v1.0.0` released.
- **2026-04-24..25** — v1.1 development; every commit trailer references a
  chainlink issue number, all closed in chainlink with handoff comments.
- **2026-04-25** — recovery sweep: auto-memory rules retargeted at chainlink;
  legacy crosslink-aware Claude Code hooks removed; `.crosslink/` archived
  to `.crosslink.archive/`.

The migration completed during v1.0 development; the numbering divergence
between the two trackers first surfaced as a bookkeeping question during v1.1
(see "Why the confusion arose" below).

## What's where on disk

- `.chainlink/issues.db` — active, authoritative tracker state.
- `.chainlink/rules/` — language and project coding rules; tracked at remote.
- `.crosslink.archive/` — legacy snapshot from pre-migration. Read-only.
  Do not modify. Gitignored.

The Claude Code hooks were **removed** rather than re-pointed at chainlink
equivalents (commit `286c155`). The original `.claude/hooks/*.py` scripts
were crosslink-aware and emitted stale `<crosslink-behavioral-guard>`
reminders instructing future agents to use `crosslink quick` — which would
write to the legacy tracker. Discipline now relies on the auto-memory rules
(`feedback_issue_numbering.md`, `feedback_tracker_scope.md`).

chainlink ships hook equivalents installable via `chainlink init --force`.
That's a deliberate opt-in path if hook-based enforcement is wanted later;
it's not a one-time-only operation.

## v1.1 commit trailers map to chainlink

All v1.1 trailers reference real chainlink issues, all closed cleanly:

| Trailer | chainlink # | Title                                                                | Commit range          |
|---------|-------------|----------------------------------------------------------------------|-----------------------|
| `(#23)` | #23         | Add `/health` and `/ready` endpoints for orchestrator probes         | `5155c41..ad3ca25`    |
| `(#13)` | #13         | cargo-audit / cargo-deny security scan in CI                         | `c8eb115..a0d290a`    |
| `(#24)` | #24         | `cairn moderator` add/remove/list CLI subcommands                    | `e577bd2..27203a0`    |
| `(#7)`  | #7          | CLI: admin-side `cairn report` subcommands (list/view/resolve/…)     | `04cb432..dbd9b99`    |
| `(#6)`  | #6          | `cairn audit` CLI subcommand                                         | `0d1a1bc..cd58127`    |
| `(#8)`  | #8          | Auto-publish or verify-only startup check for service record (§F1)   | `876cc06..2456e73`    |

These numbers are correct as filed. There are no "ghost numbers" in v1.1
history — the apparent mismatch in one earlier investigation came from
checking against crosslink (legacy) instead of chainlink (active).

## Why the confusion arose

- The `prompt-guard.py` hook (since removed) emitted a
  `<crosslink-behavioral-guard>` block on every prompt, instructing future
  agents to use `crosslink quick`. That text was stale post-migration.
- The auto-memory rules (`feedback_issue_numbering.md`,
  `feedback_tracker_scope.md`) formerly told future agents to verify issue
  numbers via `crosslink issue show N`. Following that rule against the
  legacy tracker led to a "ghost number" investigation and a four-commit
  recovery sweep (this doc + the three preceding commits).

Both surfaces have been corrected. Future agents should:

- Use `chainlink issue show N` for verification.
- Treat any residual "use `crosslink`" reminder text as stale and ignore.
- Not write to `.crosslink.archive/` under any circumstance.

## Cross-reference

- Auto-memory rules (machine-local, outside this repo):
  - `feedback_issue_numbering.md` — issue-number verification rule.
  - `feedback_tracker_scope.md` — scope verification rule.
- Commits in this repo:
  - `b3079ba` — migration rationale (full text in git log).
  - `286c155` — crosslink-aware hook removal.
  - `1424d8a` — `.crosslink/` → `.crosslink.archive/` rename.
