# Cairn Mod v1.0 Retrospective

**Author:** @skydeval
**Date:** 2026-04-24
**Timeline:** 26 hours of focused work over 2.5 days, idea to shipped v1.0.0 on crates.io.

## What Cairn Mod is

Cairn Mod is a minimal, self-hostable AT Protocol labeler. It implements the labeler side of the protocol correctly, with byte-exact DRISL signing parity against `@atproto/crypto`, full moderator authentication via PDS-mediated service auth JWTs, and an audit log with single-transaction integrity. It's a single binary backed by SQLite, deployable behind Caddy or nginx, with systemd templates included.

v1.0 is not a feature-complete alternative to Ozone. It's a correct foundation that I intend to build toward Ozone-alternative status over subsequent releases.

## What got built

In roughly 26 hours across 2.5 days:

- Full design document with threat model and five review rounds
- 297+ tests including crypto parity corpus
- Full moderator auth pipeline (`com.atproto.server.getServiceAuth` → Cairn Mod-side JWT verification)
- 8 admin XRPC endpoints (applyLabel, negateLabel, retract, listLabels, listReports, resolveReport, applyLabelAndResolveReport, listAuditLog)
- Report intake via `com.atproto.moderation.createReport`
- Label federation via `com.atproto.label.subscribeLabels` (WebSocket)
- Audit log with transaction atomicity across state changes
- Non-enumerating 404s on all unauthorized access
- SSRF-hardened HTTP fetching with DNS validation
- Single-instance lease enforcement (SQLite-backed)
- File permission enforcement (0600) on signing keys and session files
- Signing key explicitly rejected via environment variable (file-only)
- Complete OSS paperwork: dual LICENSE (MIT + Apache), CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, MAINTAINERS, CHANGELOG
- Deployment templates for Caddy, nginx, systemd in `contrib/`
- Release workflow with dry-run pre-check, version bump, CHANGELOG migration, tag push, cargo publish, GitHub release, and non-blocking post-publish smoke test

## What worked

### Design-first architecture

Before any code got written, the design doc existed. Every significant decision — threat model, auth boundaries, storage shape, federation semantics, non-enumeration, lease enforcement — was argued through as prose before becoming Rust. The doc went through five substantive review rounds. When implementation hit ambiguity, the answer was in the doc. When the doc had gaps, they got filled before code proceeded.

This front-loaded the hard thinking. Implementation decisions during the 26-hour build window were mostly mechanical because the architectural decisions had already been made.

### Scope discipline

Every issue had a tracker entry before work started. Every session was scoped to a single issue. When an agent mid-session surfaced "while I'm in here, I should also fix X," the answer was almost always "file X as its own issue and continue with the current scope." Design-doc drift got batched into dedicated sweep sessions rather than fixed inline in unrelated PRs.

This kept commits clean, review surfaces small, and rollback simple.

### Agent-driven development with careful direction

I didn't write most of the code. Agents did, directed by specific prompts tied to tracker issues with explicit acceptance criteria. But I read every diff, reviewed every commit, and pushed back on scope creep and pattern drift. "The agent wrote it" and "the code is correct" are different statements; I treated them differently.

The agents surfaced multiple things I would have missed: scope overreach in proposed fixes, invariants worth naming explicitly, test coverage gaps, subtle concurrent-write bugs (e.g., chainlink close hook racing an in-progress Edit). Good pushback on them in return kept the collaboration productive.

### §14.1 Production Checklist walkthrough

This is the single most important practice of the whole project.

The release gate list (§14.1 in the design doc) required walking through the production checklist before tagging v1.0. Every item had to be verified against reality, not just against documentation.

When I got to this gate, I realized I'd built Cairn Mod without ever running it. Tests passed. CI was green. The design was reviewed. But I hadn't deployed it myself to verify it operated as designed. I wasn't sure whether it actually worked.

I paused the release and set up a test instance locally, walking through the quickstart exactly as a new user would.

Within an hour I found three real bugs, all of which would have shipped in v1.0:

1. **#18 — README quickstart config missing `operator.pds_url`.** someone following the README wouldn't have been able to get Cairn Mod working.

2. **#19 — Spontaneous shutdown at 30 seconds.** The server exited on its own 33 seconds after startup with a misleading "HTTP drain timeout exceeded" message. Root cause: `tokio::time::timeout(DRAIN_TIMEOUT, serve_fut)` wrapped the entire server lifetime, not just the drain phase. Tests never caught that because they used explicit shutdown futures on short timescales. This would have crashed every first install in under a minute.

3. **#20 — Audit log writing on wrong path.** Three bugs in one fix: first publish's audit row had `content_changed: false` (should have been true), skip path wrote no audit at all (should have written with `content_changed: false`), and audit INSERT was outside the labeler_config transaction (atomicity gap). Tests had verified the shape of audit rows but not the correctness of their content.

Every one of these was invisible to the test suite by design. Tests exercise what the author thought to test; real deployment exercises everything else.

### The core lesson

"Tests pass" and "I have verified this works" are different statements. The gap between them is specifically the set of bugs that live in the interface between the test harness and the real world: time-behavior over long windows, documentation-versus-reality consistency, correctness-of-content (not just shape-of-content) in audit trails.

Walking through production as an operator, not as a developer, is the only way to close that gap. Nothing else substitutes.

## Key principles worth keeping

### "I have to verify that it does what I'm saying it does."

If I'm putting my name on software, so people can trust my code in their stacks, the tests passing isn't enough. The agent saying it works isn't enough. The design being sound isn't enough. I have to set it up myself and watch it work. That's the only form of deployment-confidence that substitutes for the others being insufficient.

Tests verify what the author thought to test. Deployments verify what the user will actually experience. These are different. And it is important to me that i can speak with confidence that software i'm building actually does function.

### Three kinds of confidence

A v1.0 claim requires all three:

1. **Design-confidence** — the architecture is sound.
2. **Implementation-confidence** — the code implements the design correctly.
3. **Deployment-confidence** — the binary actually works in the real world.

Cairn Mod had (1) and (2) before the §14.1 walkthrough. It did not have (3). The walkthrough is what produced (3), and in the process it produced specific evidence that (2) had gaps that tests alone couldn't surface.

Future releases will go through the same walkthrough before tagging. §14.1 is not a soft gate anymore; it's a mandatory pre-release practice.

### Scope discipline pays compound interest

Every architectural decision made cleanly during design reduced the implementation surface area. Every implementation decision made cleanly during a session reduced the debugging surface area. Every bug caught pre-release reduced the post-release surface area.

I noticed this compounding when the later sessions (the §14.1 walkthrough, the release workflow debugging) were faster than the earlier ones despite being more complex. The early discipline had paid down the cognitive cost of the later work.

### Trust hazard signals

The §14.1 walkthrough existed as a gate only because I insisted on it. Every other signal said v1.0 was ready. Tests passed. CI was green. Five design rounds had been completed. The checklist items in the README looked accurate. By every proxy I had, shipping was the right move.

But something felt off. I'd never run Cairn Mod. I was putting my name on a binary I hadn't watched work.

That discomfort was real information. I listened to it instead of reasoning my way past it. Three release-blockers came out of that one choice.

For future projects: when every signal says ready except one lingering discomfort, trust the discomfort.

## What didn't work

### CHANGELOG hygiene

I didn't maintain [Unreleased] entries as I went. When the release workflow migrated [Unreleased] → [1.0.0], there was nothing to migrate. The result was a shipped v1.0.0 release with empty subheaders in CHANGELOG.md. I had to write proper release notes manually at release-time.

**Change for v1.1:** update CHANGELOG.md as part of each session's commit sequence. Tracker session completion includes a CHANGELOG entry.

### Release workflow sequencing

The release workflow needed three attempts to complete end-to-end. First attempt failed on `cargo publish --dry-run` because the step order put the dry-run after the version bump but before the commit, leaving the working tree "dirty." Second attempt succeeded at publish but failed at tag creation and GitHub release due to a tag-push sequencing bug. Third attempt worked, but produced a duplicate commit on main and required manual tagging afterward.

**Change for v1.1:** fix the workflow before the next release. Specifically: dry-run with `--allow-dirty` inline, commit-before-push-tags order, detect and skip already-completed steps on re-run.

### Test coverage for time-behavior

The spontaneous shutdown bug (#19) was invisible because no test exercised a multi-minute serve with wall-clock semantics. Test harnesses used explicit shutdown futures, which was the sensible choice for fast test runs but left a coverage gap for the real deployment scenario.

**Change for v1.1:** for any time-dependent behavior, include at least one test that exercises it with `tokio::time::pause/advance` simulating the real-duration scenario.

### My estimates for my own pace

I consistently underestimated how fast the work would go when planning. Advisors consistently overestimated. The actual pace was ~12 shipped issues per day at sprint. Neither my plans nor external estimates accounted for this; both were off by 3-5x.

**Change for v1.1:** trust the empirical pace from this project, not calibration-against-industry-averages. The pace is what it is.

## The meta-story

Cairn Mod v1.0 is the output of a specific bet: that disciplined-but-fast agent-directed development could produce correct software on a timescale that would surprise people. The bet paid off. 26 hours produced a correct, documented, auditable AT Protocol labeler with full OSS paperwork.

The bet only paid off because the discipline was real. Scope control, design-first, verify-before-claim, trust-hazard-signals; these weren't optional additions to the process. They were the process.

Future projects will use the same approach. The goal now is to bring Cairn Mod toward Ozone-alternative status over the next few months, using the v1.0 foundation as the base for a v1.x trajectory that adds health endpoints, label rotation, moderator management CLI, automod signal integration, and eventually a UI layer. The path is long but the pace is known.

## Acknowledgments

Cairn Mod was built as a solo project with agent-driven implementation. The specific agents that participated in development sessions directly shaped the code and deserve credit. Design review went through multiple iterations with me as the only human in the loop, testing architectural ideas against agents asked to find weaknesses.

The `chainlink` issue tracker (by [@dollspace-gay](https://github.com/dollspace-gay)) was what I used for tracker work throughout most of development. It quietly did its job — a rare and valuable property in developer tools.

Thanks to the AT Protocol team at Bluesky for documenting the labeler contract clearly enough that a third-party implementation was possible in this timeline.

## What's next

v1.1 scope is being planned. Likely targets: `/health` and `/ready` endpoints, `cairn moderator` CLI, label rotation support, automod signal pipeline.

Ultimate goal: Cairn Mod as a serious alternative to Ozone for ATProto moderation deployments.

See you there.