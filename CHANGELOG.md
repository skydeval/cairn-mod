# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

### Security

## [1.1.0] - 2026-04-25

> v1.1 "Pleasant to operate" focuses on operational comfort for
> self-hosters. The release adds orchestrator-friendly health
> probes, supply-chain security scanning in CI, the full admin
> CLI surface (moderator / report / audit / retention), startup-
> time service-record drift detection, and a 41% trim of the
> published crates.io tarball. The housekeeping pass deflakes
> three timing-sensitive cache tests, validates `contrib/`
> deployment configs in CI, and ships a quickstart rot-check
> that exercises the README's operator workflow against a mock
> PDS — silent doc drift now fails CI.
>
> Also: this release reconciled a tracker numbering migration
> mid-development (chainlink replaced an earlier crosslink
> instance), and removed a stale auto-generated hook system that
> was emitting misleading reminders. See
> [docs/tracker-history.md](docs/tracker-history.md) for the
> migration record.

### Added
- `/health` and `/ready` orchestrator probe endpoints (unauthenticated, per-check rationale in [§F14](cairn-design.md#f14-health-and-readiness-probe-endpoints-v11)) (#23)
- CI security scanning: `cargo-audit` + `cargo-deny` on push/PR plus a scheduled daily audit that opens an issue on new advisories; hard-fail posture with a dated-review-comment escape hatch in [`deny.toml`](deny.toml) (policy in [§F15](cairn-design.md#f15-dependency-security-scanning-in-ci-v11)) (#13)
- `cairn moderator {add, remove, list}` CLI subcommands for managing the `moderators` table directly; one-shot, no lease conflict with running `cairn serve` (contract in [§F16](cairn-design.md#f16-moderator-management-cli-v11)) (#24)
- `cairn report {list, view, resolve, flag, unflag}` admin CLI subcommands wrapping the `tools.cairn.admin.*` HTTP endpoints; audit attribution preserved via JWT iss (contract in [§F17](cairn-design.md#f17-report-management-cli-v11)) (#7)
- `cairn audit list` admin-only CLI subcommand wrapping `tools.cairn.admin.listAuditLog` with actor / action / outcome / time-window filters and `--cursor` pagination (contract in [§F18](cairn-design.md#f18-audit-log-cli-v11)) (#6)
- `cairn serve` startup verify-only check against the published service record on the operator's PDS; drift / absent / unreachable each fail-start with a distinct exit code (12/13/14); reconciliation via `cairn publish-service-record` (contract in [§F19](cairn-design.md#f19-service-record-verify-on-startup-v11)) (#8)
- subscribeLabels retention sweep — daily writer-task batched DELETEs against `labels` older than `[subscribe].retention_days` (default 180); operator-initiated runs via `tools.cairn.admin.retentionSweep` (admin-only, audited per call) and `cairn retention sweep`; new `[retention]` config block. Full contract in [§F4](cairn-design.md#f4-comatprotolabelsubscribelabels-endpoint) (#12)
- E2E quickstart rot-check: new [`tests/e2e/quickstart.sh`](tests/e2e/quickstart.sh) walks the README's operator workflow end-to-end (signing-key generation → config → `publish-service-record` → `serve` → `curl /.well-known/did.json`) against a [mock PDS binary](examples/mock_pds.rs). New `e2e-quickstart` CI job — silent README drift now fails CI (#10)
- contrib syntax smoke check: new `contrib-smoke` CI job runs `systemd-analyze verify` on `cairn.service`, `caddy adapt` on `Caddyfile` (syntax-only — `validate` opens log paths that CI's non-root runner can't write), and `nginx -t` on `cairn.conf` (wrapped in a minimal events+http shell since the snippet declares http-block directives without the top-level wrappers). Rate-limiting in `contrib/nginx/cairn.conf` is now operator-add with a documented example, matching the Caddyfile pattern; defaults ship without to avoid version-specific syntax (`r/h` rate units landed in nginx 1.27, postdating the Ubuntu LTS nginx CI runs against). End-to-end deployment scenarios with real TLS / header forwarding / IP propagation track separately as chainlink #32 (#9)

### Changed
- crates.io tarball trimmed from 287 files to 168 via [`Cargo.toml`](Cargo.toml) `[package].exclude` rules — drops `.chainlink/`, `.claude/`, `.github/`, internal docs (`cairn-design.md`, `RETROSPECTIVE.md`, `MAINTAINERS.md`, `CODE_OF_CONDUCT.md`, `docs/`), and `tests/` (which alone account for ~70 files including the ~40-file signature corpus). The `.sqlx/` offline cache (~95 entries) is a hard floor required for downstream `SQLX_OFFLINE=true` builds without sqlx-cli; further reduction would require splitting the cache into lib-only vs all-targets variants and is deferred (#22)
- §20.4 of [cairn-design.md](cairn-design.md) replaced its three-paragraph "named handoff target TBD" narrative (stale post-v1.0) with a brief two-sentence pointer to [MAINTAINERS.md](MAINTAINERS.md) as the durable source of truth for the archive-on-silence policy. Single-source-of-truth — no policy duplication (#17)

### Fixed
- Three timing-sensitive auth-cache tests (`doc_cache_returns_cached_then_expires`, `doc_cache_negative_has_shorter_ttl`, `jti_cache_expiry_permits_reuse`) deflaked by routing wall-clock reads through a new `Clock` trait. Production wires `SystemClock`; tests substitute `MockClock` with explicit `advance(Duration)` calls. Zero `thread::sleep` in cache tests; deterministic regardless of CI scheduler jitter. Verified correctness power before commit by intentionally breaking `DidDocCache::get` and `JtiCache::check_and_record` and confirming the relevant tests panic (#21)

### Removed

### Security

## [1.0.0] - 2026-04-24

### Added

### Changed
- Design-doc drift sweep: crate name, security contact, tracker references, CHANGELOG phrasing (#5)
- Release workflow: manual workflow_dispatch triggers crates.io publish + GitHub Release, with non-blocking post-publish smoke test (#4)
- CI hardening: rustdoc + MSRV gates, rust-cache; MSRV bumped 1.85→1.88 (#3)
- Complete rustdoc sweep for tier 3 items deferred from #22 (#11)

### Fixed
- `cairn publish-service-record` audit trail: skip path now audits (was silent), publish path records `content_changed=true` (was inverted on first publish), and `labeler_config` upsert + audit row share one transaction (#20)
- `cairn serve` exited ~30 seconds after startup with no signal received; the drain timeout now bounds only the post-shutdown drain phase (#19)
- Clippy 1.95 `collapsible_if` on five nested if-let sites (#14)

### Removed

### Security
