# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `/health` and `/ready` orchestrator probe endpoints (unauthenticated, per-check rationale in [§F14](cairn-design.md#f14-health-and-readiness-probe-endpoints-v11)) (#23)

### Changed

### Fixed

### Removed

### Security

## [1.0.0] - 2026-04-24

### Added

### Changed

### Fixed

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
