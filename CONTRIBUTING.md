# Contributing to Cairn

Thanks for considering a contribution. This file covers the practical
mechanics; for architectural questions, read
[`cairn-design.md`](cairn-design.md) at repo root first — it is the
authoritative design reference and most "how does X work" questions
are answered there.

## Prerequisites

- **Rust toolchain 1.88 or newer.** The crate's minimum supported Rust
  version is pinned in [`Cargo.toml`](Cargo.toml) (`rust-version`). Do
  not file bugs against older toolchains.
- **`sqlx-cli`**, needed for offline query cache regeneration. Install
  with `cargo install sqlx-cli --no-default-features --features
  sqlite`.

## Building and testing

```
# Build.
cargo build --all-targets

# Run the full test suite (unit + integration).
cargo test --all-targets

# Lints must pass; -D warnings is the gate.
cargo clippy --all-targets --all-features -- -D warnings

# Formatting.
cargo fmt --all -- --check
```

### Updating the SQLx offline cache

Cairn uses SQLx's compile-time query checking. Whenever a test or
source file adds or changes a `sqlx::query!` / `query_as!` /
`query_scalar!` invocation, the offline cache under `.sqlx/` must be
regenerated:

```
TMPDB=$(mktemp -d)/cairn.db
export DATABASE_URL="sqlite:${TMPDB}?mode=rwc"
sqlx database create
sqlx migrate run
cargo sqlx prepare -- --all-targets
```

Commit the resulting `.sqlx/query-*.json` files alongside the code
change. The CI build runs with `SQLX_OFFLINE=true` and will fail if
the cache is stale.

### Security scanning tools

CI runs `cargo-audit` and `cargo-deny` on every push and PR (see
[§F15](cairn-design.md#f15-dependency-security-scanning-in-ci)),
and a daily scheduled `cargo audit` opens a tracking issue when
new advisories land. Contributors rarely need to run these
locally, but when investigating an advisory the pinned versions
are:

```
cargo install --locked cargo-audit --version 0.22.1
cargo install --locked cargo-deny  --version 0.19.4
```

These versions are the ones CI uses and the ones all local scans
should use to avoid skew. Bumps are allowed but require verifying
the current `deny.toml` still parses and that CI stays green with
the new version; treat a bump as a load-bearing change, not a
drive-by. The pinning rationale: the scanner is part of the
security posture, so its version should be auditable and change
deliberately, not silently.

## Code style

- **No `unsafe`.** The crate has `#![forbid(unsafe_code)]` and we
  route around required-unsafe APIs rather than scoping down the
  forbid. Examples from the history: `rustix::process::geteuid`
  instead of `libc::geteuid`; `Config::load_from(Option<&Path>)`
  instead of `std::env::set_var` (unsafe under Rust 2024).
- **`thiserror` for library errors, typed exit codes for the CLI.**
  The exit-code contract is defined in [`src/cli/error.rs`](src/cli/error.rs);
  scripts may depend on these codes, so adding a new class appends a
  new constant rather than reshuffling existing ones.
- **Tests ground invariants.** The "invariant = named artifact +
  dedicated test" pattern recurs across the codebase (e.g.
  `AUDIT_REASON_SCHEMA`, `EXPECTED_LEXICON_STEMS`,
  `SIGNING_KEY_ENV_REJECTED`). If you add a load-bearing constant or
  shape, add a test that would break if a future PR drifts from it.
- **Comments explain the *why*.** Well-named identifiers and types
  document the *what*. A comment earns its keep when it captures a
  hidden constraint, a surprising invariant, or a workaround — not
  when it narrates the next line.

## Submitting changes

- One logical change per PR. Bundling unrelated refactors makes review
  slower.
- The PR template under [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
  prompts for a summary, test plan, and related issue. Fill them in.
- CI must be green (build + test + clippy + fmt).
- Reference the relevant tracker issue in the PR description if the
  change is substantive.

## Substantial changes go through an issue first

New features, lexicon additions, protocol-surface changes, and any
shift to the security posture should be discussed in an issue before
implementation. This project uses a planning-first workflow:

- Tracker issue describes the scope.
- Acceptance criteria are drafted and confirmed before code lands.
- Implementation follows the confirmed criteria; deviations surface
  in commit messages or follow-up issues rather than quietly.

This process catches scope ambiguities early and produces tighter
commits. Small fixes (typos, doc clarifications, obvious bugs) don't
need a preceding issue — file a PR directly.

## Code of conduct

Participation in this project is governed by the
[Contributor Covenant 2.1](CODE_OF_CONDUCT.md). By contributing you
agree to uphold it. Reports of unacceptable behavior go to the
enforcement contact in that file (same pipeline as security
reports — one mailbox, one maintainer).

## Security

Do **not** file security vulnerabilities as public issues. See
[`SECURITY.md`](SECURITY.md) for the disclosure contact and process.

## License

By contributing, you agree that your contributions will be licensed
under the same dual MIT OR Apache-2.0 terms as the rest of the
project. See [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE).

## AI pair-programming

If you used an AI tool to draft a substantive portion of a change,
acknowledging it in the commit trailer is welcome but not required.
The existing history uses the Rust-convention-style
`Co-Authored-By:` line for this.
