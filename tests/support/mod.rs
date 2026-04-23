//! Shared test-support crate for the CLI integration tests.
//!
//! Each test file that needs these helpers does `mod support;` at
//! the top. Cargo does not treat this directory as a standalone
//! test binary (no `.rs` file directly under `tests/` with name
//! `support`), so putting common fixtures here avoids the
//! "compiled once per test" cost of inlining.
//!
//! Because each integration test file re-compiles this module in
//! its own crate context and typically uses only a subset of the
//! helpers, `dead_code` fires inside individual test binaries for
//! the unused portions — hence the module-level allow.

#![allow(dead_code)]

pub mod mock_pds;
