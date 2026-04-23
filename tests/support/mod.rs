//! Shared test-support crate for the CLI integration tests.
//!
//! Each test file that needs these helpers does `mod support;` at
//! the top. Cargo does not treat this directory as a standalone
//! test binary (no `.rs` file directly under `tests/` with name
//! `support`), so putting common fixtures here avoids the
//! "compiled once per test" cost of inlining.

pub mod mock_pds;
