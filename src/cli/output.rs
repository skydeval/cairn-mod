//! Shared CLI output helpers (#28).
//!
//! Started as the home for the `truncate` table-cell helper that
//! cli/audit.rs, cli/report.rs, and cli/trust_chain.rs all
//! needed for human-readable column rendering. The cli/mod.rs
//! scaffolding comment names this module as the future home for
//! "human vs --json formatting" — `truncate` is the first piece
//! of that. Format-tabulation primitives that reach the same
//! duplication threshold (3+ identical copies) move here too.

/// Char-aware right-truncation with a trailing `…`. Returns the
/// input unchanged when its character count is `<= max`; otherwise
/// returns the first `max - 1` characters followed by `…` so the
/// total visible length is `max`.
///
/// Length is in `char` count, not bytes — so multi-byte characters
/// (CJK, emoji) and combining marks are handled correctly for
/// column rendering, even if visually-wide CJK runes still
/// overflow at the terminal level. Producing exactly-`max`-cell
/// output is out of scope for v1.2.
pub(super) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}
