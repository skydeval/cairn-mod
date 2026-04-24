## Summary

<!-- One to three bullets. What does this change and why? -->

## Test plan

<!-- Mark what you've run locally before merging. CI runs the same gates. -->

- [ ] `cargo test --all-targets`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] SQLx offline cache regenerated and committed (if the change
      touches a `sqlx::query!` / `query_as!` / `query_scalar!`
      invocation — see CONTRIBUTING.md)

## Related

<!-- Tracker issue, design-doc section, or related PRs. "N/A" if
     this is a trivial fix. -->

---

<!-- By submitting, you agree the contribution is licensed under
     the dual MIT OR Apache-2.0 terms per the LICENSE-* files. -->
