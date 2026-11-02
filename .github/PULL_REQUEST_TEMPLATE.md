## Task

Issue / task ID: <!-- e.g. #12 or C-02 -->

## What changed and why

<!-- One short paragraph. Link the spec section you implemented. -->

## Evidence

<!-- Paste the exact commands you ran and their summarised results. Do not claim results you did not run. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`  → N passed, 0 failed
- [ ] Security tests for touched components pass (list them)
- [ ] Website build (if `website/` or user-facing docs changed)

## Security checklist

- [ ] No detected value, mapping value or request body is logged or printed
- [ ] Every new error path on a protected flow fails closed (blocks) and has a test
- [ ] No real credentials in code, tests or fixtures
- [ ] No new `unsafe`; no new dependency without justification below
- [ ] Docs and status labels updated (Planned / Implemented / Tested / Verified)

## New dependencies (if any)

| Crate / package | Version | Licence | Why needed |
|---|---|---|---|

## Known limitations / follow-ups
