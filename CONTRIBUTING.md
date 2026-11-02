# Contributing to DPG

Thank you for helping. DPG handles secrets, so the bar for correctness and honesty is high.

## Before you start

1. Read the website pages *How DPG works*, *Architecture* and *Security & privacy* (`website/src/content/docs/`).
2. Check open issues and the *Project status* page for the work you plan to do.
3. For anything that changes architecture, scope, dependencies or security behaviour, open an issue first and wait for maintainer agreement.

## Development setup

Rust stable (rustup), a C compiler (SQLCipher is compiled from source; on Windows the Visual Studio Build Tools plus Perl on `PATH`), Node.js 22+ for the website.

## Workflow

In short:

- Branch from `main` as `feat/<task-id>-short-name`, `fix/...` or `docs/...`.
- Keep pull requests small and tied to one task ID.
- Run before pushing:
  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace --all-features
  ```
- If you changed the website: `cd website && npm ci && npm run build`.

## Rules that are never relaxed

- **Never commit a real credential**, even an expired one. Test secrets are generated at test time.
- **Never weaken, skip or delete a security test** to make CI green.
- **Never log a detected value**, a mapping value or a request body.
- **No `unsafe`** without an ADR, a `// SAFETY:` comment and a dedicated test.
- **Never mark a feature Implemented or Verified** in docs without evidence (test name and result).
- New dependencies need a justification in the PR (purpose, licence, maintenance status); licences are checked by `cargo-deny` (`deny.toml`).

## Detection rules

New rules must come with true-positive and false-positive fixtures, a rule ID, a category and a
source/licence note if adapted from another project.

## Developer Certificate of Origin

By contributing you certify that you wrote the change or have the right to submit it under the
Apache License 2.0. Sign off commits with `git commit -s`.
