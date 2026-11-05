---
title: Development setup
description: Build DPG and this website locally.
---

Prerequisites: Rust stable (rustup), a C compiler (for the bundled SQLite), Node.js 22+, Git.

```bash
cargo build --workspace
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all
```

Website:

```bash
cd website
npm ci
npm run dev     # local preview
npm run build   # static output in website/dist
```

Never use real credentials in tests; the repository will include a synthetic-secret generator.
On Windows, install the Visual Studio Build Tools (C compiler for the bundled SQLite).
