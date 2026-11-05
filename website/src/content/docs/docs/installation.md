---
title: Installation
description: How DPG will be installed, and how to build it from source once code exists.
---

:::caution[No release yet]
There is no published DPG binary and no Rust code yet. The commands below will be enabled once tested.
:::

## Build from source

Requirements: Rust stable via [rustup](https://rustup.rs), a C compiler (SQLite is compiled from
source), Git. On Windows, install the Visual Studio Build Tools.

```bash
git clone https://github.com/mrAbhishek1105/dpg
cd dpg
cargo build --release -p dpg
```

## Planned

- Pre-built binaries for Linux, macOS and Windows on GitHub Releases, with `SHA256SUMS.txt`.
- `cargo install dpg --locked`.
- Signed macOS and Windows binaries once code-signing certificates are obtained.

Always verify the checksum of a downloaded binary before running it.
