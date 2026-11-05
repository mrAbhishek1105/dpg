---
title: Configuration
description: Global and project configuration, precedence, and what a project file may change.
---

:::caution[Pre-release]
Keys and defaults below are the V1 specification.
:::

## Files and precedence

From lowest to highest priority: built-in defaults → global `config.toml` (your user config
directory, for example `~/.config/dpg/config.toml` on Linux) → project `.dpg.toml` → `DPG_*`
environment variables → command-line flags.

A project `.dpg.toml` is committed with the repository, so DPG treats it as **untrusted**: it can add
rules and terms and make actions **stricter**, but cannot loosen anything. Loosening is only possible
in your global config or with `dpg ignore`.

## Project example

```toml
# .dpg.toml
[terms]
values = ["Acme Corp", "project-falcon", "internal.acme.example", "10.20.0.0/16"]

[policy]
entropy = "mask"     # stricter than the default "warn"

[[rules]]
id = "acme.internal-token"
category = "KnownSecret"
regex = "acme_tok_[a-z0-9]{32}"
```

## Global keys (defaults)

```toml
[policy]
known_secret = "mask"
private_key = "mask"
key_value_secret = "mask"
connection_string = "mask"
custom_term = "mask"
indian_id = "mask"
pii = "warn"
entropy = "warn"
prompt_known_secret = "block"
placeholder_in_other_tool = "warn"

[storage]
key_backend = "keychain"
expiry_days = 30

[hook]
timeout_seconds = 10

[proxy]
port = 8787
restore_in_responses = true
max_body_bytes = 33554432

[log]
level = "info"
events = true
```

Configuration files must never contain secrets; DPG rejects values that look like secrets.
`dpg doctor --config` shows where each setting came from without printing term lists.
