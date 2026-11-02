---
title: CLI reference
description: The six V1 commands.
---

:::caution[Planned behaviour]
Flags may change before the first release.
:::

| Command | Purpose |
|---|---|
| `dpg inspect <file or ->` | List findings (rule ID, category, action, line:column). Values are hidden unless `--show-values` |
| `dpg sanitize <file or ->` | Print a masked copy to stdout. On any error, prints nothing and exits non-zero |
| `dpg ignore --last` / `--rule <id>` / `--remove` | Ignore the last finding (or a rule) for this project; stored outside the repository |
| `dpg forget [--project or --all] [--reset]` | Delete stored mappings; `--reset` also creates a new key |
| `dpg install claude-code [--dry-run] [--uninstall]` | Add or remove DPG hooks in user-level Claude Code settings, with backup |
| `dpg doctor [--config]` | Check installation, hooks, keychain, store, rules, versions and configuration sources |

Internal subcommands used by integrations: `dpg hook post-tool-use`, `dpg hook pre-tool-use`,
`dpg hook user-prompt-submit`, `dpg proxy`.
