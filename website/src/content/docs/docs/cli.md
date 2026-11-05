---
title: CLI reference
description: The six V1 commands.
---

:::note[Pre-release]
Flags may still change before the first release (v0.0.1 is unreleased).
:::

| Command | Purpose |
|---|---|
| `dpg inspect [file or -] [--json] [--show-values]` | List findings (rule ID, category, line, redacted preview). Values are hidden unless `--show-values` |
| `dpg sanitize [file or -] [--exit-code]` | Print a masked copy to stdout. If content is blocked or anything fails, prints nothing and exits non-zero |
| `dpg ignore --list` / `--add <rule> <value>` / `--remove <rule> <value>` | Manage this project's ignore list (stored as keyed fingerprints, never values, outside the repository) |
| `dpg forget [--project <id>] [--all] [--all --reset]` | Delete stored mappings; `--all --reset` deletes the store and its master key (recovery for a locked store) |
| `dpg install [claude-code] [--dry-run] [--uninstall]` | Add or remove DPG hooks in user-level Claude Code settings, with a backup |
| `dpg doctor` | Check hooks, rules, configuration, master key backend, mapping store and a detection self-test |
| `dpg proxy [--port N] [--print-env]` | Run the loopback proxy, or print the `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` exports |
| `dpg completions <bash\|zsh\|fish\|powershell>` | Print shell completions |

Internal subcommands used by integrations: `dpg hook post-tool-use`, `dpg hook pre-tool-use`,
`dpg hook user-prompt-submit`.
