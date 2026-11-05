---
title: Claude Code integration
description: What DPG's Claude Code hooks do, what they cannot do, and the documented gaps.
---

:::caution[Pre-release]
Hook behaviour depends on Claude Code's hook API, which changes between versions. DPG will publish
a tested version range with each release.
:::

## Hooks DPG installs

| Hook | What DPG does |
|---|---|
| `PostToolUse` (all tools) | Masks secrets in the tool's output before Claude sees it, keeping the output's exact structure |
| `PreToolUse` (`Write`, `Edit`) | Restores real values for placeholders, only for paths inside the project |
| `PreToolUse` (other tools) | Never restores. Warns (default) or blocks when a placeholder appears in, for example, a shell command |
| `UserPromptSubmit` | Blocks a typed prompt containing a known-format secret (hooks cannot rewrite prompts) |

`dpg install claude-code` writes these into your **user** settings (after a backup) and sets
`CLAUDE_CODE_DISABLE_FILE_MENTIONS=1`. `dpg install claude-code --uninstall` removes them.

## Edits

Because Claude saw a masked file, its `Edit` calls contain placeholders in `old_string` too. DPG
restores both `old_string` and `new_string` so the edit matches the real file on disk.

## Documented gaps

- **`@` mentions** insert file contents before any hook runs. The `CLAUDE_CODE_DISABLE_FILE_MENTIONS` setting (Claude Code 2.1.299 or later) tells Claude to read mentioned files with its tools instead; whether that reliably happens is being tested. Until then, `@` mentions are **not protected**.
- **Timeouts and crashes:** by default Claude Code continues when a hook times out or exits with an unexpected code. DPG sets the documented `onFailure: "block"` option and enforces a shorter internal deadline. Its effect on tool-output masking is being tested.
- **Telemetry:** Claude Code documents that its telemetry captures the original tool output even when a hook replaces it.
- Content Claude Code loads itself (such as `CLAUDE.md` or memory files) does not pass through tool hooks.
