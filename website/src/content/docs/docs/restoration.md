---
title: Restoration
description: When and where DPG puts real values back.
---

DPG restores a placeholder only when **all** of these hold:

1. The tool is `Write` or `Edit` (Claude Code hook route).
2. The target path, after resolving symlinks, is inside the project root and not inside `.git`.
3. The placeholder exactly matches a mapping stored for this project.

Everything else is left unchanged:

- Placeholders in shell commands, web fetches, searches or MCP tool calls are **never restored**; DPG warns (or blocks, if configured).
- Placeholders the model altered or invented are left as-is and listed in DPG's report.

On the proxy route, placeholders are restored in reply **text** only (configurable), never in tool-call arguments.

**Limitation:** Claude Code performs the actual write after DPG approves it. A program already
running as your user could swap a directory for a symlink in between; DPG re-checks the path after
the write and alerts if it ended up outside the project.
