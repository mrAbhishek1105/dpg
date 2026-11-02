---
title: Quick start
description: The intended first-run flow for Claude Code users and proxy users.
---

:::caution[Planned behaviour]
These steps describe V1 as designed. They will be tested and updated before the first release.
:::

## Claude Code

```bash
dpg install claude-code   # adds DPG hooks to your user-level Claude Code settings (backup first)
dpg doctor                # checks hooks, keychain, store, rules and Claude Code version
```

Then use Claude Code as usual. When it reads a file containing secrets, Claude sees placeholders
such as `DPG_SECRET_7K2M9QXA`. When it writes or edits a file in your project, DPG puts the real
values back.

Try it with a fake value:

```bash
echo 'API_TOKEN=EXAMPLE_NOT_A_SECRET_0000000000' > demo.env
dpg inspect demo.env
```

## Proxy (Aider, Cline, other base-URL tools)

```bash
dpg proxy --print-env     # prints ANTHROPIC_BASE_URL / OPENAI_BASE_URL including your local token
dpg proxy                 # starts the proxy on 127.0.0.1:8787
```

Point your tool at the printed base URL. It keeps using your own API key.
