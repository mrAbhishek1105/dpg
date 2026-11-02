---
title: Local proxy
description: Using DPG with tools that accept a custom Anthropic or OpenAI base URL.
---

:::caution[Planned behaviour]
The proxy is specified but not implemented.
:::

## Setup

```bash
dpg proxy --print-env
# ANTHROPIC_BASE_URL=http://127.0.0.1:8787/t/<token>/anthropic
# OPENAI_BASE_URL=http://127.0.0.1:8787/t/<token>/openai/v1
dpg proxy
```

Your tool keeps sending its own API key; DPG forwards it to the provider over HTTPS and never stores it.

## Supported APIs

| API | Status |
|---|---|
| Anthropic Messages (including streaming) | Planned |
| OpenAI Chat Completions (including streaming) | Planned |
| OpenAI Responses API | Not in V1 |

## What is masked and restored

- **Requests:** every text value the client sends — prompts, system prompts, tool results — is scanned and masked. Images and documents are not inspected.
- **Replies:** placeholders in reply **text** are restored, including when a placeholder is split across streamed chunks. Tool-call arguments are never restored.
- Tools that apply edits from reply text (for example Aider) therefore receive real values in that text, and DPG's project path guard cannot apply. Set `restore_in_responses = false` to keep placeholders everywhere.

## Security

The proxy listens only on `127.0.0.1`, requires the token in the URL, rejects non-loopback `Host`
headers and all browser requests, and forwards only to fixed provider endpoints.

## Unverified

Using Claude Code through the proxy with a Pro/Max subscription login (instead of an API key) has
not been tested.
