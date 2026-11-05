---
title: Introduction
description: What DPG is, who V1 is for, and how to read these docs.
---

:::note[Pre-release]
DPG v1 is implemented and tested but not yet released: build it from source. It has not yet been
validated against a live Claude Code session. Check [Project status](/status/) for what is tested
and what is unverified.
:::

DPG (Data Protection Gateway) is a local-first protection layer between AI coding agents and AI
providers. It masks secrets and confidential terms in what the agent reads and restores the real
values only into files the agent writes inside your project.

**V1 is for** freelance developers and small agencies who use Claude Code, or base-URL agents such as
Aider and Cline, on client code.

**V1 supports** two routes:

- **Claude Code hooks** — mask tool output, restore into `Write`/`Edit`, block prompts containing known secrets.
- **Local proxy** — for tools with a custom API base URL (Anthropic or OpenAI format).

**V1 does not support** Cursor, GitHub Copilot, web chats, images or documents.

Continue with [Installation](/docs/installation/) and the [Quick start](/docs/quick-start/).
