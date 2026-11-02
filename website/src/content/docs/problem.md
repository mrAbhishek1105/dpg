---
title: The problem
description: How secrets and confidential data can reach AI providers while you work with coding agents.
---

## Documented behaviour of coding agents

These are documented properties of agents such as Claude Code — not hypotheticals:

- Agents **read files** in your project with tools.
- Agents **run shell commands** and read their output.
- Whatever a tool returns becomes part of the conversation sent to the model provider.
- You can attach a file directly (for example `@.env` in Claude Code); its contents are inserted before any hook runs.

## Risk scenarios

The following are **scenarios**, not reported incidents:

| Scenario | What can leave your machine |
|---|---|
| The agent opens `.env` to debug a config error | API keys, database passwords |
| The agent runs tests and a log prints a connection string | Database credentials and hostnames |
| You work on client code at an agency | Client names, internal hostnames, IP ranges |
| Your app handles Indian customer data | Aadhaar, PAN, GSTIN or UPI IDs in fixtures and logs |
| A README contains a prompt injection asking the agent to put a key into a URL | Any value the agent can see |

Once a value reaches a provider, it is subject to that provider's retention policy. It cannot be recalled.

## Why blocking alone falls short

Tools that block the prompt or the tool call stop the agent mid-task. Developers then disable them
or work around them. DPG is designed to keep the agent working: it masks, continues, and restores
real values only into local files.

## Where DPG fits

DPG addresses **sensitive information disclosure** (OWASP LLM02:2025). It does not prevent prompt
injection (LLM01) or excessive agency (LLM06); its restore guard only limits what an injection can
exfiltrate through restored values.
