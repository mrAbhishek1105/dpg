---
title: Project status
description: What exists today, what is planned, and what is unverified. Updated with every stage.
---

Last updated: **2026-11-03**. Current phase: **Foundation (design, specifications, CI)**.

Labels: **Planned** (designed, not built) · **In progress** · **Implemented** (code merged) ·
**Tested** (automated tests pass) · **Verified** (acceptance metric measured and met) ·
**Unverified** (depends on third-party behaviour not yet tested) · **Not supported**.

| Capability | Status |
|---|---|
| Architecture, threat model, specifications | Implemented (documents) |
| Detection engine | Planned |
| Policy engine | Planned |
| Placeholders + encrypted mapping store | Planned |
| Restore guard + path guard | Planned |
| Claude Code `PostToolUse` masking | Planned |
| Claude Code `PreToolUse` restoration (Write/Edit) | Planned |
| Claude Code `UserPromptSubmit` blocking | Planned |
| Fail-closed on hook timeout / crash | Unverified (depends on Claude Code `onFailure`) |
| `@` mention protection | Unverified |
| Local proxy — Anthropic Messages / OpenAI Chat Completions | Planned |
| Claude Code through the proxy with Pro/Max login | Unverified |
| CLI: inspect, sanitize, ignore, forget, install, doctor | Planned |
| Signed releases | Not yet (checksums planned; signing needs certificates) |
| Cursor, Copilot, browser extension | Not supported in V1 |

## Acceptance targets

These are the project's own V1 targets, not industry standards. None has been measured yet.

| Metric | Target | Measured |
|---|---|---|
| Original values in outbound requests (covered cases) | 0 | — |
| Known-format secret recall | ≥ 95 % | — |
| Detection precision | ≥ 90 % | — |
| PostToolUse latency, 500-line file | < 100 ms | — |
| Coding task success drop | ≤ 10 points | — |
| Exact placeholder restoration | 100 % | — |
| Restorations outside the project | 0 | — |
| Fail-closed tests passing | 100 % | — |
