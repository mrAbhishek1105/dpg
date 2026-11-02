---
title: Security & privacy
description: How DPG handles your data, what it defends against, and what it cannot protect.
---

:::caution
DPG is security software that has **not yet been implemented or audited**. Nothing on this page is
a guarantee. DPG does not claim complete protection, zero leaks or any certification.
:::

## Local-first

All detection, masking and restoration runs on your machine. DPG has no server, no telemetry, no
crash upload and no update check in V1. The only outbound traffic is the proxy forwarding your
(masked) requests to the provider you configured, with your own credentials.

## Mapping storage and keys

- Placeholder ↔ value mappings are stored per project in a local SQLite database encrypted with SQLCipher.
- The 256-bit key is generated on first run and stored in your OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service).
- Mappings expire 30 days after last use; `dpg forget` deletes them on demand.
- If the key is missing, DPG never silently creates a new database over the old one.

## Local proxy hardening

- Listens on `127.0.0.1` only.
- Requires a random install token in the URL path.
- Rejects requests whose `Host` is not the loopback address (defeats DNS rebinding).
- Rejects browser requests (`Origin` header or cross-site fetch metadata) — web pages cannot use it.
- Forwards only to fixed HTTPS provider endpoints and a short list of API paths: it is not an open proxy.
- Limits request size; never logs headers or bodies.

## Restoration safety

- Only `Write` and `Edit` tools; never shell commands, URLs, web fetches or MCP calls.
- Only into paths that resolve (following symlinks) inside the project root, never into `.git`.
- Only placeholders that exactly match a stored mapping for this project.
- **Limitation:** the agent performs the write after DPG approves it, so a process already running as you could race a symlink swap. DPG re-checks after the write and alerts.

## Logging

The event log records rule ID, category, action, counts and timings. It never records values,
file contents, prompts, request bodies, headers or file paths in clear.

## Untrusted repositories

A project's `.dpg.toml` can add rules and make policy stricter, but cannot loosen it. A cloned
repository cannot switch DPG off.

## Known limitations

- Prompts you type into Claude Code cannot be rewritten by hooks — only blocked.
- `@file` mentions in Claude Code bypass hooks; a documented setting may route them through tools, but it is unverified and depends on the model choosing to read the file.
- Claude Code documents that its own telemetry captures original tool output even when a hook replaces it.
- If Claude Code kills or times out a hook, it continues by default; DPG relies on the `onFailure: "block"` option, whose behaviour for tool output is still being tested.
- Unknown secret formats, secrets split across lines, and encoded secrets can be missed.
- Images and documents sent through the proxy are not inspected.
- Malware running as your user can read the keychain and the store.
- Data already sent to a provider cannot be recalled.

## Threat model

DPG addresses OWASP LLM02:2025 (Sensitive Information Disclosure). It only limits the impact of
LLM01:2025 (Prompt Injection) and LLM06:2025 (Excessive Agency); it does not prevent them. To report a vulnerability, see
[Community → Security reports](/community/#security-reports).
