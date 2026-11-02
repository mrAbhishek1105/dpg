# DPG — Data Protection Gateway

> Keep coding with your AI agent; DPG swaps your secrets for placeholders and puts them back only in your local files.

**Status: pre-alpha. Nothing is implemented yet.** This repository currently contains the
project foundation (governance, CI) and the website. No installable
build exists. The website's *Project status* page (source: `website/src/content/docs/status.md`) lists what is done and what is not.

DPG is a local-first data protection layer that sits between AI coding agents and external AI
services. It detects secrets and confidential terms, replaces them with placeholders before the
agent's model sees them, and restores the real values only when the agent writes files inside your
project.

## What DPG v1 is designed to do

| Capability | Route | Status |
|---|---|---|
| Mask secrets in what Claude Code reads (tool output) | Claude Code `PostToolUse` hook | Planned |
| Restore real values in Claude Code `Write` / `Edit` inside the project | Claude Code `PreToolUse` hook | Planned |
| Mask outbound requests and restore streamed replies | Local proxy on `127.0.0.1` (Anthropic / OpenAI formats) | Planned |
| `dpg inspect`, `sanitize`, `ignore`, `forget`, `install`, `doctor` | CLI | Planned |
| Indian identifiers (Aadhaar, PAN, GSTIN, UPI ID) | Detection | Planned |
| Custom confidential terms per project | Detection | Planned |

## What DPG does **not** protect

These limits are permanent design facts or unverified platform behaviour, not bugs:

- **Text you type into a prompt.** No Claude Code hook can rewrite a typed prompt; it can only block it. Use the local proxy if you need prompt rewriting.
- **`@file` mentions in Claude Code.** The client inserts the file before any hook runs. A setting that may route mentions through hooks is **unverified**.
- **Cursor, GitHub Copilot, web chats, documents and images.** Not in v1.
- **Secrets the model already received.** DPG prevents; it cannot recall.
- **Unknown secret formats.** No detector finds every secret. DPG does not guarantee zero leaks.
- **Prompt injection.** DPG limits what an injection can exfiltrate through restoration; it does not prevent injection.

## Repository layout

```text
apps/dpg/            single binary: CLI, `dpg hook`, `dpg proxy`      (planned)
crates/dpg-core      request lifecycle, context, fail-closed           (planned)
crates/dpg-detect    detection rules and engine                        (planned)
crates/dpg-policy    mask / block / warn / allow decisions             (planned)
crates/dpg-protect   placeholders and encrypted mapping store          (planned)
crates/dpg-restore   restore guard and path guard                      (planned)
crates/dpg-connect   Claude Code hook adapter, local proxy, installer  (planned)
website/             public website and documentation portal (Astro Starlight)
```

## Documentation

The public documentation is the website in [website/](website) (Astro Starlight):
how DPG works, architecture, security and known limitations, roadmap, configuration and CLI reference.

```bash
cd website && npm ci && npm run dev
```

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md) — please do not report vulnerabilities in public issues.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [GOVERNANCE.md](GOVERNANCE.md)

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Detection rules adapted from
gitleaks (MIT) will carry attribution in NOTICE.
