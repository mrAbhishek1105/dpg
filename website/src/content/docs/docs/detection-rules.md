---
title: Detection rules
description: What DPG V1 is designed to detect, and what it will miss.
---

| Category | Examples | Default action |
|---|---|---|
| Known-format secrets | AWS, GitHub, OpenAI, Anthropic, Stripe, Slack and Google API keys; rules adapted from gitleaks (MIT, attributed) | mask |
| Private keys | PEM and OpenSSH private-key blocks (multi-line) | mask |
| Key-value secrets | `PASSWORD=…`, `"api_key": "…"`, `secret: …` in .env, JSON, YAML, TOML, shell | mask |
| Connection strings | `postgres://user:pass@host:5432/db` → user, password and host masked; scheme, port and path kept | mask |
| Custom terms | Your client names, codenames, internal domains, IP ranges (per project) | mask |
| Indian identifiers | Aadhaar (12 digits with Verhoeff checksum), PAN, GSTIN (with check digit), UPI IDs on known handles | mask |
| Entropy | Random-looking strings with no known prefix | **warn only** |

## Known misses

No detector finds every secret. DPG will miss unknown formats, secrets split across lines,
base64- or otherwise encoded secrets, and custom terms written with non-ASCII case variants.
Reports with synthetic examples help improve the rules.
