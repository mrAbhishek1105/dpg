---
title: Policy
description: Mask, block, warn and allow, and how DPG chooses between them.
---

| Action | Effect |
|---|---|
| **mask** | Replace the value with a placeholder and continue |
| **block** | Withhold the output, deny the tool call or block the prompt, naming the rule |
| **warn** | Leave content unchanged and show a warning naming the rule |
| **allow** | Do nothing |

Resolution order: a rule-specific setting beats a category setting; your global config may loosen
or tighten; a project `.dpg.toml` may only tighten; `dpg ignore` entries skip a specific finding.

Typed prompts in Claude Code cannot be rewritten, so known-format secrets in prompts are **blocked**
by default and other categories produce a warning.

Every decision names the rule and the setting that caused it, for example:
`Masked by rule gitleaks.aws-access-token (policy.known_secret = mask, from defaults)`.
