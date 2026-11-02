---
title: Roadmap
description: V1 and beyond, with honest status labels.
---

| Stage | Adds | Depends on | Status |
|---|---|---|---|
| **V1** | Claude Code hooks, local proxy, CLI; for freelancers and small agencies | This plan | Planned |
| **V1.x** | Codex CLI hooks; `MultiEdit`/notebook restoration; OpenAI Responses API | Spike confirming Codex `updatedInput` restore and output masking | Unverified |
| **V2 Teams** | Shared policy files, per-client profiles for agencies | Policy files synced through git or a small sync service | Planned |
| **V2 Integrations** | Cursor, Copilot and other IDE agents | Vendors adding hooks that can rewrite content | Deferred |
| **V3 Enterprise** | Central console, metadata-only audit, device-management deployment, SSO | A hosted service plus SOC 2 or ISO 27001 | Deferred |
| **Future** | Documents and images; browser extension for web chats; other tools calling the DPG engine through its local API | Text extraction pipelines; per-site maintenance | Deferred |

The V1 build is organised in stages (foundation → core → detect → policy → protect → restore →
Claude Code → proxy → CLI → release), each ending at a test gate. A failed gate means fix or
pivot, not move on.
