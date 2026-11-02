---
title: FAQ
description: Common questions about DPG.
---

**Is DPG ready to use?**
No. It is pre-alpha; see [Project status](/status/).

**Does DPG send my data anywhere?**
No. There is no DPG server, telemetry or crash upload. The proxy forwards masked requests only to the provider you configured.

**Does DPG guarantee no secret reaches the AI provider?**
No. It reduces exposure on the documented routes. Unknown formats, `@` mentions (until verified) and typed prompts on the hook route are not covered.

**Can I use it with Cursor or Copilot?**
Not in V1. Their hooks cannot replace content, and Cursor sends model requests from its own servers.

**How is this different from secret scanners that block prompts?**
DPG masks and lets the agent continue, then restores real values in local file writes.

**Is the whole thing open source?**
The engine — detection, policy, masking, mapping and restoration — is Apache-2.0.

**Will it break my code?**
It might, if a model mangles a placeholder. DPG never restores altered placeholders and reports them. Measuring the effect on real coding tasks is part of the V1 acceptance criteria.
