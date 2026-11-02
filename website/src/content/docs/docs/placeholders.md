---
title: Placeholders
description: Placeholder format and consistency rules.
---

Format: `DPG_<CATEGORY>_<8 characters>`, for example `DPG_SECRET_7K2M9QXA`.

- `CATEGORY` is one of `SECRET`, `PASS`, `USER`, `HOST`, `CONN`, `TERM`, `ID`, `PII`.
- The 8 characters are random (Crockford base32, 40 bits), not derived from the value.
- The same value gets the same placeholder within one project, across sessions, until it expires (30 days unused) or you run `dpg forget`.
- Different projects get different placeholders; a placeholder from one project is never restored in another.
- The format is code-safe: valid inside identifiers, strings, URLs, YAML, JSON and shell.

The exact format may change after testing which formats AI models copy back unchanged most reliably.
