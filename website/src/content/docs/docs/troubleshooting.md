---
title: Troubleshooting
description: Planned diagnostics and common situations.
---

:::caution[Pre-release]
Error codes are stable for V1; messages may still change before the first release.
:::

Start with:

```bash
dpg doctor
```

| Symptom | Likely cause | What to do |
|---|---|---|
| Claude reports "Output withheld: inspection failed" | DPG could not inspect output (fail-closed) | Run `dpg doctor`; the error code (for example `DPG-M001`) names the failing part |
| "Restoration unavailable" notice | Keychain or mapping store not reachable; DPG masked with temporary placeholders | Unlock your keychain or check `dpg doctor`; temporary placeholders cannot be restored |
| A write was denied with `DPG-V001` | Target path is outside the project, or a symlink leads outside | Write inside the project root |
| A harmless value keeps being masked | False positive | `dpg ignore --last`, and report a detection issue with a synthetic example |
| A placeholder ended up in a file | The model altered the placeholder, or the tool was not `Write`/`Edit` | Replace it manually; DPG reports unknown placeholders |
| Proxy returns 403 | Request came with a browser `Origin` or a wrong `Host` | Use the exact base URL from `dpg proxy --print-env` |
| Proxy returns 401 | Missing or wrong token in the base URL | Re-run `dpg proxy --print-env` |
