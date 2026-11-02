# Third-Party Rules Attribution

## 1. Gitleaks Detection Rules

- **Source Repository:** [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
- **Pinned Commit:** `7cb43d81b490f0556f8742d4a520e5c8e31a1ba7` (v8.18.4)
- **Original Author:** Zachary Rice and Gitleaks Contributors
- **Licence:** MIT License

### MIT Licence Text
```text
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Imported Rules
| Rule ID | Category | Keywords |
|---|---|---|
| `gitleaks.aws-access-token` | `KnownSecret` | `AKIA, AGPA, AIDA, AROA, AIPA, ANPA, ANVA, ASIA` |
| `gitleaks.github-pat` | `KnownSecret` | `ghp_, gho_, ghu_, ghs_, ghr_` |
| `gitleaks.github-fine-grained-pat` | `KnownSecret` | `github_pat_` |
| `gitleaks.gitlab-pat` | `KnownSecret` | `glpat-` |
| `gitleaks.slack-bot-token` | `KnownSecret` | `xoxb-` |
| `gitleaks.slack-user-token` | `KnownSecret` | `xoxp-` |
| `gitleaks.stripe-api-key` | `KnownSecret` | `sk_test_, sk_live_, rk_test_, rk_live_` |
| `gitleaks.sendgrid-api-key` | `KnownSecret` | `SG.` |
| `gitleaks.twilio-api-key` | `KnownSecret` | `SK` |
| `gitleaks.mailgun-api-key` | `KnownSecret` | `key-` |
| `gitleaks.square-access-token` | `KnownSecret` | `sq0atp-` |
| `gitleaks.npm-access-token` | `KnownSecret` | `npm_` |
| `gitleaks.pypi-upload-token` | `KnownSecret` | `pypi-AgEIcHlwaS5vcmc` |
| `gitleaks.huggingface-api-token` | `KnownSecret` | `hf_` |
| `gitleaks.telegram-bot-token` | `KnownSecret` | `:` |
| `gitleaks.datadog-api-key` | `KnownSecret` | `datadog` |
| `gitleaks.shopify-access-token` | `KnownSecret` | `shpat_, shpca_, shppa_` |

### Untranslatable Rules
Certain upstream rules from gitleaks were not imported due to regex engine compatibility (lack of lookaround in linear-time automata) or architectural differences:

| Rule ID | Reason for Exclusion |
|---|---|
| `gitleaks.generic-api-key-entropy` | Requires Shannon entropy sliding window and custom heuristics, moved to DPG entropy stage C-07 / DT-4. |
| `gitleaks.jwt-arbitrary-claims` | Uses complex lookaround expressions unsupported in linear-time RE2 / Rust regex. |
