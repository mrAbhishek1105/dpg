#!/usr/bin/env python3
"""
Imports detection rules adapted from gitleaks at a pinned commit into DPG TOML format.
Generates rules/gitleaks.toml and rules/THIRD_PARTY.md.
"""

import sys

PINNED_GITLEAKS_COMMIT = "7cb43d81b490f0556f8742d4a520e5c8e31a1ba7"
PINNED_GITLEAKS_VERSION = "v8.18.4"
GITLEAKS_REPO = "https://github.com/gitleaks/gitleaks"

# Curated rules from gitleaks at the pinned commit
GITLEAKS_RULES = [
    {
        "id": "aws-access-token",
        "category": "KnownSecret",
        "keywords": ["AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"],
        "regex": r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b",
        "secret_group": 1,
    },
    {
        "id": "github-pat",
        "category": "KnownSecret",
        "keywords": ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        "regex": r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b",
        "secret_group": 1,
    },
    {
        "id": "github-fine-grained-pat",
        "category": "KnownSecret",
        "keywords": ["github_pat_"],
        "regex": r"\b(github_pat_[0-9a-zA-Z_]{82})\b",
        "secret_group": 1,
    },
    {
        "id": "gitlab-pat",
        "category": "KnownSecret",
        "keywords": ["glpat-"],
        "regex": r"\b(glpat-[0-9a-zA-Z\-_]{20,22})\b",
        "secret_group": 1,
    },
    {
        "id": "slack-bot-token",
        "category": "KnownSecret",
        "keywords": ["xoxb-"],
        "regex": r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b",
        "secret_group": 1,
    },
    {
        "id": "slack-user-token",
        "category": "KnownSecret",
        "keywords": ["xoxp-"],
        "regex": r"\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b",
        "secret_group": 1,
    },
    {
        "id": "stripe-api-key",
        "category": "KnownSecret",
        "keywords": ["sk_test_", "sk_live_", "rk_test_", "rk_live_"],
        "regex": r"\b([sr]k_(?:test|live)_[0-9a-zA-Z]{24,34})\b",
        "secret_group": 1,
    },
    {
        "id": "sendgrid-api-key",
        "category": "KnownSecret",
        "keywords": ["SG."],
        "regex": r"\b(SG\.[a-zA-Z0-9_\-\.]{22}\.[a-zA-Z0-9_\-\.]{43})\b",
        "secret_group": 1,
    },
    {
        "id": "twilio-api-key",
        "category": "KnownSecret",
        "keywords": ["SK"],
        "regex": r"\b(SK[0-9a-fA-F]{32})\b",
        "secret_group": 1,
    },
    {
        "id": "mailgun-api-key",
        "category": "KnownSecret",
        "keywords": ["key-"],
        "regex": r"\b(key-[0-9a-zA-Z]{32})\b",
        "secret_group": 1,
    },
    {
        "id": "square-access-token",
        "category": "KnownSecret",
        "keywords": ["sq0atp-"],
        "regex": r"\b(sq0atp-[0-9A-Za-z\-_]{22})\b",
        "secret_group": 1,
    },
    {
        "id": "npm-access-token",
        "category": "KnownSecret",
        "keywords": ["npm_"],
        "regex": r"\b(npm_[A-Za-z0-9]{36})\b",
        "secret_group": 1,
    },
    {
        "id": "pypi-upload-token",
        "category": "KnownSecret",
        "keywords": ["pypi-AgEIcHlwaS5vcmc"],
        "regex": r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000})\b",
        "secret_group": 1,
    },
    {
        "id": "huggingface-api-token",
        "category": "KnownSecret",
        "keywords": ["hf_"],
        "regex": r"\b(hf_[a-zA-Z0-9]{34})\b",
        "secret_group": 1,
    },
    {
        "id": "telegram-bot-token",
        "category": "KnownSecret",
        "keywords": [":"],
        "regex": r"\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b",
        "secret_group": 1,
    },
    {
        "id": "datadog-api-key",
        "category": "KnownSecret",
        "keywords": ["datadog"],
        "regex": r"(?i)datadog(?:[_-]?api[_-]?key)?\s*[:=]\s*[\"\x27]?([a-f0-9]{32})[\"\x27]?",
        "secret_group": 1,
    },
    {
        "id": "shopify-access-token",
        "category": "KnownSecret",
        "keywords": ["shpat_", "shpca_", "shppa_"],
        "regex": r"\b(shp(?:at|ca|pa)_[a-fA-F0-9]{32})\b",
        "secret_group": 1,
    },
]

UNTRANSLATABLE_RULES = [
    {
        "id": "gitleaks.generic-api-key-entropy",
        "reason": "Requires Shannon entropy sliding window and custom heuristics, moved to DPG entropy stage C-07 / DT-4.",
    },
    {
        "id": "gitleaks.jwt-arbitrary-claims",
        "reason": "Uses complex lookaround expressions unsupported in linear-time RE2 / Rust regex.",
    },
]

def generate_toml():
    lines = [
        f"# Detection rules imported from gitleaks ({PINNED_GITLEAKS_VERSION})",
        f"# Upstream commit: {PINNED_GITLEAKS_COMMIT}",
        f"# Licence: MIT (see rules/THIRD_PARTY.md)",
        "",
    ]
    for r in GITLEAKS_RULES:
        lines.append("[[rules]]")
        lines.append(f'id = "gitleaks.{r["id"]}"')
        lines.append(f'category = "{r["category"]}"')
        lines.append('confidence = "High"')
        kws = ", ".join(f'"{k}"' for k in r["keywords"])
        lines.append(f"keywords = [{kws}]")
        regex_val = r["regex"]
        if "'" in regex_val:
            lines.append(f'regex = """{regex_val}"""')
        else:
            lines.append(f"regex = '{regex_val}'")
        lines.append(f'secret_group = {r["secret_group"]}')
        lines.append("")
    return "\n".join(lines)

def generate_third_party_md():
    rule_table = "\n".join(
        f"| `gitleaks.{r['id']}` | `{r['category']}` | `{', '.join(r['keywords'])}` |"
        for r in GITLEAKS_RULES
    )
    untrans_table = "\n".join(
        f"| `{u['id']}` | {u['reason']} |"
        for u in UNTRANSLATABLE_RULES
    )

    return f"""# Third-Party Rules Attribution

## 1. Gitleaks Detection Rules

- **Source Repository:** [{GITLEAKS_REPO}]({GITLEAKS_REPO})
- **Pinned Commit:** `{PINNED_GITLEAKS_COMMIT}` ({PINNED_GITLEAKS_VERSION})
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
{rule_table}

### Untranslatable Rules
Certain upstream rules from gitleaks were not imported due to regex engine compatibility (lack of lookaround in linear-time automata) or architectural differences:

| Rule ID | Reason for Exclusion |
|---|---|
{untrans_table}
"""

def main():
    toml_content = generate_toml()
    with open("rules/gitleaks.toml", "w", encoding="utf-8") as f:
        f.write(toml_content)
    print("Wrote rules/gitleaks.toml")

    md_content = generate_third_party_md()
    with open("rules/THIRD_PARTY.md", "w", encoding="utf-8") as f:
        f.write(md_content)
    print("Wrote rules/THIRD_PARTY.md")

if __name__ == "__main__":
    main()
