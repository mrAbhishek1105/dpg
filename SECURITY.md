# Security Policy

DPG is security software. We take reports seriously and we are honest about limits.

## Supported versions

DPG has not been released. Once releases exist, only the latest minor release receives security fixes.

| Version | Supported |
|---|---|
| unreleased (`main`) | Best effort |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). If the button is not visible yet, the maintainer
has not enabled it; please wait rather than filing a public issue.

Please include:

- Affected component (Detect, Policy, Protect, Restore, Connect/hook, Connect/proxy, CLI, installer).
- DPG version or commit, OS, and the agent/tool version involved.
- Reproduction steps using **synthetic** secrets only.
- Impact: what original value could leave the machine, or what could be written where.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 5 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan | agreed with the reporter |
| Public advisory | after a fix is released, with credit if wanted |

These are targets for a small volunteer-run project, not contractual SLAs.

## In scope

- An original value reaching an outbound request in a case DPG documents as covered.
- A restore outside the approved project, or into a shell command, URL, network or MCP call.
- Fail-open behaviour on a protected path (timeout, crash, malformed input).
- Local proxy reachable by a web page (DNS rebinding, CSRF), or usable as an open proxy.
- Mapping values readable without the keychain key, or written to logs.

## Out of scope

Behaviour documented as unprotected on the website's *Security & privacy* page
(for example typed prompts through hooks, `@` mentions while unverified, malware running as the same user).
Detector misses of unknown secret formats are welcome as normal issues with synthetic examples.
