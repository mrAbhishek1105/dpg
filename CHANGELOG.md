# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may break).

## [Unreleased]

### Added
- Repository foundation: governance files, CI workflows, issue and PR templates.
- Architecture, component specifications, threat model, security requirements, test strategy.
- ADR-0001 … ADR-0006.
- Public website and documentation portal (Astro Starlight) under `website/`.
- Antigravity implementation instructions and task breakdown.

- DPG V1 workspace: detection (gitleaks-derived and DPG rules, key/value, connection strings,
  entropy, Indian identifiers, custom terms and rules), policy engine with ignore list,
  placeholders and encrypted mapping store, restore guard and path guard, Claude Code hooks
  (PostToolUse, PreToolUse, UserPromptSubmit), loopback proxy for Anthropic Messages and OpenAI
  Chat Completions with streaming restoration, CLI (inspect, sanitize, ignore, forget, install,
  doctor, proxy, completions), security and integration test suites.
- Shared runtime: project identity is an HMAC of the git/`.dpg.toml` root; global and project
  configuration (tighten-only) now drive policy, terms, rules, hook deadline and proxy settings.
- Master key in the OS keychain on Windows and macOS (owner-only file elsewhere); DPG never
  creates a new key over an existing store.

### Security
- Path guard: reject `..` components lexically and fail closed when a path or the project root
  cannot be canonicalized (fixes a containment bypass through non-existent directories on Unix).
- Restorer: deny on mapping-store lookup errors; restore only `content` (Write) and
  `old_string`/`new_string` (Edit); honour `policy.placeholder_in_other_tool`.
- Mapping store: ciphertexts bound to project and placeholder (AES-GCM associated data);
  wrong key fails at open; key file created owner-only and never overwritten.
- Detector: never re-mask DPG's own placeholders; ignore documentation example keys and image
  digests.
- Proxy: streaming (SSE) responses restored incrementally without splitting UTF-8; held-back text
  flushed before block boundaries; upstream client has connect and read timeouts but no total
  timeout; content type passed through.
- Hooks: if DPG cannot initialise, PostToolUse withholds output, PreToolUse denies calls that carry
  placeholders, and UserPromptSubmit blocks.
