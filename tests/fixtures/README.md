# Test fixtures

**Never commit real or realistic-looking secrets here.** Secrets for tests are generated at test time
by the `dpg-testgen` crate (task A-06) from a seed, and written to temporary directories.

Allowed in this directory:
- Recorded Claude Code hook payloads (`claude-code/<version>/`) from spike S0-1, with fake values only and personal paths redacted.
- Generator configuration and negative-source lists (`negative_sources.toml`).
