//! Policy engine, action resolution, explanations, and ignore list evaluation for DPG.
//!
//! This crate owns:
//! - Mapping findings and active configuration to security actions (`Allow`, `Warn`, `Mask`, `Block`).
//! - Severity and conflict resolution across multiple decisions.
//! - Generating developer-facing explanations for blocked or warned items.
//! - Ignore list checks (HMAC-based suppression of known false positives).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod engine;
pub mod explain;
pub mod ignore;

pub use engine::{action_config_to_action, DpgPolicy};
pub use explain::{explain, format_reason, PolicySource};
pub use ignore::{compute_fingerprint, Fingerprint, IgnoreList, InMemoryIgnoreList};

/// Returns the version of the `dpg-policy` crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_policy() {
        assert_eq!(version(), "0.0.1");
    }
}
