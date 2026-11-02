//! Placeholder scanning, restore guard, and path guard for DPG.
//!
//! This crate owns:
//! - Exact-token placeholder scanning in agent input/output payloads.
//! - Restore guard allowlist validation (`Write`, `Edit` only).
//! - Path guard canonicalization, project root boundary verification, and `.git` traversal blocking.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod path_guard;
pub mod restorer;
pub mod scan;

pub use path_guard::PathGuard;
pub use restorer::{DpgRestorer, Restore};
pub use scan::{scan_tokens, ScannedToken};

/// Returns the version of the `dpg-restore` crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_restore() {
        assert_eq!(version(), "0.0.1");
    }
}
