//! Placeholder generation, mapping store, key management, and forget operations for DPG.
//!
//! This crate owns:
//! - Deterministic placeholder generation and formatting (`DPG_SECRET_<BODY>`).
//! - Encrypted SQLite/SQLCipher persistent mapping store.
//! - OS keychain key provider integration.
//! - Mapping retention, expiration, and project/global forget operations.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

/// Returns the version of the `dpg-protect` crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_protect() {
        assert_eq!(version(), "0.0.1");
    }
}
