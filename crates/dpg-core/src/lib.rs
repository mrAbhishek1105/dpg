//! Core types, configuration, error taxonomy, contexts, event logging, and engine traits for DPG.
//!
//! This crate owns the foundational abstractions of DPG:
//! - Shared domain types (`Span`, `Finding`, `Category`, `Action`, `Decision`, `RuleId`).
//! - Error taxonomy (`DpgError`, `ErrorCode`).
//! - Configuration loading and validation.
//! - Request and project contexts.
//! - Metadata-only event logging.
//! - The `Engine` orchestrator and its component traits (`Detector`, `PolicyEngine`, `Protector`, `Restorer`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

/// Returns the version of the `dpg-core` crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_core() {
        assert_eq!(version(), "0.0.1");
    }
}
