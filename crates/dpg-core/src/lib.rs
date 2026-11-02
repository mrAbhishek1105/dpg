//! Core types, configuration, error taxonomy, contexts, event logging, and engine traits for DPG.
//!
//! This crate owns the foundational abstractions of DPG:
//! - Shared domain types (`Span`, `Finding`, `Category`, `Action`, `Decision`, `RuleId`, `Route`, `Report`, `ProtectOutcome`).
//! - Error taxonomy (`DpgError`, `ErrorCode`, `SafeDetail`).
//! - Configuration loading and validation (`Config`, `load_config`, `ConfigWarning`).
//! - Request and project contexts.
//! - Metadata-only event logging (`Event`, `EventLog`, `init_logging`).
//! - The `Engine` orchestrator and its component traits (`Detector`, `PolicyEngine`, `Protector`, `Restorer`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
pub mod error;
pub mod event;
pub mod logging;
pub mod types;

pub use config::{load_config, Config, ConfigWarning, LoadOptions};
pub use error::{DpgError, ErrorCode, SafeDetail};
pub use event::{hash_identifier, hash_path, Event, EventLog};
pub use logging::init_logging;
pub use types::{
    Action, BlockItem, Category, Confidence, Decision, Finding, PartKind, ProtectOutcome, Report,
    Route, RuleId, Span, WarnItem,
};

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
