//! Detection rules, compilation, scanning, validators, and entropy calculation for DPG.
//!
//! This crate owns:
//! - Rule definitions (built-in TOML rule sets and custom user rules).
//! - Multi-pattern scanning using regex and Aho-Corasick prefilters.
//! - Checksum validators (Verhoeff for Aadhaar, PAN format checks, GSTIN checksums).
//! - Shannon entropy analysis for high-entropy secret detection.
//! - Overlap and priority resolution between candidate findings.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod prefilter;
pub mod rules;
pub mod ruleset;

pub use prefilter::Prefilter;
pub use rules::{load_rules_toml, parse_category, Rule, RuleDef, RuleFile, RuleSource, Validator};
pub use ruleset::RuleSet;

/// Returns the version of the `dpg-detect` crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_detect() {
        assert_eq!(version(), "0.0.1");
    }
}
