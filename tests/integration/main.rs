//! Cross-crate integration test suite for DPG.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn integration_harness_smoke_test() {
    assert_eq!(dpg_core::version(), "0.0.1");
}
