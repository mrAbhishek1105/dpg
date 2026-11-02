//! Security test suite for DPG requirements (SECURITY_TEST_CASES.md).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn security_harness_smoke_test() {
    assert_eq!(dpg_core::version(), "0.0.1");
}
