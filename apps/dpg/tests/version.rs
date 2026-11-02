//! CLI version tests for `dpg`.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_dpg_version_output() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("dpg")?;
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("dpg 0.0.1"));
    Ok(())
}
