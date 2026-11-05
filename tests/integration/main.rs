//! Cross-crate integration test suite for DPG CLI and workflows.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

/// A `dpg` command isolated from the developer's real data dir and OS keychain.
fn dpg_cmd() -> Command {
    let data = std::env::temp_dir().join(format!("dpg-it-{}", std::process::id()));
    let mut cmd = Command::cargo_bin("dpg").unwrap();
    cmd.env("DPG_DATA_DIR", &data)
        .env("DPG_STORAGE_BACKEND", "file")
        .env("DPG_CONFIG", data.join("no-global-config.toml"));
    cmd
}

#[test]
fn integration_harness_smoke_test() {
    assert_eq!(dpg_core::version(), "0.0.1");
}

#[test]
fn test_cli_inspect_no_leak_and_json() {
    let mut rng = dpg_testgen::create_rng(12345);
    let secret = dpg_testgen::gen_openai_token(&mut rng);

    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("secret.txt");
    fs::write(&file_path, format!("MY_KEY={}\n", secret)).unwrap();

    // 1. Default inspect: Must NEVER leak raw secret value
    let mut cmd = dpg_cmd();
    let assert = cmd.arg("inspect").arg(&file_path).assert().success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(
        !stdout.contains(&secret),
        "CF-03: Default dpg inspect must not print raw secrets in stdout"
    );
    assert!(
        !stderr.contains(&secret),
        "CF-03: Default dpg inspect must not print raw secrets in stderr"
    );
    assert!(stdout.contains("DPG Inspect - Found"));

    // 2. Inspect with --json: structured findings with redacted preview
    let mut cmd_json = dpg_cmd();
    let assert_json = cmd_json
        .arg("inspect")
        .arg(&file_path)
        .arg("--json")
        .assert()
        .success();

    let json_str = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    assert!(
        !json_str.contains(&secret),
        "Inspect --json must not contain raw secret value"
    );
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);

    // 3. Inspect with --show-values: emits warning to stderr and unredacted in stdout
    let mut cmd_show = dpg_cmd();
    let assert_show = cmd_show
        .arg("inspect")
        .arg(&file_path)
        .arg("--show-values")
        .assert()
        .success();

    let stdout_show = String::from_utf8(assert_show.get_output().stdout.clone()).unwrap();
    let stderr_show = String::from_utf8(assert_show.get_output().stderr.clone()).unwrap();

    assert!(
        stderr_show.contains("[DPG WARNING] --show-values specified"),
        "Must warn on stderr when --show-values is used"
    );
    assert!(
        stdout_show.contains(&secret),
        "With --show-values, secret is displayed"
    );
}

#[test]
fn test_cli_sanitize_replaces_secret() {
    let mut rng = dpg_testgen::create_rng(54321);
    let secret = dpg_testgen::gen_openai_token(&mut rng);

    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("config.env");
    fs::write(&file_path, format!("API_TOKEN={}\n", secret)).unwrap();

    let mut cmd = dpg_cmd();
    let assert = cmd
        .arg("sanitize")
        .arg(&file_path)
        .arg("--exit-code")
        .assert()
        .code(1); // Exit code 1 when sensitive content masked

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains(&secret),
        "dpg sanitize must replace secret with placeholder"
    );
    assert!(
        stdout.contains("API_TOKEN=DPG_"),
        "dpg sanitize must output Crockford placeholder prefix"
    );
}

#[test]
fn test_cli_doctor_runs_cleanly() {
    let mut cmd = dpg_cmd();
    let assert = cmd.arg("doctor").assert();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("DPG Doctor System Health Check:"),
        "dpg doctor must output health check header"
    );
}

#[test]
fn test_cli_completions_generation() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let mut cmd = dpg_cmd();
        cmd.arg("completions").arg(shell).assert().success();
    }
}

#[test]
fn test_cli_install_claude_code_dry_run() {
    let mut cmd = dpg_cmd();
    cmd.arg("install")
        .arg("claude-code")
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("DPG: dry-run"));
}

/// End-to-end through the real binary: PostToolUse masks in one process, a later
/// PreToolUse (separate process) restores the exact value for a Write inside the
/// project, and denies the same Write outside the project.
#[test]
fn test_e2e_hook_mask_then_restore_across_processes() {
    let mut rng = dpg_testgen::create_rng(777);
    let secret = dpg_testgen::gen_aws_access_key(&mut rng);
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    fs::create_dir_all(proj.join(".git")).unwrap();
    let data = tmp.path().join("data");
    let run = |input: serde_json::Value| -> serde_json::Value {
        let out = Command::cargo_bin("dpg")
            .unwrap()
            .env("DPG_DATA_DIR", &data)
            .env("DPG_STORAGE_BACKEND", "file")
            .env("DPG_CONFIG", data.join("none.toml"))
            .arg("hook")
            .write_stdin(serde_json::to_vec(&input).unwrap())
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice(&out).unwrap()
    };

    let post = run(serde_json::json!({
        "session_id": "s", "cwd": proj, "hook_event_name": "PostToolUse",
        "tool_name": "Bash", "tool_input": {"command": "cat .env"},
        "tool_response": {"stdout": format!("AWS_ACCESS_KEY_ID={secret}\n"), "stderr": "", "interrupted": false, "isImage": false}
    }));
    let masked = post["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !masked.contains(&secret),
        "original must not reach the model"
    );
    assert!(masked.contains("DPG_"), "placeholder present: {masked}");
    assert_eq!(
        post["hookSpecificOutput"]["updatedToolOutput"]["interrupted"],
        false
    );

    let pre = run(serde_json::json!({
        "session_id": "s", "cwd": proj, "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": proj.join(".env"), "content": masked}
    }));
    assert_eq!(pre["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        pre["hookSpecificOutput"]["updatedInput"]["content"],
        format!("AWS_ACCESS_KEY_ID={secret}\n")
    );

    let outside = tmp.path().join("outside.env");
    let pre_out = run(serde_json::json!({
        "session_id": "s", "cwd": proj, "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": outside, "content": masked}
    }));
    assert_eq!(pre_out["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(!outside.exists());
}

/// A broken project config must not open a hole: PostToolUse withholds output.
#[test]
fn test_e2e_hook_invalid_config_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    fs::create_dir_all(proj.join(".git")).unwrap();
    fs::write(proj.join(".dpg.toml"), "this is = = not toml").unwrap();
    let data = tmp.path().join("data");
    let input = serde_json::json!({
        "session_id": "s", "cwd": proj, "hook_event_name": "PostToolUse",
        "tool_name": "Bash", "tool_input": {"command": "env"},
        "tool_response": {"stdout": "anything at all", "stderr": "", "interrupted": false, "isImage": false}
    });
    let out = Command::cargo_bin("dpg")
        .unwrap()
        .env("DPG_DATA_DIR", &data)
        .env("DPG_STORAGE_BACKEND", "file")
        .env("DPG_CONFIG", data.join("none.toml"))
        .arg("hook")
        .write_stdin(serde_json::to_vec(&input).unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let stdout = v["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap();
    assert!(stdout.contains("withheld"), "{stdout}");
    assert!(stdout.contains("DPG-C001"), "{stdout}");
}
