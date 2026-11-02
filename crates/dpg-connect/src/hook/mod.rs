//! Claude Code hook adapters and execution dispatcher.

pub mod post_tool_use;
pub mod pre_tool_use;
pub mod protocol;
pub mod user_prompt_submit;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use dpg_core::context::{ProjectContext, ProjectId, RequestContext, SessionId};
use dpg_core::engine::Engine;
use dpg_core::types::Route;

use self::post_tool_use::handle_post_tool_use;
use self::pre_tool_use::handle_pre_tool_use;
use self::protocol::HookInput;
use self::user_prompt_submit::handle_user_prompt_submit;

/// Dispatches Claude Code hook JSON execution over reader/writer streams.
/// Returns the process exit code (0 for success / permitted, 2 for blocked / fatal error).
pub fn run<R: Read, W: Write>(engine: &Engine, mut stdin: R, mut stdout: W) -> i32 {
    let mut stdin_bytes = Vec::new();
    if let Err(e) = stdin.read_to_end(&mut stdin_bytes) {
        eprintln!("[DPG] Fatal: Failed to read stdin: {e}");
        return 2;
    }

    // FC-04: If stdin is not valid JSON or truncated, exit 2, stderr notice, nothing echoed
    let hook_input: HookInput = match serde_json::from_slice(&stdin_bytes) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("[DPG] Fatal: Stdin payload is not valid JSON: {e}");
            return 2;
        }
    };

    let event_name = hook_input
        .hook_event_name
        .as_deref()
        .unwrap_or("UnknownEvent");

    let cwd = hook_input
        .cwd
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Derive or canonicalize project root from cwd
    let project_root = dunce::canonicalize(&cwd).unwrap_or(cwd);
    let project_id_str = format!("{:x}", md5_or_simple_hash(&project_root));

    let session = hook_input
        .session_id
        .unwrap_or_else(|| "session-hook-default".to_string());

    let route = match event_name {
        "PostToolUse" => Route::HookPostToolUse,
        "PreToolUse" => Route::HookPreToolUse,
        "UserPromptSubmit" => Route::HookUserPrompt,
        _ => Route::HookPostToolUse,
    };

    // Internal deadline (default 8s within a 10s Claude Code hook timeout)
    let deadline = Instant::now() + Duration::from_secs(8);

    let ctx = RequestContext {
        project: ProjectContext {
            root: project_root,
            id: ProjectId::new(project_id_str),
        },
        session: SessionId::new(session),
        route,
        deadline,
    };

    match event_name {
        "PostToolUse" => {
            let output = handle_post_tool_use(engine, &ctx, hook_input.tool_response);
            // FC-12: Write output; return exit 2 if serialization fails
            if serde_json::to_writer(&mut stdout, &output).is_err() {
                return 2;
            }
            0
        }
        "PreToolUse" => {
            let output = handle_pre_tool_use(
                engine,
                &ctx,
                hook_input.tool_name.as_deref(),
                hook_input.tool_input,
            );
            if serde_json::to_writer(&mut stdout, &output).is_err() {
                return 2;
            }
            0
        }
        "UserPromptSubmit" => {
            let (output, exit_code) =
                handle_user_prompt_submit(engine, &ctx, hook_input.prompt.as_deref());
            if serde_json::to_writer(&mut stdout, &output).is_err() {
                return 2;
            }
            exit_code
        }
        _ => {
            // Unknown event name: pass-through allowed but logged
            tracing::info!(event = %event_name, "Unknown hook event name, passing through");
            let empty = serde_json::json!({});
            if serde_json::to_writer(&mut stdout, &empty).is_err() {
                return 2;
            }
            0
        }
    }
}

fn md5_or_simple_hash(path: &std::path::Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::sync::Arc;

    use dpg_core::config::Config;
    use dpg_detect::DpgDetector;
    use dpg_policy::DpgPolicy;
    use dpg_protect::key::FixedKeyProvider;
    use dpg_protect::store::MappingStore;
    use dpg_protect::DpgProtector;
    use dpg_restore::DpgRestorer;
    use serde_json::json;

    fn setup_test_engine() -> (Engine, Arc<MappingStore>) {
        let detector = Arc::new(DpgDetector::new().expect("detector"));
        let policy = Arc::new(DpgPolicy::default_policy());
        let keys = FixedKeyProvider::new([99u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store"));
        let protector = Arc::new(DpgProtector::with_store(store.clone()));
        let restorer = Arc::new(DpgRestorer::with_store(store.clone()));
        let config = Arc::new(Config::default());

        let engine = Engine::new(detector, policy, protector, restorer, config, None);
        (engine, store)
    }

    #[test]
    fn test_sr_fc_04_stdin_not_json_exits_2_and_no_echo() {
        let (engine, _) = setup_test_engine();
        let invalid_stdin = b"This is not JSON at all! {";
        let mut stdout = Vec::new();

        let exit_code = run(&engine, &invalid_stdin[..], &mut stdout);

        assert_eq!(exit_code, 2, "FC-04: Non-JSON stdin must exit with code 2");
        assert!(
            stdout.is_empty(),
            "FC-04: Nothing should be echoed to stdout on JSON parse failure"
        );
    }

    #[test]
    fn test_post_tool_use_masks_sensitive_strings_and_preserves_shape() {
        let (engine, _) = setup_test_engine();
        let mut rng = dpg_testgen::create_rng(12345);
        let aws_key = dpg_testgen::gen_aws_access_key(&mut rng);

        let input = json!({
            "session_id": "test-session",
            "cwd": std::env::current_dir().unwrap(),
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {
                "stdout": format!("Found key in environment: {aws_key}\nDone."),
                "stderr": "",
                "exit_code": 0,
                "nested": {
                    "count": 42,
                    "items": ["safe_string", format!("API_SECRET={aws_key}")]
                }
            }
        });

        let stdin_bytes = serde_json::to_vec(&input).unwrap();
        let mut stdout = Vec::new();

        let exit_code = run(&engine, &stdin_bytes[..], &mut stdout);
        assert_eq!(exit_code, 0);

        let output: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        let updated = &output["hookSpecificOutput"]["updatedToolOutput"];
        assert!(updated.is_object());

        // Verify shape is preserved
        assert_eq!(updated["exit_code"], 0);
        assert_eq!(updated["nested"]["count"], 42);

        // Verify AWS key is completely masked in both places
        let stdout_str = updated["stdout"].as_str().unwrap();
        assert!(!stdout_str.contains(&aws_key));
        assert!(stdout_str.contains("DPG_SECRET_"));

        let item_str = updated["nested"]["items"][1].as_str().unwrap();
        assert!(!item_str.contains(&aws_key));
        assert!(item_str.contains("DPG_SECRET_"));
    }

    #[test]
    fn test_sr_fc_01_and_fc_02_withheld_output_on_failure() {
        // Build an engine with a detector that always fails
        struct FailingDetector;
        impl dpg_core::engine::Detector for FailingDetector {
            fn scan(
                &self,
                _text: &str,
                _ctx: &RequestContext,
            ) -> Result<Vec<dpg_core::types::Finding>, dpg_core::error::DpgError> {
                Err(dpg_core::error::DpgError::Detection {
                    code: dpg_core::error::ErrorCode::D001,
                    detail: dpg_core::error::SafeDetail::from_static("Simulated detector fault"),
                })
            }
        }

        let detector = Arc::new(FailingDetector);
        let policy = Arc::new(DpgPolicy::default_policy());
        let protector = Arc::new(DpgProtector::ephemeral());
        let restorer = Arc::new(DpgRestorer::new(None));
        let config = Arc::new(Config::default());
        let engine = Engine::new(detector, policy, protector, restorer, config, None);

        let input = json!({
            "session_id": "test-session",
            "cwd": std::env::current_dir().unwrap(),
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "secret information here",
                "stderr": "error output",
                "exit_code": 1
            }
        });

        let stdin_bytes = serde_json::to_vec(&input).unwrap();
        let mut stdout = Vec::new();

        let exit_code = run(&engine, &stdin_bytes[..], &mut stdout);
        assert_eq!(exit_code, 0);

        let output: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        let updated = &output["hookSpecificOutput"]["updatedToolOutput"];

        // All strings must be replaced by the withheld notice (FC-01)
        assert!(updated["stdout"]
            .as_str()
            .unwrap()
            .contains("[DPG] Output withheld: inspection failed (DPG-D001)"));
        assert!(updated["stderr"]
            .as_str()
            .unwrap()
            .contains("[DPG] Output withheld: inspection failed (DPG-D001)"));
        assert_eq!(updated["exit_code"], 1);
    }

    #[test]
    fn test_pre_tool_use_restores_write_and_edit() {
        let (engine, store) = setup_test_engine();
        let temp = tempfile::tempdir().unwrap();
        let project_id = ProjectId::new(format!("{:x}", md5_or_simple_hash(temp.path())));

        let secret = "super_classified_secret_key_999";
        let ph = store
            .get_or_create(&project_id, secret, dpg_protect::PlaceholderCat::Secret)
            .unwrap();

        let target_file = temp.path().join("out.txt");
        let input = json!({
            "session_id": "test-session",
            "cwd": temp.path(),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": target_file.to_string_lossy(),
                "content": format!("MY_KEY={ph}\n")
            }
        });

        let stdin_bytes = serde_json::to_vec(&input).unwrap();
        let mut stdout = Vec::new();

        let exit_code = run(&engine, &stdin_bytes[..], &mut stdout);
        assert_eq!(exit_code, 0);

        let output: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        let hook_output = &output["hookSpecificOutput"];
        assert_eq!(hook_output["permissionDecision"], "allow");

        let updated_input = &hook_output["updatedInput"];
        let content = updated_input["content"].as_str().unwrap();
        assert_eq!(content, format!("MY_KEY={secret}\n"));
    }

    #[test]
    fn test_sr_fc_06_pre_tool_use_malformed_file_path_denied() {
        let (engine, _) = setup_test_engine();

        // file_path is an array instead of a string
        let input = json!({
            "session_id": "test-session",
            "cwd": std::env::current_dir().unwrap(),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": ["invalid", "path"],
                "content": "some text"
            }
        });

        let stdin_bytes = serde_json::to_vec(&input).unwrap();
        let mut stdout = Vec::new();

        let exit_code = run(&engine, &stdin_bytes[..], &mut stdout);
        assert_eq!(exit_code, 0);

        let output: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        let hook_output = &output["hookSpecificOutput"];
        assert_eq!(hook_output["permissionDecision"], "deny");
        assert!(hook_output["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("DPG-V004"));
    }

    #[test]
    fn test_user_prompt_submit_blocks_known_secrets() {
        let (engine, _) = setup_test_engine();
        let mut rng = dpg_testgen::create_rng(54321);
        let aws_key = dpg_testgen::gen_aws_access_key(&mut rng);

        let input = json!({
            "session_id": "test-session",
            "cwd": std::env::current_dir().unwrap(),
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("Please analyze this AWS key: {aws_key}")
        });

        let stdin_bytes = serde_json::to_vec(&input).unwrap();
        let mut stdout = Vec::new();

        let exit_code = run(&engine, &stdin_bytes[..], &mut stdout);
        assert_eq!(exit_code, 2, "Secret in prompt must cause exit code 2");

        let output: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(output["decision"], "block");
        assert!(output["reason"]
            .as_str()
            .unwrap()
            .contains("Confidential secret detected in prompt"));
    }

    #[test]
    fn test_sr_fc_12_output_serialization_failure_exits_2() {
        let (engine, _) = setup_test_engine();
        let input = json!({
            "session_id": "test-session",
            "cwd": std::env::current_dir().unwrap(),
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": { "stdout": "clean text" }
        });

        let stdin_bytes = serde_json::to_vec(&input).unwrap();

        // Writer that immediately fails on write
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken pipe",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let exit_code = run(&engine, &stdin_bytes[..], FailingWriter);
        assert_eq!(
            exit_code, 2,
            "FC-12: Write serialization failure must exit 2"
        );
    }
}
