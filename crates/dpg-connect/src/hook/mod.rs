//! Claude Code hook adapters and execution dispatcher.

pub mod post_tool_use;
pub mod pre_tool_use;
pub mod protocol;
pub mod user_prompt_submit;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use dpg_core::context::{ProjectContext, ProjectId, RequestContext, SessionId};
use dpg_core::engine::Engine;
use dpg_core::error::DpgError;
use dpg_core::types::Route;
use serde_json::Value;

use self::post_tool_use::{handle_post_tool_use, withhold_string_leaves};
use self::pre_tool_use::handle_pre_tool_use;
use self::protocol::{
    HookInput, PostToolUseOutput, PostToolUseSpecific, PreToolUseOutput, PreToolUseSpecific,
    UserPromptSubmitOutput,
};
use self::user_prompt_submit::handle_user_prompt_submit;
use crate::runtime::{Runtime, RuntimeOptions};

/// What a hook invocation runs against: an engine, the resolved project, and a deadline.
pub struct HookTarget<'a> {
    /// Configured engine.
    pub engine: &'a Engine,
    /// Resolved project (canonical root + project id).
    pub project: ProjectContext,
    /// Internal deadline for this invocation.
    pub deadline: Instant,
}

/// Production entry point for `dpg hook`: resolves the project from the hook's `cwd`,
/// loads configuration and the mapping store, then dispatches the event.
pub fn run_hook_process<R: Read, W: Write>(stdin: R, stdout: W) -> i32 {
    let mut slot: Option<Runtime> = None;
    let slot_ref = &mut slot;
    run_with(stdin, stdout, move |cwd| {
        let rt = slot_ref.insert(Runtime::build(&RuntimeOptions::for_cwd(cwd))?);
        if let Some(ref e) = rt.store_error {
            eprintln!(
                "[DPG] Warning [{}]: mapping store unavailable; masking with ephemeral placeholders, restoration disabled. Run 'dpg doctor'.",
                e.code()
            );
        }
        Ok(HookTarget {
            engine: &rt.engine,
            project: rt.project.clone(),
            deadline: rt.hook_deadline(),
        })
    })
}

/// Dispatches a hook with a caller-provided engine. The project root is the
/// canonicalized `cwd` and the project id is fixed; intended for embedding and tests.
pub fn run<R: Read, W: Write>(engine: &Engine, stdin: R, stdout: W) -> i32 {
    run_with(stdin, stdout, |cwd| {
        Ok(HookTarget {
            engine,
            project: ProjectContext {
                root: dunce::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf()),
                id: ProjectId::new("embedded".to_string()),
            },
            deadline: Instant::now() + Duration::from_secs(8),
        })
    })
}

/// Reads the hook JSON from `stdin`, builds the target via `build(cwd)`, dispatches,
/// and writes the response to `stdout`. Returns the process exit code
/// (0 = response written, 2 = blocking failure with a stderr notice).
pub fn run_with<'a, R, W, F>(mut stdin: R, mut stdout: W, build: F) -> i32
where
    R: Read,
    W: Write,
    F: FnOnce(&Path) -> Result<HookTarget<'a>, DpgError>,
{
    let mut stdin_bytes = Vec::new();
    if let Err(e) = stdin.read_to_end(&mut stdin_bytes) {
        eprintln!("[DPG] Fatal: Failed to read stdin: {e}");
        return 2;
    }

    // FC-04: If stdin is not valid JSON or truncated, exit 2, stderr notice, nothing echoed
    let hook_input: HookInput = match serde_json::from_slice(&stdin_bytes) {
        Ok(input) => input,
        Err(_) => {
            eprintln!("[DPG] Fatal: hook stdin is not valid JSON (DPG-I001)");
            return 2;
        }
    };

    let event_name = hook_input
        .hook_event_name
        .clone()
        .unwrap_or_else(|| "UnknownEvent".to_string());

    let cwd = hook_input
        .cwd
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let target = match build(&cwd) {
        Ok(t) => t,
        Err(e) => return fail_closed_without_engine(&event_name, hook_input, &e, &mut stdout),
    };

    let route = match event_name.as_str() {
        "PostToolUse" => Route::HookPostToolUse,
        "PreToolUse" => Route::HookPreToolUse,
        "UserPromptSubmit" => Route::HookUserPrompt,
        _ => Route::HookPostToolUse,
    };

    let ctx = RequestContext {
        project: target.project,
        session: SessionId::new(
            hook_input
                .session_id
                .clone()
                .unwrap_or_else(|| "session-hook-default".to_string()),
        ),
        route,
        deadline: target.deadline,
    };
    let engine = target.engine;

    match event_name.as_str() {
        "PostToolUse" => {
            let output = handle_post_tool_use(engine, &ctx, hook_input.tool_response);
            // FC-12: Write output; return exit 2 if serialization fails
            write_json(&mut stdout, &output)
        }
        "PreToolUse" => {
            let output = handle_pre_tool_use(
                engine,
                &ctx,
                hook_input.tool_name.as_deref(),
                hook_input.tool_input,
            );
            write_json(&mut stdout, &output)
        }
        "UserPromptSubmit" => {
            let (output, exit_code) =
                handle_user_prompt_submit(engine, &ctx, hook_input.prompt.as_deref());
            if exit_code == 2 {
                // Exit 2 makes Claude Code ignore stdout and show stderr instead.
                if let Some(ref reason) = output.reason {
                    eprintln!("{reason}");
                }
                return 2;
            }
            write_json(&mut stdout, &output)
        }
        _ => {
            // Unknown event name: pass-through allowed but logged
            tracing::info!(event = %event_name, "Unknown hook event name, passing through");
            write_json(&mut stdout, &serde_json::json!({}))
        }
    }
}

fn write_json<W: Write, T: serde::Serialize>(stdout: &mut W, value: &T) -> i32 {
    if serde_json::to_writer(&mut *stdout, value).is_err() || stdout.flush().is_err() {
        eprintln!("[DPG] Fatal: could not write hook response (DPG-Z001)");
        return 2;
    }
    0
}

/// Fail-closed responses when the runtime itself cannot be built (bad config,
/// missing key, detector init failure). Nothing can be inspected, so:
/// * PostToolUse: every string leaf of the tool output is withheld;
/// * PreToolUse: allowed only if the input carries no placeholders (nothing to
///   restore, nothing to guard); otherwise denied;
/// * UserPromptSubmit: blocked;
/// * unknown events: passed through.
fn fail_closed_without_engine<W: Write>(
    event: &str,
    input: HookInput,
    err: &DpgError,
    stdout: &mut W,
) -> i32 {
    let code = err.code().to_string();
    eprintln!("[DPG] Error [{code}]: {err}. Run 'dpg doctor'.");
    match event {
        "PostToolUse" => {
            let updated = input.tool_response.map(|mut v| {
                withhold_string_leaves(&mut v, &code);
                v
            });
            write_json(
                stdout,
                &PostToolUseOutput {
                    hook_specific_output: PostToolUseSpecific {
                        hook_event_name: "PostToolUse",
                        updated_tool_output: updated,
                    },
                },
            )
        }
        "PreToolUse" => {
            let has_placeholders = input
                .tool_input
                .as_ref()
                .map(value_has_placeholder)
                .unwrap_or(false);
            let output = if has_placeholders {
                PreToolUseOutput {
                    hook_specific_output: PreToolUseSpecific {
                        hook_event_name: "PreToolUse",
                        permission_decision: "deny",
                        permission_decision_reason: Some(format!(
                            "[DPG] Denied ({code}): DPG is not operational and this call contains placeholders"
                        )),
                        updated_input: None,
                    },
                }
            } else {
                PreToolUseOutput {
                    hook_specific_output: PreToolUseSpecific {
                        hook_event_name: "PreToolUse",
                        permission_decision: "allow",
                        permission_decision_reason: None,
                        updated_input: None,
                    },
                }
            };
            write_json(stdout, &output)
        }
        "UserPromptSubmit" => write_json(
            stdout,
            &UserPromptSubmitOutput {
                decision: Some("block"),
                reason: Some(format!(
                    "[DPG] Prompt inspection unavailable ({code}). Run 'dpg doctor'."
                )),
            },
        ),
        _ => write_json(stdout, &serde_json::json!({})),
    }
}

fn value_has_placeholder(v: &Value) -> bool {
    match v {
        Value::String(s) => !dpg_restore::scan_tokens(s).is_empty(),
        Value::Array(a) => a.iter().any(value_has_placeholder),
        Value::Object(m) => m.values().any(value_has_placeholder),
        _ => false,
    }
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
        let project_id = ProjectId::new("embedded".to_string());

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
        assert_eq!(
            exit_code, 0,
            "Secret in prompt blocks via decision JSON (exit 0)"
        );

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
