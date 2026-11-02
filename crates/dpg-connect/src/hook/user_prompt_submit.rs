//! UserPromptSubmit hook handling.

use dpg_core::context::RequestContext;
use dpg_core::engine::Engine;
use dpg_core::types::ProtectOutcome;

use crate::hook::protocol::UserPromptSubmitOutput;

/// Handles a UserPromptSubmit event, detecting secrets and blocking if found.
/// Returns (UserPromptSubmitOutput, exit_code).
pub fn handle_user_prompt_submit(
    engine: &Engine,
    ctx: &RequestContext,
    prompt: Option<&str>,
) -> (UserPromptSubmitOutput, i32) {
    let prompt_text = match prompt {
        Some(p) if !p.is_empty() => p,
        _ => return (UserPromptSubmitOutput::default(), 0),
    };

    // Panic-safe fail-closed execution (FC-07)
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        engine.protect(ctx, prompt_text)
    }));

    match result {
        Ok(Ok(ProtectOutcome::Blocked { report })) => {
            let reason = report
                .blocked
                .first()
                .map(|b| b.reason.to_string())
                .unwrap_or_else(|| "Rule violation".to_string());

            (
                UserPromptSubmitOutput {
                    decision: Some("block"),
                    reason: Some(format!(
                        "[DPG] Confidential secret detected in prompt: {reason}. Please use the local proxy or remove the secret before proceeding."
                    )),
                },
                2,
            )
        }
        Ok(Ok(ProtectOutcome::Allowed { report, .. })) => {
            if report.masked > 0 {
                // In prompt route, masked secrets should be blocked
                (
                    UserPromptSubmitOutput {
                        decision: Some("block"),
                        reason: Some(
                            "[DPG] Confidential secret detected in prompt. Please use the local proxy or remove the secret before proceeding."
                                .to_string(),
                        ),
                    },
                    2,
                )
            } else {
                // Allowed, no secrets found
                (UserPromptSubmitOutput::default(), 0)
            }
        }
        Ok(Err(e)) => {
            // Detector error (FC-07) -> block
            (
                UserPromptSubmitOutput {
                    decision: Some("block"),
                    reason: Some(format!(
                        "[DPG] Prompt inspection failed ({}). Blocking prompt submission for safety.",
                        e.code()
                    )),
                },
                2,
            )
        }
        Err(_) => {
            // Panic during prompt inspection (FC-07) -> block
            (
                UserPromptSubmitOutput {
                    decision: Some("block"),
                    reason: Some(
                        "[DPG] Prompt inspection failed (DPG-Z001). Blocking prompt submission for safety."
                            .to_string(),
                    ),
                },
                2,
            )
        }
    }
}
