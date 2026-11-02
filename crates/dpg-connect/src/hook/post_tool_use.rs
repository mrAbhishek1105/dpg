//! PostToolUse hook handling and shape-preserving string leaf masking.

use dpg_core::context::RequestContext;
use dpg_core::engine::Engine;
use dpg_core::types::ProtectOutcome;
use serde_json::Value;

use crate::hook::protocol::{PostToolUseOutput, PostToolUseSpecific};

/// Replaces all string leaves in `val` with a fail-closed withheld notice.
pub fn withhold_string_leaves(val: &mut Value, code: &str) {
    match val {
        Value::String(s) => {
            *s = format!("[DPG] Output withheld: inspection failed ({code}). Run 'dpg doctor'.");
        }
        Value::Array(arr) => {
            for item in arr {
                withhold_string_leaves(item, code);
            }
        }
        Value::Object(map) => {
            for (_, v) in map {
                withhold_string_leaves(v, code);
            }
        }
        _ => {}
    }
}

/// Recursively traverses and masks sensitive strings in a JSON value.
/// Returns Ok(true) if at least one string was masked, or Err(code) on inspection failure.
fn mask_string_leaves(
    engine: &Engine,
    ctx: &RequestContext,
    val: &mut Value,
) -> Result<bool, String> {
    let mut any_masked = false;

    match val {
        Value::String(s) => match engine.protect(ctx, s) {
            Ok(ProtectOutcome::Allowed { text, report }) => {
                if report.masked > 0 {
                    *s = text;
                    any_masked = true;
                }
            }
            Ok(ProtectOutcome::Blocked { .. }) => {
                return Err("DPG-P001".to_string());
            }
            Err(e) => {
                return Err(format!("{}", e.code()));
            }
        },
        Value::Array(arr) => {
            for item in arr {
                if mask_string_leaves(engine, ctx, item)? {
                    any_masked = true;
                }
            }
        }
        Value::Object(map) => {
            for (_, v) in map {
                if mask_string_leaves(engine, ctx, v)? {
                    any_masked = true;
                }
            }
        }
        _ => {}
    }

    Ok(any_masked)
}

/// Handles a PostToolUse event by inspecting and masking `tool_response`.
pub fn handle_post_tool_use(
    engine: &Engine,
    ctx: &RequestContext,
    tool_response: Option<Value>,
) -> PostToolUseOutput {
    let mut response_val = match tool_response {
        Some(v) => v,
        None => {
            return PostToolUseOutput {
                hook_specific_output: PostToolUseSpecific {
                    hook_event_name: "PostToolUse",
                    updated_tool_output: None,
                },
            };
        }
    };

    // Panic-safe fail-closed execution (FC-02)
    let inspect_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut cloned = response_val.clone();
        match mask_string_leaves(engine, ctx, &mut cloned) {
            Ok(true) => Ok(Some(cloned)),
            Ok(false) => Ok(None),
            Err(code) => Err(code),
        }
    }));

    match inspect_result {
        Ok(Ok(Some(masked_val))) => PostToolUseOutput {
            hook_specific_output: PostToolUseSpecific {
                hook_event_name: "PostToolUse",
                updated_tool_output: Some(masked_val),
            },
        },
        Ok(Ok(None)) => {
            // Nothing was masked, allow unchanged without updatedToolOutput
            PostToolUseOutput {
                hook_specific_output: PostToolUseSpecific {
                    hook_event_name: "PostToolUse",
                    updated_tool_output: None,
                },
            }
        }
        Ok(Err(code)) => {
            // Inspection error (FC-01, FC-03)
            withhold_string_leaves(&mut response_val, &code);
            PostToolUseOutput {
                hook_specific_output: PostToolUseSpecific {
                    hook_event_name: "PostToolUse",
                    updated_tool_output: Some(response_val),
                },
            }
        }
        Err(_) => {
            // Internal panic (FC-02)
            withhold_string_leaves(&mut response_val, "DPG-Z001");
            PostToolUseOutput {
                hook_specific_output: PostToolUseSpecific {
                    hook_event_name: "PostToolUse",
                    updated_tool_output: Some(response_val),
                },
            }
        }
    }
}
