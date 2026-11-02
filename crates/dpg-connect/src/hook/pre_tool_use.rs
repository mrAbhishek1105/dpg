//! PreToolUse hook handling and restore guard enforcement.

use std::path::PathBuf;

use dpg_core::context::RequestContext;
use dpg_core::engine::{Engine, RestoreRequest};
use serde_json::Value;

use crate::hook::protocol::{PreToolUseOutput, PreToolUseSpecific};

/// Handles a PreToolUse event, enforcing restore guards and returning updatedInput.
pub fn handle_pre_tool_use(
    engine: &Engine,
    ctx: &RequestContext,
    tool_name: Option<&str>,
    tool_input: Option<Value>,
) -> PreToolUseOutput {
    let input_val = match tool_input {
        Some(v) => v,
        None => {
            return PreToolUseOutput {
                hook_specific_output: PreToolUseSpecific {
                    hook_event_name: "PreToolUse",
                    permission_decision: "allow",
                    permission_decision_reason: None,
                    updated_input: None,
                },
            };
        }
    };

    let name = tool_name.unwrap_or("Unknown");

    // Panic-safe fail-closed execution
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        process_pre_tool_use(engine, ctx, name, &input_val)
    }));

    match result {
        Ok(output) => output,
        Err(_) => PreToolUseOutput {
            hook_specific_output: PreToolUseSpecific {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: Some(
                    "[DPG] Denied (DPG-Z001): Internal error during PreToolUse evaluation"
                        .to_string(),
                ),
                updated_input: Some(input_val),
            },
        },
    }
}

fn process_pre_tool_use(
    engine: &Engine,
    ctx: &RequestContext,
    tool_name: &str,
    input_val: &Value,
) -> PreToolUseOutput {
    let is_write_or_edit =
        tool_name.eq_ignore_ascii_case("Write") || tool_name.eq_ignore_ascii_case("Edit");

    // Check FC-06: For Write/Edit, file_path must be a valid string if present
    if is_write_or_edit {
        if let Some(file_val) = input_val.get("file_path") {
            if !file_val.is_string() {
                return PreToolUseOutput {
                    hook_specific_output: PreToolUseSpecific {
                        hook_event_name: "PreToolUse",
                        permission_decision: "deny",
                        permission_decision_reason: Some(
                            "[DPG] Denied (DPG-V004): file_path must be a string".to_string(),
                        ),
                        updated_input: Some(input_val.clone()),
                    },
                };
            }
        }
    }

    // Extract target path and string fields
    let target_path = input_val
        .get("file_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let mut fields = Vec::new();
    if let Some(obj) = input_val.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                fields.push((k.clone(), s.to_string()));
            }
        }
    }

    let req = RestoreRequest {
        tool_name: tool_name.to_string(),
        target_path,
        fields,
    };

    match engine.restore(ctx, req) {
        Ok(outcome) => {
            if !outcome.allowed {
                let reason = outcome
                    .report
                    .blocked
                    .first()
                    .map(|b| b.reason.to_string())
                    .unwrap_or_else(|| "Restoration disallowed by path guard".to_string());

                PreToolUseOutput {
                    hook_specific_output: PreToolUseSpecific {
                        hook_event_name: "PreToolUse",
                        permission_decision: "deny",
                        permission_decision_reason: Some(format!("[DPG] Denied: {reason}")),
                        updated_input: Some(input_val.clone()),
                    },
                }
            } else if outcome.report.masked > 0 {
                // Values were restored, update input_val with restored values
                let mut updated = input_val.clone();
                if let Some(obj) = updated.as_object_mut() {
                    for (k, v) in outcome.updated_fields {
                        obj.insert(k, Value::String(v));
                    }
                }

                PreToolUseOutput {
                    hook_specific_output: PreToolUseSpecific {
                        hook_event_name: "PreToolUse",
                        permission_decision: "allow",
                        permission_decision_reason: Some(format!(
                            "[DPG] Restored {} confidential placeholder(s)",
                            outcome.report.masked
                        )),
                        updated_input: Some(updated),
                    },
                }
            } else {
                // Allowed without changes
                PreToolUseOutput {
                    hook_specific_output: PreToolUseSpecific {
                        hook_event_name: "PreToolUse",
                        permission_decision: "allow",
                        permission_decision_reason: None,
                        updated_input: None,
                    },
                }
            }
        }
        Err(e) => {
            // Error during restore (e.g. FC-05: R001)
            PreToolUseOutput {
                hook_specific_output: PreToolUseSpecific {
                    hook_event_name: "PreToolUse",
                    permission_decision: "deny",
                    permission_decision_reason: Some(format!("[DPG] Denied ({}): {}", e.code(), e)),
                    updated_input: Some(input_val.clone()),
                },
            }
        }
    }
}
