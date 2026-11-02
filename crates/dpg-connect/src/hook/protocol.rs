//! Hook JSON request and response data types.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

/// Raw JSON stdin received from Claude Code hook execution.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HookInput {
    /// Conversation or tool session ID.
    pub session_id: Option<String>,
    /// Working directory of Claude Code process.
    pub cwd: Option<PathBuf>,
    /// Event name: PostToolUse, PreToolUse, or UserPromptSubmit.
    pub hook_event_name: Option<String>,
    /// Invoked tool name (for tool events).
    pub tool_name: Option<String>,
    /// Raw tool input object (for PreToolUse/PostToolUse).
    pub tool_input: Option<Value>,
    /// Raw tool response object (for PostToolUse).
    pub tool_response: Option<Value>,
    /// Tool use call ID.
    pub tool_use_id: Option<String>,
    /// User prompt content (for UserPromptSubmit).
    pub prompt: Option<String>,
    /// Additional unknown fields preserved dynamically.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// PostToolUse specific output wrapper.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PostToolUseOutput {
    /// Inner payload for PostToolUse.
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: PostToolUseSpecific,
}

/// Inner payload for PostToolUse.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PostToolUseSpecific {
    /// Event name matching Claude Code hook protocol.
    #[serde(rename = "hookEventName")]
    pub hook_event_name: &'static str,
    /// Updated tool output JSON value with sensitive data masked.
    #[serde(rename = "updatedToolOutput", skip_serializing_if = "Option::is_none")]
    pub updated_tool_output: Option<Value>,
}

/// PreToolUse specific output wrapper.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PreToolUseOutput {
    /// Inner payload for PreToolUse.
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: PreToolUseSpecific,
}

/// Inner payload for PreToolUse.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PreToolUseSpecific {
    /// Event name matching Claude Code hook protocol.
    #[serde(rename = "hookEventName")]
    pub hook_event_name: &'static str,
    /// Permission decision: "allow" or "deny".
    #[serde(rename = "permissionDecision")]
    pub permission_decision: &'static str,
    /// Explanation reason for the decision.
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
    /// Full tool input object with placeholders restored where permitted.
    #[serde(rename = "updatedInput", skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<Value>,
}

/// UserPromptSubmit output wrapper.
#[derive(Debug, Clone, Serialize, Default)]
pub struct UserPromptSubmitOutput {
    /// Decision string, typically "block" when confidential content is detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<&'static str>,
    /// User-facing reason explaining why prompt was blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
