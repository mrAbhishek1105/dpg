//! Non-streaming response placeholder restoration for proxy endpoints.
//!
//! Defined per `docs/components/CONNECT.md` §11 and `docs/testing/SECURITY_TEST_CASES.md` (PX-10).

use dpg_core::context::ProjectId;
use dpg_protect::store::MappingStore;
use dpg_restore::scan_tokens;
use serde_json::Value;

/// Restores placeholder tokens in non-streaming model responses (Anthropic and OpenAI).
/// Restores text blocks and message content ONLY. Never restores tool call arguments (PX-10).
pub fn restore_response_body(store: &MappingStore, project_id: &ProjectId, val: &mut Value) -> u32 {
    let mut restored_count = 0;

    // 1. Anthropic shape: content array containing {"type": "text", "text": "..."}
    if let Some(content_arr) = val.get_mut("content").and_then(|c| c.as_array_mut()) {
        for block in content_arr {
            let is_text_block = block
                .get("type")
                .and_then(|t| t.as_str())
                .map(|t| t == "text")
                .unwrap_or(false);

            if is_text_block {
                if let Some(text_val) = block.get_mut("text") {
                    if let Some(s) = text_val.as_str() {
                        let (restored, count) = restore_text_placeholders(store, project_id, s);
                        if count > 0 {
                            *text_val = Value::String(restored);
                            restored_count += count;
                        }
                    }
                }
            }
        }
    }

    // 2. OpenAI shape: choices array containing {"message": {"content": "..."}}
    if let Some(choices_arr) = val.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices_arr {
            if let Some(content_val) = choice.get_mut("message").and_then(|m| m.get_mut("content"))
            {
                if let Some(s) = content_val.as_str() {
                    let (restored, count) = restore_text_placeholders(store, project_id, s);
                    if count > 0 {
                        *content_val = Value::String(restored);
                        restored_count += count;
                    }
                }
            }
        }
    }

    restored_count
}

/// Replaces all known placeholder tokens in `text` with their real secrets from `store`.
pub fn restore_text_placeholders(
    store: &MappingStore,
    project_id: &ProjectId,
    text: &str,
) -> (String, u32) {
    let tokens = scan_tokens(text);
    if tokens.is_empty() {
        return (text.to_string(), 0);
    }

    let mut replacements = Vec::new();
    let mut count = 0;

    for scanned in tokens {
        if let Ok(Some(secret)) = store.lookup(project_id, scanned.token) {
            replacements.push((scanned.span, secret));
            count += 1;
        }
    }

    if replacements.is_empty() {
        return (text.to_string(), 0);
    }

    // Sort descending by start offset
    replacements.sort_by_key(|a| std::cmp::Reverse(a.0.start));

    let mut restored = text.to_string();
    let mut last_start = usize::MAX;

    for (span, secret) in replacements {
        if span.end > last_start {
            continue;
        }
        if span.end <= restored.len()
            && restored.is_char_boundary(span.start)
            && restored.is_char_boundary(span.end)
        {
            restored.replace_range(span.start..span.end, &secret);
            last_start = span.start;
        }
    }

    (restored, count)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use dpg_protect::key::FixedKeyProvider;
    use dpg_protect::PlaceholderCat;
    use serde_json::json;

    #[test]
    fn test_sr_px_10_restore_text_content_only_never_tool_arguments() {
        let keys = FixedKeyProvider::new([55u8; 32]);
        let store = MappingStore::in_memory(&keys).expect("store init");
        let project_id = ProjectId::new("proj-restore".to_string());

        let secret = "super_secret_value_123";
        let ph = store
            .get_or_create(&project_id, secret, PlaceholderCat::Secret)
            .expect("insert mapping");

        // Anthropic response with text block and tool_use block
        let mut response = json!({
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": format!("Here is your token: {ph}")
                },
                {
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "write_file",
                    "input": {
                        "path": "/etc/secrets.txt",
                        "content": format!("WRITE_KEY={ph}")
                    }
                }
            ]
        });

        let restored_count = restore_response_body(&store, &project_id, &mut response);
        assert_eq!(restored_count, 1);

        // Verify text block WAS restored
        let text_block = response["content"][0]["text"].as_str().unwrap();
        assert_eq!(text_block, format!("Here is your token: {secret}"));

        // Verify tool_use input was NEVER restored (PX-10)
        let tool_input = response["content"][1]["input"]["content"].as_str().unwrap();
        assert_eq!(
            tool_input,
            format!("WRITE_KEY={ph}"),
            "PX-10: Tool use arguments must NEVER be restored by proxy"
        );
    }
}
