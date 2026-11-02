//! Request body confidential data masking for proxy endpoints.
//!
//! Defined per `docs/components/CONNECT.md` §11 and `docs/testing/SECURITY_TEST_CASES.md` (PX-08, FC-08, FC-09).

use axum::http::StatusCode;
use dpg_core::context::RequestContext;
use dpg_core::engine::Engine;
use dpg_core::types::ProtectOutcome;
use serde_json::Value;

/// Structural keys in Anthropic and OpenAI schemas that define protocol semantics
/// and must never be masked.
pub const STRUCTURAL_KEYS: &[&str] = &[
    "model",
    "role",
    "type",
    "id",
    "tool_use_id",
    "name",
    "anthropic_version",
    "finish_reason",
    "stop_reason",
];

/// Checks if a JSON object key is structural.
pub fn is_structural_key(key: &str) -> bool {
    STRUCTURAL_KEYS.contains(&key)
}

/// Recursively inspects and masks sensitive string values in a request body,
/// skipping structural protocol keys.
pub fn mask_request_body(
    engine: &Engine,
    ctx: &RequestContext,
    val: &mut Value,
) -> Result<u32, StatusCode> {
    let mut masked_count = 0;
    walk_and_mask(engine, ctx, val, None, &mut masked_count)?;
    Ok(masked_count)
}

fn walk_and_mask(
    engine: &Engine,
    ctx: &RequestContext,
    val: &mut Value,
    parent_key: Option<&str>,
    masked_count: &mut u32,
) -> Result<(), StatusCode> {
    match val {
        Value::String(s) => {
            // Skip structural keys
            if let Some(key) = parent_key {
                if is_structural_key(key) {
                    return Ok(());
                }
            }

            // Run protection on text content
            match engine.protect(ctx, s) {
                Ok(ProtectOutcome::Allowed { text, report }) => {
                    if report.masked > 0 {
                        *s = text;
                        *masked_count += report.masked;
                    }
                }
                Ok(ProtectOutcome::Blocked { .. }) => {
                    // Blocked finding in request -> 502 (FC-08)
                    return Err(StatusCode::BAD_GATEWAY);
                }
                Err(_) => {
                    // Detector fault -> 502 Bad Gateway (FC-08)
                    return Err(StatusCode::BAD_GATEWAY);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                walk_and_mask(engine, ctx, item, parent_key, masked_count)?;
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                walk_and_mask(engine, ctx, v, Some(k), masked_count)?;
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    use dpg_core::config::Config;
    use dpg_core::context::{ProjectContext, ProjectId, SessionId};
    use dpg_core::types::Route;
    use dpg_detect::DpgDetector;
    use dpg_policy::DpgPolicy;
    use dpg_protect::DpgProtector;
    use dpg_restore::DpgRestorer;
    use serde_json::json;

    fn setup_engine() -> (Engine, RequestContext) {
        let detector = Arc::new(DpgDetector::new().expect("detector"));
        let policy = Arc::new(DpgPolicy::default_policy());
        let protector = Arc::new(DpgProtector::ephemeral());
        let restorer = Arc::new(DpgRestorer::new(None));
        let config = Arc::new(Config::default());
        let engine = Engine::new(detector, policy, protector, restorer, config, None);

        let ctx = RequestContext {
            project: ProjectContext {
                root: std::path::PathBuf::from("/test/proxy"),
                id: ProjectId::new("proj-proxy".to_string()),
            },
            session: SessionId::new("sess-proxy".to_string()),
            route: Route::Proxy,
            deadline: Instant::now() + std::time::Duration::from_secs(10),
        };

        (engine, ctx)
    }

    #[test]
    fn test_sr_px_08_request_masking_anthropic_and_openai_shapes() {
        let (engine, ctx) = setup_engine();
        let mut rng = dpg_testgen::create_rng(8888);
        let aws_key = dpg_testgen::gen_aws_access_key(&mut rng);
        let github_token = dpg_testgen::gen_github_token(&mut rng);

        // Anthropic messages shape with system, messages, and tool_result
        let mut anthropic_body = json!({
            "model": "claude-3-7-sonnet-20250219",
            "anthropic_version": "2023-06-01",
            "system": format!("System instructions with secret: {aws_key}"),
            "messages": [
                {
                    "role": "user",
                    "content": "Hello!"
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01A",
                            "name": "bash",
                            "input": { "command": "echo hello" }
                        }
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01A",
                            "content": format!("Tool output credentials: {github_token}")
                        }
                    ]
                }
            ]
        });

        let count = mask_request_body(&engine, &ctx, &mut anthropic_body).expect("mask anthropic");
        assert!(count >= 2);

        // Verify structural keys are completely preserved
        assert_eq!(anthropic_body["model"], "claude-3-7-sonnet-20250219");
        assert_eq!(anthropic_body["anthropic_version"], "2023-06-01");
        assert_eq!(anthropic_body["messages"][0]["role"], "user");
        assert_eq!(anthropic_body["messages"][1]["content"][0]["type"], "tool_use");
        assert_eq!(anthropic_body["messages"][1]["content"][0]["name"], "bash");

        // Verify original secrets are completely replaced with placeholders
        let body_str = serde_json::to_string(&anthropic_body).unwrap();
        assert!(
            !body_str.contains(&aws_key),
            "PX-08: AWS key must not appear in masked request body"
        );
        assert!(
            !body_str.contains(&github_token),
            "PX-08: GitHub token must not appear in masked request body"
        );
        assert!(body_str.contains("DPG_SECRET_"));
    }
}
