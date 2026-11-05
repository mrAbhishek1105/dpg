//! Policy engine resolving detector findings to security decisions and actions.

use std::collections::HashMap;
use std::sync::Arc;

use dpg_core::config::{ActionConfig, PolicyConfig};
use dpg_core::context::RequestContext;
use dpg_core::engine::PolicyEngine;
use dpg_core::error::DpgError;
use dpg_core::types::{Action, Category, Decision, Finding, Route, RuleId};

use crate::explain::{format_reason, PolicySource};
use crate::ignore::{compute_fingerprint, IgnoreList, InMemoryIgnoreList};

/// Converts an `ActionConfig` to its domain `Action` equivalent.
pub fn action_config_to_action(ac: ActionConfig) -> Action {
    match ac {
        ActionConfig::Allow => Action::Allow,
        ActionConfig::Warn => Action::Warn,
        ActionConfig::Mask => Action::Mask,
        ActionConfig::Block => Action::Block,
    }
}

/// DPG policy decision engine.
pub struct DpgPolicy {
    config: PolicyConfig,
    rule_overrides: HashMap<RuleId, Action>,
    ignore_list: Arc<dyn IgnoreList>,
    hmac_key: [u8; 32],
}

impl DpgPolicy {
    /// Creates a new `DpgPolicy` with the given configuration and ignore list.
    pub fn new(
        config: PolicyConfig,
        rule_overrides: HashMap<RuleId, Action>,
        ignore_list: Arc<dyn IgnoreList>,
        hmac_key: [u8; 32],
    ) -> Self {
        Self {
            config,
            rule_overrides,
            ignore_list,
            hmac_key,
        }
    }

    /// Creates a `DpgPolicy` with default policy settings and an in-memory ignore list.
    pub fn default_policy() -> Self {
        Self::new(
            PolicyConfig::default(),
            HashMap::new(),
            Arc::new(InMemoryIgnoreList::new()),
            [0u8; 32],
        )
    }

    /// Resolves a single finding to an `Action` and `PolicySource`.
    pub fn resolve(
        &self,
        finding: &Finding,
        secret_val: &str,
        route: Route,
        project_id: &dpg_core::context::ProjectId,
    ) -> Result<(Action, PolicySource), DpgError> {
        // 1. Check ignore list first
        let fp = compute_fingerprint(&self.hmac_key, &finding.rule_id, secret_val);
        if self.ignore_list.is_ignored(project_id, &fp)? {
            return Ok((Action::Allow, PolicySource::IgnoreList));
        }

        // 2. Check rule-level overrides
        if let Some(&action) = self.rule_overrides.get(&finding.rule_id) {
            return Ok((action, PolicySource::RuleOverride));
        }

        // 3. Resolve category action
        let (mut action, mut source) = match finding.category {
            Category::KnownSecret => (
                action_config_to_action(self.config.known_secret),
                PolicySource::CategoryDefault,
            ),
            Category::PrivateKey => (
                action_config_to_action(self.config.private_key),
                PolicySource::CategoryDefault,
            ),
            Category::KeyValueSecret => (
                action_config_to_action(self.config.key_value_secret),
                PolicySource::CategoryDefault,
            ),
            Category::ConnectionString => (
                action_config_to_action(self.config.connection_string),
                PolicySource::CategoryDefault,
            ),
            Category::CustomTerm => (
                action_config_to_action(self.config.custom_term),
                PolicySource::CategoryDefault,
            ),
            Category::IndianId => (
                action_config_to_action(self.config.indian_id),
                PolicySource::CategoryDefault,
            ),
            Category::Pii => (
                action_config_to_action(self.config.pii),
                PolicySource::CategoryDefault,
            ),
            Category::Entropy => (
                action_config_to_action(self.config.entropy),
                PolicySource::CategoryDefault,
            ),
        };

        // 4. Route specialization: HookUserPrompt cannot rewrite prompts with placeholders
        if route == Route::HookUserPrompt {
            if finding.category == Category::KnownSecret || finding.category == Category::PrivateKey
            {
                action = action_config_to_action(self.config.prompt_known_secret);
                source = PolicySource::RouteSpecialization(route);
            } else if action == Action::Mask {
                // For other categories in prompts, Mask downgrades to Warn
                action = Action::Warn;
                source = PolicySource::RouteSpecialization(route);
            }
        }

        Ok((action, source))
    }
}

impl PolicyEngine for DpgPolicy {
    fn decide(
        &self,
        ctx: &RequestContext,
        text: &str,
        findings: &[Finding],
    ) -> Result<Vec<Decision>, DpgError> {
        ctx.check_deadline()?;

        let mut decisions = Vec::with_capacity(findings.len());

        for (idx, finding) in findings.iter().enumerate() {
            let secret_val = finding.span.as_str(text);
            let (action, source) = self.resolve(finding, secret_val, ctx.route, &ctx.project.id)?;

            let reason = format_reason(action, &finding.rule_id, finding.category, source);

            decisions.push(Decision {
                finding: idx,
                action,
                rule_id: finding.rule_id.clone(),
                reason,
            });
        }

        Ok(decisions)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use dpg_core::context::{ProjectContext, ProjectId, SessionId};
    use dpg_core::types::{Confidence, Span};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn mock_context(route: Route) -> RequestContext {
        RequestContext {
            project: ProjectContext {
                root: PathBuf::from("/test/project"),
                id: ProjectId::new("test-project-id".to_string()),
            },
            session: SessionId::new("test-session".to_string()),
            route,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    #[test]
    fn test_default_policy_matrix_post_tool_use() {
        let policy = DpgPolicy::default_policy();
        let ctx = mock_context(Route::HookPostToolUse);

        let text = "sample secret text payload";
        let span = Span::new_raw(0, 6);

        // Test all categories under default matrix
        let categories = [
            (Category::KnownSecret, Action::Mask),
            (Category::PrivateKey, Action::Mask),
            (Category::KeyValueSecret, Action::Mask),
            (Category::ConnectionString, Action::Mask),
            (Category::CustomTerm, Action::Mask),
            (Category::IndianId, Action::Mask),
            (Category::Pii, Action::Warn),
            (Category::Entropy, Action::Warn),
        ];

        for (cat, expected_action) in categories {
            let finding = Finding {
                rule_id: RuleId::from_static("test.rule"),
                category: cat,
                span,
                parts: vec![],
                confidence: Confidence::High,
            };

            let decisions = policy
                .decide(&ctx, text, &[finding])
                .expect("decide succeeds");
            assert_eq!(decisions.len(), 1);
            assert_eq!(
                decisions[0].action, expected_action,
                "Action mismatch for category {:?}",
                cat
            );
            assert!(!decisions[0].reason.is_empty(), "Reason must not be empty");
        }
    }

    #[test]
    fn test_user_prompt_route_specialization_blocks_known_secrets() {
        let policy = DpgPolicy::default_policy();
        let ctx = mock_context(Route::HookUserPrompt);

        let text = &format!("Here is my {}{} key", "AKIA", "1234567890ABCDEF");
        let span = Span::new_raw(11, 31);

        let finding = Finding {
            rule_id: RuleId::from_static("dpg.aws-access-key-id"),
            category: Category::KnownSecret,
            span,
            parts: vec![],
            confidence: Confidence::High,
        };

        let decisions = policy.decide(&ctx, text, &[finding]).expect("decide");
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            decisions[0].action,
            Action::Block,
            "UserPrompt must map KnownSecret to Block"
        );
        assert!(decisions[0].reason.contains("HookUserPrompt"));
    }

    #[test]
    fn test_ignore_list_allows_suppressed_finding() {
        let ignore_list = Arc::new(InMemoryIgnoreList::new());
        let hmac_key = [1u8; 32];
        let policy = DpgPolicy::new(
            PolicyConfig::default(),
            HashMap::new(),
            ignore_list.clone(),
            hmac_key,
        );

        let ctx = mock_context(Route::HookPostToolUse);
        let fp_val = format!("{}{}", "sk_", "123456789");
        let text = &format!("False positive test token: {fp_val}");
        let span = Span::new_raw(27, 39);
        let rule = RuleId::from_static("dpg.test-rule");

        let finding = Finding {
            rule_id: rule.clone(),
            category: Category::KnownSecret,
            span,
            parts: vec![],
            confidence: Confidence::High,
        };

        // Before ignore: Mask
        let d1 = policy
            .decide(&ctx, text, std::slice::from_ref(&finding))
            .expect("decide");
        assert_eq!(d1[0].action, Action::Mask);

        // Add to ignore list
        let fp = compute_fingerprint(&hmac_key, &rule, &fp_val);
        ignore_list.ignore(ctx.project.id.clone(), fp);

        // After ignore: Allow
        let d2 = policy.decide(&ctx, text, &[finding]).expect("decide");
        assert_eq!(d2[0].action, Action::Allow);
        assert!(d2[0].reason.contains("ignore list"));
    }
}
