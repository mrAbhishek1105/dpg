//! Explanation string formatting for policy decisions.

use std::borrow::Cow;

use dpg_core::types::{Action, Category, Decision, Route, RuleId};

/// Origin source of a policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    /// Action resolved from default category matrix.
    CategoryDefault,
    /// Action resolved from global configuration.
    GlobalConfig,
    /// Action resolved from project tighten-only configuration.
    ProjectConfig,
    /// Explicit rule-level override.
    RuleOverride,
    /// Route-specific mapping (e.g. user prompt submission).
    RouteSpecialization(Route),
    /// Finding ignored via ignore list.
    IgnoreList,
}

/// Generates a developer-facing explanation reason string for a decision.
pub fn format_reason(
    action: Action,
    rule_id: &RuleId,
    category: Category,
    source: PolicySource,
) -> Cow<'static, str> {
    let action_str = match action {
        Action::Allow => "Allowed",
        Action::Warn => "Warned",
        Action::Mask => "Masked",
        Action::Block => "Blocked",
    };

    let cat_key = match category {
        Category::KnownSecret => "known_secret",
        Category::PrivateKey => "private_key",
        Category::KeyValueSecret => "key_value_secret",
        Category::ConnectionString => "connection_string",
        Category::CustomTerm => "custom_term",
        Category::IndianId => "indian_id",
        Category::Pii => "pii",
        Category::Entropy => "entropy",
    };

    match source {
        PolicySource::CategoryDefault => Cow::Owned(format!(
            "{} by rule {} (policy.{} = {}, from defaults)",
            action_str,
            rule_id,
            cat_key,
            action_str.to_ascii_lowercase()
        )),
        PolicySource::GlobalConfig => Cow::Owned(format!(
            "{} by rule {} (policy.{} = {}, from global config)",
            action_str,
            rule_id,
            cat_key,
            action_str.to_ascii_lowercase()
        )),
        PolicySource::ProjectConfig => Cow::Owned(format!(
            "{} by rule {} (policy.{} = {}, from project config)",
            action_str,
            rule_id,
            cat_key,
            action_str.to_ascii_lowercase()
        )),
        PolicySource::RuleOverride => Cow::Owned(format!(
            "{} by rule {} (explicit rule override)",
            action_str, rule_id
        )),
        PolicySource::RouteSpecialization(route) => Cow::Owned(format!(
            "{} by rule {} (route {:?} maps {} to {})",
            action_str,
            rule_id,
            route,
            cat_key,
            action_str.to_ascii_lowercase()
        )),
        PolicySource::IgnoreList => {
            Cow::Owned(format!("Allowed by ignore list for rule {}", rule_id))
        }
    }
}

/// Helper method returning the explanation from an existing decision.
pub fn explain(decision: &Decision) -> &str {
    &decision.reason
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_reason_contains_rule_and_source() {
        let rule = RuleId::from_static("gitleaks.aws-access-token");
        let reason = format_reason(
            Action::Mask,
            &rule,
            Category::KnownSecret,
            PolicySource::CategoryDefault,
        );

        assert!(reason.contains("gitleaks.aws-access-token"));
        assert!(reason.contains("known_secret"));
        assert!(reason.contains("defaults"));
    }

    #[test]
    fn test_format_reason_route_specialization() {
        let rule = RuleId::from_static("dpg.pem-private-key");
        let reason = format_reason(
            Action::Block,
            &rule,
            Category::PrivateKey,
            PolicySource::RouteSpecialization(Route::HookUserPrompt),
        );

        assert!(reason.contains("Blocked"));
        assert!(reason.contains("dpg.pem-private-key"));
        assert!(reason.contains("HookUserPrompt"));
    }
}
