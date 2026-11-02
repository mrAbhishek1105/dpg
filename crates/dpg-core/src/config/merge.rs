//! Configuration merging with ADR-0006 tighten-only semantics.

use serde::Deserialize;

use crate::config::model::{ActionConfig, Config, ConfigWarning, CustomRuleConfig, PolicyConfig};

/// Partial policy configuration used when deserializing project `.dpg.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialPolicyConfig {
    /// Action for standard known secrets.
    pub known_secret: Option<ActionConfig>,
    /// Action for private keys.
    pub private_key: Option<ActionConfig>,
    /// Action for key-value secrets.
    pub key_value_secret: Option<ActionConfig>,
    /// Action for connection strings.
    pub connection_string: Option<ActionConfig>,
    /// Action for custom terms.
    pub custom_term: Option<ActionConfig>,
    /// Action for Indian IDs.
    pub indian_id: Option<ActionConfig>,
    /// Action for PII.
    pub pii: Option<ActionConfig>,
    /// Action for entropy findings.
    pub entropy: Option<ActionConfig>,
    /// Action for prompt known secrets.
    pub prompt_known_secret: Option<ActionConfig>,
    /// Action for placeholders in other tools.
    pub placeholder_in_other_tool: Option<ActionConfig>,
}

/// Project-level configuration structure from `.dpg.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfigFile {
    /// Optional terms configuration.
    pub terms: Option<crate::config::model::TermsConfig>,
    /// Optional custom rules list.
    pub rules: Option<Vec<CustomRuleConfig>>,
    /// Optional policy tighten-only section.
    pub policy: Option<PartialPolicyConfig>,
    /// Disallowed restore section (captured to produce warnings).
    pub restore: Option<toml::Value>,
    /// Disallowed storage section.
    pub storage: Option<toml::Value>,
    /// Disallowed hook section.
    pub hook: Option<toml::Value>,
    /// Disallowed proxy section.
    pub proxy: Option<toml::Value>,
    /// Disallowed log section.
    pub log: Option<toml::Value>,
}

/// Merges project configuration into `base` enforcing tighten-only semantics (ADR-0006).
pub fn merge_project_config(
    base: &mut Config,
    project: ProjectConfigFile,
    warnings: &mut Vec<ConfigWarning>,
) {
    // 1. Check disallowed sections
    if project.restore.is_some() {
        warnings.push(ConfigWarning {
            key: "restore".to_string(),
            message: "Project configuration cannot modify restore settings (ignored)".to_string(),
        });
    }
    if project.storage.is_some() {
        warnings.push(ConfigWarning {
            key: "storage".to_string(),
            message: "Project configuration cannot modify storage settings (ignored)".to_string(),
        });
    }
    if project.hook.is_some() {
        warnings.push(ConfigWarning {
            key: "hook".to_string(),
            message: "Project configuration cannot modify hook settings (ignored)".to_string(),
        });
    }
    if project.proxy.is_some() {
        warnings.push(ConfigWarning {
            key: "proxy".to_string(),
            message: "Project configuration cannot modify proxy settings (ignored)".to_string(),
        });
    }
    if project.log.is_some() {
        warnings.push(ConfigWarning {
            key: "log".to_string(),
            message: "Project configuration cannot modify log settings (ignored)".to_string(),
        });
    }

    // 2. Append terms
    if let Some(terms) = project.terms {
        for val in terms.values {
            if !base.terms.values.contains(&val) {
                base.terms.values.push(val);
            }
        }
    }

    // 3. Append custom rules
    if let Some(rules) = project.rules {
        for rule in rules {
            if !base.rules.iter().any(|r| r.id == rule.id) {
                base.rules.push(rule);
            }
        }
    }

    // 4. Merge policy (tighten-only)
    if let Some(policy) = project.policy {
        merge_policy_tighten_only(&mut base.policy, policy, warnings);
    }
}

fn check_tighten_action(
    current: &mut ActionConfig,
    candidate: ActionConfig,
    field_name: &'static str,
    warnings: &mut Vec<ConfigWarning>,
) {
    if candidate.severity() >= current.severity() {
        *current = candidate;
    } else {
        warnings.push(ConfigWarning {
            key: format!("policy.{field_name}"),
            message: format!(
                "Project configuration tried to loosen policy from {:?} to {:?} (ignored)",
                current, candidate
            ),
        });
    }
}

fn merge_policy_tighten_only(
    base: &mut PolicyConfig,
    partial: PartialPolicyConfig,
    warnings: &mut Vec<ConfigWarning>,
) {
    if let Some(act) = partial.known_secret {
        check_tighten_action(&mut base.known_secret, act, "known_secret", warnings);
    }
    if let Some(act) = partial.private_key {
        check_tighten_action(&mut base.private_key, act, "private_key", warnings);
    }
    if let Some(act) = partial.key_value_secret {
        check_tighten_action(
            &mut base.key_value_secret,
            act,
            "key_value_secret",
            warnings,
        );
    }
    if let Some(act) = partial.connection_string {
        check_tighten_action(
            &mut base.connection_string,
            act,
            "connection_string",
            warnings,
        );
    }
    if let Some(act) = partial.custom_term {
        check_tighten_action(&mut base.custom_term, act, "custom_term", warnings);
    }
    if let Some(act) = partial.indian_id {
        check_tighten_action(&mut base.indian_id, act, "indian_id", warnings);
    }
    if let Some(act) = partial.pii {
        check_tighten_action(&mut base.pii, act, "pii", warnings);
    }
    if let Some(act) = partial.entropy {
        check_tighten_action(&mut base.entropy, act, "entropy", warnings);
    }
    if let Some(act) = partial.prompt_known_secret {
        check_tighten_action(
            &mut base.prompt_known_secret,
            act,
            "prompt_known_secret",
            warnings,
        );
    }
    if let Some(act) = partial.placeholder_in_other_tool {
        check_tighten_action(
            &mut base.placeholder_in_other_tool,
            act,
            "placeholder_in_other_tool",
            warnings,
        );
    }
}

/// Applies environment variable overrides to a configuration.
pub fn apply_env_overrides(config: &mut Config) {
    if let Ok(val) = std::env::var("DPG_LOG_LEVEL") {
        if !val.trim().is_empty() {
            config.log.level = val.trim().to_string();
        }
    }

    if let Ok(val) = std::env::var("DPG_PROXY_PORT") {
        if let Ok(port) = val.trim().parse::<u16>() {
            config.proxy.port = port;
        }
    }

    if let Ok(val) = std::env::var("DPG_STORAGE_BACKEND") {
        if !val.trim().is_empty() {
            config.storage.key_backend = val.trim().to_string();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_tighten_policy_allowed() {
        let mut base = Config::default();
        assert_eq!(base.policy.entropy, ActionConfig::Warn);

        let project = ProjectConfigFile {
            policy: Some(PartialPolicyConfig {
                entropy: Some(ActionConfig::Mask),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut warnings = Vec::new();
        merge_project_config(&mut base, project, &mut warnings);

        assert_eq!(base.policy.entropy, ActionConfig::Mask);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_loosen_policy_ignored_with_warning() {
        let mut base = Config::default();
        assert_eq!(base.policy.known_secret, ActionConfig::Mask);

        let project = ProjectConfigFile {
            policy: Some(PartialPolicyConfig {
                known_secret: Some(ActionConfig::Allow),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut warnings = Vec::new();
        merge_project_config(&mut base, project, &mut warnings);

        assert_eq!(base.policy.known_secret, ActionConfig::Mask);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].key, "policy.known_secret");
    }

    #[test]
    fn test_project_override_disallowed_sections_ignored() {
        let mut base = Config::default();
        let project = ProjectConfigFile {
            restore: Some(toml::Value::String("disallowed".to_string())),
            storage: Some(toml::Value::String("disallowed".to_string())),
            proxy: Some(toml::Value::String("disallowed".to_string())),
            ..Default::default()
        };

        let mut warnings = Vec::new();
        merge_project_config(&mut base, project, &mut warnings);

        assert_eq!(warnings.len(), 3);
        assert!(warnings.iter().any(|w| w.key == "restore"));
        assert!(warnings.iter().any(|w| w.key == "storage"));
        assert!(warnings.iter().any(|w| w.key == "proxy"));
    }
}
