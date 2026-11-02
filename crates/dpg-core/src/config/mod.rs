//! Layered configuration system for DPG.
//!
//! Precedence order (low to high):
//! 1. Built-in defaults
//! 2. Global configuration (`<config_dir>/dpg/config.toml` or `DPG_CONFIG`)
//! 3. Project configuration (`<project_root>/.dpg.toml`, tighten-only per ADR-0006)
//! 4. Environment variables (`DPG_*`)
//! 5. CLI flags
//!
//! Adheres strictly to security requirements:
//! - CF-01: Project config is tighten-only; loosening keys are ignored with a warning.
//! - CF-02: Configuration diagnostics never print term lists, tokens, or keychain keys.

pub mod load;
pub mod merge;
pub mod model;
pub mod validate;

pub use load::{default_global_config_path, load_config, load_project_toml_str, LoadOptions};
pub use merge::{apply_env_overrides, merge_project_config, ProjectConfigFile};
pub use model::{
    ActionConfig, Config, ConfigDiagnostics, ConfigWarning, CustomRuleConfig, HookConfig,
    LogConfig, PolicyConfig, ProxyConfig, RestoreConfig, StorageConfig, TermsConfig,
};
pub use validate::validate_config;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use std::fs;

    #[test]
    fn test_sr_cf_01_tighten_only_enforcement() {
        let mut base = Config::default();
        // Built-in default for known_secret is Mask (2)
        assert_eq!(base.policy.known_secret, ActionConfig::Mask);
        assert_eq!(base.policy.entropy, ActionConfig::Warn);

        // Project config tries to:
        // 1. Loosen known_secret to Allow (0) -> MUST be ignored with warning
        // 2. Loosen indian_id to Warn (1) -> MUST be ignored with warning
        // 3. Tighten entropy to Mask (2) -> MUST be accepted
        // 4. Override restore tools to ["Bash"] -> MUST be ignored with warning
        // 5. Override proxy bind_address to "0.0.0.0" -> MUST be ignored with warning
        let toml_content = r#"
[policy]
known_secret = "allow"
indian_id = "warn"
entropy = "mask"

[restore]
tools = ["Bash"]

[proxy]
bind_address = "0.0.0.0"

[terms]
values = ["ProjectSecretTerm"]
"#;

        let warnings = load_project_toml_str(&mut base, toml_content)
            .expect("Valid TOML should parse and merge");

        // Assert tighten-only behavior:
        assert_eq!(
            base.policy.known_secret,
            ActionConfig::Mask,
            "known_secret should NOT be loosened"
        );
        assert_eq!(
            base.policy.indian_id,
            ActionConfig::Mask,
            "indian_id should NOT be loosened"
        );
        assert_eq!(
            base.policy.entropy,
            ActionConfig::Mask,
            "entropy should be tightened to Mask"
        );
        assert_eq!(
            base.restore.tools,
            vec!["Write".to_string(), "Edit".to_string()],
            "Restore tools must not be widened"
        );
        assert_eq!(
            base.proxy.bind_address, "127.0.0.1",
            "Proxy settings must not be overwritten by project"
        );
        assert_eq!(base.terms.values, vec!["ProjectSecretTerm".to_string()]);

        // Check warning count and keys
        assert!(warnings.iter().any(|w| w.key == "policy.known_secret"));
        assert!(warnings.iter().any(|w| w.key == "policy.indian_id"));
        assert!(warnings.iter().any(|w| w.key == "restore"));
        assert!(warnings.iter().any(|w| w.key == "proxy"));
    }

    #[test]
    fn test_sr_cf_02_diagnostics_never_leak_terms_or_tokens() {
        let mut config = Config::default();
        config.terms.values = vec![
            "ultra-secret-term-123".to_string(),
            "confidential-project-falcon".to_string(),
        ];

        let diag = config.diagnostics();
        assert_eq!(diag.terms_count, 2);

        let diag_str = format!("{diag:?}");
        assert!(
            !diag_str.contains("ultra-secret"),
            "Diagnostics must never contain term values"
        );
        assert!(
            !diag_str.contains("falcon"),
            "Diagnostics must never contain term values"
        );
    }

    #[test]
    fn test_invalid_toml_returns_c001() {
        let mut base = Config::default();
        let invalid_toml = "this is not valid [[ toml";
        let res = load_project_toml_str(&mut base, invalid_toml);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.code(), ErrorCode::C001);
    }

    #[test]
    fn test_precedence_order() {
        let temp_dir = tempfile::tempdir().expect("temp dir created");
        let global_path = temp_dir.path().join("global.toml");
        let project_dir = temp_dir.path().join("project");
        fs::create_dir_all(&project_dir).expect("project dir created");
        let project_file = project_dir.join(".dpg.toml");

        // 1. Write global config setting proxy port to 9000 and entropy to mask
        fs::write(
            &global_path,
            r#"
[proxy]
port = 9000

[policy]
entropy = "mask"
"#,
        )
        .expect("write global");

        // 2. Write project config adding terms and tightening pii to mask
        fs::write(
            &project_file,
            r#"
[terms]
values = ["ProjectTerm"]

[policy]
pii = "mask"
"#,
        )
        .expect("write project");

        // 3. Load with CLI flag overriding proxy port to 9999
        let opts = LoadOptions {
            custom_global_path: Some(global_path),
            project_root: Some(project_dir),
            cli_port: Some(9999),
            cli_log_level: Some("debug".to_string()),
        };

        let (config, warnings) = load_config(&opts).expect("load succeeds");
        assert!(warnings.is_empty());

        // Precedence checks:
        // CLI flag (9999) beat global (9000) beat default (8787)
        assert_eq!(config.proxy.port, 9999);
        // CLI log level ("debug") beat default ("info")
        assert_eq!(config.log.level, "debug");
        // Global entropy ("mask") beat default ("warn")
        assert_eq!(config.policy.entropy, ActionConfig::Mask);
        // Project pii ("mask") beat default ("warn")
        assert_eq!(config.policy.pii, ActionConfig::Mask);
        // Project terms present
        assert_eq!(config.terms.values, vec!["ProjectTerm".to_string()]);
    }
}
