//! Configuration loading and orchestration.

use std::fs;
use std::path::PathBuf;

use directories::ProjectDirs;

use crate::config::merge::{apply_env_overrides, merge_project_config, ProjectConfigFile};
use crate::config::model::{Config, ConfigWarning};
use crate::config::validate::validate_config;
use crate::error::{DpgError, ErrorCode, SafeDetail};

/// Options controlling how configuration is loaded and overridden.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// Explicit path to global configuration file.
    pub custom_global_path: Option<PathBuf>,
    /// Project root directory where `.dpg.toml` is searched.
    pub project_root: Option<PathBuf>,
    /// CLI override for proxy port.
    pub cli_port: Option<u16>,
    /// CLI override for log level.
    pub cli_log_level: Option<String>,
}

/// Resolves the default global config file path.
pub fn default_global_config_path() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("DPG_CONFIG") {
        if !env_path.trim().is_empty() {
            return Some(PathBuf::from(env_path.trim()));
        }
    }

    ProjectDirs::from("", "", "dpg").map(|dirs| dirs.config_dir().join("config.toml"))
}

/// Loads, merges, and validates the complete configuration hierarchy.
pub fn load_config(opts: &LoadOptions) -> Result<(Config, Vec<ConfigWarning>), DpgError> {
    let mut config = Config::default();
    let mut warnings = Vec::new();

    // 1. Global config file
    let global_path = opts
        .custom_global_path
        .clone()
        .or_else(default_global_config_path);

    if let Some(path) = global_path {
        if path.is_file() {
            let content = fs::read_to_string(&path).map_err(|_| DpgError::Configuration {
                code: ErrorCode::C001,
                detail: SafeDetail::from_static("Could not read global config file"),
            })?;
            let parsed: Config = toml::from_str(&content).map_err(|_| DpgError::Configuration {
                code: ErrorCode::C001,
                detail: SafeDetail::from_static("Invalid TOML syntax in global config"),
            })?;
            config = parsed;
        }
    }

    // 2. Project config file (.dpg.toml)
    let project_dir = opts
        .project_root
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let project_file = project_dir.join(".dpg.toml");

    if project_file.is_file() {
        let content = fs::read_to_string(&project_file).map_err(|_| DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static("Could not read project .dpg.toml file"),
        })?;
        let parsed: ProjectConfigFile =
            toml::from_str(&content).map_err(|_| DpgError::Configuration {
                code: ErrorCode::C001,
                detail: SafeDetail::from_static("Invalid TOML syntax in project .dpg.toml"),
            })?;
        merge_project_config(&mut config, parsed, &mut warnings);
    }

    // 3. Environment variable overrides
    apply_env_overrides(&mut config);

    // 4. CLI flag overrides
    if let Some(port) = opts.cli_port {
        config.proxy.port = port;
    }
    if let Some(ref level) = opts.cli_log_level {
        if !level.trim().is_empty() {
            config.log.level = level.trim().to_string();
        }
    }

    // 5. Final validation
    validate_config(&config)?;

    Ok((config, warnings))
}

/// Helper function to parse a TOML string as project config and merge into base.
pub fn load_project_toml_str(
    base: &mut Config,
    toml_str: &str,
) -> Result<Vec<ConfigWarning>, DpgError> {
    let mut warnings = Vec::new();
    let parsed: ProjectConfigFile =
        toml::from_str(toml_str).map_err(|_| DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static("Invalid TOML syntax in project config string"),
        })?;
    merge_project_config(base, parsed, &mut warnings);
    validate_config(base)?;
    Ok(warnings)
}
