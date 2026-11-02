//! System diagnostic health checks (`dpg doctor`).
//!
//! Defined per `docs/components/CONNECT.md` and task G-07.

use std::fs;
use std::path::{Path, PathBuf};

use dpg_core::error::DpgError;
use dpg_detect::ruleset::RuleSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::install::resolve_claude_settings_dir;

/// Result status of a single diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    /// Check passed successfully.
    Pass,
    /// Check identified an issue that should be addressed.
    Warn,
    /// Check failed critical requirement.
    Fail,
}

/// A single diagnostic check item in the health report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticItem {
    /// Unique name of the diagnostic check.
    pub name: String,
    /// Outcome status.
    pub status: CheckStatus,
    /// Descriptive detail or remediation guidance (never includes secrets).
    pub message: String,
}

/// Comprehensive health check report returned by `dpg doctor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// List of individual diagnostic check results.
    pub items: Vec<DiagnosticItem>,
    /// Overall health summary.
    pub all_passed: bool,
}

impl DoctorReport {
    /// Formats the report as a user-friendly CLI table/output.
    pub fn format_cli(&self) -> String {
        let mut out = String::new();
        out.push_str("DPG Doctor System Health Check:\n");
        out.push_str("----------------------------------------\n");

        for item in &self.items {
            let symbol = match item.status {
                CheckStatus::Pass => "[OK]  ",
                CheckStatus::Warn => "[WARN]",
                CheckStatus::Fail => "[FAIL]",
            };
            out.push_str(&format!("{} {}: {}\n", symbol, item.name, item.message));
        }

        out.push_str("----------------------------------------\n");
        if self.all_passed {
            out.push_str("System status: All health checks PASSED.\n");
        } else {
            out.push_str("System status: Some checks generated warnings or failures.\n");
        }

        out
    }
}

/// Executes all system diagnostic checks.
pub fn run_doctor(custom_settings_dir: Option<&Path>) -> Result<DoctorReport, DpgError> {
    let mut items = Vec::new();

    // 1. Binary presence check
    let current_exe = std::env::current_exe();
    match current_exe {
        Ok(path) => {
            items.push(DiagnosticItem {
                name: "Binary Location".to_string(),
                status: CheckStatus::Pass,
                message: format!("Running executable at {}", path.display()),
            });
        }
        Err(e) => {
            items.push(DiagnosticItem {
                name: "Binary Location".to_string(),
                status: CheckStatus::Warn,
                message: format!("Unable to resolve current executable path: {e}"),
            });
        }
    }

    // 2. Claude Code settings check
    let settings_dir_res = resolve_claude_settings_dir(custom_settings_dir);
    match settings_dir_res {
        Ok(dir) => {
            let settings_file = dir.join("settings.json");
            if settings_file.exists() {
                check_claude_settings(&settings_file, &mut items);
            } else {
                items.push(DiagnosticItem {
                    name: "Claude Code Hooks".to_string(),
                    status: CheckStatus::Warn,
                    message: "settings.json not found. Run 'dpg install claude-code' to enable protection.".to_string(),
                });
            }
        }
        Err(_) => {
            items.push(DiagnosticItem {
                name: "Claude Code Settings".to_string(),
                status: CheckStatus::Warn,
                message: "Could not determine user home directory for .claude/settings.json"
                    .to_string(),
            });
        }
    }

    // 3. Built-in ruleset compilation check
    match RuleSet::builtin() {
        Ok(ruleset) => {
            items.push(DiagnosticItem {
                name: "Built-in Rules".to_string(),
                status: CheckStatus::Pass,
                message: format!(
                    "{} detection rules loaded and verified",
                    ruleset.rules().len()
                ),
            });
        }
        Err(e) => {
            items.push(DiagnosticItem {
                name: "Built-in Rules".to_string(),
                status: CheckStatus::Fail,
                message: format!("Failed to compile built-in rules: {e}"),
            });
        }
    }

    // 4. Default mapping store initialization check
    let store_dir = default_store_dir();
    match store_dir {
        Some(dir) => {
            items.push(DiagnosticItem {
                name: "Mapping Store Path".to_string(),
                status: CheckStatus::Pass,
                message: format!("Store directory: {}", dir.display()),
            });
        }
        None => {
            items.push(DiagnosticItem {
                name: "Mapping Store Path".to_string(),
                status: CheckStatus::Warn,
                message: "Default application data directory could not be resolved".to_string(),
            });
        }
    }

    let all_passed = items.iter().all(|i| i.status == CheckStatus::Pass);

    Ok(DoctorReport { items, all_passed })
}

fn check_claude_settings(path: &Path, items: &mut Vec<DiagnosticItem>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            items.push(DiagnosticItem {
                name: "Claude Code Settings".to_string(),
                status: CheckStatus::Warn,
                message: "Failed to read settings.json".to_string(),
            });
            return;
        }
    };

    let json_val: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => {
            items.push(DiagnosticItem {
                name: "Claude Code Settings".to_string(),
                status: CheckStatus::Fail,
                message: "settings.json contains invalid JSON syntax".to_string(),
            });
            return;
        }
    };

    // Check disable file mentions env
    let disable_mentions = json_val
        .get("env")
        .and_then(|e| e.get("CLAUDE_CODE_DISABLE_FILE_MENTIONS"))
        .and_then(|v| v.as_str())
        == Some("1");

    if disable_mentions {
        items.push(DiagnosticItem {
            name: "Disable File Mentions".to_string(),
            status: CheckStatus::Pass,
            message: "CLAUDE_CODE_DISABLE_FILE_MENTIONS is active".to_string(),
        });
    } else {
        items.push(DiagnosticItem {
            name: "Disable File Mentions".to_string(),
            status: CheckStatus::Warn,
            message: "CLAUDE_CODE_DISABLE_FILE_MENTIONS is not set. Run 'dpg install claude-code'."
                .to_string(),
        });
    }

    // Check hook entries
    let has_hooks = content.contains("dpg hook post-tool-use")
        && content.contains("dpg hook pre-tool-use")
        && content.contains("dpg hook user-prompt-submit");

    if has_hooks {
        items.push(DiagnosticItem {
            name: "Claude Code Hooks".to_string(),
            status: CheckStatus::Pass,
            message: "All DPG hooks (PostToolUse, PreToolUse, UserPromptSubmit) configured"
                .to_string(),
        });
    } else {
        items.push(DiagnosticItem {
            name: "Claude Code Hooks".to_string(),
            status: CheckStatus::Warn,
            message:
                "Some DPG hooks are missing from settings.json. Run 'dpg install claude-code'."
                    .to_string(),
        });
    }
}

fn default_store_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "dpg", "dpg").map(|d| d.data_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_doctor_smoke_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let report = run_doctor(Some(temp.path())).expect("doctor run");

        assert!(!report.items.is_empty());
        let cli_output = report.format_cli();
        assert!(cli_output.contains("DPG Doctor System Health Check"));
        assert!(cli_output.contains("Built-in Rules"));
    }
}
