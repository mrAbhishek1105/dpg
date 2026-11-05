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
    run_doctor_with(custom_settings_dir, None)
}

/// Runs diagnostics with explicit runtime options (data dir, config); `None` uses defaults
/// for the current directory.
pub fn run_doctor_with(
    custom_settings_dir: Option<&Path>,
    runtime_opts: Option<&crate::runtime::RuntimeOptions>,
) -> Result<DoctorReport, DpgError> {
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

    // 5. Full runtime: config, key backend, mapping store, project identity, self-test
    check_runtime(&mut items, runtime_opts);

    let all_passed = items.iter().all(|i| i.status != CheckStatus::Fail);

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

fn check_runtime(
    items: &mut Vec<DiagnosticItem>,
    runtime_opts: Option<&crate::runtime::RuntimeOptions>,
) {
    use crate::runtime::{Runtime, RuntimeOptions};
    use dpg_core::types::{ProtectOutcome, Route};

    let default_opts;
    let opts = match runtime_opts {
        Some(o) => o,
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            default_opts = RuntimeOptions::for_cwd(cwd);
            &default_opts
        }
    };
    let rt = match Runtime::build(opts) {
        Ok(rt) => rt,
        Err(e) => {
            items.push(DiagnosticItem {
                name: "Runtime".to_string(),
                status: CheckStatus::Fail,
                message: format!(
                    "Cannot initialise DPG [{}]: {e}. Hooks will fail closed (tool output withheld, prompts blocked).",
                    e.code()
                ),
            });
            return;
        }
    };

    items.push(DiagnosticItem {
        name: "Configuration".to_string(),
        status: if rt.warnings.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: if rt.warnings.is_empty() {
            format!(
                "Loaded ({} custom term(s), {} custom rule(s))",
                rt.config.terms.values.len(),
                rt.config.rules.len()
            )
        } else {
            rt.warnings
                .iter()
                .map(|w| format!("{}: {}", w.key, w.message))
                .collect::<Vec<_>>()
                .join("; ")
        },
    });

    items.push(match rt.key_backend {
        dpg_protect::key::KeyBackend::Keychain => DiagnosticItem {
            name: "Master Key".to_string(),
            status: CheckStatus::Pass,
            message: "Stored in the OS keychain".to_string(),
        },
        dpg_protect::key::KeyBackend::File => DiagnosticItem {
            name: "Master Key".to_string(),
            status: CheckStatus::Warn,
            message: format!(
                "Stored in an owner-only file in {} (no OS keychain backend on this platform/config)",
                crate::runtime::data_dir().display()
            ),
        },
    });

    items.push(match rt.store_error {
        None => DiagnosticItem {
            name: "Mapping Store".to_string(),
            status: CheckStatus::Pass,
            message: "Opened and key verified".to_string(),
        },
        Some(ref e) => DiagnosticItem {
            name: "Mapping Store".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "Unavailable [{}]: masking uses ephemeral placeholders and restoration is denied",
                e.code()
            ),
        },
    });

    items.push(DiagnosticItem {
        name: "Project".to_string(),
        status: CheckStatus::Pass,
        message: format!("{} (id {})", rt.project.root.display(), rt.project.id),
    });

    // Self-test: a synthetic (non-functional) AWS-style key must be masked.
    let probe_key = format!("AKIA{}", "Q7ZT4M2XK9LBN3VD");
    let probe = format!("aws_access_key_id = {probe_key}");
    let ctx = rt.context(
        Route::Cli,
        "doctor",
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    );
    let ok = match rt.engine.protect(&ctx, &probe) {
        Ok(ProtectOutcome::Allowed { text, report }) => {
            report.masked > 0 && !text.contains(probe_key.as_str())
        }
        Ok(ProtectOutcome::Blocked { .. }) => true,
        Err(_) => false,
    };
    items.push(DiagnosticItem {
        name: "Detection Self-Test".to_string(),
        status: if ok {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        message: if ok {
            "Synthetic credential detected and masked".to_string()
        } else {
            "Synthetic credential was NOT masked".to_string()
        },
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_doctor_smoke_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let data = temp.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(
            data.join("g.toml"),
            "[storage]
key_backend = \"file\"
",
        )
        .unwrap();
        let opts = crate::runtime::RuntimeOptions {
            cwd: temp.path().to_path_buf(),
            data_dir: data.clone(),
            global_config: Some(data.join("g.toml")),
        };
        let report = run_doctor_with(Some(temp.path()), Some(&opts)).expect("doctor run");
        let cli = report.format_cli();
        assert!(cli.contains("Detection Self-Test"), "{cli}");
        assert!(cli.contains("Mapping Store"), "{cli}");
        assert!(
            report
                .items
                .iter()
                .all(|i| i.name != "Detection Self-Test" || i.status == CheckStatus::Pass),
            "{cli}"
        );

        assert!(!report.items.is_empty());
        let cli_output = report.format_cli();
        assert!(cli_output.contains("DPG Doctor System Health Check"));
        assert!(cli_output.contains("Built-in Rules"));
    }
}
