//! Claude Code automated hook installer and uninstaller.
//!
//! Defined per `docs/integrations/CLAUDE_CODE.md` §2 and `docs/components/CONNECT.md`.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Options configuring the Claude Code installation operation.
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// If true, performs uninstall of DPG hooks rather than install.
    pub uninstall: bool,
    /// If true, reports planned changes without writing to disk.
    pub dry_run: bool,
    /// Optional override for the settings directory (defaults to `~/.claude`).
    pub settings_dir: Option<PathBuf>,
}

/// Diagnostic report returned by the install/uninstall command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    /// Path of the modified settings file.
    pub settings_path: PathBuf,
    /// Path of the timestamped backup file if created.
    pub backup_path: Option<PathBuf>,
    /// Summary of actions taken.
    pub action: String,
    /// Whether any changes were applied.
    pub changed: bool,
}

/// Resolves the Claude Code settings directory (e.g. `~/.claude`).
pub fn resolve_claude_settings_dir(custom: Option<&Path>) -> Result<PathBuf, DpgError> {
    if let Some(dir) = custom {
        return Ok(dir.to_path_buf());
    }

    let home = directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .ok_or_else(|| DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Could not determine user home directory"),
        })?;

    Ok(home.join(".claude"))
}

/// Installs or uninstalls DPG hooks into Claude Code user settings (`~/.claude/settings.json`).
pub fn install_claude_code(opts: &InstallOptions) -> Result<InstallReport, DpgError> {
    let settings_dir = resolve_claude_settings_dir(opts.settings_dir.as_deref())?;
    let settings_path = settings_dir.join("settings.json");

    if opts.uninstall {
        return uninstall_claude_code(&settings_path, opts.dry_run);
    }

    // Ensure settings directory exists
    if !opts.dry_run && !settings_dir.exists() {
        fs::create_dir_all(&settings_dir).map_err(|_| DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Failed to create .claude directory"),
        })?;
    }

    // Read or initialize settings JSON
    let mut settings: Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path).map_err(|_| DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Failed to read settings.json"),
        })?;

        serde_json::from_str(&content).map_err(|_| DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Invalid JSON in existing settings.json; refusing to overwrite"),
        })?
    } else {
        json!({})
    };

    if !settings.is_object() {
        return Err(DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Existing settings.json root is not a JSON object"),
        });
    }

    // Make timestamped backup before any modifications
    let mut backup_path = None;
    if settings_path.exists() && !opts.dry_run {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let b_path = settings_dir.join(format!("settings.json.backup.{ts}"));
        fs::copy(&settings_path, &b_path).map_err(|_| DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Failed to create timestamped backup of settings.json"),
        })?;
        backup_path = Some(b_path);
    }

    // 1. Merge env flag: CLAUDE_CODE_DISABLE_FILE_MENTIONS = "1"
    if let Some(settings_obj) = settings.as_object_mut() {
        let env_map = settings_obj
            .entry("env")
            .or_insert_with(|| json!({}));

        if let Some(env_obj) = env_map.as_object_mut() {
            env_obj.insert(
                "CLAUDE_CODE_DISABLE_FILE_MENTIONS".to_string(),
                json!("1"),
            );
        }

        // 2. Merge hooks
        let hooks_map = settings_obj
            .entry("hooks")
            .or_insert_with(|| json!({}));

        if let Some(hooks_obj) = hooks_map.as_object_mut() {
            // PostToolUse hook
            let post_entry = json!({
                "matcher": "*",
                "hooks": [
                    {
                        "type": "command",
                        "command": "dpg hook post-tool-use",
                        "timeout": 10,
                        "onFailure": "block"
                    }
                ]
            });
            merge_hook_matcher_entry(hooks_obj, "PostToolUse", post_entry);

            // PreToolUse hook
            let pre_entry = json!({
                "matcher": "*",
                "hooks": [
                    {
                        "type": "command",
                        "command": "dpg hook pre-tool-use",
                        "timeout": 10,
                        "onFailure": "block"
                    }
                ]
            });
            merge_hook_matcher_entry(hooks_obj, "PreToolUse", pre_entry);

            // UserPromptSubmit hook
            let prompt_entry = json!({
                "hooks": [
                    {
                        "type": "command",
                        "command": "dpg hook user-prompt-submit",
                        "timeout": 10,
                        "onFailure": "block"
                    }
                ]
            });
            merge_hook_simple_entry(hooks_obj, "UserPromptSubmit", prompt_entry);
        }
    }

    let serialized = serde_json::to_string_pretty(&settings).map_err(|_| {
        DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Failed to serialize updated settings.json"),
        }
    })?;

    if !opts.dry_run {
        fs::write(&settings_path, &serialized).map_err(|_| DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Failed to write updated settings.json"),
        })?;
    }

    Ok(InstallReport {
        settings_path,
        backup_path,
        action: if opts.dry_run {
            "dry-run install".to_string()
        } else {
            "installed".to_string()
        },
        changed: true,
    })
}

fn merge_hook_matcher_entry(hooks_obj: &mut serde_json::Map<String, Value>, event: &str, new_entry: Value) {
    let arr = hooks_obj.entry(event).or_insert_with(|| json!([]));
    if let Some(list) = arr.as_array_mut() {
        // Check if command already exists
        let already_present = list.iter().any(|item| {
            if let Some(hooks) = item.get("hooks").and_then(|h| h.as_array()) {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(|c| c.as_str())
                        .map(|c| c.contains("dpg hook"))
                        .unwrap_or(false)
                })
            } else {
                false
            }
        });

        if !already_present {
            list.push(new_entry);
        }
    }
}

fn merge_hook_simple_entry(hooks_obj: &mut serde_json::Map<String, Value>, event: &str, new_entry: Value) {
    let arr = hooks_obj.entry(event).or_insert_with(|| json!([]));
    if let Some(list) = arr.as_array_mut() {
        let already_present = list.iter().any(|item| {
            if let Some(hooks) = item.get("hooks").and_then(|h| h.as_array()) {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(|c| c.as_str())
                        .map(|c| c.contains("dpg hook"))
                        .unwrap_or(false)
                })
            } else {
                false
            }
        });

        if !already_present {
            list.push(new_entry);
        }
    }
}

fn uninstall_claude_code(settings_path: &Path, dry_run: bool) -> Result<InstallReport, DpgError> {
    if !settings_path.exists() {
        return Ok(InstallReport {
            settings_path: settings_path.to_path_buf(),
            backup_path: None,
            action: "settings file does not exist, nothing to uninstall".to_string(),
            changed: false,
        });
    }

    let content = fs::read_to_string(settings_path).map_err(|_| DpgError::Integration {
        code: ErrorCode::I001,
        detail: SafeDetail::from_static("Failed to read settings.json for uninstall"),
    })?;

    let mut settings: Value = serde_json::from_str(&content).map_err(|_| DpgError::Integration {
        code: ErrorCode::I001,
        detail: SafeDetail::from_static("Invalid JSON in settings.json during uninstall"),
    })?;

    let mut changed = false;

    // Filter DPG hooks out of hooks arrays
    if let Some(hooks_obj) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        for (_, val) in hooks_obj.iter_mut() {
            if let Some(list) = val.as_array_mut() {
                let initial_len = list.len();
                list.retain(|item| {
                    if let Some(hooks) = item.get("hooks").and_then(|h| h.as_array()) {
                        !hooks.iter().any(|h| {
                            h.get("command")
                                .and_then(|c| c.as_str())
                                .map(|c| c.contains("dpg hook"))
                                .unwrap_or(false)
                        })
                    } else {
                        true
                    }
                });
                if list.len() != initial_len {
                    changed = true;
                }
            }
        }
    }

    // Remove CLAUDE_CODE_DISABLE_FILE_MENTIONS if present
    if let Some(env_obj) = settings.get_mut("env").and_then(|e| e.as_object_mut()) {
        if env_obj.remove("CLAUDE_CODE_DISABLE_FILE_MENTIONS").is_some() {
            changed = true;
        }
    }

    if changed && !dry_run {
        let serialized = serde_json::to_string_pretty(&settings).map_err(|_| DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Failed to serialize settings.json after uninstall"),
        })?;
        fs::write(settings_path, serialized).map_err(|_| DpgError::Integration {
            code: ErrorCode::I001,
            detail: SafeDetail::from_static("Failed to write settings.json after uninstall"),
        })?;
    }

    Ok(InstallReport {
        settings_path: settings_path.to_path_buf(),
        backup_path: None,
        action: if dry_run {
            "dry-run uninstall".to_string()
        } else {
            "uninstalled".to_string()
        },
        changed,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_installer_idempotency_and_uninstall() {
        let temp = tempfile::tempdir().expect("tempdir");
        let settings_dir = temp.path().to_path_buf();
        let settings_path = settings_dir.join("settings.json");

        // Initial existing user configuration
        let initial_json = json!({
            "env": {
                "USER_CUSTOM_ENV": "value"
            },
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "custom",
                        "hooks": [{ "command": "my-custom-tool" }]
                    }
                ]
            }
        });
        fs::write(&settings_path, serde_json::to_string_pretty(&initial_json).unwrap()).unwrap();

        let opts = InstallOptions {
            uninstall: false,
            dry_run: false,
            settings_dir: Some(settings_dir.clone()),
        };

        // 1. First install
        let report1 = install_claude_code(&opts).expect("install 1");
        assert!(report1.changed);
        assert!(report1.backup_path.is_some());

        let content1 = fs::read_to_string(&settings_path).unwrap();
        assert!(content1.contains("dpg hook post-tool-use"));
        assert!(content1.contains("dpg hook pre-tool-use"));
        assert!(content1.contains("dpg hook user-prompt-submit"));
        assert!(content1.contains("CLAUDE_CODE_DISABLE_FILE_MENTIONS"));
        assert!(content1.contains("my-custom-tool")); // preserved!

        // 2. Second install: must be 100% idempotent
        let _report2 = install_claude_code(&opts).expect("install 2");
        let content2 = fs::read_to_string(&settings_path).unwrap();

        // Count occurrences of dpg hook
        let count = content2.matches("dpg hook post-tool-use").count();
        assert_eq!(count, 1, "Idempotency: hook must not be duplicated");

        // 3. Uninstall: restores file without DPG hooks
        let uninstall_opts = InstallOptions {
            uninstall: true,
            dry_run: false,
            settings_dir: Some(settings_dir),
        };
        let report3 = install_claude_code(&uninstall_opts).expect("uninstall");
        assert!(report3.changed);

        let content3 = fs::read_to_string(&settings_path).unwrap();
        assert!(!content3.contains("dpg hook"));
        assert!(!content3.contains("CLAUDE_CODE_DISABLE_FILE_MENTIONS"));
        assert!(content3.contains("my-custom-tool")); // preserved!
    }

    #[test]
    fn test_installer_refuses_invalid_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let settings_path = temp.path().join("settings.json");
        fs::write(&settings_path, "invalid { syntax JSON").unwrap();

        let opts = InstallOptions {
            uninstall: false,
            dry_run: false,
            settings_dir: Some(temp.path().to_path_buf()),
        };

        let err = install_claude_code(&opts).expect_err("Must refuse invalid JSON");
        assert_eq!(err.code(), ErrorCode::I001);
    }
}
