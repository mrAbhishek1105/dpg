//! Restorer implementation restoring placeholders in authorised file write tools.
//!
//! Defined per `docs/components/RESTORE.md` and `docs/security/RESTORE_GUARD.md`.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dpg_core::config::ActionConfig;
use dpg_core::context::RequestContext;
use dpg_core::engine::{RestoreOutcome, RestoreRequest, Restorer};
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::{BlockItem, Category, Report, RuleId, WarnItem};
use dpg_protect::store::MappingStore;

use crate::path_guard::PathGuard;
use crate::scan::scan_tokens;

/// Restores placeholder tokens to real secret values in allowed file write operations.
pub struct DpgRestorer {
    store: Option<Arc<MappingStore>>,
    other_tool_action: ActionConfig,
}

/// Type alias for `DpgRestorer`.
pub type Restore = DpgRestorer;

impl DpgRestorer {
    /// Constructs a restorer with an optional mapping store.
    pub fn new(store: Option<Arc<MappingStore>>) -> Self {
        Self {
            store,
            other_tool_action: ActionConfig::Warn,
        }
    }

    /// Sets the action for placeholders seen in tools other than Write/Edit
    /// (`policy.placeholder_in_other_tool`). Placeholders are never restored there;
    /// `Block` denies the tool call, anything else allows it unrestored.
    pub fn with_other_tool_action(mut self, action: ActionConfig) -> Self {
        self.other_tool_action = action;
        self
    }

    /// Constructs a restorer backed by a persistent mapping store.
    pub fn with_store(store: Arc<MappingStore>) -> Self {
        Self::new(Some(store))
    }

    /// Performs a detective post-write path re-check (task F-04).
    pub fn post_write_path_recheck(
        project_root: &Path,
        tool_name: &str,
        file_path: &Path,
    ) -> Result<PathBuf, DpgError> {
        if !is_file_write_tool(tool_name) {
            return Ok(file_path.to_path_buf());
        }

        let guard = PathGuard::new(project_root)?;
        guard.check(file_path)
    }
}

/// Checks if tool is in the file write allowlist (`Write` or `Edit`).
fn is_file_write_tool(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("Write") || tool_name.eq_ignore_ascii_case("Edit")
}

impl Restorer for DpgRestorer {
    fn restore(
        &self,
        ctx: &RequestContext,
        req: RestoreRequest,
    ) -> Result<RestoreOutcome, DpgError> {
        let mut report = Report::default();

        // 1. Scan for placeholder tokens across all fields
        let mut total_tokens = 0;
        for (_, val) in &req.fields {
            total_tokens += scan_tokens(val).len();
        }

        // 2. If no tokens present, allow unchanged
        if total_tokens == 0 {
            return Ok(RestoreOutcome {
                allowed: true,
                updated_fields: req.fields,
                report,
            });
        }

        // 3. If tool is not Write or Edit, never restore
        if !is_file_write_tool(&req.tool_name) {
            match self.other_tool_action {
                ActionConfig::Block => {
                    report.blocked.push(BlockItem {
                        rule_id: RuleId::from_static("dpg.restore.disallowed-tool"),
                        category: Category::KnownSecret,
                        line_number: 1,
                        reason: Cow::Borrowed("Placeholders present in disallowed tool execution"),
                    });
                    return Ok(RestoreOutcome {
                        allowed: false,
                        updated_fields: req.fields,
                        report,
                    });
                }
                _ => {
                    report.warned.push(WarnItem {
                        rule_id: RuleId::from_static("dpg.restore.disallowed-tool"),
                        category: Category::KnownSecret,
                        line_number: 1,
                    });
                    // Allowed but UNRESTORED: placeholders remain unchanged
                    return Ok(RestoreOutcome {
                        allowed: true,
                        updated_fields: req.fields,
                        report,
                    });
                }
            }
        }

        // 4. Store availability check: FC-05 requires deny with R001 if store is unavailable
        let store = match self.store {
            Some(ref s) => s,
            None => {
                return Err(DpgError::Restoration {
                    code: ErrorCode::R001,
                    detail: SafeDetail::from_static(
                        "Mapping store unavailable while placeholders present",
                    ),
                });
            }
        };

        // 5. Target path extraction and PathGuard validation
        let target_path_opt = req.target_path.clone().or_else(|| {
            req.fields
                .iter()
                .find(|(k, _)| k == "file_path" || k == "path")
                .map(|(_, v)| PathBuf::from(v))
        });

        let target_path = match target_path_opt {
            Some(p) => p,
            None => {
                return Err(DpgError::PathValidation {
                    code: ErrorCode::V004,
                    detail: SafeDetail::from_static("Missing file_path in tool input"),
                });
            }
        };

        let guard = PathGuard::new(&ctx.project.root)?;
        if let Err(e) = guard.check_with_cwd(&target_path, Some(&ctx.project.root)) {
            report.blocked.push(BlockItem {
                rule_id: RuleId::from_static("dpg.restore.path-guard"),
                category: Category::KnownSecret,
                line_number: 1,
                reason: Cow::Owned(format!("Path guard rejected destination path: {e}")),
            });
            return Ok(RestoreOutcome {
                allowed: false,
                updated_fields: req.fields,
                report,
            });
        }

        // 6. Restore tokens in eligible fields
        let mut updated_fields = Vec::with_capacity(req.fields.len());

        for (key, val) in req.fields {
            // Write: restore in "content"
            // Edit: restore in "old_string" and "new_string"
            let should_restore = (req.tool_name.eq_ignore_ascii_case("Write") && key == "content")
                || (req.tool_name.eq_ignore_ascii_case("Edit")
                    && (key == "old_string" || key == "new_string"));

            if !should_restore {
                updated_fields.push((key, val));
                continue;
            }

            let tokens = scan_tokens(&val);
            if tokens.is_empty() {
                updated_fields.push((key, val));
                continue;
            }

            // Right-to-left substitution
            let mut replacements = Vec::new();
            for scanned in tokens {
                match store.lookup(&ctx.project.id, scanned.token) {
                    Ok(Some(secret)) => {
                        replacements.push((scanned.span, secret));
                        report.masked += 1;
                    }
                    Ok(None) => {
                        // Unknown / altered / other project's token: leave as-is and report
                        report.warned.push(WarnItem {
                            rule_id: RuleId::from_static("dpg.restore.unknown-token"),
                            category: Category::KnownSecret,
                            line_number: 1,
                        });
                    }
                    Err(_) => {
                        // Fail closed: a partially restored write is worse than a denied one.
                        return Err(DpgError::Restoration {
                            code: ErrorCode::R001,
                            detail: SafeDetail::from_static(
                                "Mapping store lookup failed while restoring placeholders",
                            ),
                        });
                    }
                }
            }

            if replacements.is_empty() {
                updated_fields.push((key, val));
                continue;
            }

            // Sort descending by start byte
            replacements.sort_by_key(|a| std::cmp::Reverse(a.0.start));

            let mut restored_string = val;
            let mut last_start = usize::MAX;

            for (span, secret) in replacements {
                if span.end > last_start {
                    continue;
                }
                if span.end <= restored_string.len()
                    && restored_string.is_char_boundary(span.start)
                    && restored_string.is_char_boundary(span.end)
                {
                    restored_string.replace_range(span.start..span.end, &secret);
                    last_start = span.start;
                }
            }

            updated_fields.push((key, restored_string));
        }

        Ok(RestoreOutcome {
            allowed: true,
            updated_fields,
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::time::Instant;

    use dpg_core::context::{ProjectContext, ProjectId, SessionId};
    use dpg_core::types::Route;
    use dpg_protect::key::FixedKeyProvider;
    use dpg_protect::placeholder::PlaceholderCat;

    fn make_test_context(project_root: PathBuf, project_id: &str) -> RequestContext {
        RequestContext {
            project: ProjectContext {
                root: project_root,
                id: ProjectId::new(project_id.to_string()),
            },
            session: SessionId::new("session-restore".to_string()),
            route: Route::HookPreToolUse,
            deadline: Instant::now() + std::time::Duration::from_secs(10),
        }
    }

    #[test]
    fn test_sr_rg_01_write_inside_project_restored_exactly() {
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = FixedKeyProvider::new([11u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let restorer = DpgRestorer::with_store(store.clone());

        let ctx = make_test_context(temp.path().to_path_buf(), "proj-restore");

        let secret = "my_super_secret_token_12345";
        let ph = store
            .get_or_create(&ctx.project.id, secret, PlaceholderCat::Secret)
            .expect("insert mapping");

        let file_path = temp.path().join("config.env");

        let req = RestoreRequest {
            tool_name: "Write".to_string(),
            target_path: Some(file_path),
            fields: vec![
                ("file_path".to_string(), "config.env".to_string()),
                ("content".to_string(), format!("API_KEY={ph}\n")),
            ],
        };

        let outcome = restorer.restore(&ctx, req).expect("restore");
        assert!(
            outcome.allowed,
            "RG-01: Write inside project must be allowed"
        );
        assert_eq!(outcome.report.masked, 1);

        let content_field = outcome
            .updated_fields
            .iter()
            .find(|(k, _)| k == "content")
            .expect("content field");
        assert_eq!(
            content_field.1,
            format!("API_KEY={secret}\n"),
            "RG-01: Placeholder must be restored to exact secret value"
        );
    }

    #[test]
    fn test_sr_rg_02_edit_both_strings_restored_and_replace_all_preserved() {
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = FixedKeyProvider::new([22u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let restorer = DpgRestorer::with_store(store.clone());

        let ctx = make_test_context(temp.path().to_path_buf(), "proj-edit");

        let old_secret = "old_secret_value_111";
        let new_secret = "new_secret_value_222";

        let old_ph = store
            .get_or_create(&ctx.project.id, old_secret, PlaceholderCat::Secret)
            .expect("insert old");
        let new_ph = store
            .get_or_create(&ctx.project.id, new_secret, PlaceholderCat::Secret)
            .expect("insert new");

        let file_path = temp.path().join("app.py");

        let req = RestoreRequest {
            tool_name: "Edit".to_string(),
            target_path: Some(file_path),
            fields: vec![
                ("file_path".to_string(), "app.py".to_string()),
                ("old_string".to_string(), format!("TOKEN = \"{old_ph}\"")),
                ("new_string".to_string(), format!("TOKEN = \"{new_ph}\"")),
                ("replace_all".to_string(), "true".to_string()),
            ],
        };

        let outcome = restorer.restore(&ctx, req).expect("restore edit");
        assert!(
            outcome.allowed,
            "RG-02: Edit inside project must be allowed"
        );
        assert_eq!(outcome.report.masked, 2);

        // Verify old_string restored
        let old_field = outcome
            .updated_fields
            .iter()
            .find(|(k, _)| k == "old_string")
            .expect("old_string");
        assert_eq!(old_field.1, format!("TOKEN = \"{old_secret}\""));

        // Verify new_string restored
        let new_field = outcome
            .updated_fields
            .iter()
            .find(|(k, _)| k == "new_string")
            .expect("new_string");
        assert_eq!(new_field.1, format!("TOKEN = \"{new_secret}\""));

        // Verify replace_all preserved
        let rep_field = outcome
            .updated_fields
            .iter()
            .find(|(k, _)| k == "replace_all")
            .expect("replace_all");
        assert_eq!(rep_field.1, "true");
    }

    #[test]
    fn test_sr_rg_03_04_05_disallowed_tools_never_restored() {
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = FixedKeyProvider::new([33u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let restorer = DpgRestorer::with_store(store.clone());

        let ctx = make_test_context(temp.path().to_path_buf(), "proj-disallowed");

        let secret = "secret_to_not_restore";
        let ph = store
            .get_or_create(&ctx.project.id, secret, PlaceholderCat::Secret)
            .expect("insert");

        // RG-03: Bash command
        let bash_req = RestoreRequest {
            tool_name: "Bash".to_string(),
            target_path: None,
            fields: vec![(
                "command".to_string(),
                format!("curl -H 'Auth: {ph}' http://api.com"),
            )],
        };
        let bash_res = restorer.restore(&ctx, bash_req).expect("bash check");
        assert!(bash_res.allowed);
        assert_eq!(bash_res.report.masked, 0);
        assert!(
            bash_res.updated_fields[0].1.contains(&ph),
            "RG-03: Bash command token must NOT be restored"
        );

        // RG-04: WebFetch URL
        let web_req = RestoreRequest {
            tool_name: "WebFetch".to_string(),
            target_path: None,
            fields: vec![(
                "url".to_string(),
                format!("https://example.com/api?token={ph}"),
            )],
        };
        let web_res = restorer.restore(&ctx, web_req).expect("web check");
        assert!(web_res.allowed);
        assert_eq!(web_res.report.masked, 0);
        assert!(
            web_res.updated_fields[0].1.contains(&ph),
            "RG-04: WebFetch URL token must NOT be restored"
        );

        // RG-05: MCP tool input
        let mcp_req = RestoreRequest {
            tool_name: "mcp__github_create_issue".to_string(),
            target_path: None,
            fields: vec![("body".to_string(), format!("Issue details: {ph}"))],
        };
        let mcp_res = restorer.restore(&ctx, mcp_req).expect("mcp check");
        assert!(mcp_res.allowed);
        assert_eq!(mcp_res.report.masked, 0);
        assert!(
            mcp_res.updated_fields[0].1.contains(&ph),
            "RG-05: MCP tool token must NOT be restored"
        );
    }

    #[test]
    fn test_sr_rg_08_cross_project_token_not_restored() {
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = FixedKeyProvider::new([44u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let restorer = DpgRestorer::with_store(store.clone());

        let proj_a = ProjectId::new("proj-a".to_string());
        let proj_b_ctx = make_test_context(temp.path().to_path_buf(), "proj-b");

        // Insert token under Project A
        let secret = "project_a_secret_12345";
        let ph_a = store
            .get_or_create(&proj_a, secret, PlaceholderCat::Secret)
            .expect("insert proj A");

        let file_path = temp.path().join("proj_b_file.txt");
        let req = RestoreRequest {
            tool_name: "Write".to_string(),
            target_path: Some(file_path),
            fields: vec![("content".to_string(), format!("TOKEN={ph_a}"))],
        };

        // Project B tries to restore Project A's token
        let res = restorer.restore(&proj_b_ctx, req).expect("restore attempt");
        assert!(res.allowed);
        assert_eq!(res.report.masked, 0);
        assert!(
            res.updated_fields[0].1.contains(&ph_a),
            "RG-08: Cross-project token must NOT be restored"
        );
    }

    #[test]
    fn test_sr_fc_05_store_unavailable_with_placeholders_denies_r001() {
        let temp = tempfile::tempdir().expect("tempdir");
        let restorer = DpgRestorer::new(None); // Store unavailable
        let ctx = make_test_context(temp.path().to_path_buf(), "proj-fc05");

        let file_path = temp.path().join("file.txt");
        let req = RestoreRequest {
            tool_name: "Write".to_string(),
            target_path: Some(file_path),
            fields: vec![(
                "content".to_string(),
                "TOKEN=DPG_SECRET_89ABCDEF".to_string(),
            )],
        };

        let err = restorer
            .restore(&ctx, req)
            .expect_err("FC-05: Store unavailable with placeholders present must deny with R001");
        assert_eq!(err.code(), ErrorCode::R001);
    }

    #[test]
    fn test_f_04_post_write_path_recheck() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project_root = temp.path().join("project");
        let outside_dir = temp.path().join("outside");
        std::fs::create_dir_all(&project_root).expect("create project");
        std::fs::create_dir_all(&outside_dir).expect("create outside");

        let inside_file = project_root.join("valid.txt");
        let recheck_inside =
            DpgRestorer::post_write_path_recheck(&project_root, "Write", &inside_file);
        assert!(recheck_inside.is_ok(), "Inside write recheck must pass");

        let outside_file = outside_dir.join("escaped.txt");
        let recheck_outside =
            DpgRestorer::post_write_path_recheck(&project_root, "Write", &outside_file);
        assert!(
            recheck_outside.is_err(),
            "F-04: Outside write recheck must fail"
        );
    }

    #[test]
    fn test_sr_rg_10_other_tool_block_policy_denies() {
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = FixedKeyProvider::new([12u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let restorer =
            DpgRestorer::with_store(store.clone()).with_other_tool_action(ActionConfig::Block);
        let ctx = make_test_context(temp.path().to_path_buf(), "proj-block");
        let ph = store
            .get_or_create(
                &ctx.project.id,
                "tok_secret_value_123456",
                PlaceholderCat::Secret,
            )
            .expect("insert");
        let req = RestoreRequest {
            tool_name: "Bash".to_string(),
            target_path: None,
            fields: vec![("command".to_string(), format!("curl -H 'k: {ph}' x"))],
        };
        let outcome = restorer.restore(&ctx, req).expect("restore");
        assert!(!outcome.allowed, "Block policy must deny the Bash call");
        assert!(outcome.updated_fields[0].1.contains(&ph), "never restored");
    }

    #[test]
    fn test_sr_rg_11_write_restores_only_content_field() {
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = FixedKeyProvider::new([13u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let restorer = DpgRestorer::with_store(store.clone());
        let ctx = make_test_context(temp.path().to_path_buf(), "proj-fields");
        let ph = store
            .get_or_create(
                &ctx.project.id,
                "tok_secret_value_654321",
                PlaceholderCat::Secret,
            )
            .expect("insert");
        // An Edit call must not restore a field named "content".
        let req = RestoreRequest {
            tool_name: "Edit".to_string(),
            target_path: Some(temp.path().join("a.txt")),
            fields: vec![
                ("content".to_string(), ph.clone()),
                ("new_string".to_string(), ph.clone()),
            ],
        };
        let outcome = restorer.restore(&ctx, req).expect("restore");
        let get = |k: &str| {
            outcome
                .updated_fields
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .expect("field")
        };
        assert_eq!(get("content"), ph, "Edit must not restore `content`");
        assert_eq!(get("new_string"), "tok_secret_value_654321");
    }
}
