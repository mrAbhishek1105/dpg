//! Shared composition root: resolves the project, loads configuration, opens the
//! mapping store, and wires a fully configured [`Engine`].
//!
//! Every entry point (hook, proxy, CLI) builds its engine here so that project
//! identity, `.dpg.toml` policy, custom terms/rules and the key backend behave the
//! same way everywhere.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dpg_core::config::{load_config, Config, ConfigWarning, LoadOptions};
use dpg_core::context::{resolve_project, ProjectContext, RequestContext, SessionId};
use dpg_core::engine::Engine;
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::Route;
use dpg_detect::{DpgDetector, Rule, RuleDef, RuleSource};
use dpg_policy::ignore::{IgnoreList, InMemoryIgnoreList};
use dpg_policy::DpgPolicy;
use dpg_protect::key::{resolve_master_key, FixedKeyProvider, KeyBackend};
use dpg_protect::store::MappingStore;
use dpg_protect::DpgProtector;
use dpg_restore::DpgRestorer;
use zeroize::Zeroizing;

/// File name of the mapping database inside the data directory.
pub const MAPPING_DB_FILE: &str = "mapping.db";

/// Returns the DPG data directory (`DPG_DATA_DIR` overrides the platform default).
pub fn data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("DPG_DATA_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p.trim());
        }
    }
    directories::ProjectDirs::from("com", "dpg", "dpg")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".dpg"))
}

/// Options for [`Runtime::build`].
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// Working directory used to locate the project root (`.git` / `.dpg.toml`).
    pub cwd: PathBuf,
    /// DPG data directory (mapping DB, file key). Defaults to [`data_dir`].
    pub data_dir: PathBuf,
    /// Optional global config path override (tests).
    pub global_config: Option<PathBuf>,
}

impl RuntimeOptions {
    /// Default options for the given working directory.
    pub fn for_cwd(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            data_dir: data_dir(),
            global_config: None,
        }
    }
}

/// A fully wired DPG runtime for one project.
pub struct Runtime {
    /// Configured engine.
    pub engine: Arc<Engine>,
    /// Persistent mapping store, if it could be opened.
    pub store: Option<Arc<MappingStore>>,
    /// Effective (merged, validated) configuration.
    pub config: Arc<Config>,
    /// Resolved project (canonical root + HMAC project id).
    pub project: ProjectContext,
    /// Backend that supplied the master key.
    pub key_backend: KeyBackend,
    /// Non-fatal configuration warnings (e.g. ignored loosening attempts).
    pub warnings: Vec<ConfigWarning>,
    /// Why the store is unavailable (`None` when it opened).
    pub store_error: Option<DpgError>,
    /// HMAC key for ignore-list fingerprints.
    ignore_key: Zeroizing<[u8; 32]>,
    /// Loopback proxy path token (derived from the master key).
    proxy_token: Zeroizing<String>,
}

fn derive(master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = match <Hmac<sha2::Sha256> as Mac>::new_from_slice(master) {
        Ok(m) => m,
        Err(_) => unreachable!("HMAC-SHA256 accepts 32-byte keys"),
    };
    mac.update(label);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Compiles `[[rules]]` from configuration into project rules.
pub fn compile_project_rules(config: &Config) -> Result<Vec<Rule>, DpgError> {
    config
        .rules
        .iter()
        .map(|r| {
            Rule::from_def(
                RuleDef {
                    id: r.id.clone(),
                    category: r.category.clone(),
                    confidence: None,
                    keywords: Vec::new(),
                    regex: r.regex.clone(),
                    secret_group: None,
                    entropy_min: None,
                    validator: None,
                },
                RuleSource::Project,
            )
        })
        .collect()
}

impl Runtime {
    /// Builds the runtime. Fails closed on configuration, key, or detector errors.
    ///
    /// A mapping store that cannot be opened is *not* fatal: masking then uses
    /// ephemeral placeholders (still safe: originals never leave), restoration is
    /// denied with `DPG-R001`, and `store_error` records why.
    pub fn build(opts: &RuntimeOptions) -> Result<Self, DpgError> {
        let db_path = opts.data_dir.join(MAPPING_DB_FILE);

        // 1. Project root (needed before config, since `.dpg.toml` lives there).
        //    The id is derived after the key is available; root resolution itself
        //    does not need a key, so use a throwaway key here.
        let provisional = resolve_project(&opts.cwd, &FixedKeyProvider::new([0u8; 32]))?;

        // 2. Configuration: global -> project (tighten-only) -> env -> validate.
        let (config, warnings) = load_config(&LoadOptions {
            project_root: Some(provisional.root.clone()),
            custom_global_path: opts.global_config.clone(),
            ..LoadOptions::default()
        })?;

        // 3. Master key. Never mint a new key over an existing database.
        let allow_create = !db_path.exists();
        let (master, key_backend) =
            resolve_master_key(&config.storage.key_backend, &opts.data_dir, allow_create)?;

        // 4. Project identity: HMAC(project-id key, canonical root).
        let project_key = derive(&master, b"dpg/project-id/v1");
        let project = resolve_project(&opts.cwd, &FixedKeyProvider::new(project_key))?;

        // 5. Store (non-fatal; see doc comment).
        let (store, store_error) =
            match MappingStore::open(&db_path, &FixedKeyProvider::new(*master)) {
                Ok(s) => {
                    // Expire mappings unused for `storage.expiry_days` (best effort).
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    if config.storage.expiry_days > 0 && now > 0 {
                        let _ = s.purge_expired(now, config.storage.expiry_days);
                    }
                    (Some(Arc::new(s)), None)
                }
                Err(e) => (None, Some(e)),
            };

        // 6. Detector with project terms and rules.
        let detector = DpgDetector::new()?
            .with_custom_terms(&config.terms.values)?
            .with_project_rules(compile_project_rules(&config)?)?;

        // 7. Policy with persistent ignore list.
        let ignore_key = Zeroizing::new(match store {
            Some(ref s) => s.ignore_fingerprint_key(),
            None => derive(&master, b"dpg/ignore/v1"),
        });
        let ignore_list: Arc<dyn IgnoreList> = match store {
            Some(ref s) => s.clone(),
            None => Arc::new(InMemoryIgnoreList::new()),
        };
        let policy = DpgPolicy::new(
            config.policy.clone(),
            HashMap::new(),
            ignore_list,
            *ignore_key,
        );

        // 8. Protector / restorer.
        let protector = DpgProtector::new(store.clone());
        let restorer = DpgRestorer::new(store.clone())
            .with_other_tool_action(config.policy.placeholder_in_other_tool);

        // 9. Metadata-only event log (counts, route, HMAC project id; never values).
        let event_log = if config.log.events {
            dpg_core::event::EventLog::open(
                opts.data_dir.join("events.jsonl"),
                config.log.max_file_bytes,
                3,
            )
            .ok()
            .map(Arc::new)
        } else {
            None
        };

        let config = Arc::new(config);
        let engine = Engine::new(
            Arc::new(detector),
            Arc::new(policy),
            Arc::new(protector),
            Arc::new(restorer),
            config.clone(),
            event_log,
        );

        let token_bytes = Zeroizing::new(derive(&master, b"dpg/proxy-token/v1"));
        let proxy_token = Zeroizing::new(
            token_bytes
                .iter()
                .map(|b| dpg_protect::CROCKFORD_BASE32[(*b as usize) % 32] as char)
                .collect::<String>(),
        );

        Ok(Self {
            engine: Arc::new(engine),
            store,
            config,
            project,
            key_backend,
            warnings,
            store_error,
            ignore_key,
            proxy_token,
        })
    }

    /// Key used to fingerprint ignore-list entries (`dpg ignore`).
    pub fn ignore_key(&self) -> &[u8; 32] {
        &self.ignore_key
    }

    /// Path token the loopback proxy requires (`/t/<token>/...`): 32 Crockford
    /// base32 characters (160 bits), stable for this master key.
    pub fn proxy_token(&self) -> &str {
        &self.proxy_token
    }

    /// Internal deadline for a hook invocation: `timeout_seconds * internal_deadline_ratio`.
    pub fn hook_deadline(&self) -> Instant {
        let secs =
            self.config.hook.timeout_seconds as f64 * self.config.hook.internal_deadline_ratio;
        let secs = if secs.is_finite() && secs > 0.0 {
            secs
        } else {
            8.0
        };
        Instant::now() + Duration::from_secs_f64(secs)
    }

    /// Builds a request context for this project.
    pub fn context(
        &self,
        route: Route,
        session: impl Into<String>,
        deadline: Instant,
    ) -> RequestContext {
        RequestContext {
            project: self.project.clone(),
            session: SessionId::new(session.into()),
            route,
            deadline,
        }
    }
}

/// Convenience error for a missing mapping store where one is required.
pub fn store_required_error() -> DpgError {
    DpgError::MappingStore {
        code: ErrorCode::M001,
        detail: SafeDetail::from_static("Mapping store unavailable"),
    }
}

/// Re-export for callers that only need the path helper.
pub fn mapping_db_path(dir: &Path) -> PathBuf {
    dir.join(MAPPING_DB_FILE)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use dpg_core::engine::RestoreRequest;
    use dpg_core::types::ProtectOutcome;

    fn opts(project: &Path, data: &Path) -> RuntimeOptions {
        RuntimeOptions {
            cwd: project.to_path_buf(),
            data_dir: data.to_path_buf(),
            global_config: Some(data.join("no-global.toml")),
        }
    }

    fn file_backend(data: &Path) {
        // Force the file backend so tests never touch the real OS keychain.
        std::fs::create_dir_all(data).unwrap();
        std::fs::write(
            data.join("no-global.toml"),
            "[storage]\nkey_backend = \"file\"\n",
        )
        .unwrap();
    }

    #[test]
    fn project_id_is_hmac_of_git_root_and_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(proj.join(".git")).unwrap();
        std::fs::create_dir_all(proj.join("src/deep")).unwrap();
        let data = tmp.path().join("data");
        file_backend(&data);

        let a = Runtime::build(&opts(&proj, &data)).unwrap();
        let b = Runtime::build(&opts(&proj.join("src/deep"), &data)).unwrap();
        assert_eq!(
            a.project.id, b.project.id,
            "subdir resolves to the git root"
        );
        assert_eq!(a.project.root, dunce::canonicalize(&proj).unwrap());
        assert_eq!(a.project.id.as_str().len(), 32);
        assert!(a.store.is_some());
    }

    #[test]
    fn project_dpg_toml_terms_and_rules_are_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(proj.join(".git")).unwrap();
        std::fs::write(
            proj.join(".dpg.toml"),
            "[terms]\nvalues = [\"project-falcon\"]\n\n[[rules]]\nid = \"acme.tok\"\ncategory = \"KnownSecret\"\nregex = \"acme_tok_[a-z0-9]{32}\"\n",
        )
        .unwrap();
        let data = tmp.path().join("data");
        file_backend(&data);
        let rt = Runtime::build(&opts(&proj, &data)).unwrap();
        let ctx = rt.context(
            Route::HookPostToolUse,
            "s",
            Instant::now() + Duration::from_secs(10),
        );
        let text = "codename project-falcon key acme_tok_0123456789abcdefghijklmnopqrstuv";
        match rt.engine.protect(&ctx, text).unwrap() {
            ProtectOutcome::Allowed { text: masked, .. } => {
                assert!(!masked.contains("project-falcon"), "custom term masked");
                assert!(
                    !masked.contains("acme_tok_0123456789abcdefghijklmnopqrstuv"),
                    "custom rule masked"
                );
            }
            ProtectOutcome::Blocked { .. } => {}
        }
    }

    #[test]
    fn existing_db_without_key_fails_closed_k001() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let data = tmp.path().join("data");
        file_backend(&data);
        Runtime::build(&opts(&proj, &data)).unwrap();
        std::fs::remove_file(data.join("master.key")).unwrap();
        let err = match Runtime::build(&opts(&proj, &data)) {
            Ok(_) => panic!("must not mint a new key over an existing store"),
            Err(e) => e,
        };
        assert_eq!(err.code(), ErrorCode::K001);
    }

    #[test]
    fn mapping_persists_across_runtime_instances() {
        // Hooks run as separate processes: a placeholder minted by PostToolUse
        // must be restorable by a later PreToolUse.
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(proj.join(".git")).unwrap();
        let data = tmp.path().join("data");
        file_backend(&data);
        let secret = "AKIAZ7Q3XK2LM4NP5RST";
        let masked = {
            let rt = Runtime::build(&opts(&proj, &data)).unwrap();
            let ctx = rt.context(Route::HookPostToolUse, "s", rt.hook_deadline());
            match rt.engine.protect(&ctx, &format!("key={secret}")).unwrap() {
                ProtectOutcome::Allowed { text, report } => {
                    assert_eq!(report.masked, 1);
                    text
                }
                ProtectOutcome::Blocked { .. } => panic!("unexpected block"),
            }
        };
        let rt = Runtime::build(&opts(&proj, &data)).unwrap();
        let ctx = rt.context(Route::HookPreToolUse, "s", rt.hook_deadline());
        let out = rt
            .engine
            .restore(
                &ctx,
                RestoreRequest {
                    tool_name: "Write".into(),
                    target_path: Some(proj.join("a.env")),
                    fields: vec![("content".into(), masked)],
                },
            )
            .unwrap();
        assert!(out.allowed);
        assert_eq!(out.updated_fields[0].1, format!("key={secret}"));

        // The event log records metadata only.
        let log = std::fs::read_to_string(data.join("events.jsonl")).unwrap();
        assert!(log.contains("\"allowed\""), "{log}");
        assert!(!log.contains(secret), "event log must never contain values");
    }
}
