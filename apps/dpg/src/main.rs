//! Data Protection Gateway (DPG) CLI and composition root.
//!
//! Exposes command-line subcommands, agent hook interfaces, and the local
//! proxy by wiring concrete implementations across the DPG crates into
//! the core engine.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use dpg_core::config::Config;
use dpg_core::context::{ProjectContext, ProjectId, RequestContext, SessionId};
use dpg_core::engine::Engine;
use dpg_core::error::DpgError;
use dpg_core::types::Route;
use dpg_core::Detector;
use dpg_detect::DpgDetector;
use dpg_policy::ignore::compute_fingerprint;
use dpg_policy::DpgPolicy;
use dpg_protect::key::FileKeyProvider;
use dpg_protect::store::MappingStore;
use dpg_protect::DpgProtector;
use dpg_restore::DpgRestorer;
use serde_json::json;

#[derive(Parser, Debug)]
#[command(
    name = "dpg",
    version,
    about = "Data Protection Gateway (DPG) for AI coding agents",
    long_about = "DPG is a local-first privacy gateway that sits between AI coding agents and AI providers, detecting and masking secrets."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Claude Code hook entry points
    Hook {
        /// Hook event name (e.g. post-tool-use, pre-tool-use, user-prompt-submit)
        event: Option<String>,
    },
    /// Run the local loopback proxy
    Proxy {
        /// Port to listen on (default 8787)
        #[arg(long, default_value_t = 8787)]
        port: u16,
        /// Print environment variables for client configuration and exit
        #[arg(long)]
        print_env: bool,
    },
    /// Inspect file or text for sensitive content
    Inspect {
        /// File to inspect (omit or '-' to read from stdin)
        file: Option<PathBuf>,
        /// Output findings as structured JSON
        #[arg(long)]
        json: bool,
        /// Show raw secret values (WARNING: reveals sensitive credentials in console)
        #[arg(long)]
        show_values: bool,
    },
    /// Sanitize text from file or stdin to stdout with placeholders
    Sanitize {
        /// File to sanitize (omit or '-' to read from stdin)
        file: Option<PathBuf>,
        /// Exit code 1 if any secrets are detected and masked
        #[arg(long)]
        exit_code: bool,
    },
    /// Manage ignored false positive findings
    Ignore {
        /// List currently ignored findings for project
        #[arg(long)]
        list: bool,
        /// Add an ignore rule for a token/secret: <rule_id> <secret_value>
        #[arg(long, num_args = 2, value_names = ["RULE", "SECRET"])]
        add: Option<Vec<String>>,
        /// Remove an ignore rule for a token/secret: <rule_id> <secret_value>
        #[arg(long, num_args = 2, value_names = ["RULE", "SECRET"])]
        remove: Option<Vec<String>>,
    },
    /// Forget stored secret mappings
    Forget {
        /// Project ID to forget mappings for
        #[arg(long)]
        project: Option<String>,
        /// Forget mappings for all projects
        #[arg(long)]
        all: bool,
        /// Reset and vacuum database
        #[arg(long)]
        reset: bool,
    },
    /// Install agent integrations
    Install {
        /// Integration target (e.g. "claude-code")
        target: Option<String>,
        /// Uninstall integration
        #[arg(long)]
        uninstall: bool,
        /// Dry-run mode
        #[arg(long)]
        dry_run: bool,
    },
    /// Run diagnostic environment checks
    Doctor,
    /// Generate shell auto-completion scripts
    Completions {
        /// Shell to generate completions for
        shell: ShellArg,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ShellArg {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

fn build_engine() -> Result<(Engine, Option<Arc<MappingStore>>), DpgError> {
    let detector = Arc::new(DpgDetector::new()?);
    let policy = Arc::new(DpgPolicy::default_policy());

    let store_dir = directories::ProjectDirs::from("com", "dpg", "dpg")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".dpg"));

    let db_path = store_dir.join("mapping.db");
    let key_provider = FileKeyProvider::new(store_dir.join(".master.key"));

    let store_opt = MappingStore::open(&db_path, &key_provider).ok().map(Arc::new);

    let protector = match store_opt {
        Some(ref s) => Arc::new(DpgProtector::with_store(s.clone())),
        None => Arc::new(DpgProtector::ephemeral()),
    };

    let restorer = match store_opt {
        Some(ref s) => Arc::new(DpgRestorer::with_store(s.clone())),
        None => Arc::new(DpgRestorer::new(None)),
    };

    let config = Arc::new(Config::default());
    let engine = Engine::new(detector, policy, protector, restorer, config, None);

    Ok((engine, store_opt))
}

fn make_cli_context(route: Route) -> RequestContext {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let root = dunce::canonicalize(&cwd).unwrap_or(cwd);
    let id_str = format!("{:x}", {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        root.hash(&mut h);
        h.finish()
    });

    RequestContext {
        project: ProjectContext {
            root,
            id: ProjectId::new(id_str),
        },
        session: SessionId::new("cli-session".to_string()),
        route,
        deadline: Instant::now() + std::time::Duration::from_secs(30),
    }
}

/// Redacts a sensitive value for safe CLI display (first 2 chars + ... + last 2 chars).
fn redact_for_cli(s: &str) -> String {
    if s.len() <= 4 {
        "***".to_string()
    } else {
        format!("{}...{}", &s[..2], &s[s.len() - 2..])
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(cmd) => match cmd {
            Commands::Hook { .. } => {
                let (engine, _) = match build_engine() {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[DPG] Fatal: Failed to initialize engine [{}]: {}", e.code(), e);
                        std::process::exit(2);
                    }
                };
                let exit_code = dpg_connect::run(
                    &engine,
                    io::stdin().lock(),
                    io::stdout().lock(),
                );
                std::process::exit(exit_code);
            }
            Commands::Inspect { file, json, show_values } => {
                let (_engine, _) = match build_engine() {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[DPG] Inspection error [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                };

                let content = match file {
                    Some(ref p) if p != &PathBuf::from("-") => {
                        match std::fs::read_to_string(p) {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Failed to read file '{}': {e}", p.display());
                                std::process::exit(1);
                            }
                        }
                    }
                    _ => {
                        let mut buf = String::new();
                        if let Err(e) = io::stdin().read_to_string(&mut buf) {
                            eprintln!("Failed to read stdin: {e}");
                            std::process::exit(1);
                        }
                        buf
                    }
                };

                if show_values {
                    eprintln!("[DPG WARNING] --show-values specified: sensitive secrets will be displayed in plaintext.");
                }

                let ctx = make_cli_context(Route::Cli);
                let detector = DpgDetector::new().unwrap_or_else(|_| unreachable!());
                let findings = match detector.scan(&content, &ctx) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("Scan error [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                };

                if json {
                    let json_findings: Vec<_> = findings
                        .iter()
                        .map(|f| {
                            let secret_text = &content[f.span.start..f.span.end];
                            let preview = if show_values {
                                secret_text.to_string()
                            } else {
                                redact_for_cli(secret_text)
                            };
                            json!({
                                "rule_id": f.rule_id.as_str(),
                                "category": format!("{:?}", f.category),
                                "start": f.span.start,
                                "end": f.span.end,
                                "preview": preview,
                                "confidence": format!("{:?}", f.confidence)
                            })
                        })
                        .collect();
                    match serde_json::to_string_pretty(&json_findings) {
                        Ok(json_str) => println!("{json_str}"),
                        Err(e) => {
                            eprintln!("Failed to serialize json: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    println!("DPG Inspect - Found {} sensitive finding(s):", findings.len());
                    println!("{:<32} {:<16} {:<10} {:<16}", "RULE", "CATEGORY", "LINE", "PREVIEW");
                    println!("{:-<78}", "");
                    for f in &findings {
                        let line_no = content[..f.span.start.min(content.len())]
                            .bytes()
                            .filter(|&b| b == b'\n')
                            .count()
                            + 1;
                        let secret_text = &content[f.span.start..f.span.end];
                        let preview = if show_values {
                            secret_text.to_string()
                        } else {
                            redact_for_cli(secret_text)
                        };
                        println!(
                            "{:<32} {:<16} {:<10} {:<16}",
                            f.rule_id.as_str(),
                            format!("{:?}", f.category),
                            line_no,
                            preview
                        );
                    }
                }
            }
            Commands::Sanitize { file, exit_code } => {
                let (engine, _) = match build_engine() {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[DPG] Sanitize init error [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                };

                let text = match file {
                    Some(ref p) if p != &PathBuf::from("-") => {
                        match std::fs::read_to_string(p) {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Failed to read file '{}': {e}", p.display());
                                std::process::exit(1);
                            }
                        }
                    }
                    _ => {
                        let mut buf = String::new();
                        if let Err(e) = io::stdin().read_to_string(&mut buf) {
                            eprintln!("Failed to read stdin: {e}");
                            std::process::exit(1);
                        }
                        buf
                    }
                };

                let ctx = make_cli_context(Route::Cli);
                match engine.protect(&ctx, &text) {
                    Ok(dpg_core::types::ProtectOutcome::Allowed { text: masked, report }) => {
                        print!("{masked}");
                        eprintln!("[DPG] Sanitize: Masked {} sensitive finding(s)", report.masked);
                        if exit_code && report.masked > 0 {
                            std::process::exit(1);
                        }
                    }
                    Ok(dpg_core::types::ProtectOutcome::Blocked { report }) => {
                        eprintln!("[DPG] Content BLOCKED by policy ({} item(s))", report.blocked.len());
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("[DPG] Sanitize failed [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                }
            }
            Commands::Ignore { list, add, remove } => {
                let (_, store_opt) = match build_engine() {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[DPG] Error [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                };
                let store = match store_opt {
                    Some(s) => s,
                    None => {
                        eprintln!("[DPG] Error: Mapping store unavailable");
                        std::process::exit(1);
                    }
                };

                let ctx = make_cli_context(Route::Cli);
                let hmac_key = [0u8; 32];

                if let Some(pair) = add {
                    let rule = dpg_core::types::RuleId::from(pair[0].clone());
                    let secret = &pair[1];
                    let fp = compute_fingerprint(&hmac_key, &rule, secret);
                    match store.ignore(&ctx.project.id, &fp, &rule) {
                        Ok(()) => println!("Added ignore rule for '{}'", rule),
                        Err(e) => eprintln!("Failed to add ignore rule [{}]: {}", e.code(), e),
                    }
                } else if let Some(pair) = remove {
                    let rule = dpg_core::types::RuleId::from(pair[0].clone());
                    let secret = &pair[1];
                    let fp = compute_fingerprint(&hmac_key, &rule, secret);
                    match store.remove_ignore(&ctx.project.id, &fp) {
                        Ok(true) => println!("Removed ignore rule for '{}'", rule),
                        Ok(false) => println!("No existing ignore rule found for '{}'", rule),
                        Err(e) => eprintln!("Failed to remove ignore rule [{}]: {}", e.code(), e),
                    }
                } else if list {
                    println!("Project ID: {}", ctx.project.id);
                    println!("Ignore list stored in mapping database.");
                } else {
                    println!("Specify --list, --add <rule> <secret>, or --remove <rule> <secret>");
                }
            }
            Commands::Forget { project, all, reset } => {
                let (_, store_opt) = match build_engine() {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[DPG] Error [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                };
                let store = match store_opt {
                    Some(s) => s,
                    None => {
                        eprintln!("[DPG] Error: Mapping store unavailable");
                        std::process::exit(1);
                    }
                };

                if all || reset {
                    match store.forget_all() {
                        Ok(count) => println!("Forgot all {count} secret mappings across all projects."),
                        Err(e) => eprintln!("Failed to forget mappings [{}]: {}", e.code(), e),
                    }
                } else if let Some(proj) = project {
                    let proj_id = ProjectId::new(proj);
                    match store.forget_project(&proj_id) {
                        Ok(count) => println!("Forgot {count} secret mappings for project '{}'.", proj_id),
                        Err(e) => eprintln!("Failed to forget project mappings [{}]: {}", e.code(), e),
                    }
                } else {
                    let ctx = make_cli_context(Route::Cli);
                    match store.forget_project(&ctx.project.id) {
                        Ok(count) => println!("Forgot {count} secret mappings for current project '{}'.", ctx.project.id),
                        Err(e) => eprintln!("Failed to forget project mappings [{}]: {}", e.code(), e),
                    }
                }
            }
            Commands::Proxy { port, print_env } => {
                let token = dpg_connect::proxy::generate_proxy_token();
                if print_env {
                    println!("export ANTHROPIC_BASE_URL=\"http://127.0.0.1:{port}/t/{token}/anthropic\"");
                    println!("export OPENAI_BASE_URL=\"http://127.0.0.1:{port}/t/{token}/openai/v1\"");
                    return;
                }

                let bind_addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                if let Err(e) = dpg_connect::proxy::validate_bind_address(&bind_addr) {
                    eprintln!("[DPG] Proxy bind rejected [{}]: {}", e.code(), e);
                    std::process::exit(1);
                }

                println!("DPG Proxy starting on 127.0.0.1:{port}");
                println!("Anthropic: http://127.0.0.1:{port}/t/{token}/anthropic");
                println!("OpenAI:    http://127.0.0.1:{port}/t/{token}/openai/v1");

                let (engine, store_opt) = match build_engine() {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[DPG] Engine init error [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                };

                let proxy_config = Arc::new(dpg_connect::proxy::ProxyConfig {
                    bind_addr,
                    upstream_anthropic: "https://api.anthropic.com".to_string(),
                    upstream_openai: "https://api.openai.com".to_string(),
                    token,
                    restore_in_responses: true,
                });

                let client = match reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(60))
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[DPG] Failed to create HTTP client: {e}");
                        std::process::exit(1);
                    }
                };

                let state = dpg_connect::proxy::ProxyState {
                    engine: Arc::new(engine),
                    store: store_opt,
                    config: proxy_config,
                    client,
                };

                let app = dpg_connect::proxy::build_proxy_router(state);

                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[DPG] Failed to build async runtime: {e}");
                        std::process::exit(1);
                    }
                };

                rt.block_on(async {
                    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("[DPG] Failed to bind proxy listener: {e}");
                            std::process::exit(1);
                        }
                    };
                    if let Err(e) = axum::serve(listener, app).await {
                        eprintln!("[DPG] Proxy server error: {e}");
                    }
                });
            }
            Commands::Install { target, uninstall, dry_run } => {
                let target_name = target.as_deref().unwrap_or("claude-code");
                if target_name.eq_ignore_ascii_case("claude-code") {
                    let opts = dpg_connect::InstallOptions {
                        uninstall,
                        dry_run,
                        settings_dir: None,
                    };
                    match dpg_connect::install_claude_code(&opts) {
                        Ok(report) => {
                            println!("DPG: {}", report.action);
                            println!("Target: {}", report.settings_path.display());
                            if let Some(b) = report.backup_path {
                                println!("Backup created at: {}", b.display());
                            }
                        }
                        Err(e) => {
                            eprintln!("DPG Install failed [{}]: {}", e.code(), e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("Unknown installation target '{target_name}'. Supported targets: claude-code");
                    std::process::exit(1);
                }
            }
            Commands::Doctor => {
                match dpg_connect::run_doctor(None) {
                    Ok(report) => {
                        print!("{}", report.format_cli());
                        if !report.all_passed {
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("DPG Doctor failed to run [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                }
            }
            Commands::Completions { shell } => {
                let mut cmd = Cli::command();
                let shell_type = match shell {
                    ShellArg::Bash => Shell::Bash,
                    ShellArg::Zsh => Shell::Zsh,
                    ShellArg::Fish => Shell::Fish,
                    ShellArg::Powershell => Shell::PowerShell,
                };
                generate(shell_type, &mut cmd, "dpg", &mut io::stdout());
            }
        },
        None => {
            println!("DPG: Data Protection Gateway. Use --help for usage information.");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn smoke_test_cli_parse() {
        let args = ["dpg", "--help"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err()); // --help prints help and exits
    }

    #[test]
    fn test_cli_subcommands_parse() {
        assert!(Cli::try_parse_from(["dpg", "inspect", "test.txt"]).is_ok());
        assert!(Cli::try_parse_from(["dpg", "sanitize"]).is_ok());
        assert!(Cli::try_parse_from(["dpg", "ignore", "--list"]).is_ok());
        assert!(Cli::try_parse_from(["dpg", "forget", "--all"]).is_ok());
        assert!(Cli::try_parse_from(["dpg", "proxy", "--port", "9000"]).is_ok());
        assert!(Cli::try_parse_from(["dpg", "completions", "bash"]).is_ok());
    }

    #[test]
    fn test_redact_for_cli() {
        assert_eq!(redact_for_cli("AKIA1234567890ABCDEF"), "AK...EF");
        assert_eq!(redact_for_cli("123"), "***");
    }
}
