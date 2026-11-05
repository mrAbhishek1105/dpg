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
use dpg_connect::runtime::{compile_project_rules, Runtime, RuntimeOptions};
use dpg_core::config::{load_config, LoadOptions};
use dpg_core::context::{ProjectId, RequestContext};
use dpg_core::types::{ProtectOutcome, Route, RuleId};
use dpg_core::Detector;
use dpg_detect::DpgDetector;
use dpg_policy::ignore::compute_fingerprint;
use dpg_protect::key::delete_master_key;
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
        /// Port to listen on (default: `proxy.port` from config, 8787)
        #[arg(long)]
        port: Option<u16>,
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
        /// With --all: delete the database and the master key (recovery for a locked store)
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

/// Builds the runtime for the current directory or exits with a coded error.
fn runtime_or_exit(what: &str) -> Runtime {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match Runtime::build(&RuntimeOptions::for_cwd(cwd)) {
        Ok(rt) => {
            for w in &rt.warnings {
                eprintln!("[DPG] Config warning: {}: {}", w.key, w.message);
            }
            rt
        }
        Err(e) => {
            eprintln!("[DPG] {what} failed to initialise [{}]: {e}", e.code());
            std::process::exit(1);
        }
    }
}

fn cli_context(rt: &Runtime) -> RequestContext {
    rt.context(
        Route::Cli,
        "cli-session",
        Instant::now() + std::time::Duration::from_secs(30),
    )
}

fn read_input(file: Option<&PathBuf>) -> String {
    match file {
        Some(p) if p.as_os_str() != "-" => match std::fs::read_to_string(p) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to read file '{}': {e}", p.display());
                std::process::exit(1);
            }
        },
        _ => {
            let mut buf = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut buf) {
                eprintln!("Failed to read stdin: {e}");
                std::process::exit(1);
            }
            buf
        }
    }
}

/// Redacts a sensitive value for safe CLI display (first 2 chars + ... + last 2 chars).
fn redact_for_cli(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        "***".to_string()
    } else {
        let head: String = chars[..2].iter().collect();
        let tail: String = chars[chars.len() - 2..].iter().collect();
        format!("{head}...{tail}")
    }
}

fn main() {
    let cli = Cli::parse();
    let Some(cmd) = cli.command else {
        println!("DPG: Data Protection Gateway. Use --help for usage information.");
        return;
    };
    match cmd {
        Commands::Hook { .. } => {
            let code = dpg_connect::hook::run_hook_process(io::stdin().lock(), io::stdout().lock());
            std::process::exit(code);
        }
        Commands::Inspect {
            file,
            json,
            show_values,
        } => {
            let rt = runtime_or_exit("Inspect");
            let content = read_input(file.as_ref());
            if show_values {
                eprintln!("[DPG WARNING] --show-values specified: sensitive secrets will be displayed in plaintext.");
            }
            let detector = match DpgDetector::new()
                .and_then(|d| d.with_custom_terms(&rt.config.terms.values))
                .and_then(|d| d.with_project_rules(compile_project_rules(&rt.config)?))
            {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[DPG] Detector init error [{}]: {e}", e.code());
                    std::process::exit(1);
                }
            };
            let ctx = cli_context(&rt);
            let findings = match detector.scan(&content, &ctx) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Scan error [{}]: {}", e.code(), e);
                    std::process::exit(1);
                }
            };

            let preview_of = |f: &dpg_core::types::Finding| {
                let secret_text = content.get(f.span.start..f.span.end).unwrap_or_default();
                if show_values {
                    secret_text.to_string()
                } else {
                    redact_for_cli(secret_text)
                }
            };
            let line_of = |f: &dpg_core::types::Finding| {
                content[..f.span.start.min(content.len())]
                    .bytes()
                    .filter(|&b| b == b'\n')
                    .count()
                    + 1
            };

            if json {
                let json_findings: Vec<_> = findings
                    .iter()
                    .map(|f| {
                        json!({
                            "rule_id": f.rule_id.as_str(),
                            "category": format!("{:?}", f.category),
                            "line": line_of(f),
                            "start": f.span.start,
                            "end": f.span.end,
                            "preview": preview_of(f),
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
                println!(
                    "DPG Inspect - Found {} sensitive finding(s):",
                    findings.len()
                );
                println!(
                    "{:<32} {:<16} {:<10} {:<16}",
                    "RULE", "CATEGORY", "LINE", "PREVIEW"
                );
                println!("{:-<78}", "");
                for f in &findings {
                    println!(
                        "{:<32} {:<16} {:<10} {:<16}",
                        f.rule_id.as_str(),
                        format!("{:?}", f.category),
                        line_of(f),
                        preview_of(f)
                    );
                }
            }
        }
        Commands::Sanitize { file, exit_code } => {
            let rt = runtime_or_exit("Sanitize");
            let text = read_input(file.as_ref());
            let ctx = cli_context(&rt);
            match rt.engine.protect(&ctx, &text) {
                Ok(ProtectOutcome::Allowed {
                    text: masked,
                    report,
                }) => {
                    print!("{masked}");
                    eprintln!(
                        "[DPG] Sanitize: Masked {} sensitive finding(s)",
                        report.masked
                    );
                    if exit_code && report.masked > 0 {
                        std::process::exit(1);
                    }
                }
                Ok(ProtectOutcome::Blocked { report }) => {
                    eprintln!(
                        "[DPG] Content BLOCKED by policy ({} item(s)); nothing written to stdout",
                        report.blocked.len()
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("[DPG] Sanitize failed [{}]: {}", e.code(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Ignore { list, add, remove } => {
            let rt = runtime_or_exit("Ignore");
            let Some(store) = rt.store.clone() else {
                let code = rt.store_error.as_ref().map(|e| e.code().to_string());
                eprintln!(
                    "[DPG] Error [{}]: Mapping store unavailable",
                    code.unwrap_or_else(|| "DPG-M001".to_string())
                );
                std::process::exit(1);
            };
            let key = *rt.ignore_key();
            let project = rt.project.id.clone();

            if let Some(pair) = add {
                let rule = RuleId::from(pair[0].clone());
                let fp = compute_fingerprint(&key, &rule, &pair[1]);
                match store.ignore(&project, &fp, &rule) {
                    Ok(()) => println!("Added ignore rule for '{rule}' in project {project}"),
                    Err(e) => {
                        eprintln!("Failed to add ignore rule [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                }
            } else if let Some(pair) = remove {
                let rule = RuleId::from(pair[0].clone());
                let fp = compute_fingerprint(&key, &rule, &pair[1]);
                match store.remove_ignore(&project, &fp) {
                    Ok(true) => println!("Removed ignore rule for '{rule}'"),
                    Ok(false) => println!("No existing ignore rule found for '{rule}'"),
                    Err(e) => {
                        eprintln!("Failed to remove ignore rule [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                }
            } else if list {
                match store.list_ignores(&project) {
                    Ok(entries) => {
                        println!("Project {project}: {} ignored finding(s)", entries.len());
                        for (rule, created) in entries {
                            println!("  {rule:<40} added {created} (unix time)");
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to list ignore rules [{}]: {}", e.code(), e);
                        std::process::exit(1);
                    }
                }
            } else {
                println!("Specify --list, --add <rule> <secret>, or --remove <rule> <secret>");
            }
        }
        Commands::Forget {
            project,
            all,
            reset,
        } => {
            if reset {
                if !all {
                    eprintln!("--reset requires --all (it deletes the whole store and its key)");
                    std::process::exit(1);
                }
                // Works even when the store is locked (key missing): no runtime needed.
                let dir = dpg_connect::runtime::data_dir();
                let backend = std::env::var("DPG_STORAGE_BACKEND")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or_else(|| {
                        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                        load_config(&LoadOptions {
                            project_root: Some(cwd),
                            ..LoadOptions::default()
                        })
                        .map(|(c, _)| c.storage.key_backend)
                        .unwrap_or_else(|_| "keychain".to_string())
                    });
                let db = dpg_connect::runtime::mapping_db_path(&dir);
                for suffix in ["", "-wal", "-shm"] {
                    let mut p = db.clone().into_os_string();
                    p.push(suffix);
                    let _ = std::fs::remove_file(PathBuf::from(p));
                }
                if let Err(e) = delete_master_key(backend.trim(), &dir) {
                    eprintln!("[DPG] Reset failed [{}]: {e}", e.code());
                    std::process::exit(1);
                }
                println!("DPG store and master key deleted. A new key is created on next use.");
                return;
            }
            let rt = runtime_or_exit("Forget");
            let Some(store) = rt.store.clone() else {
                eprintln!(
                    "[DPG] Error: Mapping store unavailable. Use 'dpg forget --all --reset'."
                );
                std::process::exit(1);
            };
            let result = if all {
                store
                    .forget_all()
                    .map(|n| format!("Forgot all {n} mapping(s) across all projects."))
            } else {
                let proj_id = project
                    .map(ProjectId::new)
                    .unwrap_or_else(|| rt.project.id.clone());
                store
                    .forget_project(&proj_id)
                    .map(|n| format!("Forgot {n} mapping(s) for project '{proj_id}'."))
            };
            match result {
                Ok(msg) => println!("{msg}"),
                Err(e) => {
                    eprintln!("Failed to forget mappings [{}]: {}", e.code(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Proxy { port, print_env } => run_proxy(port, print_env),
        Commands::Install {
            target,
            uninstall,
            dry_run,
        } => {
            let target_name = target.as_deref().unwrap_or("claude-code");
            if !target_name.eq_ignore_ascii_case("claude-code") {
                eprintln!(
                    "Unknown installation target '{target_name}'. Supported targets: claude-code"
                );
                std::process::exit(1);
            }
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
        }
        Commands::Doctor => match dpg_connect::run_doctor(None) {
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
        },
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
    }
}

fn run_proxy(port_flag: Option<u16>, print_env: bool) {
    let rt = runtime_or_exit("Proxy");
    let pc = &rt.config.proxy;
    let port = port_flag.unwrap_or(pc.port);
    let ip: std::net::IpAddr = match pc.bind_address.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("[DPG] Proxy bind rejected [DPG-C003]: invalid bind address");
            std::process::exit(1);
        }
    };
    let bind_addr = std::net::SocketAddr::new(ip, port);
    if let Err(e) = dpg_connect::proxy::validate_bind_address(&bind_addr) {
        eprintln!("[DPG] Proxy bind rejected [{}]: {}", e.code(), e);
        std::process::exit(1);
    }

    // Stable per installation (derived from the master key), so `--print-env`
    // output stays valid across proxy restarts. Rotate with `dpg forget --all --reset`.
    let token = rt.proxy_token().to_string();
    let host = if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    println!(
        "DPG Proxy on {host}:{port} for project {}",
        rt.project.root.display()
    );
    println!("export ANTHROPIC_BASE_URL=\"http://{host}:{port}/t/{token}/anthropic\"");
    println!("export OPENAI_BASE_URL=\"http://{host}:{port}/t/{token}/openai/v1\"");
    if print_env {
        return;
    }
    if let Some(ref e) = rt.store_error {
        eprintln!(
            "[DPG] Warning [{}]: mapping store unavailable; responses will not be restored.",
            e.code()
        );
    }

    let client = match dpg_connect::proxy::build_upstream_client(
        std::time::Duration::from_secs(pc.connect_timeout_seconds),
        std::time::Duration::from_secs(pc.request_timeout_seconds),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[DPG] Failed to create HTTP client [{}]", e.code());
            std::process::exit(1);
        }
    };

    let state = dpg_connect::proxy::ProxyState {
        engine: rt.engine.clone(),
        store: rt.store.clone(),
        config: Arc::new(dpg_connect::proxy::ProxyConfig {
            bind_addr,
            upstream_anthropic: pc.upstream_anthropic.clone(),
            upstream_openai: pc.upstream_openai.clone(),
            token,
            restore_in_responses: pc.restore_in_responses,
        }),
        client,
        project: rt.project.clone(),
    };
    let app = dpg_connect::proxy::build_proxy_router(state);

    let tokio_rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[DPG] Failed to build async runtime: {e}");
            std::process::exit(1);
        }
    };
    tokio_rt.block_on(async {
        let listener = match tokio::net::TcpListener::bind(bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[DPG] Failed to bind proxy listener: {e}");
                std::process::exit(1);
            }
        };
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("[DPG] Proxy server error: {e}");
            std::process::exit(1);
        }
    });
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
        assert_eq!(
            redact_for_cli(&format!("{}{}", "AKIA", "1234567890ABCDEF")),
            "AK...EF"
        );
        assert_eq!(redact_for_cli("123"), "***");
        assert_eq!(redact_for_cli("short1"), "***");
        // Multi-byte input must not panic and must not reveal the middle.
        assert_eq!(redact_for_cli("ééééééééééé"), "éé...éé");
    }
}
