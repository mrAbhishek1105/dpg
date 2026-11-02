//! Data Protection Gateway (DPG) CLI and composition root.
//!
//! Exposes command-line subcommands, agent hook interfaces, and the local
//! proxy by wiring the concrete implementations across the DPG crates into
//! the core engine.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use dpg_core::config::Config;
use dpg_core::engine::Engine;
use dpg_detect::DpgDetector;
use dpg_policy::DpgPolicy;
use dpg_protect::key::FileKeyProvider;
use dpg_protect::store::MappingStore;
use dpg_protect::DpgProtector;
use dpg_restore::DpgRestorer;

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
    Proxy,
    /// Inspect file or text for sensitive content
    Inspect,
    /// Sanitize text from stdin
    Sanitize,
    /// Manage ignored false positive findings
    Ignore,
    /// Forget stored secret mappings
    Forget,
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
}

fn build_engine() -> Result<Engine, dpg_core::error::DpgError> {
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

    Ok(Engine::new(detector, policy, protector, restorer, config, None))
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(cmd) => match cmd {
            Commands::Hook { .. } => {
                let engine = match build_engine() {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[DPG] Fatal: Failed to initialize engine [{}]: {}", e.code(), e);
                        std::process::exit(2);
                    }
                };
                let exit_code = dpg_connect::run(
                    &engine,
                    std::io::stdin().lock(),
                    std::io::stdout().lock(),
                );
                std::process::exit(exit_code);
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
            Commands::Proxy => println!("Proxy placeholder"),
            Commands::Inspect => println!("Inspect placeholder"),
            Commands::Sanitize => println!("Sanitize placeholder"),
            Commands::Ignore => println!("Ignore placeholder"),
            Commands::Forget => println!("Forget placeholder"),
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
    fn test_cli_hook_subcommand_parse() {
        let args = ["dpg", "hook", "post-tool-use"];
        let cli = Cli::try_parse_from(args).expect("parse hook");
        match cli.command {
            Some(Commands::Hook { event }) => {
                assert_eq!(event, Some("post-tool-use".to_string()));
            }
            _ => panic!("Expected Hook command"),
        }
    }

    #[test]
    fn test_cli_install_subcommand_parse() {
        let args = ["dpg", "install", "claude-code", "--dry-run"];
        let cli = Cli::try_parse_from(args).expect("parse install");
        match cli.command {
            Some(Commands::Install { target, uninstall, dry_run }) => {
                assert_eq!(target, Some("claude-code".to_string()));
                assert!(!uninstall);
                assert!(dry_run);
            }
            _ => panic!("Expected Install command"),
        }
    }

    #[test]
    fn test_cli_doctor_subcommand_parse() {
        let args = ["dpg", "doctor"];
        let cli = Cli::try_parse_from(args).expect("parse doctor");
        assert!(matches!(cli.command, Some(Commands::Doctor)));
    }
}
