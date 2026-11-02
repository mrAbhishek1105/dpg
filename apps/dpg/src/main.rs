//! Data Protection Gateway (DPG) CLI and composition root.
//!
//! Exposes command-line subcommands, agent hook interfaces, and the local
//! proxy by wiring the concrete implementations across the DPG crates into
//! the core engine.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use clap::{Parser, Subcommand};

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
    Hook,
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
    Install,
    /// Run diagnostic environment checks
    Doctor,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(cmd) => match cmd {
            Commands::Hook => println!("Hook adapter placeholder"),
            Commands::Proxy => println!("Proxy placeholder"),
            Commands::Inspect => println!("Inspect placeholder"),
            Commands::Sanitize => println!("Sanitize placeholder"),
            Commands::Ignore => println!("Ignore placeholder"),
            Commands::Forget => println!("Forget placeholder"),
            Commands::Install => println!("Install placeholder"),
            Commands::Doctor => println!("Doctor placeholder"),
        },
        None => {
            println!("DPG: Data Protection Gateway. Use --help for usage information.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_cli_parse() {
        let args = ["dpg", "--help"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err()); // --help prints help and exits
    }
}
