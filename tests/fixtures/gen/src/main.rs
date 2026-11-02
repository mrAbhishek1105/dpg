//! CLI for deterministic synthetic test fixture generation.
//!
//! Run with `cargo run -p dpg-testgen -- --seed 1 --kind env`.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use clap::Parser;
use dpg_testgen::{
    create_rng, gen_aadhaar, gen_aws_access_key, gen_env_file, gen_gstin, gen_json_file, gen_pan,
    gen_yaml_file,
};

#[derive(Parser, Debug)]
#[command(
    name = "dpg-testgen",
    about = "Synthetic secret and labelled corpus generator for DPG"
)]
struct Args {
    /// PRNG seed for deterministic output
    #[arg(short, long, default_value_t = 1)]
    seed: u64,

    /// Kind of fixture to generate ("env", "yaml", "json", "aadhaar", "pan", "gstin", "aws")
    #[arg(short, long, default_value = "env")]
    kind: String,

    /// Print labels in JSON format instead of plain text
    #[arg(long, default_value_t = false)]
    with_labels: bool,
}

fn main() {
    let args = Args::parse();
    let mut rng = create_rng(args.seed);

    match args.kind.to_lowercase().as_str() {
        "env" => {
            let sample = gen_env_file(&mut rng);
            if args.with_labels {
                if let Ok(json) = serde_json::to_string_pretty(&sample) {
                    println!("{json}");
                }
            } else {
                print!("{}", sample.text);
            }
        }
        "yaml" => {
            let sample = gen_yaml_file(&mut rng);
            if args.with_labels {
                if let Ok(json) = serde_json::to_string_pretty(&sample) {
                    println!("{json}");
                }
            } else {
                print!("{}", sample.text);
            }
        }
        "json" => {
            let sample = gen_json_file(&mut rng);
            if args.with_labels {
                if let Ok(json) = serde_json::to_string_pretty(&sample) {
                    println!("{json}");
                }
            } else {
                print!("{}", sample.text);
            }
        }
        "aadhaar" => {
            println!("{}", gen_aadhaar(&mut rng));
        }
        "pan" => {
            println!("{}", gen_pan(&mut rng));
        }
        "gstin" => {
            println!("{}", gen_gstin(&mut rng));
        }
        "aws" => {
            println!("{}", gen_aws_access_key(&mut rng));
        }
        other => {
            eprintln!(
                "Unknown kind '{other}'. Choose from: env, yaml, json, aadhaar, pan, gstin, aws."
            );
            std::process::exit(1);
        }
    }
}
