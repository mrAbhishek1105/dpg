//! Deterministic synthetic fake secrets and labelled corpus generator for DPG.
//!
//! Generates synthetic secrets (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, PEM,
//! JWT, Connection Strings, Aadhaar, PAN, GSTIN, UPI) and negative benign samples.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod corpus;
pub mod generators;
pub mod verhoeff;

pub use corpus::{gen_env_file, gen_json_file, gen_yaml_file};
pub use generators::{
    gen_aadhaar, gen_anthropic_token, gen_aws_access_key, gen_aws_secret_key,
    gen_connection_string, gen_github_token, gen_gstin, gen_jwt_token, gen_negative_sample,
    gen_openai_token, gen_pan, gen_pem_private_key, gen_slack_token, gen_stripe_token, gen_upi_id,
    SpanLabel, SyntheticSample,
};
pub use verhoeff::validate_verhoeff;

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// Creates a seeded deterministic pseudo-random number generator.
pub fn create_rng(seed: u64) -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(seed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_determinism() {
        let mut rng1 = create_rng(42);
        let mut rng2 = create_rng(42);

        let s1 = gen_env_file(&mut rng1);
        let s2 = gen_env_file(&mut rng2);

        assert_eq!(s1.text, s2.text);
        assert_eq!(s1.labels, s2.labels);
    }

    #[test]
    fn test_aadhaar_verhoeff_valid() {
        let mut rng = create_rng(12345);
        for _ in 0..100 {
            let aadhaar = gen_aadhaar(&mut rng);
            assert_eq!(aadhaar.len(), 12);
            assert!(
                validate_verhoeff(&aadhaar),
                "Generated Aadhaar {aadhaar} must be Verhoeff-valid"
            );
        }
    }

    #[test]
    fn test_pan_validity() {
        let mut rng = create_rng(12345);
        for _ in 0..100 {
            let pan = gen_pan(&mut rng);
            assert_eq!(pan.len(), 10);
            let fourth = pan.chars().nth(3).expect("4th char");
            assert!(
                "PCHFATBLJG".contains(fourth),
                "4th char of PAN must be valid entity type"
            );
        }
    }

    #[test]
    fn test_gstin_validity() {
        let mut rng = create_rng(12345);
        for _ in 0..50 {
            let gstin = gen_gstin(&mut rng);
            assert_eq!(gstin.len(), 15);
            assert_eq!(gstin.chars().nth(13).expect("14th char"), 'Z');
        }
    }
}
