//! Synthetic secret and negative pattern generators.

use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::verhoeff::{compute_check_digit, validate_verhoeff};

/// Label describing a sensitive finding in synthetic output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanLabel {
    /// Byte offset start.
    pub start: usize,
    /// Byte offset end.
    pub end: usize,
    /// Specific rule kind (e.g. "aws_access_key", "aadhaar").
    pub kind: String,
    /// Category name matching DPG taxonomy (e.g. "KnownSecret", "IndianId").
    pub category: String,
}

/// A synthetic sample with accompanying ground-truth labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticSample {
    /// Generated text.
    pub text: String,
    /// Labels indicating exact byte spans of sensitive content.
    pub labels: Vec<SpanLabel>,
}

/// Generates a fake AWS Access Key ID (`AKIA` + 16 alphanumeric).
pub fn gen_aws_access_key<R: Rng>(rng: &mut R) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let suffix: String = (0..16)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    format!("AKIA{suffix}")
}

/// Generates a fake AWS Secret Access Key (40 chars base64-like).
pub fn gen_aws_secret_key<R: Rng>(rng: &mut R) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";
    (0..40)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generates a fake GitHub token (`ghp_` or `gho_` + 36 chars).
pub fn gen_github_token<R: Rng>(rng: &mut R) -> String {
    let prefix = if rng.gen_bool(0.5) { "ghp_" } else { "gho_" };
    let body: String = rng
        .sample_iter(&Alphanumeric)
        .take(36)
        .map(char::from)
        .collect();
    format!("{prefix}{body}")
}

/// Generates a fake OpenAI-style token (`sk-proj-` or `sk-` + 48 chars).
pub fn gen_openai_token<R: Rng>(rng: &mut R) -> String {
    let prefix = if rng.gen_bool(0.5) { "sk-proj-" } else { "sk-" };
    let body: String = rng
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();
    format!("{prefix}{body}")
}

/// Generates a fake Anthropic API key (`sk-ant-api03-` + 95 chars).
pub fn gen_anthropic_token<R: Rng>(rng: &mut R) -> String {
    let body: String = rng
        .sample_iter(&Alphanumeric)
        .take(95)
        .map(char::from)
        .collect();
    format!("sk-ant-api03-{body}")
}

/// Generates a fake Stripe API key (`sk_test_` or `sk_live_` + 24 chars).
pub fn gen_stripe_token<R: Rng>(rng: &mut R) -> String {
    let prefix = if rng.gen_bool(0.5) {
        "sk_test_"
    } else {
        "sk_live_"
    };
    let body: String = rng
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    format!("{prefix}{body}")
}

/// Generates a fake Slack token (`xoxb-` or `xoxp-`).
pub fn gen_slack_token<R: Rng>(rng: &mut R) -> String {
    let prefix = if rng.gen_bool(0.5) { "xoxb" } else { "xoxp" };
    let p1: u64 = rng.gen_range(1_000_000_000..9_999_999_999);
    let p2: u64 = rng.gen_range(1_000_000_000..9_999_999_999);
    let suffix: String = rng
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    format!("{prefix}-{p1}-{p2}-{suffix}")
}

/// Generates a fake PEM private key with random base64 body (not an actual cryptographic key).
pub fn gen_pem_private_key<R: Rng>(rng: &mut R) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lines = Vec::new();
    lines.push("-----BEGIN PRIVATE KEY-----".to_string());
    for _ in 0..4 {
        let line: String = (0..64)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        lines.push(line);
    }
    let last_line: String = (0..44)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    lines.push(format!("{last_line}=="));
    lines.push("-----END PRIVATE KEY-----".to_string());
    lines.join("\n")
}

/// Generates a fake JWT token string (`header.payload.signature`).
pub fn gen_jwt_token<R: Rng>(rng: &mut R) -> String {
    let p1: String = rng
        .sample_iter(&Alphanumeric)
        .take(36)
        .map(char::from)
        .collect();
    let p2: String = rng
        .sample_iter(&Alphanumeric)
        .take(96)
        .map(char::from)
        .collect();
    let p3: String = rng
        .sample_iter(&Alphanumeric)
        .take(43)
        .map(char::from)
        .collect();
    format!("eyJ{p1}.ey{p2}.{p3}")
}

/// Generates a fake database connection string with password.
pub fn gen_connection_string<R: Rng>(rng: &mut R) -> String {
    let schemes = ["postgres", "mysql", "mongodb", "redis"];
    let scheme = schemes[rng.gen_range(0..schemes.len())];
    let user = "app_user";
    let password: String = rng
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let port = match scheme {
        "postgres" => 5432,
        "mysql" => 3306,
        "mongodb" => 27017,
        _ => 6379,
    };
    format!("{scheme}://{user}:{password}@db.internal.example:{port}/production")
}

/// Generates a valid 12-digit Aadhaar number with correct Verhoeff checksum.
pub fn gen_aadhaar<R: Rng>(rng: &mut R) -> String {
    loop {
        // Aadhaar numbers do not start with 0 or 1
        let first_digit = rng.gen_range(2..=9);
        let middle_digits: String = (0..10)
            .map(|_| {
                let d = rng.gen_range(0..10);
                std::char::from_digit(d, 10).unwrap_or('0')
            })
            .collect();
        let prefix = format!("{first_digit}{middle_digits}");
        if let Some(check_digit) = compute_check_digit(&prefix) {
            let candidate = format!("{prefix}{check_digit}");
            if validate_verhoeff(&candidate) {
                return candidate;
            }
        }
    }
}

/// Generates a valid PAN (Permanent Account Number).
/// Format: 5 uppercase letters (4th is P/C/H/F/A/T/B/L/J/G), 4 digits, 1 letter.
pub fn gen_pan<R: Rng>(rng: &mut R) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const FOURTH: &[u8] = b"PCHFATBLJG";

    let l1 = ALPHA[rng.gen_range(0..ALPHA.len())] as char;
    let l2 = ALPHA[rng.gen_range(0..ALPHA.len())] as char;
    let l3 = ALPHA[rng.gen_range(0..ALPHA.len())] as char;
    let l4 = FOURTH[rng.gen_range(0..FOURTH.len())] as char;
    let l5 = ALPHA[rng.gen_range(0..ALPHA.len())] as char;
    let digits = rng.gen_range(1000..9999);
    let l6 = ALPHA[rng.gen_range(0..ALPHA.len())] as char;

    format!("{l1}{l2}{l3}{l4}{l5}{digits}{l6}")
}

/// Generates a valid GSTIN (15 characters) with correct Modulo 36 checksum.
pub fn gen_gstin<R: Rng>(rng: &mut R) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // 2-digit state code (01..37)
    let state_code = format!("{:02}", rng.gen_range(1..=37));
    let pan = gen_pan(rng);
    let entity_num = (rng.gen_range(1..=9)).to_string();
    let prefix = format!("{state_code}{pan}{entity_num}Z");

    // Compute Modulo 36 checksum
    let mut sum = 0;
    for (i, ch) in prefix.chars().enumerate() {
        let val = if ch.is_ascii_digit() {
            ch as usize - '0' as usize
        } else {
            ch as usize - 'A' as usize + 10
        };

        let factor = if i % 2 == 0 { 1 } else { 2 };
        let product = val * factor;
        let quotient = product / 36;
        let remainder = product % 36;
        sum += quotient + remainder;
    }

    let check_code = (36 - (sum % 36)) % 36;
    let check_char = CHARS[check_code] as char;

    format!("{prefix}{check_char}")
}

/// Generates a fake UPI ID.
pub fn gen_upi_id<R: Rng>(rng: &mut R) -> String {
    const HANDLES: &[&str] = &[
        "okhdfcbank",
        "okaxis",
        "oksbi",
        "okicici",
        "paytm",
        "upi",
        "ybl",
    ];
    let username: String = rng
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(|c| (c as char).to_ascii_lowercase())
        .collect();
    let handle = HANDLES[rng.gen_range(0..HANDLES.len())];
    format!("{username}@{handle}")
}

/// Generates negative non-secret samples (UUID, SHA-256, hex hashes, normal code identifiers).
pub fn gen_negative_sample<R: Rng>(rng: &mut R) -> String {
    match rng.gen_range(0..4) {
        0 => {
            // UUID v4
            let u1: u32 = rng.gen();
            let u2: u16 = rng.gen();
            let u3: u16 = (rng.gen::<u16>() & 0x0fff) | 0x4000;
            let u4: u16 = (rng.gen::<u16>() & 0x3fff) | 0x8000;
            let u5: u64 = rng.gen::<u64>() & 0x0000_ffff_ffff_ffff;
            format!("{u1:08x}-{u2:04x}-{u3:04x}-{u4:04x}-{u5:012x}")
        }
        1 => {
            // SHA-256 hash
            let hash: String = (0..64)
                .map(|_| {
                    let d = rng.gen_range(0..16);
                    std::char::from_digit(d, 16).unwrap_or('0')
                })
                .collect();
            hash
        }
        2 => {
            // Git commit SHA (40 hex)
            let hash: String = (0..40)
                .map(|_| {
                    let d = rng.gen_range(0..16);
                    std::char::from_digit(d, 16).unwrap_or('0')
                })
                .collect();
            hash
        }
        _ => {
            // Standard benign identifier
            let names = [
                "TIMEOUT_SECONDS = 30",
                "DEFAULT_BUFFER_SIZE = 4096",
                "user_account_id = 98124",
                "SESSION_PREFIX = \"session_tmp_\"",
            ];
            names[rng.gen_range(0..names.len())].to_string()
        }
    }
}
