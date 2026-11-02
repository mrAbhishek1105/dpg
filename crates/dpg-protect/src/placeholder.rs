//! Placeholder token generation, Crockford base32 encoding, and validation (ADR-0005).

use dpg_core::types::{Category, PartKind};
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Standard Crockford Base32 alphabet (32 characters: 0-9, A-H, J-K, M-N, P-T, V-Z).
/// Excludes ambiguous letters: I, L, O, and U.
pub const CROCKFORD_BASE32: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Regular expression pattern matching any valid DPG placeholder token.
pub const PATTERN: &str =
    r"\bDPG_(?:SECRET|PASS|USER|HOST|CONN|TERM|ID|PII)_[0-9A-HJKMNP-TV-Z]{8}\b";

static RE_PLACEHOLDER: OnceLock<Regex> = OnceLock::new();

fn get_placeholder_re() -> &'static Regex {
    RE_PLACEHOLDER.get_or_init(|| {
        Regex::new(&format!(
            "^{}$",
            PATTERN.trim_start_matches(r"\b").trim_end_matches(r"\b")
        ))
        .unwrap_or_else(|_| {
            let fallback = Regex::new(r"^DPG_SECRET_[0-9A-Z]{8}$");
            match fallback {
                Ok(r) => r,
                Err(_) => unreachable!(),
            }
        })
    })
}

/// Category classification of placeholder tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlaceholderCat {
    /// Generic secret or API key.
    Secret,
    /// Password component.
    Pass,
    /// Username component.
    User,
    /// Host or network address component.
    Host,
    /// Whole connection string (when un-splittable).
    Conn,
    /// Project custom term.
    Term,
    /// Indian national identifier (Aadhaar, PAN, GSTIN, UPI).
    Id,
    /// Personally identifiable information.
    Pii,
}

impl PlaceholderCat {
    /// Returns the uppercase 3-6 letter code for this placeholder category.
    pub const fn as_str(&self) -> &'static str {
        match self {
            PlaceholderCat::Secret => "SECRET",
            PlaceholderCat::Pass => "PASS",
            PlaceholderCat::User => "USER",
            PlaceholderCat::Host => "HOST",
            PlaceholderCat::Conn => "CONN",
            PlaceholderCat::Term => "TERM",
            PlaceholderCat::Id => "ID",
            PlaceholderCat::Pii => "PII",
        }
    }

    /// Selects an appropriate placeholder category for a finding and sub-part kind.
    pub fn from_category_and_part(cat: Category, part: PartKind) -> Self {
        match part {
            PartKind::Password => PlaceholderCat::Pass,
            PartKind::User => PlaceholderCat::User,
            PartKind::Host => PlaceholderCat::Host,
            PartKind::Whole => match cat {
                Category::KnownSecret | Category::KeyValueSecret | Category::Entropy => {
                    PlaceholderCat::Secret
                }
                Category::PrivateKey => PlaceholderCat::Secret,
                Category::ConnectionString => PlaceholderCat::Conn,
                Category::CustomTerm => PlaceholderCat::Term,
                Category::IndianId => PlaceholderCat::Id,
                Category::Pii => PlaceholderCat::Pii,
            },
        }
    }
}

/// Generates a new 8-character Crockford base32 body using the given RNG.
pub fn generate_body<R: Rng>(rng: &mut R) -> String {
    let mut body = String::with_capacity(8);
    for _ in 0..8 {
        let idx = rng.gen_range(0..CROCKFORD_BASE32.len());
        body.push(CROCKFORD_BASE32[idx] as char);
    }
    body
}

/// Generates a full placeholder token for the specified category using the given RNG.
pub fn generate<R: Rng>(rng: &mut R, cat: PlaceholderCat) -> String {
    format!("DPG_{}_{}", cat.as_str(), generate_body(rng))
}

/// Generates a full placeholder token using the cryptographically secure OS RNG.
pub fn generate_csprng(cat: PlaceholderCat) -> String {
    let mut rng = rand::thread_rng();
    generate(&mut rng, cat)
}

/// Validates whether a string slice exactly conforms to the DPG placeholder format.
pub fn is_placeholder(s: &str) -> bool {
    get_placeholder_re().is_match(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_placeholder_format_and_regex_matching() {
        let mut rng = rand::thread_rng();
        let cats = [
            PlaceholderCat::Secret,
            PlaceholderCat::Pass,
            PlaceholderCat::User,
            PlaceholderCat::Host,
            PlaceholderCat::Conn,
            PlaceholderCat::Term,
            PlaceholderCat::Id,
            PlaceholderCat::Pii,
        ];

        for cat in cats {
            let token = generate(&mut rng, cat);
            assert!(
                is_placeholder(&token),
                "Generated token '{}' must match placeholder regex",
                token
            );
            assert!(
                token.len() <= 19,
                "Token '{}' length {} exceeds max 19 bytes",
                token,
                token.len()
            );
        }
    }

    #[test]
    fn test_crockford_base32_alphabet_strictness() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let body = generate_body(&mut rng);
            assert_eq!(body.len(), 8);
            for ch in body.chars() {
                assert!(
                    CROCKFORD_BASE32.contains(&(ch as u8)),
                    "Invalid char in body: {}",
                    ch
                );
                // Ambiguous chars must never appear
                assert!(ch != 'I' && ch != 'L' && ch != 'O' && ch != 'U');
            }
        }
    }

    #[test]
    fn test_uniqueness_sample() {
        let mut rng = rand::thread_rng();
        let mut seen = HashSet::new();
        // 100,000 distinct generations in test suite
        for _ in 0..100_000 {
            let token = generate(&mut rng, PlaceholderCat::Secret);
            let is_new = seen.insert(token);
            assert!(is_new, "Collision detected in 100,000 samples");
        }
    }

    #[test]
    fn test_is_placeholder_rejections() {
        assert!(!is_placeholder("DPG_SECRET_1234")); // too short
        assert!(!is_placeholder("DPG_SECRET_123456789")); // too long
        assert!(!is_placeholder("DPG_UNKNOWN_12345678")); // invalid category
        assert!(!is_placeholder("DPG_SECRET_1234ILOU")); // invalid chars I, L, O, U
        assert!(!is_placeholder("dpg_secret_01234567")); // lowercase
    }
}
