//! Indian national identifier detection and validation (Aadhaar, PAN, GSTIN, UPI).

use std::collections::HashSet;
use std::sync::OnceLock;

use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::{Category, Confidence, Finding, PartKind, RuleId, Span};
use regex::Regex;

// Embedded list of known UPI bank/payment provider handles
const UPI_HANDLES_RAW: &str = include_str!("../../../rules/upi_handles.txt");

static UPI_HANDLES_SET: OnceLock<HashSet<&'static str>> = OnceLock::new();

fn get_upi_handles() -> &'static HashSet<&'static str> {
    UPI_HANDLES_SET.get_or_init(|| {
        UPI_HANDLES_RAW
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    })
}

// Dihedral group D5 multiplication table for Verhoeff
const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

// Permutation table for Verhoeff
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Validates an Aadhaar number using the Verhoeff algorithm.
pub fn validate_aadhaar(text: &str) -> bool {
    let clean: String = text.chars().filter(|c| c.is_ascii_digit()).collect();

    if clean.len() != 12 {
        return false;
    }

    // Aadhaar does not start with 0 or 1
    if clean.starts_with('0') || clean.starts_with('1') {
        return false;
    }

    let mut c = 0;
    let digits: Vec<u8> = clean
        .chars()
        .filter_map(|ch| ch.to_digit(10).map(|d| d as u8))
        .collect();

    for (i, &digit) in digits.iter().rev().enumerate() {
        let p_val = VERHOEFF_P[i % 8][digit as usize];
        c = VERHOEFF_D[c as usize][p_val as usize];
    }

    c == 0
}

/// Validates a PAN (Permanent Account Number).
/// Format: 5 uppercase letters (4th is P/C/H/F/A/T/B/L/J/G), 4 digits, 1 letter.
pub fn validate_pan(text: &str) -> bool {
    let s = text.trim();
    if s.len() != 10 {
        return false;
    }

    let bytes = s.as_bytes();
    for b in &bytes[0..3] {
        if !b.is_ascii_uppercase() {
            return false;
        }
    }

    const FOURTH_CHARS: &[u8] = b"PCHFATBLJG";
    if !FOURTH_CHARS.contains(&bytes[3]) {
        return false;
    }

    if !bytes[4].is_ascii_uppercase() {
        return false;
    }

    for b in &bytes[5..9] {
        if !b.is_ascii_digit() {
            return false;
        }
    }

    bytes[9].is_ascii_uppercase()
}

/// Validates a GSTIN using the Modulo 36 checksum algorithm.
pub fn validate_gstin(text: &str) -> bool {
    let s = text.trim();
    if s.len() != 15 {
        return false;
    }

    // Characters 2..12 must be a valid PAN
    if !validate_pan(&s[2..12]) {
        return false;
    }

    // Character 13 is 'Z'
    if s.as_bytes()[13] != b'Z' {
        return false;
    }

    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let chars: Vec<char> = s.chars().collect();
    let mut sum = 0;

    for (i, &ch) in chars[..14].iter().enumerate() {
        let val = if ch.is_ascii_digit() {
            ch as usize - '0' as usize
        } else if ch.is_ascii_uppercase() {
            ch as usize - 'A' as usize + 10
        } else {
            return false;
        };

        let factor = if i % 2 == 0 { 1 } else { 2 };
        let product = val * factor;
        let quotient = product / 36;
        let remainder = product % 36;
        sum += quotient + remainder;
    }

    let check_code = (36 - (sum % 36)) % 36;
    let expected_char = CHARS[check_code] as char;

    chars[14] == expected_char
}

/// Validates a UPI ID against the known handle allowlist and separates it from email addresses.
pub fn validate_upi(text: &str) -> bool {
    let parts: Vec<&str> = text.trim().split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let username = parts[0];
    let handle = parts[1].to_ascii_lowercase();

    if username.is_empty() || handle.is_empty() {
        return false;
    }

    let handles = get_upi_handles();
    handles.contains(handle.as_str())
}

/// Dedicated scanner for Indian identification numbers.
#[derive(Debug, Clone)]
pub struct IndiaScanner {
    re_aadhaar: Regex,
    re_pan: Regex,
    re_gstin: Regex,
    re_upi_or_email: Regex,
}

impl IndiaScanner {
    /// Compiles regular expressions for Indian ID scanning.
    pub fn new() -> Result<Self, DpgError> {
        let re_aadhaar = Regex::new(r"\b([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})\b").map_err(|_| {
            DpgError::Detection {
                code: ErrorCode::D001,
                detail: SafeDetail::from_static("Failed to compile Aadhaar regex"),
            }
        })?;

        let re_pan = Regex::new(r"\b([A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z])\b").map_err(|_| {
            DpgError::Detection {
                code: ErrorCode::D001,
                detail: SafeDetail::from_static("Failed to compile PAN regex"),
            }
        })?;

        let re_gstin =
            Regex::new(r"\b([0-3][0-9][A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z])\b")
                .map_err(|_| DpgError::Detection {
                    code: ErrorCode::D001,
                    detail: SafeDetail::from_static("Failed to compile GSTIN regex"),
                })?;

        let re_upi_or_email = Regex::new(r"\b([a-zA-Z0-9._-]{2,256}@([a-zA-Z0-9._-]+))\b")
            .map_err(|_| DpgError::Detection {
                code: ErrorCode::D001,
                detail: SafeDetail::from_static("Failed to compile UPI/Email regex"),
            })?;

        Ok(IndiaScanner {
            re_aadhaar,
            re_pan,
            re_gstin,
            re_upi_or_email,
        })
    }

    /// Scans text for Indian identifiers, returning verified `Finding`s.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Aadhaar
        for caps in self.re_aadhaar.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                if validate_aadhaar(m.as_str()) {
                    if let Ok(span) = Span::new(text, m.start(), m.end()) {
                        findings.push(Finding {
                            rule_id: RuleId::from_static("dpg.aadhaar"),
                            category: Category::IndianId,
                            span,
                            parts: vec![(PartKind::Whole, span)],
                            confidence: Confidence::High,
                        });
                    }
                }
            }
        }

        // 2. GSTIN (checked before PAN to avoid duplicate PAN inside GSTIN)
        let mut gstin_spans = Vec::new();
        for caps in self.re_gstin.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                if validate_gstin(m.as_str()) {
                    if let Ok(span) = Span::new(text, m.start(), m.end()) {
                        gstin_spans.push(span);
                        findings.push(Finding {
                            rule_id: RuleId::from_static("dpg.gstin"),
                            category: Category::IndianId,
                            span,
                            parts: vec![(PartKind::Whole, span)],
                            confidence: Confidence::High,
                        });
                    }
                }
            }
        }

        // 3. PAN (skip if already inside a valid GSTIN span)
        for caps in self.re_pan.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                let inside_gstin = gstin_spans
                    .iter()
                    .any(|gs| m.start() >= gs.start && m.end() <= gs.end);
                if !inside_gstin && validate_pan(m.as_str()) {
                    if let Ok(span) = Span::new(text, m.start(), m.end()) {
                        findings.push(Finding {
                            rule_id: RuleId::from_static("dpg.pan"),
                            category: Category::IndianId,
                            span,
                            parts: vec![(PartKind::Whole, span)],
                            confidence: Confidence::High,
                        });
                    }
                }
            }
        }

        // 4. UPI vs Email Disambiguation
        for caps in self.re_upi_or_email.captures_iter(text) {
            if let Some(whole_m) = caps.get(1) {
                let handle = caps.get(2).map(|h| h.as_str()).unwrap_or("");
                let handle_lower = handle.to_ascii_lowercase();

                if get_upi_handles().contains(handle_lower.as_str()) {
                    // Known UPI handle -> IndianId High
                    if let Ok(span) = Span::new(text, whole_m.start(), whole_m.end()) {
                        findings.push(Finding {
                            rule_id: RuleId::from_static("dpg.upi-id"),
                            category: Category::IndianId,
                            span,
                            parts: vec![(PartKind::Whole, span)],
                            confidence: Confidence::High,
                        });
                    }
                } else if !handle.contains('.') {
                    // Generic handle without dot -> Pii Low
                    if let Ok(span) = Span::new(text, whole_m.start(), whole_m.end()) {
                        findings.push(Finding {
                            rule_id: RuleId::from_static("dpg.generic-handle"),
                            category: Category::Pii,
                            span,
                            parts: vec![(PartKind::Whole, span)],
                            confidence: Confidence::Low,
                        });
                    }
                }
                // If handle contains dot (e.g. gmail.com, example.org), it is email, not UPI ID
            }
        }

        findings.sort_by_key(|f| f.span.start);
        findings
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use dpg_testgen::generators::{gen_aadhaar, gen_gstin, gen_pan, gen_upi_id};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_sr_dt_09_invalid_verhoeff_no_finding() {
        let scanner = IndiaScanner::new().expect("scanner init");

        // Valid Aadhaar
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let valid = gen_aadhaar(&mut rng);
        let text_valid = format!("User Aadhaar: {valid}");
        let findings_valid = scanner.scan(&text_valid);
        assert_eq!(
            findings_valid.len(),
            1,
            "Valid Aadhaar must produce a finding"
        );

        // Corrupt check digit (invalid Verhoeff)
        let last_char = valid.chars().last().expect("last char");
        let wrong_char = if last_char == '0' { '1' } else { '0' };
        let invalid = format!("{}{}", &valid[..valid.len() - 1], wrong_char);
        let text_invalid = format!("User Aadhaar: {invalid}");
        let findings_invalid = scanner.scan(&text_invalid);

        assert!(
            findings_invalid.is_empty(),
            "DT-09: Invalid Verhoeff Aadhaar must produce NO finding, got: {:?}",
            findings_invalid
        );
    }

    #[test]
    fn test_pan_and_gstin_detection() {
        let scanner = IndiaScanner::new().expect("scanner init");
        let mut rng = ChaCha8Rng::seed_from_u64(99);

        let pan = gen_pan(&mut rng);
        let gstin = gen_gstin(&mut rng);
        let text = format!("PAN: {pan}, GSTIN: {gstin}");

        let findings = scanner.scan(&text);
        assert_eq!(findings.len(), 2, "Must detect PAN and GSTIN");
        assert_eq!(findings[0].rule_id.as_str(), "dpg.pan");
        assert_eq!(findings[0].span.as_str(&text), pan);
        assert_eq!(findings[1].rule_id.as_str(), "dpg.gstin");
        assert_eq!(findings[1].span.as_str(&text), gstin);
    }

    #[test]
    fn test_email_vs_upi_disambiguation() {
        let scanner = IndiaScanner::new().expect("scanner init");
        let mut rng = ChaCha8Rng::seed_from_u64(77);

        let upi = gen_upi_id(&mut rng);
        let email = "support@example.com";
        let text = format!("Pay to {upi} or contact {email}");

        let findings = scanner.scan(&text);
        assert_eq!(findings.len(), 1, "Only known UPI should be IndianId");
        assert_eq!(findings[0].rule_id.as_str(), "dpg.upi-id");
        assert_eq!(findings[0].category, Category::IndianId);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].span.as_str(&text), upi);
    }
}
