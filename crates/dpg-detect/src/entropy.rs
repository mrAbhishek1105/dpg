//! Shannon entropy calculation and high-entropy secret heuristic scanner.

use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::{Category, Confidence, Finding, PartKind, RuleId, Span};
use regex::Regex;

/// Computes the Shannon entropy in bits per character for an input string.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    let mut total = 0;

    for &b in s.as_bytes() {
        counts[b as usize] += 1;
        total += 1;
    }

    let total_f = total as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Checks whether a token is purely hexadecimal.
pub fn is_hex_string(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Scanner for high-entropy tokens (Low confidence candidates).
#[derive(Debug, Clone)]
pub struct EntropyScanner {
    re_token: Regex,
    re_uuid: Regex,
    re_integrity: Regex,
}

impl EntropyScanner {
    /// Compiles a new `EntropyScanner`.
    pub fn new() -> Result<Self, DpgError> {
        let re_token =
            // `=` only as trailing base64 padding, so `KEY=value` is never one token.
            Regex::new(r"\b([A-Za-z0-9+/_-]{20,}={0,2})").map_err(|_| DpgError::Detection {
                code: ErrorCode::D001,
                detail: SafeDetail::from_static("Failed to compile entropy token regex"),
            })?;

        let re_uuid = Regex::new(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        )
        .map_err(|_| DpgError::Detection {
            code: ErrorCode::D001,
            detail: SafeDetail::from_static("Failed to compile UUID regex"),
        })?;

        let re_integrity =
            Regex::new(r"^(?:sha256|sha512|sha1|md5)-[A-Za-z0-9+/=]+$").map_err(|_| {
                DpgError::Detection {
                    code: ErrorCode::D001,
                    detail: SafeDetail::from_static("Failed to compile integrity hash regex"),
                }
            })?;

        Ok(EntropyScanner {
            re_token,
            re_uuid,
            re_integrity,
        })
    }

    /// Checks if a token is a safe non-secret artifact (UUID, lockfile integrity hash).
    pub fn is_safe_non_secret(&self, token: &str) -> bool {
        self.re_uuid.is_match(token) || self.re_integrity.is_match(token)
    }

    /// Scans text for high-entropy tokens meeting entropy thresholds.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in self.re_token.find_iter(text) {
            let token = mat.as_str();

            // Exclude UUIDs and lockfile hashes (DT-08)
            if self.is_safe_non_secret(token) {
                continue;
            }

            // Exclude content digests: 40/64/128-hex after `sha1:`/`sha256:`/`sha512:`,
            // `@sha256:` image refs, or a `commit ` prefix (git object ids).
            if is_hex_string(token) && matches!(token.len(), 40 | 64 | 128) {
                let before = &text[..mat.start()];
                let ctx_start = before
                    .char_indices()
                    .rev()
                    .nth(11)
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                let ctx = before[ctx_start..].to_ascii_lowercase();
                if ctx.ends_with("sha1:")
                    || ctx.ends_with("sha256:")
                    || ctx.ends_with("sha512:")
                    || ctx.ends_with("commit ")
                {
                    continue;
                }
            }

            let entropy = shannon_entropy(token);

            let is_hex = is_hex_string(token);
            let is_candidate = if is_hex {
                // Hex threshold: >= 3.0
                entropy >= 3.0
            } else {
                // Base64 threshold: >= 4.0
                entropy >= 4.0
            };

            if is_candidate {
                if let Ok(span) = Span::new(text, mat.start(), mat.end()) {
                    findings.push(Finding {
                        rule_id: RuleId::from_static("dpg.entropy"),
                        category: Category::Entropy,
                        span,
                        parts: vec![(PartKind::Whole, span)],
                        confidence: Confidence::Low,
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_shannon_entropy_calculation() {
        // Monotonous string has 0 entropy
        assert_eq!(shannon_entropy("aaaaaaaaaaaaaaaaaaaa"), 0.0);

        // High entropy random string
        let high_ent = "4bX8#pL9!vQ2@zW1$mR6*yT3^nK7";
        assert!(shannon_entropy(high_ent) > 4.0);
    }

    #[test]
    fn test_sr_dt_08_uuid_and_hash_exclusion() {
        let scanner = EntropyScanner::new().expect("scanner init");

        // UUID should not be reported as high-entropy finding
        let text_uuid = "Session ID: 123e4567-e89b-12d3-a456-426614174000 in logs";
        let findings = scanner.scan(text_uuid);
        assert!(
            findings.is_empty(),
            "DT-08: UUID must be excluded from entropy scan, got: {:?}",
            findings
        );

        // Lockfile integrity hash
        let text_lock = "integrity sha512-4bX8pL9vQ2zW1mR6yT3nK7abcd1234efgh5678ijkl==";
        let findings_lock = scanner.scan(text_lock);
        assert!(
            findings_lock.is_empty(),
            "DT-08: Integrity hash must be excluded, got: {:?}",
            findings_lock
        );
    }

    #[test]
    fn test_entropy_candidate_detection() {
        let scanner = EntropyScanner::new().expect("scanner init");
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let text = format!("auth_signature: {secret}");

        let findings = scanner.scan(&text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::Entropy);
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert_eq!(findings[0].span.as_str(&text), secret);
    }
}
