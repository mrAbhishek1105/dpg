//! Custom confidential term and project keyword detection with word boundary enforcement.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::{Category, Confidence, Finding, PartKind, RuleId, Span};

/// Scanner for project-configured custom terms and confidential keywords.
#[derive(Debug, Clone)]
pub struct TermsScanner {
    ac: Option<AhoCorasick>,
}

impl TermsScanner {
    /// Compiles a new `TermsScanner` from a slice of term strings.
    pub fn new(terms: &[String]) -> Result<Self, DpgError> {
        let clean_terms: Vec<&str> = terms
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if clean_terms.is_empty() {
            return Ok(TermsScanner { ac: None });
        }

        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&clean_terms)
            .map_err(|_| DpgError::Detection {
                code: ErrorCode::D001,
                detail: SafeDetail::from_static("Failed to build custom terms Aho-Corasick"),
            })?;

        Ok(TermsScanner { ac: Some(ac) })
    }

    /// Checks whether the span [start..end] in `text` has valid word boundaries on both sides.
    pub fn is_word_boundary(text: &str, start: usize, end: usize) -> bool {
        // Preceding character boundary
        if start > 0 {
            if let Some(prev_ch) = text[..start].chars().next_back() {
                if prev_ch.is_alphanumeric() || prev_ch == '_' {
                    return false;
                }
            }
        }

        // Following character boundary
        if end < text.len() {
            if let Some(next_ch) = text[end..].chars().next() {
                if next_ch.is_alphanumeric() || next_ch == '_' {
                    return false;
                }
            }
        }

        true
    }

    /// Scans text for configured custom terms, ensuring word boundary adherence.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let ac = match self.ac {
            Some(ref a) => a,
            None => return findings,
        };

        for mat in ac.find_iter(text) {
            let start = mat.start();
            let end = mat.end();

            // Word boundary check: "Acme" must not match inside "Acmeology"
            if !Self::is_word_boundary(text, start, end) {
                continue;
            }

            if let Ok(span) = Span::new(text, start, end) {
                findings.push(Finding {
                    rule_id: RuleId::from_static("dpg.custom-term"),
                    category: Category::CustomTerm,
                    span,
                    parts: vec![(PartKind::Whole, span)],
                    confidence: Confidence::High,
                });
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
    fn test_term_word_boundaries_acme_vs_acmeology() {
        let terms = vec!["Acme".to_string(), "ProjectOmega".to_string()];
        let scanner = TermsScanner::new(&terms).expect("terms scanner");

        // 1. "Acmeology" contains "Acme" as a prefix, but must NOT match due to boundary check
        let text_neg = "Studying Acmeology in college";
        let findings_neg = scanner.scan(text_neg);
        assert!(
            findings_neg.is_empty(),
            "Word boundary check failed: 'Acme' matched inside 'Acmeology'"
        );

        // 2. Exact word "Acme" in isolation and case variations
        let text_pos = "Welcome to ACME Corporation, working on projectomega today.";
        let findings_pos = scanner.scan(text_pos);
        assert_eq!(findings_pos.len(), 2);
        assert_eq!(findings_pos[0].span.as_str(text_pos), "ACME");
        assert_eq!(findings_pos[1].span.as_str(text_pos), "projectomega");
    }

    #[test]
    fn test_cidr_ip_terms() {
        let terms = vec!["10.0.4.50".to_string(), "192.168.1.0/24".to_string()];
        let scanner = TermsScanner::new(&terms).expect("terms scanner");

        let text = "Server listening at 10.0.4.50 and range 192.168.1.0/24";
        let findings = scanner.scan(text);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].span.as_str(text), "10.0.4.50");
        assert_eq!(findings[1].span.as_str(text), "192.168.1.0/24");
    }
}
