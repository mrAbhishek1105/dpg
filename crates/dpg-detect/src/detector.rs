//! Unified DPG detector integrating all rules, scanners, and overlap resolution.

use dpg_core::context::RequestContext;
use dpg_core::engine::Detector;
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::Finding;

use crate::conn::ConnScanner;
use crate::entropy::EntropyScanner;
use crate::india::IndiaScanner;
use crate::kv::KvScanner;
use crate::overlap::resolve_overlaps;
use crate::ruleset::RuleSet;
use crate::terms::TermsScanner;

/// Maximum input text size in bytes allowed for a single scan operation (16 MiB).
pub const DEFAULT_MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;

/// Unified DPG detection engine.
pub struct DpgDetector {
    ruleset: RuleSet,
    kv_scanner: KvScanner,
    conn_scanner: ConnScanner,
    india_scanner: IndiaScanner,
    entropy_scanner: EntropyScanner,
    terms_scanner: Option<TermsScanner>,
    max_scan_bytes: usize,
}

impl DpgDetector {
    /// Constructs a `DpgDetector` with the default built-in rule sets.
    pub fn new() -> Result<Self, DpgError> {
        let ruleset = RuleSet::builtin()?;
        let kv_scanner = KvScanner::new()?;
        let conn_scanner = ConnScanner::new()?;
        let india_scanner = IndiaScanner::new()?;
        let entropy_scanner = EntropyScanner::new()?;

        Ok(DpgDetector {
            ruleset,
            kv_scanner,
            conn_scanner,
            india_scanner,
            entropy_scanner,
            terms_scanner: None,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
        })
    }

    /// Extends the detector with project custom confidential terms.
    pub fn with_custom_terms(mut self, terms: &[String]) -> Result<Self, DpgError> {
        if !terms.is_empty() {
            self.terms_scanner = Some(TermsScanner::new(terms)?);
        }
        Ok(self)
    }

    /// Sets a custom maximum scan size limit in bytes.
    pub fn with_max_scan_bytes(mut self, limit: usize) -> Self {
        self.max_scan_bytes = limit;
        self
    }
}

impl Detector for DpgDetector {
    fn scan(&self, text: &str, ctx: &RequestContext) -> Result<Vec<Finding>, DpgError> {
        // DT-06: Inputs exceeding the maximum size limit fail closed with D002
        if text.len() > self.max_scan_bytes {
            return Err(DpgError::Detection {
                code: ErrorCode::D002,
                detail: SafeDetail::from_static("Input exceeds maximum scan size limit"),
            });
        }

        // Check deadline before starting compute
        ctx.check_deadline()?;

        let mut raw_findings = Vec::new();

        // 1. Prefilter + Built-in & Gitleaks rules
        let candidate_rule_indices = self.ruleset.prefilter().candidate_rules(text);
        for idx in candidate_rule_indices {
            if let Some(rule) = self.ruleset.rules().get(idx) {
                let mut matches = rule.scan(text);
                raw_findings.append(&mut matches);
            }
        }

        // 2. Custom terms (if configured)
        if let Some(ref terms) = self.terms_scanner {
            let mut terms_matches = terms.scan(text);
            raw_findings.append(&mut terms_matches);
        }

        // 3. Key-Value and .env scanner
        let mut kv_matches = self.kv_scanner.scan(text);
        raw_findings.append(&mut kv_matches);

        // 4. Connection string scanner
        let mut conn_matches = self.conn_scanner.scan(text);
        raw_findings.append(&mut conn_matches);

        // 5. Indian national identifiers
        let mut india_matches = self.india_scanner.scan(text);
        raw_findings.append(&mut india_matches);

        // 6. Entropy candidates
        let mut entropy_matches = self.entropy_scanner.scan(text);
        raw_findings.append(&mut entropy_matches);

        // 7. Resolve overlaps by priority and length
        let resolved = resolve_overlaps(raw_findings);

        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use dpg_core::context::{ProjectContext, ProjectId, SessionId};
    use dpg_core::types::Category;

    fn mock_context() -> RequestContext {
        RequestContext {
            project: ProjectContext {
                root: std::path::PathBuf::from("/test/project"),
                id: ProjectId::new(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
            },
            session: SessionId::new("test-session".to_string()),
            route: dpg_core::types::Route::HookPostToolUse,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        }
    }

    #[test]
    fn test_sr_dt_06_input_too_large_fails_with_d002() {
        let detector = DpgDetector::new()
            .expect("detector init")
            .with_max_scan_bytes(100);

        let ctx = mock_context();
        let big_input = "a".repeat(150);

        let err = detector.scan(&big_input, &ctx).expect_err("should reject");
        assert_eq!(err.code(), ErrorCode::D002);
    }

    #[test]
    fn test_sr_dt_05_unicode_cjk_emoji_char_boundaries() {
        let detector = DpgDetector::new().expect("detector init");
        let ctx = mock_context();

        // 🔒 (4 bytes) + 機密情報 (12 bytes) + ": " (2 bytes) + AWS key
        let text = "🔒機密情報: AKIA1234567890ABCDEF and more text";

        let findings = detector.scan(text, &ctx).expect("scan succeeds");
        assert!(
            !findings.is_empty(),
            "Must detect AWS key following Unicode"
        );

        let finding = &findings[0];
        assert_eq!(finding.category, Category::KnownSecret);
        assert_eq!(finding.span.as_str(text), "AKIA1234567890ABCDEF");

        // Zero-width joiner test: ZWJ inside non-alphanumeric separator
        let text_zwj = "API_KEY\u{200D}=\"super-secret-token-12345\"";
        let findings_zwj = detector.scan(text_zwj, &ctx).expect("scan succeeds");
        // Spans must always be on valid character boundaries
        for f in findings_zwj {
            assert!(text_zwj.is_char_boundary(f.span.start));
            assert!(text_zwj.is_char_boundary(f.span.end));
        }
    }
}
