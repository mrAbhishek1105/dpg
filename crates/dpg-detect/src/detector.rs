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
    placeholder_re: regex::Regex,
}

/// Matches DPG's own placeholder tokens (`DPG_<CAT>_<8 Crockford base32>`).
const PLACEHOLDER_PATTERN: &str =
    r"DPG_(?:SECRET|PASS|USER|HOST|CONN|TERM|ID|PII)_[0-9A-HJKMNP-TV-Z]{8}";

/// Digest algorithm names that appear as `name@sha256:...` in image references.
const DIGEST_HANDLES: &[&str] = &["sha1", "sha224", "sha256", "sha384", "sha512", "md5"];

/// Drops findings that are known non-secrets:
/// * any finding overlapping one of DPG's own placeholders (re-masking a placeholder
///   would map a placeholder to a placeholder and break exact restore);
/// * documentation example credentials (AWS `...EXAMPLE`, `...EXAMPLEKEY`);
/// * container digest references mistaken for payment handles (`app@sha256`).
fn suppress(text: &str, f: &Finding, placeholders: &[(usize, usize)]) -> bool {
    if placeholders
        .iter()
        .any(|&(s, e)| f.span.start < e && s < f.span.end)
    {
        return true;
    }
    let value = text.get(f.span.start..f.span.end).unwrap_or_default();
    if value.ends_with("EXAMPLE") || value.contains("EXAMPLEKEY") {
        return true;
    }
    if f.rule_id.as_str() == "dpg.generic-handle" {
        if let Some((_, handle)) = value.rsplit_once('@') {
            let h = handle.to_ascii_lowercase();
            if DIGEST_HANDLES.contains(&h.as_str()) {
                return true;
            }
        }
    }
    false
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
            placeholder_re: regex::Regex::new(PLACEHOLDER_PATTERN).map_err(|_| {
                DpgError::Detection {
                    code: ErrorCode::D001,
                    detail: SafeDetail::from_static("Failed to compile placeholder pattern"),
                }
            })?,
        })
    }

    /// Extends the detector with project custom confidential terms.
    pub fn with_custom_terms(mut self, terms: &[String]) -> Result<Self, DpgError> {
        if !terms.is_empty() {
            self.terms_scanner = Some(TermsScanner::new(terms)?);
        }
        Ok(self)
    }

    /// Extends the detector with project-specific rules from `.dpg.toml` / global config.
    pub fn with_project_rules(mut self, rules: Vec<crate::rules::Rule>) -> Result<Self, DpgError> {
        if !rules.is_empty() {
            self.ruleset = self.ruleset.with_project(&[], rules)?;
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

        // 7. Drop known non-secrets (own placeholders, doc examples, digests)
        let placeholders: Vec<(usize, usize)> = self
            .placeholder_re
            .find_iter(text)
            .map(|m| (m.start(), m.end()))
            .collect();
        raw_findings.retain(|f| !suppress(text, f, &placeholders));

        // 8. Resolve overlaps by priority and length
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

    #[test]
    fn test_own_placeholders_never_remasked_and_examples_suppressed() {
        let detector = DpgDetector::new().expect("detector");
        let ctx = mock_context();
        // Doc example keys are assembled at runtime so secret scanners never see them.
        let aws_doc_id = format!("aws_access_key_id = {}{}\n", "AKIAIOSFODNN7", "EXAMPLE");
        let aws_doc_secret = format!(
            "aws_secret_access_key = {}{}\n",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY"
        );
        for text in [
            "password=DPG_PASS_ABCDEFGH\n",
            "token: DPG_SECRET_0123ABCD\n",
            aws_doc_id.as_str(),
            aws_doc_secret.as_str(),
            "image: ghcr.io/acme/app@sha256:0123abcd\n",
            "API_KEY=your-api-key-here\n",
        ] {
            let findings = detector.scan(text, &ctx).expect("scan");
            assert!(findings.is_empty(), "{text:?} -> {findings:?}");
        }
        // A masked connection string is not re-masked (no finding touches a placeholder).
        let text =
            "DATABASE_URL=postgres://DPG_USER_0123ABCD:DPG_PASS_ABCDEFGH@DPG_HOST_ZZZZ9999/db\n";
        let first_ph = text.find("DPG_").unwrap_or(0);
        let findings = detector.scan(text, &ctx).expect("scan");
        assert!(
            findings.iter().all(|f| f.span.end <= first_ph),
            "{findings:?}"
        );
        // Real-looking values next to placeholders are still found.
        let findings = detector
            .scan(
                &format!(
                    "password=DPG_PASS_ABCDEFGH other={}\n",
                    dpg_testgen::gen_aws_access_key(&mut dpg_testgen::create_rng(4711))
                ),
                &ctx,
            )
            .expect("scan");
        assert_eq!(findings.len(), 1, "{findings:?}");
    }
}
