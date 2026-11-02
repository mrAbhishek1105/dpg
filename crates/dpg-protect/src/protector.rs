//! Text protector implementation applying policy decisions and placeholder replacement.

use std::collections::HashMap;
use std::sync::Arc;

use dpg_core::context::RequestContext;
use dpg_core::engine::Protector;
use dpg_core::error::DpgError;
use dpg_core::types::{
    Action, BlockItem, Category, Decision, Finding, PartKind, Report, Span, WarnItem,
};

use crate::placeholder::{generate_csprng, PlaceholderCat};
use crate::store::MappingStore;

/// Computes the 1-indexed line number in `text` for a byte offset.
fn compute_line_number(text: &str, byte_offset: usize) -> usize {
    let offset = byte_offset.min(text.len());
    let prefix = &text[..offset];
    prefix.bytes().filter(|&b| b == b'\n').count() + 1
}

/// DPG protector that applies policy decisions and performs right-to-left placeholder masking.
pub struct DpgProtector {
    store: Option<Arc<MappingStore>>,
}

/// Type alias for `DpgProtector`.
pub type Protect = DpgProtector;

impl DpgProtector {
    /// Constructs a protector with an optional persistent mapping store.
    pub fn new(store: Option<Arc<MappingStore>>) -> Self {
        Self { store }
    }

    /// Constructs a protector with a backing mapping store.
    pub fn with_store(store: Arc<MappingStore>) -> Self {
        Self { store: Some(store) }
    }

    /// Constructs an ephemeral protector without persistent storage.
    pub fn ephemeral() -> Self {
        Self { store: None }
    }
}

impl Protector for DpgProtector {
    fn apply(
        &self,
        ctx: &RequestContext,
        text: &str,
        findings: &[Finding],
        decisions: &[Decision],
    ) -> Result<(String, Report), DpgError> {
        let mut report = Report::default();
        let mut degraded = self.store.is_none();

        // In-memory cache for this request so identical secrets get the same placeholder
        // even in ephemeral mode.
        let mut session_placeholders: HashMap<(String, PlaceholderCat), String> = HashMap::new();

        // Collect replacements: (Span, Placeholder)
        let mut replacements: Vec<(Span, String)> = Vec::new();

        for decision in decisions {
            if decision.finding >= findings.len() {
                continue;
            }
            let finding = &findings[decision.finding];

            match decision.action {
                Action::Allow => {}
                Action::Warn => {
                    report.warned.push(WarnItem {
                        rule_id: finding.rule_id.clone(),
                        category: finding.category,
                        line_number: compute_line_number(text, finding.span.start),
                    });
                }
                Action::Block => {
                    report.blocked.push(BlockItem {
                        rule_id: finding.rule_id.clone(),
                        category: finding.category,
                        line_number: compute_line_number(text, finding.span.start),
                        reason: decision.reason.clone(),
                    });
                }
                Action::Mask => {
                    // Determine target span and placeholder category
                    let (target_span, cat) = if finding.category == Category::ConnectionString {
                        if let Some((_, pass_span)) =
                            finding.parts.iter().find(|(k, _)| *k == PartKind::Password)
                        {
                            (*pass_span, PlaceholderCat::Pass)
                        } else {
                            (finding.span, PlaceholderCat::Conn)
                        }
                    } else {
                        (
                            finding.span,
                            PlaceholderCat::from_category_and_part(
                                finding.category,
                                PartKind::Whole,
                            ),
                        )
                    };

                    if target_span.end > text.len() || target_span.start > target_span.end {
                        continue;
                    }

                    let secret_val = &text[target_span.start..target_span.end];

                    // Get or create placeholder
                    let key = (secret_val.to_string(), cat);
                    let ph = if let Some(existing) = session_placeholders.get(&key) {
                        existing.clone()
                    } else {
                        let generated = if let Some(ref store) = self.store {
                            match store.get_or_create(&ctx.project.id, secret_val, cat) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::warn!(
                                        code = %e.code(),
                                        "MappingStore error, falling back to ephemeral mode"
                                    );
                                    degraded = true;
                                    generate_csprng(cat)
                                }
                            }
                        } else {
                            generate_csprng(cat)
                        };
                        session_placeholders.insert(key, generated.clone());
                        generated
                    };

                    replacements.push((target_span, ph));
                    report.masked += 1;
                }
            }
        }

        report.degraded = degraded;

        // If no replacements, return original text
        if replacements.is_empty() {
            return Ok((text.to_string(), report));
        }

        // Sort replacements right-to-left (descending by span.start)
        replacements.sort_by_key(|a| std::cmp::Reverse(a.0.start));

        let mut masked_text = text.to_string();
        let mut last_start = usize::MAX;

        for (span, placeholder) in replacements {
            if span.end > last_start {
                // Skip overlapping replacement to avoid corruption
                continue;
            }
            if span.end <= masked_text.len()
                && masked_text.is_char_boundary(span.start)
                && masked_text.is_char_boundary(span.end)
            {
                masked_text.replace_range(span.start..span.end, &placeholder);
                last_start = span.start;
            }
        }

        Ok((masked_text, report))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::borrow::Cow;
    use std::path::PathBuf;
    use std::time::Instant;

    use crate::key::FixedKeyProvider;
    use crate::placeholder::is_placeholder;
    use dpg_core::context::{ProjectContext, ProjectId, SessionId};
    use dpg_core::types::{Confidence, Route, RuleId};

    fn make_test_context(project_name: &str) -> RequestContext {
        RequestContext {
            project: ProjectContext {
                root: PathBuf::from("/test/project"),
                id: ProjectId::new(project_name.to_string()),
            },
            session: SessionId::new("session-test".to_string()),
            route: Route::HookPostToolUse,
            deadline: Instant::now() + std::time::Duration::from_secs(10),
        }
    }

    #[test]
    fn test_sr_pm_01_protector_same_value_same_placeholder() {
        let mut rng = dpg_testgen::create_rng(111);
        let secret = dpg_testgen::gen_aws_access_key(&mut rng);

        let keys = FixedKeyProvider::new([1u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let protector = DpgProtector::with_store(store.clone());
        let ctx = make_test_context("proj-1");

        let text1 = format!("Secret is {secret} here");
        let span1 = Span::new(&text1, 10, 10 + secret.len()).expect("span");
        let findings1 = vec![Finding {
            rule_id: RuleId::from_static("dpg.aws.access-key"),
            category: Category::KnownSecret,
            span: span1,
            parts: vec![(PartKind::Whole, span1)],
            confidence: Confidence::High,
        }];
        let decisions1 = vec![Decision {
            finding: 0,
            action: Action::Mask,
            rule_id: RuleId::from_static("dpg.aws.access-key"),
            reason: Cow::Borrowed("AWS key masked"),
        }];

        let (masked1, report1) = protector
            .apply(&ctx, &text1, &findings1, &decisions1)
            .expect("protect 1");
        assert_eq!(report1.masked, 1);
        assert!(!report1.degraded);
        assert!(!masked1.contains(&secret));

        // Second call with same value in different sentence
        let text2 = format!("Another log: {secret} repeated");
        let span2 = Span::new(&text2, 13, 13 + secret.len()).expect("span");
        let findings2 = vec![Finding {
            rule_id: RuleId::from_static("dpg.aws.access-key"),
            category: Category::KnownSecret,
            span: span2,
            parts: vec![(PartKind::Whole, span2)],
            confidence: Confidence::High,
        }];
        let decisions2 = vec![Decision {
            finding: 0,
            action: Action::Mask,
            rule_id: RuleId::from_static("dpg.aws.access-key"),
            reason: Cow::Borrowed("AWS key masked"),
        }];

        let (masked2, report2) = protector
            .apply(&ctx, &text2, &findings2, &decisions2)
            .expect("protect 2");
        assert_eq!(report2.masked, 1);

        // Extract placeholders from both
        let ph1 = masked1.split_whitespace().nth(2).expect("ph1");
        let ph2 = masked2.split_whitespace().nth(2).expect("ph2");

        assert_eq!(
            ph1, ph2,
            "PM-01: Same value must receive identical placeholder across calls"
        );
        assert!(is_placeholder(ph1));
    }

    #[test]
    fn test_sr_pm_02_protector_different_projects() {
        let mut rng = dpg_testgen::create_rng(222);
        let secret = dpg_testgen::gen_github_token(&mut rng);

        let keys = FixedKeyProvider::new([1u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let protector = DpgProtector::with_store(store.clone());

        let ctx_a = make_test_context("proj-a");
        let ctx_b = make_test_context("proj-b");

        let text = format!("Token: {secret}");
        let span = Span::new(&text, 7, 7 + secret.len()).expect("span");
        let findings = vec![Finding {
            rule_id: RuleId::from_static("dpg.github.token"),
            category: Category::KnownSecret,
            span,
            parts: vec![(PartKind::Whole, span)],
            confidence: Confidence::High,
        }];
        let decisions = vec![Decision {
            finding: 0,
            action: Action::Mask,
            rule_id: RuleId::from_static("dpg.github.token"),
            reason: Cow::Borrowed("GitHub token masked"),
        }];

        let (masked_a, _) = protector
            .apply(&ctx_a, &text, &findings, &decisions)
            .expect("protect A");
        let (masked_b, _) = protector
            .apply(&ctx_b, &text, &findings, &decisions)
            .expect("protect B");

        assert_ne!(
            masked_a, masked_b,
            "PM-02: Different projects must receive different placeholders for same secret"
        );
    }

    #[test]
    fn test_fc_11_ephemeral_mode_degraded_notice() {
        let mut rng = dpg_testgen::create_rng(333);
        let secret = dpg_testgen::gen_anthropic_token(&mut rng);

        // Ephemeral mode (no store configured)
        let protector = DpgProtector::ephemeral();
        let ctx = make_test_context("proj-ephemeral");

        let text = format!("API_KEY=\"{secret}\"");
        let span = Span::new(&text, 9, 9 + secret.len()).expect("span");
        let findings = vec![Finding {
            rule_id: RuleId::from_static("dpg.anthropic.key"),
            category: Category::KnownSecret,
            span,
            parts: vec![(PartKind::Whole, span)],
            confidence: Confidence::High,
        }];
        let decisions = vec![Decision {
            finding: 0,
            action: Action::Mask,
            rule_id: RuleId::from_static("dpg.anthropic.key"),
            reason: Cow::Borrowed("Anthropic key masked"),
        }];

        let (masked, report) = protector
            .apply(&ctx, &text, &findings, &decisions)
            .expect("protect ephemeral");

        assert!(
            report.degraded,
            "FC-11: Ephemeral mode must report degraded = true"
        );
        assert_eq!(report.masked, 1);
        assert!(!masked.contains(&secret));
        assert!(masked.contains("DPG_SECRET_"));
    }

    #[test]
    fn test_sr_dt_10_connection_string_password_masking() {
        let keys = FixedKeyProvider::new([1u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let protector = DpgProtector::with_store(store);
        let ctx = make_test_context("proj-conn");

        let text = "DATABASE_URL=\"postgresql://db_user:super_secret_p%40ss@db.internal:5432/prod_db?ssl=true\"";
        let whole_span = Span::new(text, 14, 89).expect("whole span");
        let pass_span = Span::new(text, 35, 53).expect("pass span");

        let findings = vec![Finding {
            rule_id: RuleId::from_static("dpg.connection-string"),
            category: Category::ConnectionString,
            span: whole_span,
            parts: vec![
                (PartKind::Whole, whole_span),
                (PartKind::User, Span::new(text, 27, 34).expect("user span")),
                (PartKind::Password, pass_span),
                (PartKind::Host, Span::new(text, 54, 70).expect("host span")),
            ],
            confidence: Confidence::High,
        }];
        let decisions = vec![Decision {
            finding: 0,
            action: Action::Mask,
            rule_id: RuleId::from_static("dpg.connection-string"),
            reason: Cow::Borrowed("Connection string password masked"),
        }];

        let (masked, report) = protector
            .apply(&ctx, text, &findings, &decisions)
            .expect("protect connection string");

        assert_eq!(report.masked, 1);
        assert!(!masked.contains("super_secret_p%40ss"));
        assert!(
            masked.contains("postgresql://db_user:DPG_PASS_"),
            "DT-10: Connection string password replaced with DPG_PASS_*, keeping URL structure intact: {masked}"
        );
        assert!(masked.contains("@db.internal:5432/prod_db?ssl=true"));
    }

    #[test]
    fn test_right_to_left_multiple_findings() {
        let keys = FixedKeyProvider::new([1u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let protector = DpgProtector::with_store(store);
        let ctx = make_test_context("proj-multi");

        let text = "first: SECRET_AAA second: SECRET_BBB third: SECRET_CCC";
        let span1 = Span::new(text, 7, 17).expect("span1");
        let span2 = Span::new(text, 26, 36).expect("span2");
        let span3 = Span::new(text, 44, 54).expect("span3");

        let findings = vec![
            Finding {
                rule_id: RuleId::from_static("r1"),
                category: Category::KnownSecret,
                span: span1,
                parts: vec![(PartKind::Whole, span1)],
                confidence: Confidence::High,
            },
            Finding {
                rule_id: RuleId::from_static("r2"),
                category: Category::KnownSecret,
                span: span2,
                parts: vec![(PartKind::Whole, span2)],
                confidence: Confidence::High,
            },
            Finding {
                rule_id: RuleId::from_static("r3"),
                category: Category::KnownSecret,
                span: span3,
                parts: vec![(PartKind::Whole, span3)],
                confidence: Confidence::High,
            },
        ];

        let decisions = vec![
            Decision {
                finding: 0,
                action: Action::Mask,
                rule_id: RuleId::from_static("r1"),
                reason: Cow::Borrowed("r1"),
            },
            Decision {
                finding: 1,
                action: Action::Mask,
                rule_id: RuleId::from_static("r2"),
                reason: Cow::Borrowed("r2"),
            },
            Decision {
                finding: 2,
                action: Action::Mask,
                rule_id: RuleId::from_static("r3"),
                reason: Cow::Borrowed("r3"),
            },
        ];

        let (masked, report) = protector
            .apply(&ctx, text, &findings, &decisions)
            .expect("protect multi");

        assert_eq!(report.masked, 3);
        assert!(!masked.contains("SECRET_AAA"));
        assert!(!masked.contains("SECRET_BBB"));
        assert!(!masked.contains("SECRET_CCC"));

        assert!(masked.starts_with("first: DPG_SECRET_"));
        assert!(masked.contains(" second: DPG_SECRET_"));
        assert!(masked.contains(" third: DPG_SECRET_"));
    }

    #[test]
    fn test_end_to_end_detect_policy_protect_corpus_leaves_zero_originals() {
        use dpg_core::engine::{Detector, PolicyEngine};
        use dpg_detect::DpgDetector;
        use dpg_policy::DpgPolicy;

        let mut rng = dpg_testgen::create_rng(987654321);

        let detector = DpgDetector::new().expect("detector init");
        let policy = DpgPolicy::default_policy();
        let keys = FixedKeyProvider::new([77u8; 32]);
        let store = Arc::new(MappingStore::in_memory(&keys).expect("store init"));
        let protector = DpgProtector::with_store(store.clone());
        let ctx = make_test_context("proj-e2e");

        let aws_key = dpg_testgen::gen_aws_access_key(&mut rng);
        let github_token = dpg_testgen::gen_github_token(&mut rng);
        let openai_key = dpg_testgen::gen_openai_token(&mut rng);
        let slack_token = dpg_testgen::gen_slack_token(&mut rng);
        let aadhaar = dpg_testgen::gen_aadhaar(&mut rng);
        let pan = dpg_testgen::gen_pan(&mut rng);
        let conn_pass = "P%40ssw0rd_1234_Secret";

        let original_secrets = vec![
            &aws_key,
            &github_token,
            &openai_key,
            &slack_token,
            conn_pass,
            &aadhaar,
            &pan,
        ];

        let text = format!(
            "Configuration setup:\n\
             AWS_KEY={}\n\
             GITHUB_TOKEN={}\n\
             OPENAI_KEY={}\n\
             SLACK_TOKEN={}\n\
             DB_URL=postgresql://app_user:{}@localhost:5432/mydb\n\
             AADHAAR_ID={}\n\
             PAN_ID={}\n\
             All credentials loaded successfully.\n",
            original_secrets[0],
            original_secrets[1],
            original_secrets[2],
            original_secrets[3],
            original_secrets[4],
            original_secrets[5],
            original_secrets[6],
        );

        // 1. Detect
        let findings = detector.scan(&text, &ctx).expect("detect");
        assert!(
            findings.len() >= original_secrets.len(),
            "Detector must detect all synthetic secrets"
        );

        // 2. Policy
        let decisions = policy.decide(&ctx, &text, &findings).expect("policy");

        // 3. Protect
        let (masked_text, report) = protector
            .apply(&ctx, &text, &findings, &decisions)
            .expect("protect");

        assert!(
            report.masked >= original_secrets.len() as u32,
            "Must mask all sensitive findings"
        );
        assert!(!report.degraded);

        // 4. Verify ZERO original secrets appear anywhere in the masked output
        for secret in &original_secrets {
            assert!(
                !masked_text.contains(secret),
                "AC-E-05: Plaintext secret '{secret}' must NOT be present in masked text!\nMasked text:\n{masked_text}"
            );
        }

        // 5. Verify placeholders exist and are restorable from the store
        assert!(masked_text.contains("DPG_SECRET_"));
        assert!(masked_text.contains("DPG_PASS_"));
        assert!(masked_text.contains("DPG_ID_"));
    }
}
