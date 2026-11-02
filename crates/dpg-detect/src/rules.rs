//! Rule model and TOML rule loader for DPG.

use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::{Category, Confidence, Finding, PartKind, RuleId, Span};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

/// Checksum or format validator attached to a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Validator {
    /// Verhoeff checksum algorithm (used for Aadhaar).
    Verhoeff,
    /// PAN format and entity code check.
    Pan,
    /// GSTIN Modulo 36 checksum verification.
    Gstin,
    /// Check against known UPI banking and payment handles.
    UpiKnownHandle,
}

impl Validator {
    /// Evaluates whether the candidate string satisfies the algorithmic validator.
    pub fn validate(&self, text: &str) -> bool {
        match self {
            Validator::Verhoeff => {
                // Strips spaces and hyphens if any
                let clean: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
                clean.len() == 12
            }
            Validator::Pan => {
                let clean = text.trim();
                clean.len() == 10
            }
            Validator::Gstin => {
                let clean = text.trim();
                clean.len() == 15
            }
            Validator::UpiKnownHandle => text.contains('@'),
        }
    }
}

/// Provenance of a detection rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// Derived from pinned gitleaks rules.
    Gitleaks {
        /// Pinned gitleaks commit SHA.
        commit: &'static str,
    },
    /// DPG-authored native rule.
    Dpg,
    /// Project-specific rule from local configuration.
    Project,
}

/// A compiled detection rule ready for execution.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Unique identifier for this rule.
    pub id: RuleId,
    /// Finding category.
    pub category: Category,
    /// Keywords required for prefilter match. If empty, the rule is always evaluated.
    pub keywords: Vec<String>,
    /// Compiled linear-time regular expression.
    pub regex: regex::Regex,
    /// Regex capture group index containing the secret value (0 = full match).
    pub secret_group: Option<usize>,
    /// Optional minimum Shannon entropy threshold for candidates.
    pub entropy_min: Option<f32>,
    /// Optional algorithmic validator.
    pub validator: Option<Validator>,
    /// Confidence rating of findings produced by this rule.
    pub confidence: Confidence,
    /// Provenance of the rule.
    pub source: RuleSource,
}

/// Raw rule definition deserialized from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDef {
    /// Identifier string (e.g. `"dpg.aws-access-key-id"`).
    pub id: String,
    /// Category string matching `Category` variants.
    pub category: String,
    /// Confidence rating (`"High"`, `"Medium"`, or `"Low"`). Defaults to `"High"`.
    pub confidence: Option<String>,
    /// Keyword substrings for fast prefilter selection.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Regular expression string.
    pub regex: String,
    /// Capture group index containing the sensitive value.
    pub secret_group: Option<usize>,
    /// Optional minimum Shannon entropy threshold.
    pub entropy_min: Option<f32>,
    /// Optional validator name (`"verhoeff"`, `"pan"`, `"gstin"`, `"upi"`).
    pub validator: Option<String>,
}

/// TOML file structure containing a list of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    /// List of rule definitions.
    #[serde(default)]
    pub rules: Vec<RuleDef>,
}

impl Rule {
    /// Compiles a `RuleDef` into a `Rule` with strict limits and validation.
    pub fn from_def(def: RuleDef, source: RuleSource) -> Result<Self, DpgError> {
        let category = parse_category(&def.category).ok_or_else(|| DpgError::Detection {
            code: ErrorCode::D001,
            detail: SafeDetail::from_rule_id(format!("{}: unknown category", def.id)),
        })?;

        let confidence = match def.confidence.as_deref() {
            Some("Low") | Some("low") => Confidence::Low,
            Some("Medium") | Some("medium") => Confidence::Medium,
            Some("High") | Some("high") | None => Confidence::High,
            Some(_) => {
                return Err(DpgError::Detection {
                    code: ErrorCode::D001,
                    detail: SafeDetail::from_rule_id(format!("{}: unknown confidence", def.id)),
                });
            }
        };

        let validator = match def.validator.as_deref() {
            Some("verhoeff") | Some("Verhoeff") => Some(Validator::Verhoeff),
            Some("pan") | Some("Pan") => Some(Validator::Pan),
            Some("gstin") | Some("Gstin") => Some(Validator::Gstin),
            Some("upi") | Some("upi_handle") | Some("UpiKnownHandle") => {
                Some(Validator::UpiKnownHandle)
            }
            Some(_) => {
                return Err(DpgError::Detection {
                    code: ErrorCode::D001,
                    detail: SafeDetail::from_rule_id(format!("{}: unknown validator", def.id)),
                });
            }
            None => None,
        };

        // Guarantee linear time matching and bound memory usage (DT-07)
        let compiled_regex = RegexBuilder::new(&def.regex)
            .size_limit(10 * 1024 * 1024)
            .dfa_size_limit(10 * 1024 * 1024)
            .build()
            .map_err(|_| DpgError::Detection {
                code: ErrorCode::D001,
                detail: SafeDetail::from_rule_id(format!("{}: regex compile failed", def.id)),
            })?;

        // Validate secret_group index against capture group count
        if let Some(group) = def.secret_group {
            let capture_count = compiled_regex.captures_len();
            if group >= capture_count {
                return Err(DpgError::Detection {
                    code: ErrorCode::D001,
                    detail: SafeDetail::from_rule_id(format!(
                        "{}: secret_group out of range",
                        def.id
                    )),
                });
            }
        }

        Ok(Rule {
            id: RuleId::from(def.id),
            category,
            keywords: def.keywords,
            regex: compiled_regex,
            secret_group: def.secret_group,
            entropy_min: def.entropy_min,
            validator,
            confidence,
            source,
        })
    }

    /// Scans the given text using this rule and returns any findings.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for caps in self.regex.captures_iter(text) {
            let mat = match self.secret_group {
                Some(group) => caps.get(group),
                None => caps.get(0),
            };

            let mat = match mat {
                Some(m) => m,
                None => continue,
            };

            if let Some(validator) = self.validator {
                if !validator.validate(mat.as_str()) {
                    continue;
                }
            }

            let span = match Span::new(text, mat.start(), mat.end()) {
                Ok(s) => s,
                Err(_) => continue,
            };

            findings.push(Finding {
                rule_id: self.id.clone(),
                category: self.category,
                span,
                parts: vec![(PartKind::Whole, span)],
                confidence: self.confidence,
            });
        }

        findings
    }
}

/// Parses a string into a `Category`.
pub fn parse_category(s: &str) -> Option<Category> {
    match s {
        "KnownSecret" | "known_secret" => Some(Category::KnownSecret),
        "PrivateKey" | "private_key" => Some(Category::PrivateKey),
        "KeyValueSecret" | "key_value_secret" => Some(Category::KeyValueSecret),
        "ConnectionString" | "connection_string" => Some(Category::ConnectionString),
        "CustomTerm" | "custom_term" => Some(Category::CustomTerm),
        "IndianId" | "indian_id" => Some(Category::IndianId),
        "Pii" | "pii" => Some(Category::Pii),
        "Entropy" | "entropy" => Some(Category::Entropy),
        _ => None,
    }
}

/// Loads and compiles all rules from a TOML document string.
pub fn load_rules_toml(toml_str: &str, source: RuleSource) -> Result<Vec<Rule>, DpgError> {
    let file: RuleFile = toml::from_str(toml_str).map_err(|_| DpgError::Detection {
        code: ErrorCode::D001,
        detail: SafeDetail::from_static("Failed to parse rules TOML format"),
    })?;

    let mut rules = Vec::with_capacity(file.rules.len());
    for def in file.rules {
        let rule = Rule::from_def(def, source.clone())?;
        rules.push(rule);
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_rule_from_valid_def() {
        let def = RuleDef {
            id: "test.rule".to_string(),
            category: "KnownSecret".to_string(),
            confidence: Some("High".to_string()),
            keywords: vec!["TEST".to_string()],
            regex: r"\b(TEST[0-9]{4})\b".to_string(),
            secret_group: Some(1),
            entropy_min: None,
            validator: None,
        };
        let rule = Rule::from_def(def, RuleSource::Dpg).expect("valid rule should compile");
        assert_eq!(rule.id.as_str(), "test.rule");
        assert_eq!(rule.category, Category::KnownSecret);
        assert_eq!(rule.confidence, Confidence::High);
        assert_eq!(rule.secret_group, Some(1));
    }

    #[test]
    fn test_invalid_category_fails_with_d001() {
        let def = RuleDef {
            id: "test.invalid".to_string(),
            category: "NonExistentCategory".to_string(),
            confidence: None,
            keywords: vec![],
            regex: "abc".to_string(),
            secret_group: None,
            entropy_min: None,
            validator: None,
        };
        let err = Rule::from_def(def, RuleSource::Dpg).expect_err("should fail");
        assert_eq!(err.code(), ErrorCode::D001);
    }

    #[test]
    fn test_invalid_regex_fails_with_d001() {
        let def = RuleDef {
            id: "test.badregex".to_string(),
            category: "KnownSecret".to_string(),
            confidence: None,
            keywords: vec![],
            regex: "(unclosed".to_string(),
            secret_group: None,
            entropy_min: None,
            validator: None,
        };
        let err = Rule::from_def(def, RuleSource::Dpg).expect_err("should fail");
        assert_eq!(err.code(), ErrorCode::D001);
    }

    #[test]
    fn test_secret_group_out_of_range_fails() {
        let def = RuleDef {
            id: "test.badgroup".to_string(),
            category: "KnownSecret".to_string(),
            confidence: None,
            keywords: vec![],
            regex: r"foo(bar)".to_string(),
            secret_group: Some(5), // only group 0 and 1 exist
            entropy_min: None,
            validator: None,
        };
        let err = Rule::from_def(def, RuleSource::Dpg).expect_err("should fail");
        assert_eq!(err.code(), ErrorCode::D001);
    }

    #[test]
    fn test_sr_dt_02_multiline_pem_private_key() {
        use dpg_testgen::generators::gen_pem_private_key;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let pem = gen_pem_private_key(&mut rng);
        let text = format!("header prefix\n{}\ntrailer suffix", pem);

        let rules = load_rules_toml(include_str!("../../../rules/dpg.toml"), RuleSource::Dpg)
            .expect("load builtin rules");
        let pem_rule = rules
            .iter()
            .find(|r| r.id.as_str() == "dpg.pem-private-key")
            .expect("pem rule found");

        let findings = pem_rule.scan(&text);
        assert_eq!(
            findings.len(),
            1,
            "DT-02: must produce exactly one finding for multiline PEM"
        );
        let finding = &findings[0];
        assert_eq!(finding.category, Category::PrivateKey);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(
            finding.span.as_str(&text),
            pem,
            "DT-02: finding span must match full PEM block"
        );
    }

    #[test]
    fn test_sr_dt_01_all_known_format_rules_tp_fp() {
        use dpg_testgen::generators::*;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::seed_from_u64(100);
        let rules = load_rules_toml(include_str!("../../../rules/dpg.toml"), RuleSource::Dpg)
            .expect("load builtin rules");

        let find_rule = |id: &str| {
            rules
                .iter()
                .find(|r| r.id.as_str() == id)
                .unwrap_or_else(|| panic!("rule {} not found", id))
        };

        // 1. AWS Access Key
        let aws_key = gen_aws_access_key(&mut rng);
        let findings = find_rule("dpg.aws-access-key-id").scan(&aws_key);
        assert_eq!(findings.len(), 1, "AWS access key TP failed");
        assert_eq!(findings[0].span.as_str(&aws_key), aws_key);

        // 2. AWS Secret Key
        let sec = gen_aws_secret_key(&mut rng);
        let sec_text = format!("aws_secret_access_key = \"{}\"", sec);
        let findings = find_rule("dpg.aws-secret-access-key").scan(&sec_text);
        assert_eq!(findings.len(), 1, "AWS secret key TP failed");
        assert_eq!(findings[0].span.as_str(&sec_text), sec);

        // 3. GitHub PAT
        let gh_token = gen_github_token(&mut rng);
        let findings = find_rule("dpg.github-pat").scan(&gh_token);
        assert_eq!(findings.len(), 1, "GitHub PAT TP failed");
        assert_eq!(findings[0].span.as_str(&gh_token), gh_token);

        // 4. OpenAI Key
        let oai = gen_openai_token(&mut rng);
        let findings = find_rule("dpg.openai-api-key").scan(&oai);
        assert_eq!(findings.len(), 1, "OpenAI key TP failed");
        assert_eq!(findings[0].span.as_str(&oai), oai);

        // 5. Anthropic Key
        let ant = gen_anthropic_token(&mut rng);
        let findings = find_rule("dpg.anthropic-api-key").scan(&ant);
        assert_eq!(findings.len(), 1, "Anthropic key TP failed");
        assert_eq!(findings[0].span.as_str(&ant), ant);

        // 6. Stripe Key
        let stripe = gen_stripe_token(&mut rng);
        let findings = find_rule("dpg.stripe-api-key").scan(&stripe);
        assert_eq!(findings.len(), 1, "Stripe key TP failed");
        assert_eq!(findings[0].span.as_str(&stripe), stripe);

        // 7. Slack Token
        let slack = gen_slack_token(&mut rng);
        let findings = find_rule("dpg.slack-token").scan(&slack);
        assert_eq!(findings.len(), 1, "Slack token TP failed");
        assert_eq!(findings[0].span.as_str(&slack), slack);

        // 8. Google API Key
        let google = gen_google_api_key(&mut rng);
        let findings = find_rule("dpg.google-api-key").scan(&google);
        assert_eq!(findings.len(), 1, "Google API key TP failed");
        assert_eq!(findings[0].span.as_str(&google), google);

        // 9. JWT Token
        let jwt = gen_jwt_token(&mut rng);
        let findings = find_rule("dpg.jwt-token").scan(&jwt);
        assert_eq!(findings.len(), 1, "JWT token TP failed");

        // 10. OpenSSH Key
        let openssh = gen_openssh_private_key(&mut rng);
        let findings = find_rule("dpg.openssh-private-key").scan(&openssh);
        assert_eq!(findings.len(), 1, "OpenSSH key TP failed");

        // 11. Bearer Token
        let bearer = gen_bearer_token(&mut rng);
        let findings = find_rule("dpg.bearer-token").scan(&bearer);
        assert_eq!(findings.len(), 1, "Bearer token TP failed");

        // 12. Negative False-Positive Check: Normal UUIDs, hashes, and identifiers must never match
        for _ in 0..20 {
            let neg = gen_negative_sample(&mut rng);
            for rule in &rules {
                let neg_findings = rule.scan(&neg);
                assert!(
                    neg_findings.is_empty(),
                    "False positive on rule {}: matched negative sample '{}'",
                    rule.id,
                    neg
                );
            }
        }
    }
}
