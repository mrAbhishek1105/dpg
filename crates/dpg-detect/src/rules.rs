//! Rule model and TOML rule loader for DPG.

use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::{Category, Confidence, RuleId};
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
}
