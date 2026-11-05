//! Compiled rule set managing built-in rules, prefiltering, and project custom terms.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};

use crate::prefilter::Prefilter;
use crate::rules::{load_rules_toml, Rule, RuleSource};

/// Embedded built-in DPG rules TOML file.
const BUILTIN_DPG_RULES_TOML: &str = include_str!("../../../rules/dpg.toml");

/// Embedded gitleaks-derived rules TOML file.
const BUILTIN_GITLEAKS_RULES_TOML: &str = include_str!("../../../rules/gitleaks.toml");

/// Pinned gitleaks commit SHA.
pub const GITLEAKS_PINNED_COMMIT: &str = "7cb43d81b490f0556f8742d4a520e5c8e31a1ba7";

/// An immutable, compiled set of detection rules and terms prefilters.
pub struct RuleSet {
    rules: Vec<Rule>,
    prefilter: Prefilter,
    terms: Option<AhoCorasick>,
}

impl RuleSet {
    /// Loads and compiles the default built-in DPG and gitleaks detection rules.
    pub fn builtin() -> Result<Self, DpgError> {
        let mut rules = load_rules_toml(BUILTIN_DPG_RULES_TOML, RuleSource::Dpg)?;
        let mut gitleaks_rules = load_rules_toml(
            BUILTIN_GITLEAKS_RULES_TOML,
            RuleSource::Gitleaks {
                commit: GITLEAKS_PINNED_COMMIT,
            },
        )?;
        rules.append(&mut gitleaks_rules);
        Self::from_rules(rules)
    }

    /// Creates a `RuleSet` from an arbitrary collection of compiled `Rule`s.
    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, DpgError> {
        let prefilter = Prefilter::new(&rules)?;
        Ok(RuleSet {
            rules,
            prefilter,
            terms: None,
        })
    }

    /// Extends this rule set with project-specific custom terms and additional project rules.
    pub fn with_project(
        &self,
        custom_terms: &[String],
        mut additional_rules: Vec<Rule>,
    ) -> Result<Self, DpgError> {
        let mut combined_rules = self.rules.clone();
        combined_rules.append(&mut additional_rules);

        let prefilter = Prefilter::new(&combined_rules)?;

        let terms = if custom_terms.is_empty() {
            None
        } else {
            // ASCII case-insensitive terms search
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::Standard)
                .build(custom_terms)
                .map_err(|_| DpgError::Detection {
                    code: ErrorCode::D001,
                    detail: SafeDetail::from_static("Failed to compile custom terms Aho-Corasick"),
                })?;
            Some(ac)
        };

        Ok(RuleSet {
            rules: combined_rules,
            prefilter,
            terms,
        })
    }

    /// Returns a slice of all compiled rules in this set.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Returns a reference to the keyword prefilter.
    pub fn prefilter(&self) -> &Prefilter {
        &self.prefilter
    }

    /// Returns a reference to the custom terms matcher, if configured.
    pub fn terms(&self) -> Option<&AhoCorasick> {
        self.terms.as_ref()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builtin_ruleset_compiles_successfully() {
        let ruleset = RuleSet::builtin().expect("builtin ruleset must compile cleanly");
        assert!(
            !ruleset.rules().is_empty(),
            "builtin ruleset must have at least one rule"
        );
    }

    #[test]
    fn test_with_project_custom_terms() {
        let ruleset = RuleSet::builtin().expect("builtin ruleset");
        let project_terms = vec![
            "SuperSecretProjectName".to_string(),
            "ProjectCodenameOmega".to_string(),
        ];
        let extended = ruleset
            .with_project(&project_terms, vec![])
            .expect("extending with project terms");

        let terms = extended.terms().expect("terms matcher should be present");
        let matches: Vec<_> = terms
            .find_iter("Working on supersecretprojectname today")
            .collect();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_gitleaks_rules_import_and_compilation() {
        let ruleset = RuleSet::builtin().expect("builtin ruleset with gitleaks");
        let gitleaks_rules: Vec<_> = ruleset
            .rules()
            .iter()
            .filter(|r| matches!(r.source, RuleSource::Gitleaks { .. }))
            .collect();
        assert!(
            !gitleaks_rules.is_empty(),
            "must have imported gitleaks rules"
        );

        // Verify gitlab pat rule
        let gitlab_rule = gitleaks_rules
            .iter()
            .find(|r| r.id.as_str() == "gitleaks.gitlab-pat")
            .expect("gitlab pat rule found");
        let gl = format!("{}{}", "glpat-", "1234567890abcdefghij");
        let text_gitlab = &format!("token: {gl}");
        let findings = gitlab_rule.scan(text_gitlab);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].span.as_str(text_gitlab), gl);

        // Verify sendgrid rule
        let sg_rule = gitleaks_rules
            .iter()
            .find(|r| r.id.as_str() == "gitleaks.sendgrid-api-key")
            .expect("sendgrid rule found");
        let text_sg = &format!(
            "{}.{}.{}",
            "SG", "1234567890123456789012", "1234567890123456789012345678901234567890123"
        );
        let findings = sg_rule.scan(text_sg);
        assert_eq!(findings.len(), 1);
    }
}
