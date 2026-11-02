//! Compiled rule set managing built-in rules, prefiltering, and project custom terms.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};

use crate::prefilter::Prefilter;
use crate::rules::{load_rules_toml, Rule, RuleSource};

/// Embedded built-in rules TOML file.
const BUILTIN_RULES_TOML: &str = include_str!("../../../rules/dpg.toml");

/// An immutable, compiled set of detection rules and terms prefilters.
pub struct RuleSet {
    rules: Vec<Rule>,
    prefilter: Prefilter,
    terms: Option<AhoCorasick>,
}

impl RuleSet {
    /// Loads and compiles the default built-in DPG detection rules.
    pub fn builtin() -> Result<Self, DpgError> {
        let rules = load_rules_toml(BUILTIN_RULES_TOML, RuleSource::Dpg)?;
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
}
