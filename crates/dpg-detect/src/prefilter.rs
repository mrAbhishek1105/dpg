//! Aho-Corasick multi-keyword prefilter for fast candidate rule selection.

use std::collections::HashSet;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};

use crate::rules::Rule;

/// Prefilter that screens text for keywords before running expensive regular expressions.
#[derive(Debug)]
pub struct Prefilter {
    ac: Option<AhoCorasick>,
    /// Map from Aho-Corasick pattern index to list of rule indices.
    pattern_to_rules: Vec<Vec<usize>>,
    /// Rule indices that have no keywords and must always be evaluated.
    always_run_rules: Vec<usize>,
}

impl Prefilter {
    /// Builds a prefilter from a slice of compiled rules.
    pub fn new(rules: &[Rule]) -> Result<Self, DpgError> {
        let mut unique_patterns: Vec<String> = Vec::new();
        let mut pattern_map: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut pattern_to_rules: Vec<Vec<usize>> = Vec::new();
        let mut always_run_rules: Vec<usize> = Vec::new();

        for (rule_idx, rule) in rules.iter().enumerate() {
            if rule.keywords.is_empty() {
                always_run_rules.push(rule_idx);
            } else {
                for kw in &rule.keywords {
                    let pattern_idx = match pattern_map.get(kw) {
                        Some(&idx) => idx,
                        None => {
                            let idx = unique_patterns.len();
                            unique_patterns.push(kw.clone());
                            pattern_map.insert(kw.clone(), idx);
                            pattern_to_rules.push(Vec::new());
                            idx
                        }
                    };
                    pattern_to_rules[pattern_idx].push(rule_idx);
                }
            }
        }

        let ac = if unique_patterns.is_empty() {
            None
        } else {
            let ac = AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .build(&unique_patterns)
                .map_err(|_| DpgError::Detection {
                    code: ErrorCode::D001,
                    detail: SafeDetail::from_static("Failed to build Aho-Corasick prefilter"),
                })?;
            Some(ac)
        };

        Ok(Prefilter {
            ac,
            pattern_to_rules,
            always_run_rules,
        })
    }

    /// Identifies all candidate rule indices whose keywords appear in `text`.
    ///
    /// Rules without keywords are always included.
    pub fn candidate_rules(&self, text: &str) -> Vec<usize> {
        let mut candidates = HashSet::new();

        for &rule_idx in &self.always_run_rules {
            candidates.insert(rule_idx);
        }

        if let Some(ref ac) = self.ac {
            for mat in ac.find_iter(text) {
                let pat_idx = mat.pattern().as_usize();
                if let Some(rule_indices) = self.pattern_to_rules.get(pat_idx) {
                    for &r_idx in rule_indices {
                        candidates.insert(r_idx);
                    }
                }
            }
        }

        let mut res: Vec<usize> = candidates.into_iter().collect();
        res.sort_unstable();
        res
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::rules::{RuleDef, RuleSource};
    use std::time::Instant;

    #[test]
    fn test_prefilter_keyword_matching_and_skipping() {
        let rule_aws = Rule::from_def(
            RuleDef {
                id: "aws".to_string(),
                category: "KnownSecret".to_string(),
                confidence: None,
                keywords: vec!["AKIA".to_string(), "ASIA".to_string()],
                regex: r"AKIA[0-9A-Z]{16}".to_string(),
                secret_group: None,
                entropy_min: None,
                validator: None,
            },
            RuleSource::Dpg,
        )
        .expect("rule should compile");

        let rule_github = Rule::from_def(
            RuleDef {
                id: "github".to_string(),
                category: "KnownSecret".to_string(),
                confidence: None,
                keywords: vec!["ghp_".to_string()],
                regex: r"ghp_[0-9a-zA-Z]{36}".to_string(),
                secret_group: None,
                entropy_min: None,
                validator: None,
            },
            RuleSource::Dpg,
        )
        .expect("rule should compile");

        let rule_generic = Rule::from_def(
            RuleDef {
                id: "generic".to_string(),
                category: "KeyValueSecret".to_string(),
                confidence: None,
                keywords: vec![], // always run
                regex: r"secret=123".to_string(),
                secret_group: None,
                entropy_min: None,
                validator: None,
            },
            RuleSource::Dpg,
        )
        .expect("rule should compile");

        let rules = vec![rule_aws, rule_github, rule_generic];
        let prefilter = Prefilter::new(&rules).expect("prefilter should build");

        // 1. Text with only AWS keyword: candidates should be AWS (0) and generic (2), skipping github (1)
        let candidates1 =
            prefilter.candidate_rules(&format!("Found {}{} here", "AKIA", "1234567890ABCDEF"));
        assert_eq!(candidates1, vec![0, 2]);

        // 2. Text with only GitHub keyword: candidates should be GitHub (1) and generic (2), skipping AWS (0)
        let candidates2 = prefilter.candidate_rules("My token is ghp_abcd1234");
        assert_eq!(candidates2, vec![1, 2]);

        // 3. Text with neither keyword: only generic (2)
        let candidates3 = prefilter.candidate_rules("Just normal text without any credentials");
        assert_eq!(candidates3, vec![2]);
    }

    #[test]
    fn test_sr_dt_07_pathological_input_linear_time() {
        let rule = Rule::from_def(
            RuleDef {
                id: "dt07".to_string(),
                category: "KnownSecret".to_string(),
                confidence: None,
                keywords: vec!["SECRET".to_string()],
                regex: r"(a+)+b".to_string(), // classic backtracking trigger in naive regex engines
                secret_group: None,
                entropy_min: None,
                validator: None,
            },
            RuleSource::Dpg,
        )
        .expect("rule should compile in linear-time regex engine");

        let rules = vec![rule];
        let prefilter = Prefilter::new(&rules).expect("prefilter should build");

        // 1,000,000 'a's pathological input per DT-07
        let input = "a".repeat(1_000_000);

        let start = Instant::now();
        let candidates = prefilter.candidate_rules(&input);
        assert!(candidates.is_empty()); // keyword "SECRET" is not present
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 1000,
            "DT-07 failed: pathological prefilter input took {:?} >= 1s",
            elapsed
        );
    }
}
