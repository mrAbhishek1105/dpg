//! Priority-based finding overlap resolution and de-duplication.

use dpg_core::types::{Category, Finding};

/// Computes the priority ranking of a finding category per DETECT.md §11.
///
/// Priority: `PrivateKey` > `KnownSecret` > `ConnectionString` > `KeyValueSecret`
///           > `IndianId` > `CustomTerm` > `Pii` > `Entropy`
pub fn category_priority(category: Category) -> u8 {
    match category {
        Category::PrivateKey => 8,
        Category::KnownSecret => 7,
        Category::ConnectionString => 6,
        Category::KeyValueSecret => 5,
        Category::IndianId => 4,
        Category::CustomTerm => 3,
        Category::Pii => 2,
        Category::Entropy => 1,
    }
}

/// Checks whether two byte spans overlap.
pub fn spans_overlap(start_a: usize, end_a: usize, start_b: usize, end_b: usize) -> bool {
    let max_start = start_a.max(start_b);
    let min_end = end_a.min(end_b);
    max_start < min_end
}

/// Resolves overlapping finding spans using priority and length heuristics.
///
/// Guaranteed properties:
/// 1. Higher-priority category findings always defeat overlapping lower-priority findings.
/// 2. For identical priority, the longer span wins.
/// 3. The returned list has 0 overlapping spans and is sorted by `span.start`.
pub fn resolve_overlaps(mut findings: Vec<Finding>) -> Vec<Finding> {
    if findings.len() <= 1 {
        return findings;
    }

    // Sort candidates by:
    // 1. Priority descending (highest priority evaluated first)
    // 2. Length descending (longer spans win ties)
    // 3. Start position ascending (earlier spans win remaining ties)
    findings.sort_by(|a, b| {
        let prio_a = category_priority(a.category);
        let prio_b = category_priority(b.category);

        prio_b
            .cmp(&prio_a)
            .then_with(|| b.span.len().cmp(&a.span.len()))
            .then_with(|| a.span.start.cmp(&b.span.start))
    });

    let mut accepted: Vec<Finding> = Vec::new();

    for candidate in findings {
        let overlaps = accepted.iter().any(|acc| {
            spans_overlap(
                candidate.span.start,
                candidate.span.end,
                acc.span.start,
                acc.span.end,
            )
        });

        if !overlaps {
            accepted.push(candidate);
        }
    }

    // Sort accepted findings in text reading order
    accepted.sort_by_key(|f| f.span.start);
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpg_core::types::{Confidence, RuleId, Span};

    #[test]
    fn test_sr_dt_04_known_secret_beats_key_value_overlap() {
        let _text = format!("AWS_SECRET_KEY={}{}", "AKIA", "1234567890ABCDEF");

        // Span covering the AWS-style key (offset 15..35)
        let span = Span::new_raw(15, 35);

        let kv_finding = Finding {
            rule_id: RuleId::from_static("dpg.key-value-secret"),
            category: Category::KeyValueSecret,
            span,
            parts: vec![],
            confidence: Confidence::High,
        };

        let known_finding = Finding {
            rule_id: RuleId::from_static("dpg.aws-access-key-id"),
            category: Category::KnownSecret,
            span,
            parts: vec![],
            confidence: Confidence::High,
        };

        let resolved = resolve_overlaps(vec![kv_finding, known_finding]);
        assert_eq!(
            resolved.len(),
            1,
            "DT-04: Overlapping findings must be consolidated to exactly one"
        );
        assert_eq!(
            resolved[0].category,
            Category::KnownSecret,
            "DT-04: KnownSecret must beat KeyValueSecret"
        );
    }

    #[test]
    fn test_priority_hierarchy_ordering() {
        assert!(category_priority(Category::PrivateKey) > category_priority(Category::KnownSecret));
        assert!(
            category_priority(Category::KnownSecret)
                > category_priority(Category::ConnectionString)
        );
        assert!(
            category_priority(Category::ConnectionString)
                > category_priority(Category::KeyValueSecret)
        );
        assert!(
            category_priority(Category::KeyValueSecret) > category_priority(Category::IndianId)
        );
        assert!(category_priority(Category::IndianId) > category_priority(Category::CustomTerm));
        assert!(category_priority(Category::CustomTerm) > category_priority(Category::Pii));
        assert!(category_priority(Category::Pii) > category_priority(Category::Entropy));
    }
}
