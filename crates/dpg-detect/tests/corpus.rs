//! Synthetic labelled corpus evaluation for recall (AC-2 >= 95%) and precision (AC-3 >= 90%).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use dpg_core::context::{ProjectContext, ProjectId, RequestContext, SessionId};
use dpg_core::engine::Detector;
use dpg_detect::overlap::spans_overlap;
use dpg_detect::DpgDetector;
use dpg_testgen::corpus::{gen_env_file, gen_json_file, gen_yaml_file};
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::path::PathBuf;

fn mock_context() -> RequestContext {
    RequestContext {
        project: ProjectContext {
            root: PathBuf::from("/test/project"),
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
fn test_corpus_accuracy_ac_2_and_ac_3() {
    let detector = DpgDetector::new().expect("detector initialization");
    let ctx = mock_context();

    let mut rng = ChaCha8Rng::seed_from_u64(2026);

    let mut total_tp = 0;
    let mut total_fp = 0;
    let mut total_fn = 0;

    let sample_count = 100;

    for _ in 0..sample_count {
        let sample = match rand::Rng::gen_range(&mut rng, 0..3) {
            0 => gen_env_file(&mut rng),
            1 => gen_yaml_file(&mut rng),
            _ => gen_json_file(&mut rng),
        };

        let findings = detector
            .scan(&sample.text, &ctx)
            .expect("detector scan must succeed");

        let mut matched_labels = vec![false; sample.labels.len()];
        let mut matched_findings = vec![false; findings.len()];

        // Match detected findings against ground truth labels
        for (f_idx, f) in findings.iter().enumerate() {
            for (l_idx, label) in sample.labels.iter().enumerate() {
                if spans_overlap(f.span.start, f.span.end, label.start, label.end) {
                    matched_labels[l_idx] = true;
                    matched_findings[f_idx] = true;
                    break;
                }
            }
        }

        // TPs: findings that matched a ground truth label
        let tp = matched_findings.iter().filter(|&&m| m).count();
        // FPs: findings that did not match any ground truth label
        let fp = matched_findings.iter().filter(|&&m| !m).count();
        // FNs: ground truth labels that were not matched by any finding
        let fn_count = matched_labels.iter().filter(|&&m| !m).count();

        total_tp += tp;
        total_fp += fp;
        total_fn += fn_count;
    }

    let recall = total_tp as f64 / (total_tp + total_fn) as f64;
    let precision = total_tp as f64 / (total_tp + total_fp) as f64;

    println!(
        "\n=======================================================\n\
         DPG DETECT ACCURACY EVALUATION RESULTS (100 synthetic files)\n\
         True Positives (TP): {}\n\
         False Positives (FP): {}\n\
         False Negatives (FN): {}\n\
         AC-2 Recall:    {:.2}% (Threshold >= 95.0%)\n\
         AC-3 Precision: {:.2}% (Threshold >= 90.0%)\n\
         =======================================================\n",
        total_tp,
        total_fp,
        total_fn,
        recall * 100.0,
        precision * 100.0
    );

    assert!(
        recall >= 0.95,
        "AC-2 failed: Recall {:.2}% is below 95.0% target",
        recall * 100.0
    );

    assert!(
        precision >= 0.90,
        "AC-3 failed: Precision {:.2}% is below 90.0% target",
        precision * 100.0
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn test_fuzz_detector_random_inputs(s in "\\PC*") {
        let detector = match DpgDetector::new() {
            Ok(d) => d,
            Err(_) => return Ok(()),
        };
        let ctx = mock_context();

        let findings = match detector.scan(&s, &ctx) {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };

        // Assert all spans are on char boundaries and inside bounds
        for f in &findings {
            prop_assert!(f.span.start <= f.span.end);
            prop_assert!(f.span.end <= s.len());
            prop_assert!(s.is_char_boundary(f.span.start));
            prop_assert!(s.is_char_boundary(f.span.end));
        }

        // Assert no two findings overlap
        for i in 0..findings.len() {
            for j in (i + 1)..findings.len() {
                let a = &findings[i];
                let b = &findings[j];
                prop_assert!(!spans_overlap(a.span.start, a.span.end, b.span.start, b.span.end));
            }
        }
    }
}
