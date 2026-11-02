//! Criterion benchmarks for DPG processing pipeline (BENCHMARKS.md).
#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dpg_core::context::{ProjectContext, ProjectId, RequestContext, SessionId};
use dpg_core::engine::Detector;
use dpg_core::types::Route;
use dpg_detect::DpgDetector;
use dpg_testgen::corpus::gen_env_file;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

fn benchmark_detect_500_lines(c: &mut Criterion) {
    let detector = DpgDetector::new().expect("detector init");
    let ctx = RequestContext {
        project: ProjectContext {
            root: PathBuf::from("/test/project"),
            id: ProjectId::new(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
        },
        session: SessionId::new("bench-session".to_string()),
        route: Route::HookPostToolUse,
        deadline: Instant::now() + Duration::from_secs(3600),
    };

    // Construct a ~500 line / ~25 KB realistic source/config file
    let mut rng = ChaCha8Rng::seed_from_u64(12345);
    let mut file_500_lines = String::new();
    while file_500_lines.lines().count() < 500 {
        let sample = gen_env_file(&mut rng);
        file_500_lines.push_str(&sample.text);
        file_500_lines.push('\n');
    }

    c.bench_function("detect_500_lines", |b| {
        b.iter(|| {
            let findings = detector
                .scan(black_box(&file_500_lines), black_box(&ctx))
                .expect("scan");
            black_box(findings);
        });
    });
}

fn benchmark_pipeline_scaffolding(c: &mut Criterion) {
    c.bench_function("pipeline_scaffolding_baseline", |b| {
        b.iter(|| {
            let input = black_box("SAMPLE_SECRET_SCAN_PAYLOAD");
            black_box(input.len());
        });
    });
}

criterion_group!(
    benches,
    benchmark_pipeline_scaffolding,
    benchmark_detect_500_lines
);
criterion_main!(benches);
