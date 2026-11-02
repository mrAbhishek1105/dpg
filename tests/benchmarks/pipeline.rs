//! Criterion benchmarks for DPG processing pipeline (BENCHMARKS.md).
#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_pipeline_scaffolding(c: &mut Criterion) {
    c.bench_function("pipeline_scaffolding_baseline", |b| {
        b.iter(|| {
            let input = black_box("SAMPLE_SECRET_SCAN_PAYLOAD");
            black_box(input.len());
        });
    });
}

criterion_group!(benches, benchmark_pipeline_scaffolding);
criterion_main!(benches);
