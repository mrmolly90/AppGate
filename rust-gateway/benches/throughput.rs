// =============================================================================
// AppGate Gateway — Throughput Benchmark
// =============================================================================
//
// Criterion benchmark for measuring gateway throughput and latency.
// Tests the hot path (health check) and proxy path under load.
//
// Run with: cargo bench
// Results: target/criterion/report/index.html
// =============================================================================

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode,
};
use std::time::Duration;

// We benchmark the server's request handling by measuring the
// performance of the core request dispatch logic.
//
// In a real deployment, you would benchmark against a running
// server using HTTP clients. Here we benchmark the key functions
// in isolation.

fn benchmark_health_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("health_check");
    group.sampling_mode(SamplingMode::Auto);
    group.measurement_time(Duration::from_secs(10));
    group.warm_up_time(Duration::from_secs(3));

    // Benchmark the health check response construction
    group.bench_function("static_response", |b| {
        b.iter(|| {
            let response = hyper::Response::builder()
                .status(hyper::StatusCode::OK)
                .header("content-type", "text/plain")
                .body(http_body_util::Full::new(bytes::Bytes::from_static(
                    b"ok\n",
                )))
                .unwrap();
            black_box(response)
        })
    });

    group.finish();
}

fn benchmark_json_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_serialization");
    group.sampling_mode(SamplingMode::Auto);

    // Benchmark JSON response construction
    group.bench_function("error_response", |b| {
        b.iter(|| {
            let body = serde_json::json!({
                "error": "not_found",
                "message": "The requested resource was not found"
            });
            let response = hyper::Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(bytes::Bytes::from(
                    serde_json::to_string(&body).unwrap(),
                )))
                .unwrap();
            black_box(response)
        })
    });

    group.finish();
}

fn benchmark_connection_tracking(c: &mut Criterion) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut group = c.benchmark_group("connection_tracking");
    group.sampling_mode(SamplingMode::Auto);

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    group.bench_function("atomic_increment_decrement", |b| {
        b.iter(|| {
            COUNTER.fetch_add(1, Ordering::Relaxed);
            let _ = COUNTER.load(Ordering::Relaxed);
            COUNTER.fetch_sub(1, Ordering::Relaxed);
            black_box(())
        })
    });

    group.finish();
}

criterion_group!(
    name = throughput;
    config = Criterion::default()
        .sample_size(100)
        .significance_level(0.05)
        .noise_threshold(0.05);
    targets = benchmark_health_check, benchmark_json_serialization, benchmark_connection_tracking
);

criterion_main!(throughput);
