#![allow(dead_code)]

use once_cell::sync::Lazy;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec,
    CounterVec, Gauge, HistogramVec,
};
use std::time::Instant;

pub(crate) static ACTIVE_CONNECTIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("gateway_connections_active", "Current number of active connections")
        .expect("Failed to register gateway_connections_active")
});

pub(crate) static REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!("gateway_requests_total", "Total number of HTTP requests", &["status", "endpoint"])
        .expect("Failed to register gateway_requests_total")
});

pub(crate) static REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "gateway_request_duration_seconds",
        "Request latency in seconds",
        &["endpoint"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).expect("Failed to register gateway_request_duration_seconds")
});

pub(crate) static TLS_HANDSHAKE_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "gateway_tls_handshake_seconds",
        "TLS handshake duration in seconds",
        &["tls_version"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
    ).expect("Failed to register gateway_tls_handshake_seconds")
});

pub(crate) static UPSTREAM_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "gateway_upstream_duration_seconds",
        "Upstream response time in seconds",
        &["upstream"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).expect("Failed to register gateway_upstream_duration_seconds")
});

pub(crate) static AUTH_FAILURES: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!("gateway_auth_failures_total", "Total authentication failures", &["reason"])
        .expect("Failed to register gateway_auth_failures_total")
});

pub(crate) static RATE_LIMIT_EXCEEDED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!("gateway_rate_limit_exceeded_total", "Total rate limit exceeded events", &["identity"])
        .expect("Failed to register gateway_rate_limit_exceeded_total")
});

pub fn record_request(endpoint: &str, status: u16, start: Instant) {
    let elapsed = start.elapsed().as_secs_f64();
    REQUEST_DURATION.with_label_values(&[endpoint]).observe(elapsed);
    REQUESTS_TOTAL.with_label_values(&[&status_to_string(status), endpoint]).inc();
}

pub fn record_tls_handshake(tls_version: &str, start: Instant) {
    TLS_HANDSHAKE_DURATION.with_label_values(&[tls_version]).observe(start.elapsed().as_secs_f64());
}

pub fn record_upstream_duration(upstream: &str, start: Instant) {
    UPSTREAM_DURATION.with_label_values(&[upstream]).observe(start.elapsed().as_secs_f64());
}

pub fn record_auth_failure(reason: &str) {
    AUTH_FAILURES.with_label_values(&[reason]).inc();
}

pub fn record_rate_limit_exceeded(identity: &str) {
    RATE_LIMIT_EXCEEDED.with_label_values(&[identity]).inc();
}

pub fn set_active_connections(count: f64) {
    ACTIVE_CONNECTIONS.set(count);
}

pub fn gather_metrics() -> String {
    use prometheus::TextEncoder;
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = String::new();
    encoder.encode_utf8(&metric_families, &mut buffer).unwrap();
    buffer
}

fn status_to_string(status: u16) -> &'static str {
    match status {
        200 => "200", 201 => "201", 204 => "204",
        301 => "301", 302 => "302",
        400 => "400", 401 => "401", 403 => "403", 404 => "404", 429 => "429",
        500 => "500", 502 => "502", 503 => "503",
        _ => "other",
    }
}