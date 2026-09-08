use once_cell::sync::Lazy;
use prometheus::{
    register_counter_vec, register_histogram_vec,
    CounterVec, HistogramVec,
};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!("gateway_requests_total", "Total HTTP requests", &["status", "endpoint"])
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

pub(crate) static AUTH_FAILURES: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!("gateway_auth_failures_total", "Total auth failures", &["reason"])
        .expect("Failed to register gateway_auth_failures_total")
});

pub(crate) static RATE_LIMIT_EXCEEDED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!("gateway_rate_limit_exceeded_total", "Total rate limit events", &["identity"])
        .expect("Failed to register gateway_rate_limit_exceeded_total")
});

pub(crate) static UPSTREAM_ERRORS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!("gateway_upstream_errors_total", "Total upstream errors", &["provider"])
        .expect("Failed to register gateway_upstream_errors_total")
});

pub(crate) static UPSTREAM_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "gateway_upstream_duration_seconds",
        "Upstream request latency in seconds",
        &["provider", "model"],
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
    ).expect("Failed to register gateway_upstream_duration_seconds")
});

pub(crate) static POLICY_DENIALS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!("gateway_policy_denials_total", "Total policy denials", &["identity", "reason"])
        .expect("Failed to register gateway_policy_denials_total")
});

pub struct MetricsCollector {
    request_count: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            request_count: AtomicU64::new(0),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn record_request(&self, status: &str, latency_ms: u64) {
        let endpoint = "proxy";
        REQUEST_DURATION.with_label_values(&[endpoint]).observe(latency_ms as f64 / 1000.0);
        REQUESTS_TOTAL.with_label_values(&[status, endpoint]).inc();
        self.request_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_auth_failure(&self, reason: &str) {
        AUTH_FAILURES.with_label_values(&[reason]).inc();
    }

    pub fn record_rate_limit_exceeded(&self, identity: &str) {
        RATE_LIMIT_EXCEEDED.with_label_values(&[identity]).inc();
    }

    pub fn record_upstream_error(&self, provider: &str) {
        UPSTREAM_ERRORS.with_label_values(&[provider]).inc();
    }

    pub fn record_policy_denial(&self, identity: &str, reason: &str) {
        POLICY_DENIALS.with_label_values(&[identity, reason]).inc();
    }

    pub fn record_upstream_duration(&self, provider: &str, model: &str, duration_ms: f64) {
        UPSTREAM_DURATION.with_label_values(&[provider, model]).observe(duration_ms / 1000.0);
    }
}

pub async fn metrics_handler() -> impl axum::response::IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = String::new();
    encoder.encode_utf8(&metric_families, &mut buffer).unwrap();
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        buffer,
    )
}