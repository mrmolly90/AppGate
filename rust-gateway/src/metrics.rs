//! AppGate Gateway — Prometheus Metrics
//!
//! Exposes standard RED metrics (Rate, Errors, Duration) plus
//! gateway-specific gauges for active connections and auth failures.

use prometheus::{
    gather, register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Encoder,
    Gauge, HistogramVec, TextEncoder,
};

pub struct MetricsCollector;
impl MetricsCollector {
    pub fn new() -> Self {
        Self
    }
}
use std::time::Instant;
use std::sync::OnceLock;

// ── Metric Definitions ──────────────────────────────────────────────────────
static REQUESTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static REQUEST_DURATION: OnceLock<HistogramVec> = OnceLock::new();
static ACTIVE_CONNECTIONS_GAUGE: OnceLock<Gauge> = OnceLock::new();
static AUTH_FAILURES_TOTAL: OnceLock<CounterVec> = OnceLock::new();

fn requests_total() -> &'static CounterVec {
    REQUESTS_TOTAL.get_or_init(|| {
        register_counter_vec!(
            "gateway_requests_total",
            "Total number of HTTP requests",
            &["endpoint", "status"]
        )
        .expect("metric registration failed")
    })
}

fn request_duration() -> &'static HistogramVec {
    REQUEST_DURATION.get_or_init(|| {
        register_histogram_vec!(
            "gateway_request_duration_seconds",
            "Request latency in seconds",
            &["endpoint"],
            prometheus::exponential_buckets(0.001, 2.0, 15).unwrap()
        )
        .expect("metric registration failed")
    })
}

fn active_connections_gauge() -> &'static Gauge {
    ACTIVE_CONNECTIONS_GAUGE.get_or_init(|| {
        register_gauge!(
            "gateway_connections_active",
            "Current number of active connections"
        )
        .expect("metric registration failed")
    })
}

fn auth_failures_total() -> &'static CounterVec {
    AUTH_FAILURES_TOTAL.get_or_init(|| {
        register_counter_vec!(
            "gateway_auth_failures_total",
            "Total authentication failures",
            &["reason"]
        )
        .expect("metric registration failed")
    })
}

// =============================================================================
// Public API
// =============================================================================

/// Record a completed request for metrics.
pub fn record_request(endpoint: &str, status: u16, start: Instant) {
    let status_str = status.to_string();
    requests_total()
        .with_label_values(&[endpoint, &status_str])
        .inc();
    request_duration()
        .with_label_values(&[endpoint])
        .observe(start.elapsed().as_secs_f64());
}

/// Update the active connections gauge.
pub fn set_active_connections(count: f64) {
    active_connections_gauge().set(count);
}

/// Record an authentication failure.
pub fn record_auth_failure(reason: &str) {
    auth_failures_total().with_label_values(&[reason]).inc();
}

/// Gather all registered metrics in Prometheus text format.
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = gather();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return format!("# Error encoding metrics: {e}\n");
    }
    String::from_utf8(buffer).unwrap_or_default()
}