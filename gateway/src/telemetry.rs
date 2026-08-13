//! Telemetry — OpenTelemetry metrics and tracing
//!
//! Exposes Prometheus metrics and OpenTelemetry traces for observability.

/// Metrics for the gateway
pub struct Metrics {
    pub requests_total: u64,
    pub auth_failures_total: u64,
    pub authorization_denials_total: u64,
    pub rate_limit_total: u64,
    pub upstream_errors_total: u64,
    pub policy_denials_total: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: 0,
            auth_failures_total: 0,
            authorization_denials_total: 0,
            rate_limit_total: 0,
            upstream_errors_total: 0,
            policy_denials_total: 0,
        }
    }
}