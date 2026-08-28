use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn init_metrics() -> anyhow::Result<()> {
    Ok(())
}

pub fn gather_metrics() -> String {
    format!("# AppGate Gateway Metrics\nrequests_total {}\n", REQUEST_COUNT.load(Ordering::Relaxed))
}

pub fn get_gateway_id() -> String {
    "gateway-001".to_string()
}

pub fn record_request(_endpoint: &str, _status: u16, _start: Instant) { REQUEST_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn record_auth_failure(_reason: &str) {}
pub fn record_rate_limit_exceeded(_identity: &str) {}
pub fn record_policy_evaluation(_allowed: bool, _policy_id: &str, _start: Instant) {}
pub fn record_policy_refresh(_count: usize, _success: bool) {}
pub fn record_policy_refresh_duration(_start: Instant, _method: &str) {}
pub fn record_audit_send(_count: usize, _success: bool, _start: Instant) {}
pub fn record_audit_drop(_reason: &str) {}
pub fn record_overload_rejection(_reason: &str) {}
pub fn record_jwt_validation(_success: bool, _start: Instant) {}
pub fn record_tls_handshake(_version: &str, _start: Instant) {}
pub fn record_upstream_duration(_upstream: &str, _model: &str, _start: Instant) {}
pub fn record_upstream_failure(_upstream: &str, _reason: &str) {}
pub fn set_active_connections(_count: f64) {}