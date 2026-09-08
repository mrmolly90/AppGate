//! AppGate — Production Reverse Proxy Library
//!
//! Core library exposing all modules for integration testing and embedding.

use std::sync::Arc;

pub mod audit;
pub mod auth;
pub mod cache;
pub mod circuit_breaker;
pub mod config;
pub mod db;
pub mod error;
pub mod health;
pub mod jwt;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod policy;
pub mod proxy;
pub mod rate_limit;
pub mod router;
pub mod server;
pub mod ssrf;
pub mod tls;

/// Unified application state shared across all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::GatewayConfig>,
    pub jwt_validator: Arc<jwt::JwtValidator>,
    pub rate_limiter: Arc<rate_limit::RateLimiter>,
    pub policy_engine: Arc<policy::PolicyEngine>,
    pub ssrf_guard: Arc<ssrf::SSRFDefense>,
    pub audit_logger: Arc<audit::AuditLogger>,
    pub metrics: Arc<metrics::MetricsCollector>,
    pub router: Arc<router::Router>,
    pub cache: Arc<cache::ResponseCache>,
    pub circuit_breaker: Arc<circuit_breaker::CircuitBreakerRegistry>,
    pub health_checker: Arc<health::HealthChecker>,
}