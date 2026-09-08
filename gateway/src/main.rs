use std::sync::Arc;
use appgate_gateway::{
    audit, cache, circuit_breaker, config, health, jwt, metrics,
    policy, rate_limit, router, server, ssrf, AppState,
};
use tracing::info;

mod telemetry;

#[tokio::main]
async fn main() {
    // Initialize structured JSON logging
    let _guard = telemetry::init_tracing();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "AppGate production gateway starting"
    );

    let cfg = Arc::new(config::GatewayConfig::from_env());

    let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Initialize JWT validator
    let jwt_validator = match jwt::JwtValidator::from_config(&cfg.jwt) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            if cfg.jwt.enabled {
                tracing::error!("Failed to initialize JWT validator: {}", e);
                std::process::exit(1);
            }
            Arc::new(jwt::JwtValidator::noop())
        }
    };

    // Initialize rate limiter
    let rate_limiter = Arc::new(rate_limit::RateLimiter::new(&cfg.rate_limit).await);

    // Initialize policy engine
    let policy_engine = Arc::new(policy::PolicyEngine::new(&cfg).await);

    // Initialize SSRF defense with approved LLM provider domains
    let ssrf_guard = Arc::new(ssrf::SSRFDefense::from_config(&cfg));

    // Initialize audit logger
    let audit_logger = Arc::new(audit::AuditLogger::new(
        cfg.control_plane_url.clone(),
        Some(cfg.audit.endpoint.clone()),
    ));

    // Initialize metrics collector
    let metrics = Arc::new(metrics::MetricsCollector::new());

    // Initialize router
    let router = Arc::new(router::Router::new(&cfg));

    // Initialize response cache
    let cache = Arc::new(cache::ResponseCache::new(&cfg));

    // Initialize circuit breaker registry
    let circuit_breaker = Arc::new(circuit_breaker::CircuitBreakerRegistry::new(&cfg.circuit_breaker));

    // Initialize health checker
    let health_checker = Arc::new(health::HealthChecker::new(&cfg));
    
    // Register upstreams with health checker
    if !cfg.upstream.default_url.is_empty() {
        health_checker.register("default", &cfg.upstream.default_url).await;
    }
    
    let health_checker_bg = health_checker.clone();
    tokio::spawn(async move {
        health_checker_bg.start_background_checks().await;
    });

    // Spawn rate limiter cleanup task
    let rate_limiter_cleanup = rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            rate_limiter_cleanup.cleanup_old_buckets().await;
        }
    });

    let app_state = AppState {
        config: cfg.clone(),
        jwt_validator,
        rate_limiter,
        policy_engine,
        ssrf_guard,
        audit_logger,
        metrics,
        router,
        cache,
        circuit_breaker,
        health_checker,
    };

    // Start HTTP proxy server
    let server = server::AppGateServer::new(Arc::new(app_state), shutdown_rx);
    if let Err(e) = server.run().await {
        tracing::error!("Server fatal error: {}", e);
        std::process::exit(1);
    }

    info!("AppGate gateway shutdown complete");
}