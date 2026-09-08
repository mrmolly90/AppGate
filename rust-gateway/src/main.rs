use std::sync::Arc;
use tokio::signal;
use tracing::info;

mod audit;
mod cache;
mod circuit_breaker;
mod config;
mod health;
mod jwt;
mod metrics;
mod policy;
mod proxy;
mod rate_limit;
mod router;
mod server;
mod ssrf;
mod telemetry;
mod tls;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::GatewayConfig>,
    pub jwt_validator: Arc<jwt::JwtValidator>,
    pub rate_limiter: Arc<rate_limit::RateLimiterService>,
    pub policy_engine: Arc<policy::PolicyEngine>,
    pub ssrf_guard: Arc<ssrf::SsrfGuard>,
    pub audit_logger: Arc<audit::AuditLogger>,
    pub metrics: Arc<metrics::MetricsCollector>,
    pub router: Arc<router::Router>,
    pub cache: Arc<cache::ResponseCache>,
    pub circuit_breaker: Arc<circuit_breaker::CircuitBreakerRegistry>,
    pub health_checker: Arc<health::HealthChecker>,
    pub proxy_client: Arc<proxy::ProxyClient>,
}

#[tokio::main]
async fn main() {
    let _tracer = telemetry::init_tracer_provider(
        &std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:4317".into()),
        std::env::var("APPGATE_LOG_LEVEL").map(|v| v == "debug").unwrap_or(false),
    );
    info!("AppGate production gateway starting v{}", env!("CARGO_PKG_VERSION"));

    let cfg = Arc::new(config::GatewayConfig::from_env());

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    let jwt_validator = match jwt::JwtValidator::new(&cfg.jwt) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            tracing::error!("Failed to initialize JWT validator: {}", e);
            std::process::exit(1);
        }
    };

    let health_checker = Arc::new(health::HealthChecker::new(&cfg));
    let health_checker_clone = health_checker.clone();
    tokio::spawn(async move {
        health_checker_clone.start_background_checks().await;
    });

    let state = Arc::new(AppState {
        config: cfg.clone(),
        jwt_validator,
        rate_limiter: Arc::new(rate_limit::RateLimiterService::new(None).await.unwrap_or_else(|e| {
            tracing::warn!("Rate limiter init failed ({}), using local fallback", e);
            rate_limit::RateLimiterService::new_local()
        })),
        policy_engine: Arc::new(policy::PolicyEngine::new()),
        ssrf_guard: Arc::new(ssrf::SsrfGuard::new(&cfg)),
        audit_logger: Arc::new(audit::AuditLogger::new(&cfg.audit)),
        metrics: Arc::new(metrics::MetricsCollector::new()),
        router: Arc::new(router::Router::new(&cfg)),
        cache: Arc::new(cache::ResponseCache::new(&cfg)),
        circuit_breaker: Arc::new(circuit_breaker::CircuitBreakerRegistry::new(&cfg.circuit_breaker)),
        health_checker,
        proxy_client: Arc::new(proxy::ProxyClient::new()),
    });

    // Start periodic rate limiter cleanup
    let _rate_limiter = state.rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            // Rate limiter cleanup is handled internally by governor/redis TTL
        }
    });

    let server = server::AppGateServer::new(state, shutdown_rx);
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.run().await {
            tracing::error!("server error: {}", e);
        }
    });

    tokio::select! {
        _ = signal::ctrl_c() => { info!("SIGINT received, shutting down gracefully"); }
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        } => { info!("SIGTERM received, shutting down gracefully"); }
    }

    let _ = shutdown_tx.send(());
    
    match tokio::time::timeout(tokio::time::Duration::from_secs(30), server_handle).await {
        Ok(_) => info!("Server shutdown gracefully"),
        Err(_) => tracing::warn!("Server shutdown timed out after 30s"),
    }
    
    info!("AppGate shutdown complete");
}