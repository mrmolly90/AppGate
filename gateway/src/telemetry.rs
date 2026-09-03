// =============================================================================
// AppGate Gateway — Telemetry (Production)
// =============================================================================
//
// Configures structured JSON logging. OTLP tracing can be enabled by adding
// the `otel` feature and the opentelemetry crates.
// =============================================================================

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub fn init_tracer_provider(_otlp_endpoint: &str) -> TracingGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("appgate=info,warn"));

    let fmt_layer = tracing_subscriber::fmt::layer().json();

    Registry::default()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    TracingGuard
}

pub struct TracingGuard;

impl Drop for TracingGuard {
    fn drop(&mut self) {
        tracing::info!("Tracing shutdown");
    }
}