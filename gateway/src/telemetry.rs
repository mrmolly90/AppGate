use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{BatchSpanProcessor, Config, TracerProvider};
use opentelemetry_sdk::trace::Sampler;
use opentelemetry_sdk::Resource;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Global guard to prevent double initialization of tracing.
static TRACING_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize JSON logging with optional OpenTelemetry tracing.
/// Returns a TracingGuard that must be kept alive for the lifetime of the application.
/// Safe to call multiple times — subsequent calls return a no-op guard.
pub fn init_tracing() -> TracingGuard {
    // Guard against double initialization
    if TRACING_INITIALIZED.swap(true, Ordering::SeqCst) {
        tracing::warn!("init_tracing called more than once, returning no-op guard");
        return TracingGuard { tracer_provider: None };
    }

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("appgate=info,warn"));

    // Initialize OpenTelemetry if endpoint is configured
    let tracer_provider = if let Ok(otlp_endpoint) = std::env::var("APPGATE_OTLP_ENDPOINT") {
        match init_tracer_provider(&otlp_endpoint) {
            Some(provider) => {
                let tracer = provider.tracer("appgate-gateway");
                let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
                Registry::default()
                    .with(env_filter)
                    .with(telemetry)
                    .with(tracing_subscriber::fmt::layer().json())
                    .init();
                Some(provider)
            }
            None => {
                Registry::default()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().json())
                    .init();
                None
            }
        }
    } else {
        Registry::default()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
        None
    };

    TracingGuard { tracer_provider }
}

fn init_tracer_provider(endpoint: &str) -> Option<TracerProvider> {
    let exporter = match opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(10))
        .build_span_exporter()
    {
        Ok(exporter) => exporter,
        Err(e) => {
            tracing::warn!("Failed to build OTLP span exporter: {}", e);
            return None;
        }
    };

    let batch_processor = BatchSpanProcessor::builder(
        exporter,
        opentelemetry_sdk::runtime::Tokio,
    )
    .build();

    let provider = TracerProvider::builder()
        .with_config(
            Config::default()
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)))
                .with_resource(Resource::new(vec![
                    KeyValue::new("service.name", "appgate-gateway"),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    KeyValue::new("service.namespace", "appgate"),
                    KeyValue::new("telemetry.sdk.name", "opentelemetry"),
                    KeyValue::new("telemetry.sdk.language", "rust"),
                ])),
        )
        .with_span_processor(batch_processor)
        .build();

    Some(provider)
}

#[must_use = "Dropping the TracingGuard will shutdown the tracer provider"]
pub struct TracingGuard {
    tracer_provider: Option<TracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            // TracerProvider::shutdown is called automatically via Drop
            drop(provider);
        }
    }
}