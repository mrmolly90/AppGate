// =============================================================================
// AppGate Gateway — OpenTelemetry Tracing
// =============================================================================
//
// OpenTelemetry tracer provider with OTLP exporter.
// =============================================================================

use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{BatchSpanProcessor, Config, TracerProvider};
use opentelemetry_sdk::trace::Sampler;
use opentelemetry_sdk::Resource;
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Initialize the OpenTelemetry tracer provider.
pub fn init_tracer_provider(otlp_endpoint: &str) -> TracingGuard {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(otlp_endpoint)
        .with_timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build OTLP span exporter");

    let batch_processor = BatchSpanProcessor::builder(exporter)
        .with_max_queue_size(4096)
        .with_max_export_batch_size(512)
        .with_scheduled_delay(Duration::from_millis(500))
        .build();

    let tracer_provider = TracerProvider::builder()
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

    let tracer = tracer_provider.tracer("appgate-gateway");
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("appgate=info,warn"));

    Registry::default()
        .with(env_filter)
        .with(telemetry)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    TracingGuard { tracer_provider }
}

#[must_use = "Dropping the TracingGuard will shutdown the tracer provider"]
pub struct TracingGuard {
    tracer_provider: TracerProvider,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Err(e) = self.tracer_provider.shutdown() {
            eprintln!("Failed to shutdown tracer provider: {e}");
        }
    }
}