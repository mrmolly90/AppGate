// =============================================================================
// AppGate Gateway — OpenTelemetry Tracing (Production)
// =============================================================================
//
// Configures:
//   • JSON stdout logging (for log aggregation)
//   • OTLP gRPC trace export (to Jaeger/Tempo)
//   • Resource attributes (service name, version, instance)
// =============================================================================

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub fn init_tracer_provider(otlp_endpoint: &str) -> TracingGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("appgate=info,warn"));

    // JSON stdout layer
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    // Try to initialize OTLP exporter if endpoint is provided
    let otlp_layer = if !otlp_endpoint.is_empty() && otlp_endpoint != "http://otel-collector:4317" {
        match init_otlp_layer(otlp_endpoint) {
            Ok(layer) => {
                tracing::info!(target: "appgate::telemetry", endpoint = %otlp_endpoint, "OTLP exporter initialized");
                Some(layer)
            }
            Err(e) => {
                tracing::warn!(target: "appgate::telemetry", error = %e, "OTLP initialization failed, using stdout only");
                None
            }
        }
    } else {
        tracing::info!(target: "appgate::telemetry", "OTLP endpoint not configured, using stdout only");
        None
    };

    // Build subscriber
    let subscriber = Registry::default().with(env_filter).with(fmt_layer);
    if let Some(layer) = otlp_layer {
        subscriber.with(layer).init();
    } else {
        subscriber.init();
    }

    TracingGuard
}

#[cfg(feature = "otel")]
fn init_otlp_layer(
    endpoint: &str,
) -> Result<
    tracing_opentelemetry::OpenTelemetryLayer<
        Registry,
        opentelemetry::sdk::trace::Tracer,
    >,
    Box<dyn std::error::Error + Send + Sync>,
> {
    use opentelemetry::sdk::trace::{self, RandomIdGenerator, Sampler};
    use opentelemetry::sdk::Resource;
    use opentelemetry::trace::TraceError;
    use opentelemetry_otlp::WithExportConfig;

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint)
                .with_timeout(std::time::Duration::from_secs(3)),
        )
        .with_trace_config(
            trace::config()
                .with_sampler(Sampler::TraceIdRatioBased(0.1))
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", "appgate-gateway"),
                    opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                ])),
        )
        .install_batch(opentelemetry::runtime::Tokio)?;

    Ok(tracing_opentelemetry::layer().with_tracer(tracer))
}

#[cfg(not(feature = "otel"))]
fn init_otlp_layer(
    _endpoint: &str,
) -> Result<
    tracing_opentelemetry::OpenTelemetryLayer<
        Registry,
        opentelemetry::sdk::trace::Tracer,
    >,
    Box<dyn std::error::Error + Send + Sync>,
> {
    Err("OTLP feature not enabled".into())
}

pub struct TracingGuard;

impl Drop for TracingGuard {
    fn drop(&mut self) {
        tracing::info!("Tracing shutdown");
        #[cfg(feature = "otel")]
        opentelemetry::global::shutdown_tracer_provider();
    }
}