//! AppGate Gateway — OpenTelemetry Tracing
//!
//! Uses opentelemetry 0.26 API with OTLP export.

use opentelemetry_otlp::WithExportConfig;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[cfg(feature = "otel")]
use opentelemetry::trace::TracerProvider as _;

/// Initialize the tracing subscriber.
///
/// If `otel` feature is enabled, configures OTLP trace export.
/// Otherwise, uses a plain JSON fmt subscriber.
pub fn init_tracer_provider(otlp_endpoint: &str, debug: bool) -> Option<TracerGuard> {
    let env_filter = if debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    #[cfg(feature = "otel")]
    {
        match opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(otlp_endpoint)
                    .with_timeout(Duration::from_secs(10)),
            )
            .with_trace_config(
                opentelemetry_sdk::trace::Config::default()
                    .with_resource(opentelemetry_sdk::Resource::new(vec![
                        opentelemetry::KeyValue::new("service.name", "appgate-gateway"),
                        opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    ])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
        {
            Ok(provider) => {
                let tracer = provider.tracer("appgate-gateway");
                let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().json())
                    .with(telemetry)
                    .init();

                return Some(TracerGuard {
                    provider: Some(provider),
                });
            }
            Err(e) => {
                eprintln!("OTLP initialization failed ({}), using stdout only", e);
            }
        }
    }

    #[cfg(not(feature = "otel"))]
    {
        // No OTel — just init plain JSON logging
    }

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
    None
}

/// Shutdown telemetry and flush remaining spans.
pub async fn shutdown() {
    #[cfg(feature = "otel")]
    {
        opentelemetry::global::shutdown_tracer_provider();
    }
}

/// Guard that flushes remaining spans on drop.
#[cfg(feature = "otel")]
pub struct TracerGuard {
    provider: Option<opentelemetry_sdk::trace::TracerProvider>,
}

#[cfg(feature = "otel")]
impl Drop for TracerGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

#[cfg(not(feature = "otel"))]
pub struct TracerGuard;

#[cfg(not(feature = "otel"))]
impl Drop for TracerGuard {
    fn drop(&mut self) {}
}