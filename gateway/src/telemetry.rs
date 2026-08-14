//! Telemetry — OpenTelemetry metrics and tracing
//!
//! Exposes Prometheus metrics and OpenTelemetry traces for observability.
//! Initializes the OTLP exporter and provides metric recording helpers.

use opentelemetry::{
    global,
    metrics::{Counter, Histogram, Meter},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{Aggregation, SdkMeterProvider, View},
    runtime,
    Resource,
};
use std::sync::Arc;
use std::time::Duration;

/// Gateway metrics exposed via OTLP → Prometheus
pub struct Metrics {
    pub requests_total: Counter<u64>,
    pub auth_failures_total: Counter<u64>,
    pub authorization_denials_total: Counter<u64>,
    pub rate_limit_total: Counter<u64>,
    pub upstream_errors_total: Counter<u64>,
    pub policy_denials_total: Counter<u64>,
    pub request_duration: Histogram<f64>,
    pub upstream_duration: Histogram<f64>,
    meter: Meter,
}

impl Metrics {
    pub fn new(service_name: &str, otlp_endpoint: Option<&str>) -> Arc<Self> {
        let resource = Resource::new(vec![
            KeyValue::new("service.name", service_name.to_string()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        ]);

        let mut provider_builder = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(
                opentelemetry_sdk::metrics::PeriodicReader::builder(
                    opentelemetry_otlp::MetricExporter::builder()
                        .with_tonic()
                        .with_endpoint(
                            otlp_endpoint
                                .unwrap_or("http://otel-collector:4317"),
                        )
                        .build()
                        .unwrap(),
                    runtime::Tokio,
                )
                .with_interval(Duration::from_secs(15))
                .build(),
            );

        // Add explicit histogram bucket boundaries for p99 latency tracking
        let latency_boundaries = vec![
            1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
        ];
        provider_builder = provider_builder.with_view(
            View::new()
                .with_instrument_name("appgate_request_duration")
                .with_aggregation(Aggregation::ExplicitBucketHistogram {
                    boundaries: latency_boundaries,
                    record_min_max: true,
                }),
        );

        let meter_provider = provider_builder.build();
        global::set_meter_provider(meter_provider.clone());

        let meter = global::meter(service_name);

        let metrics = Arc::new(Self {
            requests_total: meter
                .u64_counter("appgate_requests_total")
                .with_description("Total number of requests processed")
                .init(),
            auth_failures_total: meter
                .u64_counter("appgate_auth_failures_total")
                .with_description("Total authentication failures")
                .init(),
            authorization_denials_total: meter
                .u64_counter("appgate_authorization_denials_total")
                .with_description("Total authorization denials")
                .init(),
            rate_limit_total: meter
                .u64_counter("appgate_rate_limit_total")
                .with_description("Total rate-limited requests")
                .init(),
            upstream_errors_total: meter
                .u64_counter("appgate_upstream_errors_total")
                .with_description("Total upstream errors")
                .init(),
            policy_denials_total: meter
                .u64_counter("appgate_policy_denials_total")
                .with_description("Total policy denials")
                .init(),
            request_duration: meter
                .f64_histogram("appgate_request_duration")
                .with_description("Request duration in milliseconds")
                .with_unit("ms")
                .init(),
            upstream_duration: meter
                .f64_histogram("appgate_upstream_duration")
                .with_description("Upstream LLM call duration in milliseconds")
                .with_unit("ms")
                .init(),
            meter,
        });

        tracing::info!(
            otlp_endpoint = %otlp_endpoint.unwrap_or("http://otel-collector:4317"),
            "OpenTelemetry initialized"
        );

        metrics
    }

    /// Record a request with its outcome and duration
    pub fn record_request(
        &self,
        provider: &str,
        model: &str,
        status: &str,
        duration_ms: f64,
    ) {
        let attrs = [
            KeyValue::new("provider", provider.to_string()),
            KeyValue::new("model", model.to_string()),
            KeyValue::new("status", status.to_string()),
        ];
        self.requests_total.add(1, &attrs);
        self.request_duration.record(duration_ms, &attrs);
    }

    /// Record an auth failure
    pub fn record_auth_failure(&self, reason: &str) {
        self.auth_failures_total
            .add(1, &[KeyValue::new("reason", reason.to_string())]);
    }

    /// Record an authorization denial
    pub fn record_authorization_denial(&self, reason: &str) {
        self.authorization_denials_total
            .add(1, &[KeyValue::new("reason", reason.to_string())]);
    }

    /// Record a rate limit event
    pub fn record_rate_limit(&self, identity_id: &str) {
        self.rate_limit_total
            .add(1, &[KeyValue::new("identity", identity_id.to_string())]);
    }

    /// Record an upstream error
    pub fn record_upstream_error(&self, provider: &str) {
        self.upstream_errors_total
            .add(1, &[KeyValue::new("provider", provider.to_string())]);
    }

    /// Record a policy denial
    pub fn record_policy_denial(&self, identity_id: &str, reason: &str) {
        self.policy_denials_total.add(
            1,
            &[
                KeyValue::new("identity", identity_id.to_string()),
                KeyValue::new("reason", reason.to_string()),
            ],
        );
    }

    /// Record upstream LLM call duration
    pub fn record_upstream_duration(&self, provider: &str, model: &str, duration_ms: f64) {
        let attrs = [
            KeyValue::new("provider", provider.to_string()),
            KeyValue::new("model", model.to_string()),
        ];
        self.upstream_duration.record(duration_ms, &attrs);
    }
}

/// Shutdown OTel gracefully — call before process exit
pub async fn shutdown() {
    if let Some(provider) = global::meter_provider()
        .as_any()
        .downcast_ref::<SdkMeterProvider>()
    {
        if let Err(e) = provider.shutdown() {
            tracing::warn!(error = %e, "meter provider shutdown failed");
        }
    }
    global::shutdown_tracer_provider();
}