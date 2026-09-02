//! AppGate Gateway - Zero-trust LLM security gateway
//!
//! This crate provides the AppGate SDP Gateway, a high-performance
//! zero-trust security gateway for LLM API access.
// =============================================================================
// AppGate Gateway — Main Entry Point
// =============================================================================

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(dead_code)] // TODO: Remove when all modules are wired up

use anyhow::Context;
use clap::Parser;
use std::net::SocketAddr;
use tokio::runtime::{self, Runtime};

mod metrics;
mod server;
mod telemetry;
mod tls;

#[cfg(feature = "audit")]
mod audit;
#[cfg(feature = "jwt-auth")]
mod jwt;
#[cfg(feature = "policy-engine")]
mod policy;
#[cfg(feature = "ratelimit")]
mod rate_limit;
#[cfg(feature = "ssrf-protection")]
mod ssrf;

/// AppGate SDP Gateway — Zero-trust security gateway
#[derive(Parser, Debug, Clone)]
#[command(name = "appgate-gateway", version, about)]
pub struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    pub listen_addr: String,

    /// Listen port
    #[arg(long, default_value_t = 8443)]
    pub listen_port: u16,

    /// Control plane gRPC endpoint
    #[arg(long, default_value = "http://control-plane:9090")]
    pub control_plane_url: String,

    /// TLS certificate path (PEM)
    #[arg(long, default_value = "/etc/appgate/tls/cert.pem")]
    pub tls_cert_path: String,

    /// TLS private key path (PEM)
    #[arg(long, default_value = "/etc/appgate/tls/key.pem")]
    pub tls_key_path: String,

    /// JWT verification key path (PEM)
    #[arg(long, default_value = "/etc/appgate/jwt/verify.pem")]
    pub jwt_key_path: String,

    /// JWT expected issuer
    #[arg(long, default_value = "https://appgate.example.com")]
    pub jwt_issuer: String,

    /// JWT expected audience
    #[arg(long, default_value = "appgate-gateway")]
    pub jwt_audience: String,

    /// Number of tokio worker threads (0 = auto-detect)
    #[arg(long, default_value_t = 0)]
    pub worker_threads: usize,

    /// OpenTelemetry endpoint
    #[arg(long, default_value = "http://otel-collector:4317")]
    pub otlp_endpoint: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Build NUMA-aware tokio runtime
    let runtime = build_runtime(args.worker_threads)?;

    // Initialize tracing (OpenTelemetry)
    let _tracing_guard = telemetry::init_tracer_provider(&args.otlp_endpoint);

    // Start server
    let addr = SocketAddr::new(
        args.listen_addr.parse().context("Invalid listen address")?,
        args.listen_port,
    );

    tracing::info!(
        target: "appgate::startup",
        addr = %addr,
        workers = runtime.metrics().num_workers(),
        "Starting AppGate Gateway"
    );

    runtime.block_on(async move { server::run_server(addr, &args).await })
}

/// Build a NUMA-aware tokio multi-thread runtime.
fn build_runtime(worker_threads: usize) -> anyhow::Result<Runtime> {
    let thread_count = if worker_threads > 0 {
        worker_threads
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    };

    runtime::Builder::new_multi_thread()
        .worker_threads(thread_count)
        .enable_io()
        .enable_time()
        .global_queue_interval(61)
        .max_io_events_per_tick(1024)
        .on_thread_start(|| {
            tracing::debug!(target: "appgate::runtime", "Worker thread started");
        })
        .on_thread_stop(|| {
            tracing::debug!(target: "appgate::runtime", "Worker thread stopped");
        })
        .build()
        .context("Failed to build tokio runtime")
}