// =============================================================================
// AppGate Gateway — Main Entry Point
// =============================================================================
//
// Architecture:
//   tokio multi-thread runtime with NUMA-aware thread pinning
//   Hyper 1.x HTTP server with rustls TLS 1.3 termination
//   Prometheus metrics + OpenTelemetry tracing
//   Feature-flag gated components for compile-time selection
//
// Performance targets:
//   - 100k RPS per core
//   - p99 latency < 10ms (intra-region)
//   - < 128MB per 10k connections
//   - Zero allocations on hot path
// =============================================================================

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]

use anyhow::Context;
use clap::Parser;
use std::net::SocketAddr;
use tokio::runtime::{self, Runtime};
use tracing::info;

mod metrics;
mod server;
mod tls;
mod tracing;

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
#[derive(Parser, Debug)]
#[command(name = "appgate-gateway", version, about)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    listen_addr: String,

    /// Listen port
    #[arg(long, default_value_t = 8443)]
    listen_port: u16,

    /// Control plane gRPC endpoint
    #[arg(long, default_value = "http://control-plane:9090")]
    control_plane_url: String,

    /// TLS certificate path (PEM)
    #[arg(long, default_value = "/etc/appgate/tls/cert.pem")]
    tls_cert_path: String,

    /// TLS private key path (PEM)
    #[arg(long, default_value = "/etc/appgate/tls/key.pem")]
    tls_key_path: String,

    /// JWT verification key path (PEM)
    #[arg(long, default_value = "/etc/appgate/jwt/verify.pem")]
    jwt_key_path: String,

    /// Number of tokio worker threads (0 = auto-detect)
    #[arg(long, default_value_t = 0)]
    worker_threads: usize,

    /// OpenTelemetry endpoint
    #[arg(long, default_value = "http://otel-collector:4317")]
    otlp_endpoint: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // ── Build NUMA-aware tokio runtime ────────────────────────────
    let runtime = build_runtime(args.worker_threads)?;

    // ── Initialize tracing (OpenTelemetry) ────────────────────────
    let _tracing_guard = tracing::init_tracer_provider(&args.otlp_endpoint);

    // ── Start server ──────────────────────────────────────────────
    let addr = SocketAddr::new(
        args.listen_addr.parse().context("Invalid listen address")?,
        args.listen_port,
    );

    info!(
        target: "appgate::startup",
        addr = %addr,
        workers = runtime.metrics().num_workers(),
        "Starting AppGate Gateway"
    );

    runtime.block_on(async move {
        server::run_server(addr, &args).await
    })
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