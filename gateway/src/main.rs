//! AppGate Gateway - Zero-trust LLM security gateway
//!
//! This crate provides the AppGate SDP Gateway, a high-performance
//! zero-trust security gateway for LLM API access.
// =============================================================================
// AppGate Gateway — Main Entry Point
// =============================================================================

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]

use clap::Parser;
use std::net::SocketAddr;
use tokio::signal;

mod audit;
#[cfg(feature = "jwt-auth")]
mod jwt;
mod metrics;
#[cfg(feature = "policy-engine")]
mod policy;
mod proxy;
#[cfg(feature = "ratelimit")]
mod rate_limit;
mod router;
#[cfg(feature = "ssrf-protection")]
mod ssrf;
mod server;
mod telemetry;
mod tls;

/// AppGate SDP Gateway — Zero-trust security gateway
#[derive(Parser, Debug, Clone)]
#[command(name = "appgate-gateway", version, about)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    listen_addr: String,

    /// Listen port
    #[arg(long, default_value_t = 8443)]
    listen_port: u16,

    /// Control plane URL
    #[arg(long, default_value = "http://appgate-control-plane:8080")]
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

    /// JWT expected issuer
    #[arg(long, default_value = "https://appgate.example.com")]
    jwt_issuer: String,

    /// JWT expected audience
    #[arg(long, default_value = "appgate-gateway")]
    jwt_audience: String,

    /// OpenTelemetry endpoint
    #[arg(long, default_value = "http://otel-collector:4317")]
    otlp_endpoint: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let _guard = telemetry::init_tracer_provider(&args.otlp_endpoint);

    // Start server
    let addr = SocketAddr::new(
        args.listen_addr.parse().expect("Invalid listen address"),
        args.listen_port,
    );

    tracing::info!(
        target: "appgate::startup",
        addr = %addr,
        "Starting AppGate Gateway"
    );

    let config = server::ServerConfig {
        listen_addr: args.listen_addr.clone(),
        listen_port: args.listen_port,
        control_plane_url: args.control_plane_url.clone(),
        tls_cert_path: args.tls_cert_path.clone(),
        tls_key_path: args.tls_key_path.clone(),
        jwt_key_path: args.jwt_key_path.clone(),
        jwt_issuer: args.jwt_issuer.clone(),
        jwt_audience: args.jwt_audience.clone(),
        otlp_endpoint: args.otlp_endpoint.clone(),
    };

    let mut server_handle = tokio::spawn(async move {
        server::run_server(addr, config).await
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            tracing::info!("SIGINT received, shutting down");
        }
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok()?;
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            Some(())
        } => {
            tracing::info!("SIGTERM received, shutting down");
        }
        result = &mut server_handle => {
            match result {
                Ok(Ok(())) => tracing::info!("Server stopped cleanly"),
                Ok(Err(e)) => tracing::error!("Server error: {}", e),
                Err(e) => tracing::error!("Server task join error: {}", e),
            }
        }
    }

    tracing::info!("AppGate shutdown complete");
    Ok(())
}

