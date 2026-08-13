//! AppGate Gateway — High-performance LLM Security Gateway
//!
//! This is the data plane component of AppGate. It sits between clients and LLM
//! providers, enforcing authentication, authorization, policy, rate limiting, and
//! audit logging before any request reaches an upstream LLM.
//!
//! # Security Principles
//! - Never trust client-provided security context
//! - Validate JWTs independently
//! - Reject private IP ranges for upstream connections (SSRF defense)
//! - No full prompts/responses in default logs
//! - Fail closed on policy evaluation errors

mod config;
mod jwt;
mod policy;
mod proxy;
mod rate_limit;
mod router;
mod ssrf;
mod telemetry;
mod audit;

use std::sync::Arc;
use std::net::SocketAddr;

use axum::{
    routing::{get, post},
    Router,
    Json,
    response::IntoResponse,
    http::StatusCode,
    extract::State,
};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser, Debug)]
#[clap(name = "appgate-gateway", about = "AppGate LLM Security Gateway")]
struct Args {
    /// Listen address
    #[clap(long, default_value = "0.0.0.0")]
    listen_addr: String,

    /// Listen port
    #[clap(long, default_value_t = 8443)]
    listen_port: u16,

    /// Control plane URL
    #[clap(long, default_value = "https://appgate-control-plane:8443")]
    control_plane_url: String,

    /// JWT verification key path
    #[clap(long, default_value = "/etc/appgate/keys/verifying.pem")]
    jwt_key_path: String,

    /// JWT issuer
    #[clap(long, default_value = "appgate-control-plane")]
    jwt_issuer: String,

    /// JWT audience
    #[clap(long, default_value = "appgate-gateway")]
    jwt_audience: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env()
            .add_directive("appgate_gateway=info".parse()?)
            .add_directive("hyper=warn".parse()?))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let args = Args::parse();

    // Load configuration
    let cfg = config::Config::load(args)?;

    // Initialize JWT validator
    let jwt_validator = jwt::Validator::new(&cfg)?;

    // Initialize policy engine
    let policy_engine = policy::Engine::new(cfg.control_plane_url.clone());

    // Initialize rate limiter
    let rate_limiter = rate_limit::RateLimiter::new();

    // Initialize router
    let router = router::Router::new(cfg.control_plane_url.clone());

    // Build the service
    let state = proxy::GatewayState::new(
        jwt_validator,
        policy_engine,
        rate_limiter,
        router,
    );

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .route("/v1/chat/completions", post(proxy::handle_chat_completion))
        .route("/v1/proxy", post(proxy::handle_proxy))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", args.listen_addr, args.listen_port).parse()?;

    tracing::info!("AppGate gateway starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}