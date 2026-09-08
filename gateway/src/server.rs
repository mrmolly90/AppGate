use axum::body::Body;
use axum::extract::{Request, State as AxumState};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::Router;
use http::Method;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::broadcast::Receiver;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::AppState;
use crate::auth::auth_middleware;
use crate::metrics::metrics_handler;
use crate::proxy::handle_proxy;

pub struct AppGateServer {
    state: Arc<AppState>,
    shutdown_rx: Receiver<()>,
}

impl AppGateServer {
    pub fn new(state: Arc<AppState>, shutdown_rx: Receiver<()>) -> Self {
        Self { state, shutdown_rx }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = self.state.clone();
        let app = build_app(state).await;

        let addr: SocketAddr = format!("{}:{}", self.state.config.bind_addr, self.state.config.port)
            .parse()?;

        info!("AppGate listening on {}", addr);

        let listener = TcpListener::bind(addr).await?;

        if self.state.config.tls.enabled {
            tracing::warn!("TLS enabled but native TLS over TCP accepted via axum requires manual TLS accept loop. Falling back to plain HTTP for now.");
            tracing::info!("For TLS: deploy behind a TLS-terminating reverse proxy (e.g. Envoy, Nginx, AWS ALB).");
        }

        let mut shutdown_rx = self.shutdown_rx;
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
                info!("graceful shutdown initiated");
            })
            .await?;

        Ok(())
    }
}

async fn build_app(state: Arc<AppState>) -> Router {
    // Restrict CORS to configured origins; default to same-origin only
    let allowed_origins = std::env::var("APPGATE_CORS_ORIGINS")
        .unwrap_or_default();
    let cors = if allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(|_origin: &http::HeaderValue, _parts: &http::request::Parts| {
                false // Same-origin only by default
            }))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([http::header::AUTHORIZATION, http::header::CONTENT_TYPE, http::header::HeaderName::from_static("x-request-id")])
    } else {
        let origins: Vec<_> = allowed_origins.split(',')
            .filter_map(|o| o.parse::<http::HeaderValue>().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([http::header::AUTHORIZATION, http::header::CONTENT_TYPE, http::header::HeaderName::from_static("x-request-id")])
    };

    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(60)))
        .layer(cors);

    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .route("/v1/chat/completions", post(handle_proxy))
        .route("/v1/proxy", post(handle_proxy))
        .route("/*path", any(handle_proxy))
        .layer(middleware_stack)
        .layer(middleware::from_fn(auth_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), request_middleware))
        .with_state(state)
}

async fn request_middleware(
    AxumState(state): AxumState<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let response = next.run(req).await;

    let latency = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();

    state.metrics.record_request(&status.to_string(), latency);

    tracing::info!(
        method = %method,
        path = %path,
        status = status,
        latency_ms = latency,
        "request completed"
    );

    response
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(serde_json::json!({ "status": "healthy" })))
}

async fn ready_handler(AxumState(state): AxumState<Arc<AppState>>) -> impl IntoResponse {
    let healthy = state.health_checker.all_healthy().await;
    if healthy.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(serde_json::json!({ "status": "no healthy upstreams" })));
    }
    (StatusCode::OK, axum::Json(serde_json::json!({ "status": "ready", "upstreams": healthy })))
}

// gRPC inter-service communication
// Proto definitions require a build.rs with tonic-build. Disabled until .proto files are committed.
// pub mod proto {
//     tonic::include_proto!("appgate");
// }

pub async fn start_grpc_service(
    addr: &str,
    _state: AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = addr.parse()?;
    tracing::info!("gRPC cluster service listening on {}", addr);

    // Stub — full gRPC service requires .proto files + tonic-build
    // Until proto files are committed, create an empty placeholder
    let _ = addr;
    tracing::warn!("gRPC service not yet registered: requires proto definitions");
    Ok(())
}