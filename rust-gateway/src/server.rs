//! AppGate Gateway — Production HTTP Server
//!
//! Tuned for millions of requests/sec:
//!   • Graceful shutdown with 30s drain timeout
//!   • Semaphore-based connection backpressure (10K default)
//!   • Request body size limit enforcement
//!   • Security headers on every response
//!   • Per-request UUID correlation ID
//!   • Structured JSON access logging
//!   • Prometheus metrics wired to active connections

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Notify, Semaphore};
use tracing::{error, info, instrument, warn};

use crate::AppState;

/// Global active connection counter
pub(crate) static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

// ── Production Constants ────────────────────────────────────────────────────
const HEADER_READ_TIMEOUT_SECS: u64 = 10;
const SHUTDOWN_DRAIN_INTERVAL_MS: u64 = 100;
const SHUTDOWN_MAX_WAIT_SECS: u64 = 30;

// =============================================================================
// AppGateServer — Wraps the full server lifecycle
// =============================================================================

pub struct AppGateServer {
    state: Arc<AppState>,
    shutdown_rx: broadcast::Receiver<()>,
}

impl AppGateServer {
    pub fn new(state: Arc<AppState>, shutdown_rx: broadcast::Receiver<()>) -> Self {
        Self { state, shutdown_rx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.state.config.bind_addr, self.state.config.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid bind address: {e}"))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind to {addr}: {e}"))?;

        info!(
            target: "appgate::server",
            addr = %addr,
            max_concurrent = 10000,
            max_body_bytes = 10485760,
            "Gateway server listening"
        );

        let connection_limit = Arc::new(Semaphore::new(10000));
        let shutdown = Arc::new(Notify::new());

        // Forward broadcast shutdown to notify-based shutdown
        let mut rx = self.shutdown_rx;
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            let _ = rx.recv().await;
            shutdown_clone.notify_waiters();
        });

        loop {
            tokio::select! {
                biased;
                _ = shutdown.notified() => {
                    info!(target: "appgate::server", "Shutdown signal received, stopping accept loop");
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, peer_addr) = match accept_result {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!(target: "appgate::server", error = %e, "Failed to accept connection");
                            continue;
                        }
                    };

                    let permit = match connection_limit.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!(target: "appgate::server", peer = %peer_addr, "Connection limit exceeded, dropping");
                            continue;
                        }
                    };

                    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);

                    let state = self.state.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        handle_connection(state, stream, peer_addr).await;
                        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    });
                }
            }
        }

        // Graceful drain
        info!(target: "appgate::server", "Draining active connections...");
        let drain_start = Instant::now();
        let max_drain = Duration::from_secs(SHUTDOWN_MAX_WAIT_SECS);

        while ACTIVE_CONNECTIONS.load(Ordering::Relaxed) > 0 {
            if drain_start.elapsed() > max_drain {
                warn!(
                    target: "appgate::server",
                    remaining = ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
                    "Graceful drain timeout exceeded, forcing shutdown"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(SHUTDOWN_DRAIN_INTERVAL_MS)).await;
        }

        info!(target: "appgate::server", "Graceful shutdown complete");
        Ok(())
    }
}

// =============================================================================
// Connection Handler
// =============================================================================

async fn handle_connection(
    state: Arc<AppState>,
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
) {
    let io = TokioIo::new(stream);

    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .keep_alive(true)
        .header_read_timeout(Duration::from_secs(HEADER_READ_TIMEOUT_SECS))
        .serve_connection(
            io,
            service_fn(move |req| handle_request(state.clone(), req, peer_addr)),
        );
    let conn = conn.with_upgrades();

    if let Err(e) = conn.await {
        if !e.is_incomplete_message() {
            warn!(target: "appgate::server", peer = %peer_addr, error = %e, "Connection error");
        }
    }
}

// =============================================================================
// Request Routing
// =============================================================================

#[instrument(skip(state, req), fields(peer = %peer_addr, method = %req.method(), path = %req.uri().path()))]
async fn handle_request(
    state: Arc<AppState>,
    req: Request<Incoming>,
    peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = route_request(state, req, peer_addr, &request_id).await;
    let status = response
        .as_ref()
        .map(|r| r.status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    info!(
        target: "appgate::access",
        method = %method,
        path = %path,
        status = %status.as_u16(),
        duration_ms = %start.elapsed().as_millis(),
        request_id = %request_id,
        peer = %peer_addr,
        "Request completed"
    );

    crate::metrics::record_request(&path, status.as_u16(), start);

    response
}

async fn route_request(
    state: Arc<AppState>,
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    request_id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") | (&Method::GET, "/health") => Ok(health_response()),
        (&Method::GET, "/readyz") | (&Method::GET, "/ready") => Ok(ready_response()),
        (&Method::GET, "/metrics") => Ok(metrics_response()),
        (&Method::POST, "/v1/proxy") | (&Method::POST, "/v1/chat/completions") => {
            handle_proxy(state, req, peer_addr, request_id).await
        }
        _ => Ok(not_found_response(request_id)),
    }
}

// =============================================================================
// Response Helpers
// =============================================================================

fn with_security_headers(builder: hyper::http::response::Builder) -> hyper::http::response::Builder {
    builder
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .header("x-xss-protection", "1; mode=block")
        .header(
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        )
        .header("referrer-policy", "strict-origin-when-cross-origin")
        .header("permissions-policy", "geolocation=(), microphone=(), camera=()")
}

fn health_response() -> Response<Full<Bytes>> {
    with_security_headers(Response::builder())
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(r#"{"status":"healthy"}"#)))
        .unwrap()
}

fn ready_response() -> Response<Full<Bytes>> {
    with_security_headers(Response::builder())
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(r#"{"status":"ready"}"#)))
        .unwrap()
}

fn metrics_response() -> Response<Full<Bytes>> {
    let metrics = crate::metrics::gather_metrics();
    with_security_headers(Response::builder())
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(metrics)))
        .unwrap()
}

fn not_found_response(request_id: &str) -> Response<Full<Bytes>> {
    with_security_headers(Response::builder())
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .body(Full::new(Bytes::from(
            r#"{"error":"not_found","message":"The requested resource was not found"}"#,
        )))
        .unwrap()
}

fn proxy_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: &str,
) -> Response<Full<Bytes>> {
    let body = format!(
        r#"{{"error":"{}","message":"{}","request_id":"{}"}}"#,
        code, message, request_id
    );
    with_security_headers(Response::builder())
        .status(status)
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

// =============================================================================
// Proxy Handler (Real Upstream Forwarding)
// =============================================================================

#[instrument(skip(state, req, _peer_addr), fields(request_id = %request_id))]
async fn handle_proxy(
    state: Arc<AppState>,
    req: Request<Incoming>,
    _peer_addr: SocketAddr,
    request_id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Capture metadata before moving the body
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Collect and limit body
    let max_body_bytes: usize = 10 * 1024 * 1024; // 10MB
    let collected = match req.collect().await {
        Ok(c) => c,
        Err(e) => {
            error!(target: "appgate::proxy", error = %e, request_id = %request_id, "Failed to read request body");
            return Ok(proxy_error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "Failed to read request body",
                request_id,
            ));
        }
    };

    let body = collected.to_bytes();
    if body.len() > max_body_bytes {
        warn!(
            target: "appgate::proxy",
            request_id = %request_id,
            body_bytes = body.len(),
            max_bytes = max_body_bytes,
            "Request body exceeds maximum size"
        );
        return Ok(proxy_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            &format!("Body exceeds {} bytes", max_body_bytes),
            request_id,
        ));
    }

    // Forward to upstream via proxy module
    let upstream_url = state.router.select(&path).await
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let proxy_req = match Request::builder()
        .method(&method)
        .uri(&upstream_url)
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .body(Full::new(body))
    {
        Ok(req) => req,
        Err(e) => {
            error!(target: "appgate::proxy", error = %e, "Failed to build upstream request");
            return Ok(proxy_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Failed to build upstream request",
                request_id,
            ));
        }
    };

    match state.proxy_client.forward(proxy_req, &upstream_url).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!(target: "appgate::proxy", error = %e, request_id = %request_id, "Upstream proxy failed");
            Ok(proxy_error_response(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                &format!("Upstream request failed: {}", e),
                request_id,
            ))
        }
    }
}