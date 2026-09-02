#![allow(dead_code)]

// =============================================================================
// AppGate Gateway — Production HTTP Server
// =============================================================================
//
// Enhancements:
//   • Graceful shutdown (SIGINT + SIGTERM) with connection draining
//   • Max concurrent connection limit (10,000) via Semaphore
//   • Request body size limit (10 MiB)
//   • Security headers on every response
//   • Per-request UUID correlation ID
//   • Structured access logging
//   • Active connections wired to Prometheus metrics
// =============================================================================

use crate::Args;
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
use tokio::sync::{Semaphore, Notify};
use tracing::{error, info, instrument, warn};

/// Global active connection counter
pub(crate) static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

// ── Production Constants ────────────────────────────────────────────────────
const MAX_CONCURRENT_CONNECTIONS: usize = 10_000;
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
const HEADER_READ_TIMEOUT_SECS: u64 = 10;
const SHUTDOWN_DRAIN_INTERVAL_MS: u64 = 100;
const SHUTDOWN_MAX_WAIT_SECS: u64 = 30;

// =============================================================================
// Public API
// =============================================================================

/// Run the HTTP server with graceful shutdown and production safeguards.
pub async fn run_server(addr: SocketAddr, args: &Args) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {addr}: {e}"))?;

    info!(
        target: "appgate::server",
        addr = %addr,
        max_concurrent = MAX_CONCURRENT_CONNECTIONS,
        max_body_bytes = MAX_BODY_BYTES,
        "Gateway server listening"
    );

    let tls_acceptor = crate::tls::load_tls_config(&args.tls_cert_path, &args.tls_key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load TLS config: {e}"))?;
    let tls_acceptor = Arc::new(tls_acceptor);

    let connection_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let shutdown = Arc::new(Notify::new());

    spawn_shutdown_handler(shutdown.clone());

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
                update_connection_metrics();

                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_connection(tls_acceptor, stream, peer_addr).await;
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    update_connection_metrics();
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

// =============================================================================
// Shutdown Handler
// =============================================================================

fn spawn_shutdown_handler(shutdown: Arc<Notify>) {
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        info!(target: "appgate::server", "Shutdown signal received, notifying accept loop");
        shutdown.notify_waiters();
    });
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => info!(target: "appgate::server", "Received SIGINT"),
        _ = sigterm.recv() => info!(target: "appgate::server", "Received SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    tokio::signal::ctrl_c().await.expect("Ctrl+C handler");
    info!(target: "appgate::server", "Received Ctrl+C");
}

// =============================================================================
// Connection Handler
// =============================================================================

async fn handle_connection(
    tls_acceptor: Arc<tokio_rustls::TlsAcceptor>,
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
) {
    let tls_stream = match tls_acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!(target: "appgate::tls", peer = %peer_addr, error = %e, "TLS handshake failed");
            crate::metrics::record_auth_failure("tls_handshake_failed");
            return;
        }
    };

    let io = TokioIo::new(tls_stream);

    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .keep_alive(true)
        .header_read_timeout(Duration::from_secs(HEADER_READ_TIMEOUT_SECS))
        .serve_connection(io, service_fn(|req| handle_request(req, peer_addr)));
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

#[instrument(skip(req), fields(peer = %peer_addr, method = %req.method(), path = %req.uri().path()))]
async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = route_request(req, peer_addr, &request_id).await;
    let status = response.as_ref().map(|r| r.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

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
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    request_id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") => Ok(health_response()),
        (&Method::GET, "/readyz") => Ok(ready_response()),
        (&Method::GET, "/metrics") => Ok(metrics_response()),
        (&Method::POST, "/v1/proxy") => handle_proxy(req, peer_addr, request_id).await,
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
        .header("strict-transport-security", "max-age=31536000; includeSubDomains")
        .header("referrer-policy", "strict-origin-when-cross-origin")
}

fn health_response() -> Response<Full<Bytes>> {
    with_security_headers(Response::builder())
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(b"ok\n")))
        .unwrap()
}

fn ready_response() -> Response<Full<Bytes>> {
    with_security_headers(Response::builder())
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(b"ready\n")))
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

// =============================================================================
// Proxy Handler
// =============================================================================

#[instrument(skip(req, _peer_addr), fields(request_id = %request_id))]
async fn handle_proxy(
    req: Request<Incoming>,
    _peer_addr: SocketAddr,
    request_id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let collected = match req.collect().await {
        Ok(c) => c,
        Err(e) => {
            error!(target: "appgate::proxy", error = %e, request_id = %request_id, "Failed to read request body");
            return Ok(proxy_error_response(StatusCode::BAD_REQUEST, "bad_request", "Failed to read request body", request_id));
        }
    };

    let body = collected.to_bytes();
    if body.len() > MAX_BODY_BYTES {
        warn!(
            target: "appgate::proxy",
            request_id = %request_id,
            body_bytes = body.len(),
            max_bytes = MAX_BODY_BYTES,
            "Request body exceeds maximum size"
        );
        return Ok(proxy_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            &format!("Body exceeds {} bytes", MAX_BODY_BYTES),
            request_id,
        ));
    }

    Ok(with_security_headers(Response::builder())
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .body(Full::new(body))
        .unwrap())
}

fn proxy_error_response(
    status: StatusCode,
    error_code: &str,
    message: &str,
    request_id: &str,
) -> Response<Full<Bytes>> {
    with_security_headers(Response::builder())
        .status(status)
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .body(Full::new(Bytes::from(format!(
            r#"{{"error":"{}","message":"{}","request_id":"{}"}}"#,
            error_code, message, request_id
        ))))
        .unwrap()
}

// =============================================================================
// Metrics Helper
// =============================================================================

fn update_connection_metrics() {
    let count = ACTIVE_CONNECTIONS.load(Ordering::Relaxed) as f64;
    crate::metrics::set_active_connections(count);
}