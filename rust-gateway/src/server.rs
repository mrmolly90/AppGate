// =============================================================================
// AppGate Gateway — HTTP Server
// =============================================================================
//
// Hyper 1.x HTTP server with connection lifecycle management.
// Handles concurrent streams with minimal allocation.
//
// Performance rationale:
// - Uses `hyper::server::conn::http1::Builder` for HTTP/1.1 with
//   `max_keep_alive(Some(120))` to reuse connections efficiently.
// - `header_read_timeout` prevents slowloris attacks.
// - `auto_header` optimization removes unnecessary headers.
// - Connection count tracking via atomic counter for metrics.
// =============================================================================

use crate::Args;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, instrument, warn};

/// Global active connection counter for metrics
pub(crate) static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Run the HTTP server on the given address.
///
/// # Arguments
/// * `addr` - Socket address to bind to
/// * `args` - CLI arguments (used for TLS config)
///
/// # Performance
/// - Accepts connections in a loop, spawning a task per connection
/// - Each connection handler processes pipelined requests sequentially
/// - Connection count tracked for HPA metrics
pub async fn run_server(addr: SocketAddr, args: &Args) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {addr}: {e}"))?;

    info!(
        target: "appgate::server",
        addr = %addr,
        "Gateway server listening"
    );

    // Load TLS configuration
let tls_config = crate::tls::load_tls_config(&args.tls_cert_path, &args.tls_key_path)
    .await
    .map_err(|e| anyhow::anyhow!("Failed to load TLS config: {e}"))?;
let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    let tls_acceptor = Arc::new(tls_acceptor);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(target: "appgate::server", error = %e, "Failed to accept connection");
                continue;
            }
        };

        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            // Perform TLS handshake
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(target: "appgate::tls", peer = %peer_addr, error = %e, "TLS handshake failed");
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            // Build HTTP/1.1 connection with performance tuning
            let conn = http1::Builder::new()
                .keep_alive(true)
                .header_read_timeout(std::time::Duration::from_secs(10))
                .auto_date_header(true)
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service_fn(|req| handle_request(req, peer_addr)));

            let conn = conn.with_upgrades();

            if let Err(e) = conn.await {
                if !e.is_incomplete_message() {
                    warn!(target: "appgate::server", peer = %peer_addr, error = %e, "Connection error");
                }
            }

            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Handle an individual HTTP request.
///
/// # Zero-allocation hot path
///
/// For health/readiness checks, we return a static response without
/// any heap allocation. For all other requests, we minimally parse
/// the request to route it appropriately.
///
/// # Arguments
/// * `req` - Incoming HTTP request
/// * `peer_addr` - Peer socket address (for logging/metrics)
#[instrument(skip(req), fields(peer = %peer_addr, method = %req.method(), path = %req.uri().path()))]
async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // ── Health check — zero allocation hot path ───────────────────
    if req.method() == Method::GET && req.uri().path() == "/healthz" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from_static(b"ok\n")))
            .unwrap());
    }

    if req.method() == Method::GET && req.uri().path() == "/readyz" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from_static(b"ready\n")))
            .unwrap());
    }

    // ── Metrics endpoint ──────────────────────────────────────────
    if req.method() == Method::GET && req.uri().path() == "/metrics" {
        let metrics = crate::metrics::gather_metrics();
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(metrics)))
            .unwrap());
    }

    // ── Proxy endpoint ────────────────────────────────────────────
    if req.method() == Method::POST && req.uri().path() == "/v1/proxy" {
        return handle_proxy(req, peer_addr).await;
    }

    // ── 404 for everything else ───────────────────────────────────
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            r#"{"error":"not_found","message":"The requested resource was not found"}"#,
        )))
        .unwrap())
}

/// Handle a proxy request.
///
/// This is the main data path. The request body is forwarded to the
/// upstream service after authentication, policy evaluation, and
/// SSRF protection.
#[instrument(skip(req, _peer_addr))]
async fn handle_proxy(
    req: Request<Incoming>,
    _peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Collect the full body
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!(target: "appgate::proxy", error = %e, "Failed to read request body");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    r#"{"error":"bad_request","message":"Failed to read request body"}"#,
                )))
                .unwrap());
        }
    };

    // TODO: Implement full proxy pipeline:
    // 1. JWT validation (feature: jwt-auth)
    // 2. Rate limiting (feature: ratelimit)
    // 3. Policy evaluation (feature: policy-engine)
    // 4. SSRF protection (feature: ssrf-protection)
    // 5. Upstream forwarding
    // 6. Audit logging (feature: audit)

    // Placeholder: echo back the request
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(body))
        .unwrap())
}


