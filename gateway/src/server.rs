use crate::metrics;

// =============================================================================
// AppGate Gateway - HTTP Server
// =============================================================================

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

pub(crate) static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Server configuration passed from main
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub control_plane_url: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub jwt_key_path: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub otlp_endpoint: String,
}

/// Run the HTTP server on the given address.
pub async fn run_server(addr: SocketAddr, config: ServerConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {addr}: {e}"))?;

    info!(target: "appgate::server", addr = %addr, "Gateway server listening");

    let tls_acceptor = crate::tls::load_tls_config(&config.tls_cert_path, &config.tls_key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load TLS config: {e}"))?;

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
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(target: "appgate::tls", peer = %peer_addr, error = %e, "TLS handshake failed");
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let conn = http1::Builder::new()
                .keep_alive(true)
                .header_read_timeout(std::time::Duration::from_secs(10))
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

#[instrument(skip(req), fields(peer = %peer_addr, method = %req.method(), path = %req.uri().path()))]
async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
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

    if req.method() == Method::GET && req.uri().path() == "/metrics" {
        let metrics = crate::metrics::gather_metrics();
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(metrics)))
            .unwrap());
    }

    if req.method() == Method::POST && req.uri().path() == "/v1/proxy" {
        return handle_proxy(req, peer_addr).await;
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            r#"{"error":"not_found","message":"The requested resource was not found"}"#,
        )))
        .unwrap())
}

#[instrument(skip(req, _peer_addr))]
async fn handle_proxy(
    req: Request<Incoming>,
    _peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
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

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(body))
        .unwrap())
}
