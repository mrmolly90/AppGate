// =============================================================================
// AppGate Gateway - HTTP Server
// =============================================================================

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, instrument, warn};

use crate::proxy::ProxyClient;
use crate::router;

pub(crate) static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Server configuration passed from main
#[derive(Clone, Debug)]
pub struct ServerConfig {
    #[allow(dead_code)]
    pub listen_addr: String,
    #[allow(dead_code)]
    pub listen_port: u16,
    pub control_plane_url: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    #[allow(dead_code)]
    pub jwt_key_path: String,
    #[allow(dead_code)]
    pub jwt_issuer: String,
    #[allow(dead_code)]
    pub jwt_audience: String,
    #[allow(dead_code)]
    pub otlp_endpoint: String,
}

/// Run the HTTP server on the given address.
pub async fn run_server(addr: SocketAddr, config: ServerConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {addr}: {e}"))?;

    info!(target: "appgate::server", addr = %addr, "Gateway server listening");

    let proxy_client = Arc::new(ProxyClient::new());
    let upstream_base = config.control_plane_url.clone();

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
        let proxy = proxy_client.clone();
        let upstream = upstream_base.clone();

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
                .serve_connection(io, service_fn(move |req| {
                    let proxy = proxy.clone();
                    let upstream = upstream.clone();
                    async move { handle_request(req, peer_addr, &proxy, &upstream).await }
                }));

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

#[instrument(skip(req, proxy), fields(peer = %peer_addr, method = %req.method(), path = %req.uri().path()))]
async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    proxy: &ProxyClient,
    upstream_base: &str,
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

    // Proxy all requests to the upstream control plane / service
    router::route_request(req, peer_addr, proxy, upstream_base).await
}
