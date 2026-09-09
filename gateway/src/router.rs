//! AppGate Gateway — Request Router
//!
//! Routes incoming requests based on path prefix to upstream services.

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use bytes::Bytes;
use http_body_util::Full;

use crate::proxy::ProxyClient;

/// Route an incoming request to the appropriate upstream.
pub async fn route_request(
    req: Request<Incoming>,
    _peer_addr: std::net::SocketAddr,
    proxy: &ProxyClient,
    upstream_base_url: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
    let upstream_url = format!("{}{}{}", upstream_base_url.trim_end_matches('/'), path, query);

    proxy.forward(req, &upstream_url).await.or_else(|e| {
        Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                format!(r#"{{"error":"upstream_failure","message":"{}"}}"#, e)
            )))
            .unwrap())
    })
}

/// Health check helper: returns current connection count.
#[allow(dead_code)]
pub fn active_connections() -> usize {
    crate::server::ACTIVE_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed)
}