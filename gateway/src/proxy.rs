//! AppGate Gateway — Upstream Proxy Engine
//!
//! Forwards validated requests to upstream services with
//! connection pooling, timeouts, and circuit breaker patterns.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, Request, Response, StatusCode};
use std::time::Duration;

/// Shared HTTP client with connection pooling for upstream requests.
#[derive(Clone)]
pub struct ProxyClient {
    client: reqwest::Client,
}

impl ProxyClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(200)
            .pool_idle_timeout(Duration::from_secs(60))
            .http2_prior_knowledge()
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    /// Forward an incoming request to the upstream service.
    pub async fn forward(
        &self,
        req: Request<Incoming>,
        upstream_url: &str,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
            .map_err(|e| ProxyError::Internal(e.to_string()))?;

        let mut upstream_req = self.client.request(method, upstream_url);

        // Forward select security-critical headers
        for (key, value) in req.headers() {
            let key_str = key.as_str().to_lowercase();
            if matches!(
                key_str.as_str(),
                "authorization"
                    | "content-type"
                    | "x-request-id"
                    | "accept"
                    | "x-api-key"
                    | "x-tenant-id"
                    | "user-agent"
            ) {
                upstream_req = upstream_req.header(key.as_str(), value.as_bytes());
            }
        }

        let resp = upstream_req
            .send()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;

        let status = StatusCode::from_u16(resp.status().as_u16())
            .unwrap_or(StatusCode::BAD_GATEWAY);

        // Capture headers before consuming body
        let content_type = resp.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        let cache_control = resp.headers().get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;

        let mut builder = Response::builder()
            .status(status)
            .header("x-appgate-proxy", "1");

        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        if let Some(cc) = cache_control {
            builder = builder.header("cache-control", cc);
        }

        Ok(builder
            .body(Full::new(body_bytes))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("{}")))
                    .unwrap()
            }))
    }
}

impl Default for ProxyClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Proxy request handler for use with the HTTP server.
#[allow(dead_code)]
pub async fn handle_proxy_request(
    client: &ProxyClient,
    req: Request<Incoming>,
    _peer_addr: std::net::SocketAddr,
    upstream_url: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match client.forward(req, upstream_url).await {
        Ok(resp) => Ok(resp),
        Err(e) => Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                format!(r#"{{"error":"upstream_error","message":"{}"}}"#, e)
            )))
            .unwrap()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
}