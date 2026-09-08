//! AppGate Gateway — Upstream Proxy Engine
//!
//! Forwards validated requests to upstream LLM APIs with
//! connection pooling, timeouts, and circuit breaker patterns.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use std::time::Duration;

/// Shared HTTP client with connection pooling for upstream requests.
pub struct ProxyClient {
    client: reqwest::Client,
}

impl ProxyClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(100)
            .http2_prior_knowledge()
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    /// Forward a request to the upstream control plane or LLM API.
    pub async fn forward(
        &self,
        req: Request<Full<Bytes>>,
        upstream_url: &str,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
            .map_err(|e| ProxyError::Internal(e.to_string()))?;

        let mut upstream_req = self.client.request(method, upstream_url);

        // Forward select headers
        for (key, value) in req.headers() {
            let key_str = key.as_str();
            if matches!(
                key_str,
                "authorization" | "content-type" | "x-request-id" | "accept"
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

        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;

        Ok(Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("x-appgate-proxy", "1")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| ProxyError::Internal(e.to_string()))?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
}