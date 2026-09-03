// =============================================================================
// AppGate Gateway — Upstream Proxy Handler (Production)
// =============================================================================
//
// Features:
//   • Pooled reqwest client (HTTP/2 + rustls)
//   • Circuit breaker pattern (fail-fast on degraded upstream)
//   • Request/response transformation
//   • Upstream metrics recording
// =============================================================================

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitState {
    Closed,      // Normal operation
    Open,        // Failing fast
    HalfOpen,    // Testing recovery
}

pub struct ProxyHandler {
    client: Client,
    circuit_state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<RwLock<u32>>,
}

impl ProxyHandler {
    pub fn new() -> Self {
        let client = Client::builder()
            .http2_prior_knowledge()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(100)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .expect("Failed to build reqwest client");

        Self {
            client,
            circuit_state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Forward request to upstream LLM provider
    pub async fn forward(
        &self,
        body: Bytes,
        request_id: &str,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let start = Instant::now();

        // Circuit breaker check
        {
            let state = *self.circuit_state.read().await;
            if state == CircuitState::Open {
                warn!(target: "appgate::proxy", request_id = %request_id, "Circuit breaker OPEN — failing fast");
                return Err(ProxyError::CircuitOpen);
            }
        }

        // TODO: Parse target provider from request body
        // For now, use configured default upstream
        let upstream_url = std::env::var("UPSTREAM_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".into());

        let result = self
            .client
            .post(&upstream_url)
            .header("content-type", "application/json")
            .header("x-request-id", request_id)
            .header("authorization", format!("Bearer {}", Self::get_upstream_key().await))
            .body(body.clone())
            .send()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                let upstream_body = resp.bytes().await.unwrap_or_default();

                // Record success metrics
                crate::metrics::record_upstream_duration(&upstream_url, start);
                self.record_success().await;

                info!(
                    target: "appgate::proxy",
                    request_id = %request_id,
                    upstream = %upstream_url,
                    status = %status.as_u16(),
                    duration_ms = %start.elapsed().as_millis(),
                    "Upstream request completed"
                );

                let mut builder = Response::builder().status(status);
                builder = builder.header("x-request-id", request_id);
                Ok(builder.body(Full::new(upstream_body)).unwrap())
            }
            Err(e) => {
                error!(target: "appgate::proxy", request_id = %request_id, error = %e, "Upstream request failed");
                self.record_failure().await;
                Err(ProxyError::UpstreamFailed(e.to_string()))
            }
        }
    }

    async fn record_success(&self) {
        let mut count = self.failure_count.write().await;
        *count = 0;
        let mut state = self.circuit_state.write().await;
        *state = CircuitState::Closed;
    }

    async fn record_failure(&self) {
        let mut count = self.failure_count.write().await;
        *count += 1;
        if *count >= 5 {
            let mut state = self.circuit_state.write().await;
            *state = CircuitState::Open;
            warn!(target: "appgate::proxy", "Circuit breaker OPENED after 5 consecutive failures");
            // TODO: Spawn async task to transition to HalfOpen after 30s
        }
    }

    async fn get_upstream_key() -> String {
        std::env::var("UPSTREAM_API_KEY")
            .unwrap_or_else(|_| "REPLACE_ME".into())
    }
}

#[derive(Debug)]
pub enum ProxyError {
    CircuitOpen,
    UpstreamFailed(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::CircuitOpen => write!(f, "Circuit breaker is open"),
            ProxyError::UpstreamFailed(msg) => write!(f, "Upstream failed: {}", msg),
        }
    }
}

impl std::error::Error for ProxyError {}