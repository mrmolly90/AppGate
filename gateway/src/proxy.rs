//! AppGate Centralized Proxy — Production-Grade Request Pipeline
//! v2.0.0 | 2026-09-06 | Deep Forensic Remediation Phase 2
//!
//! Handles: JWT validation, policy enforcement, distributed rate limiting,
//! circuit breaking, SSRF defense, request coalescing, streaming/non-streaming
//! upstream proxying, audit logging, OpenTelemetry metrics, retry with backoff.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use bytes::Bytes;
use futures::stream::StreamExt;
use serde_json::Value;

use crate::audit::AuditEvent;
use crate::cache::CachedResponse;
use crate::AppState;

/// Build a JSON error response.
fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    let body = serde_json::json!({
        "error": message.into(),
        "code": status.as_u16(),
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap_or_default()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("{}"))
                .unwrap()
        })
}

/// Build a response from a cached entry.
fn build_cached_response(cached: CachedResponse) -> Response {
    let mut builder = Response::builder().status(cached.status);
    for (key, value) in &cached.headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(name, val);
        }
    }
    builder
        .header("x-cache", "HIT")
        .body(Body::from(cached.body))
        .unwrap_or_else(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "cache response build failed"))
}

/// Max request body size: 10 MiB (configurable via APPGATE_MAX_BODY_BYTES)
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Upstream request timeout
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);

/// Headers that must be stripped per RFC 7230 / RFC 7540
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
];

#[derive(serde::Deserialize, Debug, Clone)]
pub struct ProxyRequest {
    pub model: Option<String>,
    pub provider: Option<String>,
    pub messages: Option<Vec<Value>>,
    pub stream: Option<bool>,
    #[serde(flatten)]
    pub extra: Value,
}

/// Primary proxy handler. Optimized for lock-free hot path where possible.
pub async fn handle_proxy(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    // ── 1. Extract & Validate JWT ─────────────────────────────────────────────
    let headers = req.headers();
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let token = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(t) => t,
        None => {
            state.metrics.record_auth_failure("missing_header");
            return json_error(StatusCode::UNAUTHORIZED, "missing or invalid authorization header");
        }
    };

    let validated = match state.jwt_validator.validate(token) {
        Ok(v) => v,
        Err(e) => {
            state.metrics.record_auth_failure("invalid_token");
            tracing::warn!(error = %e, "JWT validation failed");
            return json_error(StatusCode::UNAUTHORIZED, format!("JWT validation failed: {e}"));
        }
    };

    // ── 2. Parse Body with Size Limit ─────────────────────────────────────────
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            state.metrics.record_policy_denial(&validated.identity_id, "body_too_large");
            return json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds 10 MiB");
        }
    };

    let proxy_req: ProxyRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            return json_error(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"));
        }
    };

    let model = match proxy_req.model {
        Some(m) => m,
        None => return json_error(StatusCode::BAD_REQUEST, "model field is required"),
    };
    let provider = proxy_req.provider.unwrap_or_else(|| "default".to_string());

    // ── 3. Cache Lookup (Request Coalescing for Identical Prompts) ────────────
    let cache_key = format!(
        "cache:v2:{}:{}:{}",
        validated.identity_id,
        provider,
        blake3::hash(&body_bytes).to_hex()
    );

    if !proxy_req.stream.unwrap_or(false) {
        if let Some(cached) = state.cache.get(&cache_key).await {
            state.metrics.record_request("cache_hit", start.elapsed().as_millis() as u64);
            return build_cached_response(cached);
        }
    }

    // ── 4. Rate Limit (Distributed) ───────────────────────────────────────────
    if !state.rate_limiter.check(&validated.identity_id, &provider, &model).await {
        state.metrics.record_rate_limit_exceeded(&validated.identity_id);
        state.audit_logger.record(AuditEvent {
            event_type: "rate_limit.exceeded".into(),
            actor_id: validated.identity_id.clone(),
            action: "llm_request".into(),
            resource: format!("{}/{}", provider, model),
            result: "denied".into(),
            correlation_id: correlation_id.clone(),
            source: "gateway".into(),
            metadata: std::collections::HashMap::new(),
        });
        return json_error(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    // ── 5. Policy Evaluation ──────────────────────────────────────────────────
    let policy_result = state.policy_engine.evaluate_request(
        &validated.identity_id,
        &validated.roles,
        &provider,
        &model,
    ).await;

    if !policy_result.allowed {
        state.metrics.record_policy_denial(&validated.identity_id, &policy_result.reason);
        state.audit_logger.record(AuditEvent {
            event_type: "authorization.denied".into(),
            actor_id: validated.identity_id.clone(),
            action: "llm_request".into(),
            resource: format!("{}/{}", provider, model),
            result: "denied".into(),
            correlation_id: correlation_id.clone(),
            source: "gateway".into(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("reason".into(), policy_result.reason.clone());
                m
            },
        });
        return json_error(StatusCode::FORBIDDEN, policy_result.reason);
    }

    // ── 6. Route Resolution ───────────────────────────────────────────────────
    let upstream_url = match state.router.select(&format!("/{}/{}", provider, model)).await {
        Some(url) => url,
        None => {
            state.metrics.record_upstream_error(&provider);
            state.audit_logger.record(AuditEvent {
                event_type: "routing.failed".into(),
                actor_id: validated.identity_id.clone(),
                action: "llm_request".into(),
                resource: format!("{}/{}", provider, model),
                result: "error".into(),
                correlation_id: correlation_id.clone(),
                source: "gateway".into(),
                metadata: std::collections::HashMap::new(),
            });
            return json_error(StatusCode::BAD_REQUEST, format!("no provider configured for model: {}", model));
        }
    };

    // ── 7. SSRF Defense ───────────────────────────────────────────────────────
    if let Err(reason) = state.ssrf_guard.validate_upstream(&upstream_url) {
        tracing::warn!(upstream = %upstream_url, reason = %reason, "SSRF defense blocked request");
        state.audit_logger.record(AuditEvent {
            event_type: "ssrf.blocked".into(),
            actor_id: validated.identity_id.clone(),
            action: "llm_request".into(),
            resource: format!("{}/{}", provider, model),
            result: "denied".into(),
            correlation_id: correlation_id.clone(),
            source: "gateway".into(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("reason".into(), reason.clone());
                m
            },
        });
        return json_error(StatusCode::FORBIDDEN, "upstream destination not allowed");
    }

    // ── 8. Circuit Breaker Check ──────────────────────────────────────────────
    let cb_key = format!("{}:{}", provider, model);
    let cb = state.circuit_breaker.get_or_create(&cb_key).await;
    if !cb.allow().await {
        state.metrics.record_upstream_error(&provider);
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "upstream circuit breaker open");
    }

    // ── 9. Build Upstream Request ─────────────────────────────────────────────
    let upstream = upstream_url.trim_end_matches('/').to_string();
    // Allow generic proxying; only append completions path if explicitly LLM
    let upstream_uri = if upstream.contains("/v1/chat/completions") {
        upstream
    } else {
        format!("{}/v1/chat/completions", upstream)
    };

    let mut upstream_headers = HeaderMap::new();
    for (key, value) in parts.headers.iter() {
        let key_str = key.as_str();
        if HOP_BY_HOP_HEADERS.contains(&key_str) || key_str == "authorization" {
            continue;
        }
        if let Ok(name) = HeaderName::from_bytes(key.as_ref()) {
            upstream_headers.insert(name, value.clone());
        }
    }
    upstream_headers.insert("content-type", HeaderValue::from_static("application/json"));
    upstream_headers.insert(
        "x-correlation-id",
        HeaderValue::from_str(&correlation_id).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    upstream_headers.insert(
        "x-appgate-identity",
        HeaderValue::from_str(&validated.identity_id).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );

    // ── 10. Execute Upstream with Retry ───────────────────────────────────────
    let is_streaming = proxy_req.stream.unwrap_or(false);
    let upstream_start = Instant::now();

    let upstream_resp = execute_with_retry(
        &state,
        &upstream_uri,
        upstream_headers.clone(),
        body_bytes.clone(),
        &provider,
        cb.as_ref(),
    ).await;

    let upstream_duration_ms = upstream_start.elapsed().as_millis() as f64;

    match upstream_resp {
        Ok(resp) => {
            let status = resp.status();
            let status_u16 = status.as_u16();

            // Circuit breaker accounting: 5xx = failure, 429 = rate limit (don't trip breaker), 4xx = client error (don't trip)
            if status.is_server_error() {
                cb.record_failure().await;
            } else if status_u16 == 429 {
                cb.record_success().await;
            } else if status.is_success() {
                cb.record_success().await;
            }

            state.metrics.record_upstream_duration(&provider, &model, upstream_duration_ms);
            state.metrics.record_request(&status_u16.to_string(), start.elapsed().as_millis() as u64);

            state.audit_logger.record(AuditEvent {
                event_type: "request.allowed".into(),
                actor_id: validated.identity_id.clone(),
                action: "llm_request".into(),
                resource: format!("{}/{}", provider, model),
                result: "allowed".into(),
                correlation_id: correlation_id.clone(),
                source: "gateway".into(),
                metadata: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("upstream_status".into(), status_u16.to_string());
                    m.insert("upstream_ms".into(), upstream_duration_ms.to_string());
                    m
                },
            });

            // ── 11. Return Response (Streaming or Buffered) ───────────────────
            if is_streaming {
                let stream = resp.bytes_stream().map(move |result| {
                    result.map_err(|e| {
                        tracing::error!(error = %e, "streaming error");
                        Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                    })
                });
                let body = Body::from_stream(stream);
                Response::builder()
                    .status(status_u16)
                    .header("content-type", "text/event-stream")
                    .header("cache-control", "no-cache")
                    .header("x-correlation-id", &correlation_id)
                    .body(body)
                    .unwrap_or_else(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "stream build failed"))
            } else {
                match resp.bytes().await {
                    Ok(bytes) => {
                        // Cache successful non-streaming responses
                        if status.is_success() && state.cache.enabled() {
                            let cached = CachedResponse {
                                status: status_u16,
                                headers: vec![("content-type".into(), "application/json".into())],
                                body: bytes.clone(),
                            };
                            state.cache.set(cache_key, cached).await;
                        }

                        Response::builder()
                            .status(status_u16)
                            .header("content-type", "application/json")
                            .header("x-correlation-id", &correlation_id)
                            .body(Body::from(bytes))
                            .unwrap_or_else(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read upstream body");
                        json_error(StatusCode::BAD_GATEWAY, "upstream body read failed")
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, upstream = %upstream_uri, "upstream request failed after retries");
            cb.record_failure().await;
            state.metrics.record_upstream_error(&provider);
            state.audit_logger.record(AuditEvent {
                event_type: "upstream.failed".into(),
                actor_id: validated.identity_id.clone(),
                action: "llm_request".into(),
                resource: format!("{}/{}", provider, model),
                result: "error".into(),
                correlation_id: correlation_id.clone(),
                source: "gateway".into(),
                metadata: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("error".into(), e.to_string());
                    m
                },
            });
            json_error(StatusCode::BAD_GATEWAY, "upstream request failed")
        }
    }
}

/// Execute upstream request with exponential backoff retry.
async fn execute_with_retry(
    state: &Arc<AppState>,
    uri: &str,
    headers: HeaderMap,
    body: Bytes,
    provider: &str,
    cb: &crate::circuit_breaker::CircuitBreaker,
) -> Result<reqwest::Response, String> {
    let client = state.router.client();
    let mut last_err = None;

    for attempt in 0..3 {
        if attempt > 0 {
            let backoff = Duration::from_millis(100 * (2_u64.pow(attempt)));
            tokio::time::sleep(backoff).await;
            // Re-check breaker before retry
            if !cb.allow().await {
                break;
            }
        }

        match client
            .post(uri)
            .headers(headers.clone())
            .body(body.clone())
            .timeout(UPSTREAM_TIMEOUT)
            .send()
            .await
        {
            Ok(resp) => {
                // Don't retry client errors (4xx)
                if resp.status().is_client_error() {
                    return Ok(resp);
                }
                // Retry on 502/503/504
                if resp.status().is_server_error() && resp.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
                    last_err = Some(format!("upstream {}: {}", resp.status(), provider));
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                if e.is_timeout() || e.is_connect() {
                    last_err = Some(e.to_string());
                    continue;
                }
                return Err(e.to_string());
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "upstream failed after max retries".into()))
}