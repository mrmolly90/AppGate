//! Main proxy service — handles incoming HTTP requests
//!
//! This is the core request processing pipeline:
//! 1. Extract JWT from Authorization header
//! 2. Validate JWT (signature, issuer, audience, expiration)
//! 3. Evaluate policy (is this identity allowed to access this model/provider?)
//! 4. Check rate limits
//! 5. Route to upstream LLM provider
//! 6. Record audit event
//! 7. Return response

use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::audit::{AuditEvent, AuditLogger};
use crate::jwt::Validator;
use crate::policy::Engine;
use crate::rate_limit::RateLimiter;
use crate::router::Router;

/// Shared application state
#[derive(Clone)]
pub struct GatewayState {
    pub jwt_validator: Arc<Validator>,
    pub policy_engine: Arc<Engine>,
    pub rate_limiter: Arc<RateLimiter>,
    pub router: Arc<Router>,
    pub audit_logger: Arc<AuditLogger>,
    pub http_client: Arc<reqwest::Client>,
}

impl GatewayState {
    pub fn new(
        jwt_validator: Validator,
        policy_engine: Engine,
        rate_limiter: RateLimiter,
        router: Router,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        Self {
            jwt_validator: Arc::new(jwt_validator),
            policy_engine: Arc::new(policy_engine),
            rate_limiter: Arc::new(rate_limiter),
            router: Arc::new(router),
            audit_logger: Arc::new(AuditLogger::new(
                "http://localhost:8443".into(),
                http_client.clone(),
            )),
            http_client: Arc::new(http_client),
        }
    }
}

/// Request body from client
#[derive(serde::Deserialize)]
pub struct ProxyRequest {
    pub model: Option<String>,
    pub provider: Option<String>,
    pub messages: Option<Vec<serde_json::Value>>,
    pub stream: Option<bool>,
}

/// Handle /v1/chat/completions endpoint
pub async fn handle_chat_completion(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(req): Json<ProxyRequest>,
) -> Response {
    let correlation_id = uuid::Uuid::new_v4().to_string();

    // Extract auth header
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());

    let token = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(t) => t,
        None => {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "missing or invalid authorization header"
            })))
            .into_response()
        }
    };

    // Validate JWT (signature, issuer, audience, expiration, algorithm)
    let validated = match state.jwt_validator.validate(token) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": format!("JWT validation failed: {}", e)
            })))
            .into_response()
        }
    };

    let model = req.model.as_deref().unwrap_or("gpt-4");
    let provider = req.provider.as_deref().unwrap_or("openai");

    // Check rate limit
    if !state.rate_limiter.check(&validated.identity_id) {
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
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "error": "rate limit exceeded"
        })))
        .into_response()
    }

    // Evaluate policy
    let result = state.policy_engine.evaluate(
        &validated.identity_id,
        &validated.roles,
        provider,
        model,
    );

    if !result.allowed {
        state.audit_logger.record(AuditEvent {
            event_type: "authorization.denied".into(),
            actor_id: validated.identity_id,
            action: "llm_request".into(),
            resource: format!("{}/{}", provider, model),
            result: "denied".into(),
            correlation_id,
            source: "gateway".into(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("reason".into(), result.reason.clone());
                m
            },
        });
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": result.reason
        })))
        .into_response()
    }

    // Resolve upstream provider URL
    let upstream_url = match state.router.get_provider_url(model) {
        Ok(url) => url.to_string(),
        Err(_) => {
            state.audit_logger.record(AuditEvent {
                event_type: "routing.failed".into(),
                actor_id: validated.identity_id,
                action: "llm_request".into(),
                resource: format!("{}/{}", provider, model),
                result: "denied".into(),
                correlation_id: correlation_id.clone(),
                source: "gateway".into(),
                metadata: std::collections::HashMap::new(),
            });
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("no provider configured for model: {}", model)
            })))
            .into_response()
        }
    };

    // Build upstream request URL
    let upstream = format!("{}/v1/chat/completions", upstream_url.trim_end_matches('/'));

    // Forward the request body to the upstream provider
    let upstream_body = serde_json::json!({
        "model": model,
        "messages": req.messages,
        "stream": req.stream.unwrap_or(false),
    });

    // Build forwarded headers (strip hop-by-hop headers)
    let mut upstream_headers = HeaderMap::new();
    for (key, value) in headers.iter() {
        match key.as_str() {
            "host" | "authorization" | "connection" | "transfer-encoding" | "proxy-connection"
            | "keep-alive" | "upgrade" | "proxy-authenticate" | "proxy-authorization" => {
                continue;
            }
            _ => {
                upstream_headers.insert(key.clone(), value.clone());
            }
        }
    }
    upstream_headers.insert(
        "content-type",
        HeaderValue::from_static("application/json"),
    );

    // Make the upstream request
    let upstream_response = match state
        .http_client
        .post(&upstream)
        .headers(upstream_headers)
        .json(&upstream_body)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, upstream = %upstream, "upstream request failed");
            state.audit_logger.record(AuditEvent {
                event_type: "upstream.failed".into(),
                actor_id: validated.identity_id,
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
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
                "error": "upstream request failed",
                "detail": e.to_string()
            })))
            .into_response()
        }
    };

    let upstream_status = upstream_response.status();
    let upstream_body: serde_json::Value = match upstream_response.json().await {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error = %e, "failed to parse upstream response body");
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
                "error": "failed to parse upstream response"
            })))
            .into_response()
        }
    };

    // Record success audit
    state.audit_logger.record(AuditEvent {
        event_type: "request.allowed".into(),
        actor_id: validated.identity_id,
        action: "llm_request".into(),
        resource: format!("{}/{}", provider, model),
        result: "allowed".into(),
        correlation_id,
        source: "gateway".into(),
        metadata: std::collections::HashMap::new(),
    });

    (StatusCode::from_u16(upstream_status.as_u16()).unwrap_or(StatusCode::OK), Json(upstream_body))
        .into_response()
}

/// Handle /v1/proxy endpoint (generic proxy)
pub async fn handle_proxy(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(req): Json<ProxyRequest>,
) -> Response {
    handle_chat_completion(State(state), headers, Json(req)).await
}