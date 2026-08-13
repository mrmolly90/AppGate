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
    http::{HeaderMap, StatusCode},
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
}

impl GatewayState {
    pub fn new(
        jwt_validator: Validator,
        policy_engine: Engine,
        rate_limiter: RateLimiter,
        router: Router,
    ) -> Self {
        Self {
            jwt_validator: Arc::new(jwt_validator),
            policy_engine: Arc::new(policy_engine),
            rate_limiter: Arc::new(rate_limiter),
            router: Arc::new(router),
            audit_logger: Arc::new(AuditLogger::new("http://localhost:8443".into())),
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

    // Route to provider (simplified — in production, make the actual HTTP request)
    let _ = state.router.get_provider_url(model);

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

    (StatusCode::OK, Json(serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Proxied through AppGate security gateway"
            },
            "finish_reason": "stop"
        }]
    })))
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