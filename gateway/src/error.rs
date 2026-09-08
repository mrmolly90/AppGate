//! Centralized error types for the entire gateway

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Gateway-level error type
#[derive(Debug)]
pub enum GatewayError {
    Internal(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    RateLimited,
    ServiceUnavailable(String),
    Upstream(String),
    SsrfBlocked(String),
    CircuitOpen(String),
    Timeout,
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(msg) => write!(f, "Internal server error: {msg}"),
            Self::BadRequest(msg) => write!(f, "Bad request: {msg}"),
            Self::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            Self::Forbidden(msg) => write!(f, "Forbidden: {msg}"),
            Self::RateLimited => write!(f, "Rate limit exceeded"),
            Self::ServiceUnavailable(msg) => write!(f, "Service unavailable: {msg}"),
            Self::Upstream(msg) => write!(f, "Upstream error: {msg}"),
            Self::SsrfBlocked(msg) => write!(f, "SSRF blocked: {msg}"),
            Self::CircuitOpen(msg) => write!(f, "Circuit open for backend: {msg}"),
            Self::Timeout => write!(f, "Request timeout"),
        }
    }
}

/// JSON error response body
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub code: u16,
    pub request_id: String,
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (status, message) = match &self {
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            Self::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            Self::Upstream(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::SsrfBlocked(_) => (StatusCode::FORBIDDEN, self.to_string()),
            Self::CircuitOpen(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            Self::Timeout => (StatusCode::REQUEST_TIMEOUT, self.to_string()),
        };

        let body = Json(ErrorBody {
            error: message,
            code: status.as_u16(),
            request_id,
        });

        (status, body).into_response()
    }
}