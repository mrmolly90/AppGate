//! Shared data models

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Audit event severity
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuditLevel {
    Info,
    Warning,
    Error,
    Critical,
}

/// Types of auditable events
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuditEventType {
    RequestReceived,
    RequestForwarded,
    RequestBlocked,
    RateLimitExceeded,
    CircuitBreakerOpened,
    CircuitBreakerClosed,
    AuthSuccess,
    AuthFailure,
    SsrfBlocked,
    UpstreamError,
    Timeout,
}

/// Audit log record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: String,
    pub event_type: AuditEventType,
    pub level: AuditLevel,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
    pub status_code: Option<i32>,
    pub backend_host: Option<String>,
    pub duration_ms: Option<i64>,
    pub details: Option<serde_json::Value>,
    pub error_message: Option<String>,
}

impl AuditEvent {
    pub fn new(event_type: AuditEventType, level: AuditLevel) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type,
            level,
            client_ip: None,
            method: None,
            path: None,
            user_agent: None,
            status_code: None,
            backend_host: None,
            duration_ms: None,
            details: None,
            error_message: None,
        }
    }

    pub fn with_client_ip(mut self, ip: &str) -> Self {
        self.client_ip = Some(ip.into());
        self
    }
    pub fn with_method(mut self, m: &str) -> Self {
        self.method = Some(m.into());
        self
    }
    pub fn with_path(mut self, p: &str) -> Self {
        self.path = Some(p.into());
        self
    }
    pub fn with_user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.into());
        self
    }
    pub fn with_status(mut self, code: u16) -> Self {
        self.status_code = Some(code as i32);
        self
    }
    pub fn with_backend(mut self, host: &str) -> Self {
        self.backend_host = Some(host.into());
        self
    }
    pub fn with_duration(mut self, d: std::time::Duration) -> Self {
        self.duration_ms = Some(d.as_millis() as i64);
        self
    }
    pub fn with_details(mut self, d: serde_json::Value) -> Self {
        self.details = Some(d);
        self
    }
    pub fn with_error(mut self, e: &str) -> Self {
        self.error_message = Some(e.into());
        self
    }
}

/// Backend health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BackendHealth {
    Healthy,
    Degraded,
    Unhealthy,
}