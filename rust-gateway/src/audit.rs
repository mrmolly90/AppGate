// =============================================================================
// AppGate Gateway — Audit Event Logging
// =============================================================================
//
// Sends audit events to the control plane for compliance and
// forensics. Fire-and-forget to avoid blocking the hot path.
// =============================================================================

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

/// Audit event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditSeverity {
    /// Informational events (e.g., successful requests)
    Info,
    /// Warning events (e.g., rate limit approaching)
    Warning,
    /// Error events (e.g., authentication failure)
    Error,
    /// Critical events (e.g., security policy violation)
    Critical,
}

/// An audit event sent to the control plane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier
    pub id: Uuid,
    /// Event timestamp (Unix epoch nanos)
    pub timestamp: u128,
    /// Event type (e.g., "authentication.success", "proxy.request")
    pub event_type: String,
    /// Identity ID that performed the action
    pub client_id: String,
    /// Client IP address
    pub client_ip: String,
    /// Action performed
    pub action: String,
    /// Resource accessed
    pub resource: String,
    /// Result of the action
    pub result: String,
    /// Correlation ID for tracing
    pub correlation_id: String,
    /// Event severity
    pub severity: AuditSeverity,
    /// Source component
    pub source: String,
}

impl AuditEvent {
    /// Create a new audit event.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_type: &str,
        actor_id: &str,
        peer_addr: &str,
        action: &str,
        resource: &str,
        result: &str,
        correlation_id: &str,
        severity: AuditSeverity,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            event_type: event_type.to_string(),
            client_id: actor_id.to_string(),
            client_ip: peer_addr.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            result: result.to_string(),
            correlation_id: correlation_id.to_string(),
            severity,
            source: "rust-gateway".to_string(),
        }
    }
}

/// Send an audit event to the control plane (fire-and-forget).
///
/// # Performance rationale
///
/// This spawns a background task to send the event, so the hot path
/// is never blocked by network I/O to the control plane.
pub fn send_audit_event(event: AuditEvent) {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let url = "http://control-plane:8080/v1/audit/events".to_string();
        let _ = client
            .post(&url)
            .json(&event)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
    });
}
