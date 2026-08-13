//! Audit event logging
//!
//! Audit events are sent to the control plane for persistent storage.
//! Sensitive data (prompts, responses, credentials) is NOT included
//! in default audit events.

use serde::Serialize;

/// Audit event
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub event_type: String,
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub correlation_id: String,
    pub source: String,
    pub metadata: std::collections::HashMap<String, String>,
}

/// Audit logger
pub struct AuditLogger {
    control_plane_url: String,
}

impl AuditLogger {
    pub fn new(control_plane_url: String) -> Self {
        Self { control_plane_url }
    }

    /// Record an audit event
    pub fn record(&self, event: AuditEvent) {
        // In production, send to control plane via HTTP
        tracing::info!(
            event_type = %event.event_type,
            actor_id = %event.actor_id,
            action = %event.action,
            result = %event.result,
            "audit event"
        );
    }
}