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
    client: reqwest::Client,
}

impl AuditLogger {
    pub fn new(control_plane_url: String, client: reqwest::Client) -> Self {
        Self {
            control_plane_url,
            client,
        }
    }

    /// Record an audit event — sends to control plane asynchronously
    pub fn record(&self, event: AuditEvent) {
        let url = format!(
            "{}/v1/audit",
            self.control_plane_url.trim_end_matches('/')
        );
        let client = self.client.clone();

        tracing::debug!(
            event_type = %event.event_type,
            actor_id = %event.actor_id,
            action = %event.action,
            result = %event.result,
            "audit event"
        );

        // Fire-and-forget: send to control plane in background
        tokio::spawn(async move {
            match client.post(&url).json(&event).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        tracing::warn!(
                            status = %resp.status(),
                            "audit event rejected by control plane"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to send audit event to control plane"
                    );
                }
            }
        });
    }
}