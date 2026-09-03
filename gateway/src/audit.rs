// =============================================================================
// AppGate Gateway — Audit Logger (Production)
// =============================================================================
//
// Records structured audit events to:
//   • stdout (structured JSON) for log aggregation
//   • Optional async batch buffer for control plane forwarding
// =============================================================================

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_type: String,
    pub event_time: String,
    pub severity: u8,
    pub actor: Actor,
    pub action: Action,
    pub resource: Resource,
    pub result: ResultDetails,
    pub correlation_id: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Actor {
    pub id: String,
    pub type_: String,
    pub roles: Vec<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Action {
    pub name: String,
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Resource {
    pub type_: String,
    pub name: String,
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResultDetails {
    pub status: String,
    pub reason: String,
    pub policy_id: Option<String>,
}

pub struct AuditLogger;

impl AuditLogger {
    pub fn new() -> Self {
        Self
    }

    /// Record an audit event to stdout (structured JSON)
    pub fn record(&self, event: AuditEvent) {
        match serde_json::to_string(&event) {
            Ok(json) => {
                info!(
                    target: "appgate::audit",
                    event_type = %event.event_type,
                    correlation_id = %event.correlation_id,
                    actor_id = %event.actor.id,
                    action = %event.action.name,
                    resource = %event.resource.name,
                    result = %event.result.status,
                    severity = %event.severity,
                    "{}",
                    json
                );
            }
            Err(e) => {
                tracing::error!(target: "appgate::audit", error = %e, "Failed to serialize audit event");
            }
        }
    }

    /// Convenience builder for proxy request events
    pub fn proxy_request(
        &self,
        request_id: &str,
        actor_id: &str,
        provider: &str,
        model: &str,
        status: &str,
    ) {
        let event = AuditEvent {
            event_type: "proxy_request".into(),
            event_time: chrono::Utc::now().to_rfc3339(),
            severity: if status == "denied" { 7 } else { 3 },
            actor: Actor {
                id: actor_id.into(),
                type_: "service_account".into(),
                roles: vec![],
                tenant_id: None,
            },
            action: Action {
                name: "forward".into(),
                type_: "llm_proxy".into(),
            },
            resource: Resource {
                type_: "llm_api".into(),
                name: format!("{}/{}", provider, model),
                provider: provider.into(),
                model: model.into(),
            },
            result: ResultDetails {
                status: status.into(),
                reason: "".into(),
                policy_id: None,
            },
            correlation_id: request_id.into(),
            metadata: HashMap::new(),
        };
        self.record(event);
    }
}