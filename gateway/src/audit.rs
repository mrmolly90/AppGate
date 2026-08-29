use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub fn record(&self, _event: AuditEvent) {}
}
