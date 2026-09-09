#![allow(dead_code)]

//! AppGate Gateway — Audit Event Logger
//!
//! Records audit events and sends them to the control plane asynchronously.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::debug;

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
    #[serde(rename = "type")]
    pub type_: String,
    pub roles: Vec<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Action {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Resource {
    #[serde(rename = "type")]
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

pub struct AuditLogger {
    sender: mpsc::UnboundedSender<AuditEvent>,
    enabled: bool,
}

impl AuditLogger {
    pub fn new(control_plane_url: Option<String>) -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel::<AuditEvent>();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let endpoint = control_plane_url
            .unwrap_or_else(|| "http://appgate-control-plane:8080".to_string())
            .trim_end_matches('/')
            .to_string()
            + "/v1/audit/batch";

        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(100);
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

            loop {
                tokio::select! {
                    Some(event) = receiver.recv() => {
                        batch.push(event);
                        if batch.len() >= 100 {
                            Self::send_batch(&client, &endpoint, &batch).await;
                            batch.clear();
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            Self::send_batch(&client, &endpoint, &batch).await;
                            batch.clear();
                        }
                    }
                    else => break,
                }
            }
        });

        Self {
            sender,
            enabled: true,
        }
    }

    pub fn new_disabled() -> Self {
        let (sender, _) = mpsc::unbounded_channel();
        Self {
            sender,
            enabled: false,
        }
    }

    pub fn record(&self, event: AuditEvent) {
        if !self.enabled {
            return;
        }
        debug!(event_type = %event.event_type, "audit event");
        if let Err(e) = self.sender.send(event) {
            tracing::warn!(error = %e, "audit channel closed, dropping event");
        }
    }

    async fn send_batch(client: &reqwest::Client, url: &str, batch: &[AuditEvent]) {
        if batch.is_empty() {
            return;
        }
        match client.post(url).json(batch).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    tracing::warn!(status = %resp.status(), "audit batch rejected by control plane");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to send audit batch");
            }
        }
    }
}
