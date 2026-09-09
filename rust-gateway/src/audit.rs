//! AppGate Gateway — Audit Event Logger
//!
//! Batches audit events and sends them to the control plane asynchronously.

use serde::Serialize;
use tokio::sync::mpsc;
use tracing::debug;

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

pub struct AuditLogger {
    sender: mpsc::UnboundedSender<AuditEvent>,
}

impl AuditLogger {
    pub fn new(_config: &crate::config::AuditConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let (sender, mut receiver) = mpsc::unbounded_channel::<AuditEvent>();

        let client_clone = client.clone();
        let control_plane_url = std::env::var("APPGATE_CONTROL_PLANE_URL")
            .unwrap_or_else(|_| "http://appgate-control-plane:8080".to_string());
        let endpoint = format!("{}/v1/audit/batch", control_plane_url.trim_end_matches('/'));

        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(100);
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

            loop {
                tokio::select! {
                    Some(event) = receiver.recv() => {
                        batch.push(event);
                        if batch.len() >= 100 {
                            Self::send_batch(&client_clone, &endpoint, &batch).await;
                            batch.clear();
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            Self::send_batch(&client_clone, &endpoint, &batch).await;
                            batch.clear();
                        }
                    }
                    else => break,
                }
            }
        });

        Self {
            sender,
        }
    }

    pub fn record(&self, event: AuditEvent) {
        debug!(
            event_type = %event.event_type,
            actor_id = %event.actor_id,
            action = %event.action,
            result = %event.result,
            "audit event"
        );

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
                tracing::warn!(error = %e, "failed to send audit batch to control plane");
            }
        }
    }
}