// =============================================================================
// AppGate Gateway — Policy Engine
// =============================================================================
//
// Evaluates access control policies fetched from the control plane.
// Fail-closed: denies access if no policies are configured or if
// the control plane is unreachable.
// =============================================================================

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// A policy fetched from the control plane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Allowed subjects (roles or user IDs)
    pub subjects: Vec<String>,
    /// Allowed providers
    pub providers: Vec<String>,
    /// Allowed models
    pub models: Vec<String>,
    /// Whether to log all requests matching this policy
    pub logging_enabled: bool,
}

/// Result of a policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    /// Whether access is allowed
    pub allowed: bool,
    /// Policy ID that matched (if any)
    pub matched_policy: Option<String>,
    /// Reason for the decision
    pub reason: String,
}

/// Policy engine that caches policies from the control plane
pub struct PolicyEngine {
    policies: Arc<RwLock<Vec<Policy>>>,
    control_plane_url: String,
}

impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new(control_plane_url: &str) -> Self {
        Self {
            policies: Arc::new(RwLock::new(Vec::new())),
            control_plane_url: control_plane_url.to_string(),
        }
    }

    /// Start the background policy refresh loop.
    ///
    /// Fetches policies from the control plane every 60 seconds.
    pub fn start_refresh_loop(&self) {
        let policies = self.policies.clone();
        let url = self.control_plane_url.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                match Self::fetch_policies(&url).await {
                    Ok(new_policies) => {
                        *policies.write().await = new_policies;
                        tracing::info!(target: "appgate::policy", "Policies refreshed");
                    }
                    Err(e) => {
                        tracing::warn!(target: "appgate::policy", error = %e, "Failed to refresh policies");
                    }
                }
            }
        });
    }

    /// Evaluate a request against the cached policies.
    ///
    /// # Fail-closed behavior
    ///
    /// If no policies are configured, access is DENIED. This ensures
    /// that a misconfiguration cannot accidentally allow access.
    pub async fn evaluate(
        &self,
        roles: &[String],
        provider: &str,
        model: &str,
    ) -> PolicyEvaluation {
        let policies = self.policies.read().await;

        if policies.is_empty() {
            return PolicyEvaluation {
                allowed: false,
                matched_policy: None,
                reason: "No policies configured — fail closed".to_string(),
            };
        }

        for policy in policies.iter() {
            // Check subject match (role-based)
            let subject_match = roles.iter().any(|r| policy.subjects.contains(r));

            if !subject_match {
                continue;
            }

            // Check provider match
            if !policy.providers.is_empty() && !policy.providers.contains(&provider.to_string()) {
                continue;
            }

            // Check model match
            if !policy.models.is_empty() && !policy.models.contains(&model.to_string()) {
                continue;
            }

            return PolicyEvaluation {
                allowed: true,
                matched_policy: Some(policy.id.clone()),
                reason: "Access granted by policy".to_string(),
            };
        }

        PolicyEvaluation {
            allowed: false,
            matched_policy: None,
            reason: "No matching policy found".to_string(),
        }
    }

    /// Fetch policies from the control plane.
    async fn fetch_policies(url: &str) -> anyhow::Result<Vec<Policy>> {
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{url}/v1/policies"))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;

        let policies: Vec<Policy> = response.json().await?;
        Ok(policies)
    }
}
