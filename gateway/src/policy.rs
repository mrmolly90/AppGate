//! Policy evaluation engine

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub spec: PolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySpec {
    pub subjects: SubjectSelector,
    pub providers: Vec<String>,
    pub models: Vec<String>,
    pub limits: RateLimits,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectSelector {
    pub roles: Option<Vec<String>>,
    pub users: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimits {
    pub requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub metadata_only: bool,
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub allowed: bool,
    pub policy_id: Option<String>,
    pub reason: String,
}

pub struct PolicyEngine {
    policies: Arc<ArcSwap<Vec<Policy>>>,
    control_plane_url: String,
    client: reqwest::Client,
    healthy: Arc<AtomicBool>,
}

impl PolicyEngine {
    pub fn new(control_plane_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to build policy HTTP client, using default");
                reqwest::Client::new()
            });

        let engine = Self {
            policies: Arc::new(ArcSwap::new(Arc::new(Vec::new()))),
            control_plane_url,
            client,
            healthy: Arc::new(AtomicBool::new(true)),
        };

        engine.start_policy_refresh();
        engine
    }

    pub fn policy_count(&self) -> usize {
        self.policies.load().len()
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    fn start_policy_refresh(&self) {
        let url = format!("{}/v1/policies", self.control_plane_url.trim_end_matches('/'));
        let client = self.client.clone();
        let policies = Arc::clone(&self.policies);
        let healthy = Arc::clone(&self.healthy);

        tokio::spawn(async move {
            loop {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<Vec<Policy>>().await {
                            Ok(fetched) => {
                                let count = fetched.len();
                                policies.store(Arc::new(fetched));
                                tracing::info!(target: "appgate::policy", count = count, "Policies refreshed");
                                healthy.store(true, Ordering::Relaxed);
                            }
                            Err(e) => tracing::warn!(target: "appgate::policy", error = %e, "Failed to parse policies"),
                        }
                    }
                    Ok(resp) => tracing::warn!(target: "appgate::policy", status = %resp.status(), "Policy fetch returned non-success"),
                    Err(e) => {
                        tracing::warn!(target: "appgate::policy", error = %e, "Failed to fetch policies");
                        healthy.store(false, Ordering::Relaxed);
                    }
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }

    pub fn evaluate(&self, identity_id: &str, roles: &[String], provider: &str, model: &str) -> EvaluationResult {
        let policies = self.policies.load();

        if policies.is_empty() {
            return EvaluationResult {
                allowed: false,
                policy_id: None,
                reason: "No policies configured - fail closed".to_string(),
            };
        }

        for policy in policies.iter() {
            let subject_match = Self::matches_subject(policy, identity_id, roles);
            if !subject_match { continue; }

            if !policy.spec.providers.is_empty() && !policy.spec.providers.contains(&provider.to_string()) {
                continue;
            }

            if !policy.spec.models.is_empty() && !policy.spec.models.contains(&model.to_string()) {
                continue;
            }

            return EvaluationResult {
                allowed: true,
                policy_id: Some(policy.id.clone()),
                reason: "Access granted by policy".to_string(),
            };
        }

        EvaluationResult {
            allowed: false,
            policy_id: None,
            reason: "No matching policy found".to_string(),
        }
    }

    fn matches_subject(policy: &Policy, identity_id: &str, roles: &[String]) -> bool {
        if let Some(ref policy_roles) = policy.spec.subjects.roles {
            for role in roles {
                if policy_roles.contains(role) {
                    return true;
                }
            }
        }
        if let Some(ref policy_users) = policy.spec.subjects.users {
            if policy_users.contains(&identity_id.to_string()) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_policy() -> Policy {
        Policy {
            id: "test-1".into(),
            name: "Engineering LLM Access".into(),
            spec: PolicySpec {
                subjects: SubjectSelector {
                    roles: Some(vec!["engineering".into()]),
                    users: None,
                },
                providers: vec!["openai".into()],
                models: vec!["gpt-4".into()],
                limits: RateLimits {
                    requests_per_minute: 60,
                },
                logging: LoggingConfig {
                    metadata_only: true,
                },
            },
        }
    }

    #[test]
    fn test_allowed_request() {
        let engine = PolicyEngine::new("http://localhost:8443".into());
        let result = engine.evaluate("user-1", &["engineering".into()], "openai", "gpt-4");
        assert!(result.allowed);
        assert_eq!(result.reason, "Access granted by policy");
    }

    #[test]
    fn test_denied_wrong_role() {
        let engine = PolicyEngine::new("http://localhost:8443".into());
        let result = engine.evaluate("user-1", &["marketing".into()], "openai", "gpt-4");
        assert!(!result.allowed);
    }

    #[test]
    fn test_fail_closed_no_policies() {
        let engine = PolicyEngine::new("http://localhost:8443".into());
        let result = engine.evaluate("user-1", &["engineering".into()], "openai", "gpt-4");
        assert!(!result.allowed);
    }
}