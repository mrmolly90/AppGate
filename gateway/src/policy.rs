//! Policy evaluation engine
//!
//! Evaluates whether a request is allowed based on the configured policies.
//! Policies are fetched from the control plane and cached locally.

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub spec: PolicySpec,
}

/// Policy specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySpec {
    pub subjects: SubjectSelector,
    pub providers: Vec<String>,
    pub models: Vec<String>,
    pub limits: RateLimits,
    pub logging: LoggingConfig,
}

/// Subject selector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectSelector {
    pub roles: Option<Vec<String>>,
    pub users: Option<Vec<String>>,
}

/// Rate limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimits {
    pub requests_per_minute: u32,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub metadata_only: bool,
}

/// Policy evaluation result
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub allowed: bool,
    pub policy_id: Option<String>,
    pub reason: String,
}

/// Policy engine that evaluates requests against policies
pub struct Engine {
    policies: ArcSwap<Vec<Policy>>,
    control_plane_url: String,
}

impl Engine {
    pub fn new(control_plane_url: String) -> Self {
        Self {
            policies: ArcSwap::new(Arc::new(Vec::new())),
            control_plane_url,
        }
    }

    /// Evaluate a request against all policies
    pub fn evaluate(
        &self,
        identity_id: &str,
        roles: &[String],
        provider: &str,
        model: &str,
    ) -> EvaluationResult {
        let policies = self.policies.load();

        // Fail closed: if no policies, deny
        if policies.is_empty() {
            return EvaluationResult {
                allowed: false,
                policy_id: None,
                reason: "no policies configured".into(),
            };
        }

        for policy in policies.iter() {
            // Check subject match
            let subject_match = Self::matches_subject(policy, identity_id, roles);

            if !subject_match {
                continue;
            }

            // Check provider
            if !policy.spec.providers.contains(&provider.to_string()) {
                continue;
            }

            // Check model
            if !policy.spec.models.contains(&model.to_string()) {
                continue;
            }

            // All checks passed
            return EvaluationResult {
                allowed: true,
                policy_id: Some(policy.id.clone()),
                reason: "allowed by policy".into(),
            };
        }

        EvaluationResult {
            allowed: false,
            policy_id: None,
            reason: "no matching policy".into(),
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
        let engine = Engine::new("http://localhost:8443".into());
        engine.policies.store(Arc::new(vec![create_test_policy()]));

        let result = engine.evaluate(
            "user-1",
            &["engineering".into()],
            "openai",
            "gpt-4",
        );

        assert!(result.allowed);
        assert_eq!(result.reason, "allowed by policy");
    }

    #[test]
    fn test_denied_wrong_role() {
        let engine = Engine::new("http://localhost:8443".into());
        engine.policies.store(Arc::new(vec![create_test_policy()]));

        let result = engine.evaluate(
            "user-1",
            &["marketing".into()],
            "openai",
            "gpt-4",
        );

        assert!(!result.allowed);
    }

    #[test]
    fn test_denied_wrong_model() {
        let engine = Engine::new("http://localhost:8443".into());
        engine.policies.store(Arc::new(vec![create_test_policy()]));

        let result = engine.evaluate(
            "user-1",
            &["engineering".into()],
            "openai",
            "gpt-3.5-turbo",
        );

        assert!(!result.allowed);
    }

    #[test]
    fn test_fail_closed_no_policies() {
        let engine = Engine::new("http://localhost:8443".into());

        let result = engine.evaluate(
            "user-1",
            &["engineering".into()],
            "openai",
            "gpt-4",
        );

        assert!(!result.allowed);
        assert_eq!(result.reason, "no policies configured");
    }
}