use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct PolicyEngine {
    policies: Arc<RwLock<Vec<Policy>>>,
    compiled: Arc<RwLock<HashMap<String, Regex>>>,
}

#[derive(Clone, Debug)]
struct Policy {
    name: String,
    action: PolicyAction,
    condition: PolicyCondition,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum PolicyAction {
    Allow,
    Deny,
    RateLimit(u32),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum PolicyCondition {
    PathMatches(String),
    MethodIs(String),
    HeaderContains(String, String),
    BodyContains(String),
    ContentTypeIs(String),
    MaxBodySize(usize),
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub allowed: bool,
    pub reason: String,
}

impl PolicyEngine {
    pub async fn new(_config: &crate::config::GatewayConfig) -> Self {
        let mut policies = vec![];
        policies.push(Policy {
            name: "block-private-ips".into(),
            action: PolicyAction::Deny,
            condition: PolicyCondition::PathMatches(r"(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)".into()),
        });
        policies.push(Policy {
            name: "max-body-size".into(),
            action: PolicyAction::Deny,
            condition: PolicyCondition::MaxBodySize(10 * 1024 * 1024),
        });
        policies.push(Policy {
            name: "block-sensitive-files".into(),
            action: PolicyAction::Deny,
            condition: PolicyCondition::PathMatches(r"\.(env|git|ssh|aws|docker)".into()),
        });

        let mut compiled = HashMap::new();
        for policy in &policies {
            if let PolicyCondition::PathMatches(ref pat) = policy.condition {
                if let Ok(re) = Regex::new(pat) {
                    compiled.insert(policy.name.clone(), re);
                }
            }
        }

        Self {
            policies: Arc::new(RwLock::new(policies)),
            compiled: Arc::new(RwLock::new(compiled)),
        }
    }

    pub async fn evaluate_request(
        &self,
        identity_id: &str,
        roles: &[String],
        provider: &str,
        model: &str,
    ) -> PolicyResult {
        // In production: query control plane for active policies per identity
        // For now, enforce basic provider/model validation
        if provider.is_empty() || model.is_empty() {
            return PolicyResult {
                allowed: false,
                reason: "provider and model are required".into(),
            };
        }

        // Identity-based checks
        if identity_id.is_empty() || identity_id == "anonymous" {
            // Anonymous users are denied by default unless explicitly allowed
            let policies = self.policies.read().await;
            for policy in policies.iter() {
                if let PolicyCondition::PathMatches(ref _pattern) = &policy.condition {
                    let path = format!("/{}/{}", provider, model);
                    let compiled = self.compiled.read().await;
                    if let Some(re) = compiled.get(&policy.name) {
                        if re.is_match(&path) {
                            match policy.action {
                                PolicyAction::Allow => {
                                    tracing::debug!(policy = %policy.name, identity = %identity_id, "allow policy matched for anonymous");
                                    return PolicyResult {
                                        allowed: true,
                                        reason: format!("allowed by policy '{}'", policy.name),
                                    };
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            return PolicyResult {
                allowed: false,
                reason: "anonymous identity denied by default".into(),
            };
        }

        // Role-based checks
        if !roles.is_empty() {
            let has_admin = roles.iter().any(|r| r == "admin" || r == "administrator");
            if has_admin {
                tracing::debug!(identity = %identity_id, "admin role bypasses policy restrictions");
                return PolicyResult {
                    allowed: true,
                    reason: "admin bypass".into(),
                };
            }
        }

        // Check policy conditions against this request
        let policies = self.policies.read().await;
        for policy in policies.iter() {
            match &policy.condition {
                PolicyCondition::PathMatches(ref _pattern) => {
                    let path = format!("/{}/{}", provider, model);
                    let compiled = self.compiled.read().await;
                    if let Some(re) = compiled.get(&policy.name) {
                        if re.is_match(&path) {
                            match policy.action {
                                PolicyAction::Deny => {
                                    return PolicyResult {
                                        allowed: false,
                                        reason: format!("blocked by policy '{}'", policy.name),
                                    };
                                }
                                PolicyAction::RateLimit(rps) => {
                                    tracing::debug!(policy = %policy.name, rps = %rps, "rate limit policy matched");
                                }
                                PolicyAction::Allow => {
                                    tracing::debug!(policy = %policy.name, "allow policy matched");
                                }
                            }
                        }
                    }
                }
                PolicyCondition::MaxBodySize(_max) => {
                    tracing::debug!(policy = %policy.name, max_bytes = %_max, "max body size policy active");
                    // TODO: Enforce max body size by checking Content-Length header
                    // in the middleware layer. This stub always denies until the
                    // body size can be verified at the request level.
                    return PolicyResult {
                        allowed: false,
                        reason: format!("request exceeds max body size of {} bytes", _max),
                    };
                }
                _ => {
                    tracing::debug!(policy = %policy.name, "policy condition not evaluated in hot path");
                }
            }
        }

        PolicyResult {
            allowed: true,
            reason: "allowed".into(),
        }
    }
}