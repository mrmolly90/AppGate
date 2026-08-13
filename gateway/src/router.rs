//! LLM provider routing — selects the appropriate provider based on policy
//!
//! Provider endpoints must come from trusted configuration, not from user input.
//! This is critical to prevent SSRF attacks.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// LLM provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub models: Vec<String>,
    pub health_check_path: Option<String>,
}

/// Router selects the appropriate provider for a given model
pub struct Router {
    providers: HashMap<String, Provider>,
    control_plane_url: String,
}

impl Router {
    pub fn new(control_plane_url: String) -> Self {
        Self {
            providers: HashMap::new(),
            control_plane_url,
        }
    }

    /// Get the provider URL for a given model
    /// Returns an error if no provider supports the model
    pub fn get_provider_url(&self, model: &str) -> anyhow::Result<&str> {
        for provider in self.providers.values() {
            if provider.models.contains(&model.to_string()) {
                return Ok(&provider.base_url);
            }
        }

        anyhow::bail!("no provider found for model: {}", model)
    }

    /// Get supported models for a provider
    pub fn get_provider_models(&self, provider_id: &str) -> Option<&Vec<String>> {
        self.providers.get(provider_id).map(|p| &p.models)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_rejects_unknown_model() {
        let router = Router::new("http://localhost:8443".into());
        let result = router.get_provider_url("unknown-model");
        assert!(result.is_err());
    }
}