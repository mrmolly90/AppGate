//! LLM provider routing — selects the appropriate provider based on policy
//!
//! Provider endpoints must come from trusted configuration, not from user input.
//! This is critical to prevent SSRF attacks.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
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
    providers: ArcSwap<HashMap<String, Provider>>,
    control_plane_url: String,
    client: reqwest::Client,
}

impl Router {
    pub fn new(control_plane_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        let router = Self {
            providers: ArcSwap::new(Arc::new(HashMap::new())),
            control_plane_url,
            client,
        };

        // Start background provider refresh
        router.start_provider_refresh();

        router
    }

    /// Start a background task to periodically refresh providers from the control plane
    fn start_provider_refresh(&self) {
        let url = format!(
            "{}/v1/providers",
            self.control_plane_url.trim_end_matches('/')
        );
        let client = self.client.clone();
        let providers = self.providers.clone();

        tokio::spawn(async move {
            loop {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<Vec<Provider>>().await {
                            Ok(fetched) => {
                                let mut map = HashMap::new();
                                for p in fetched {
                                    map.insert(p.name.clone(), p);
                                }
                                tracing::info!(count = map.len(), "providers refreshed");
                                providers.store(Arc::new(map));
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to parse providers response");
                            }
                        }
                    }
                    Ok(resp) => {
                        tracing::warn!(status = %resp.status(), "providers fetch returned non-success");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to fetch providers from control plane");
                    }
                }
                tokio::time::sleep(Duration::from_secs(120)).await;
            }
        });
    }

    /// Get the provider URL for a given model
    /// Returns an error if no provider supports the model
    pub fn get_provider_url(&self, model: &str) -> anyhow::Result<String> {
        let providers = self.providers.load();
        for provider in providers.values() {
            if provider.models.contains(&model.to_string()) {
                return Ok(provider.base_url.clone());
            }
        }

        anyhow::bail!("no provider found for model: {}", model)
    }

    /// Get supported models for a provider
    pub fn get_provider_models(&self, provider_id: &str) -> Option<Arc<Vec<String>>> {
        let providers = self.providers.load();
        providers.get(provider_id).map(|p| Arc::new(p.models.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_rejects_unknown_model() {
        let client = reqwest::Client::new();
        let router = Router {
            providers: ArcSwap::new(Arc::new(HashMap::new())),
            control_plane_url: "http://localhost:8443".into(),
            client,
        };
        let result = router.get_provider_url("unknown-model");
        assert!(result.is_err());
    }
}