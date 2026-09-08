use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub struct Router {
    client: Arc<Client>,
    default_upstream: String,
    routes: Vec<Route>,
}

#[derive(Clone)]
struct Route {
    path_prefix: String,
    upstream: String,
    provider: String,
}

impl Router {
    pub fn new(config: &crate::config::GatewayConfig) -> Self {
        let connect_timeout = Duration::from_millis(
            config.upstream.connect_timeout_ms.unwrap_or(5000)
        );
        let read_timeout = Duration::from_millis(
            config.upstream.read_timeout_ms.unwrap_or(60000)
        );
        let keepalive = Duration::from_secs(
            config.upstream.keepalive_duration_secs.unwrap_or(30)
        );
        let max_conns = config.upstream.max_connections.unwrap_or(1000);

        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(read_timeout)
            .pool_max_idle_per_host(max_conns)
            .pool_idle_timeout(keepalive)
            .http2_prior_knowledge()
            .build()
            .expect("failed to build HTTP client");

        let mut routes = vec![];
        if let Ok(route_env) = std::env::var("APPGATE_ROUTES") {
            for pair in route_env.split(',') {
                let parts: Vec<&str> = pair.splitn(3, '=').collect();
                if parts.len() == 3 {
                    routes.push(Route {
                        path_prefix: parts[0].to_string(),
                        provider: parts[1].to_string(),
                        upstream: parts[2].to_string(),
                    });
                }
            }
        }

        // Default production routes for LLM providers
        if routes.is_empty() {
            routes.push(Route {
                path_prefix: "/v1/chat/completions".into(),
                provider: "openai".into(),
                upstream: config.upstream.default_url.clone(),
            });
        }

        info!("router initialized with {} routes", routes.len());
        Self {
            client: Arc::new(client),
            default_upstream: config.upstream.default_url.clone(),
            routes,
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn get_client(&self) -> Arc<Client> {
        self.client.clone()
    }

    pub async fn select(&self, path: &str) -> Option<String> {
        for route in &self.routes {
            if path.starts_with(&route.path_prefix) {
                return Some(route.upstream.clone());
            }
        }
        Some(self.default_upstream.clone())
    }

    pub fn get_provider_url(&self, model: &str) -> Result<String, String> {
        // Map models to providers
        let provider = match model {
            m if m.starts_with("gpt-") => "openai",
            m if m.starts_with("claude-") => "anthropic",
            m if m.starts_with("llama-") => "meta",
            _ => "default",
        };
        
        for route in &self.routes {
            if route.provider == provider {
                return Ok(route.upstream.clone());
            }
        }
        
        if !self.default_upstream.is_empty() {
            Ok(self.default_upstream.clone())
        } else {
            Err(format!("no upstream configured for model: {}", model))
        }
    }
}