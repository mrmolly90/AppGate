use reqwest::Client;
use std::time::Duration;
use tracing::info;

pub struct Router {
    client: Client,
    default_upstream: String,
    routes: Vec<Route>,
}

#[derive(Clone)]
struct Route {
    path_prefix: String,
    upstream: String,
}

impl Router {
    pub fn new(config: &crate::config::GatewayConfig) -> Self {
        let connect_timeout = Duration::from_millis(
            config.upstream.connect_timeout_ms.unwrap_or(5000)
        );
        let read_timeout = Duration::from_millis(
            config.upstream.read_timeout_ms.unwrap_or(30000)
        );
        let keepalive = Duration::from_secs(
            config.upstream.keepalive_duration_secs.unwrap_or(30)
        );
        let max_idle = config.upstream.max_connections.unwrap_or(100);

        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(read_timeout)
            .pool_max_idle_per_host(max_idle)
            .pool_idle_timeout(keepalive)
            .http2_adaptive_window(true)
            .build()
            .expect("failed to build HTTP client");

        let mut routes = vec![];
        if let Ok(route_env) = std::env::var("APPGATE_ROUTES") {
            for pair in route_env.split(',') {
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() == 2 {
                    routes.push(Route {
                        path_prefix: parts[0].to_string(),
                        upstream: parts[1].to_string(),
                    });
                }
            }
        }

        info!("router initialized with {} routes", routes.len());
        Self {
            client,
            default_upstream: config.upstream.default_url.clone(),
            routes,
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn select(&self, path: &str) -> Option<String> {
        for route in &self.routes {
            if path.starts_with(&route.path_prefix) {
                return Some(route.upstream.clone());
            }
        }
        if !self.default_upstream.is_empty() {
            Some(self.default_upstream.clone())
        } else {
            None
        }
    }
}