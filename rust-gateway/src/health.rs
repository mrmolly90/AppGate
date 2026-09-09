use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct HealthStatus {
    pub healthy: bool,
    pub last_check: Instant,
    pub latency_ms: u64,
    pub consecutive_failures: u32,
}

pub struct HealthChecker {
    pub upstreams: Arc<RwLock<HashMap<String, HealthStatus>>>,
    client: reqwest::Client,
}

impl HealthChecker {
    pub fn new(config: &crate::config::GatewayConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        
        let upstreams = Arc::new(RwLock::new(HashMap::new()));
        
        // Register default upstream
        if !config.upstream.default_url.is_empty() {
            let url = config.upstream.default_url.clone();
            let map = upstreams.clone();
            tokio::spawn(async move {
                let mut map = map.write().await;
                map.insert(url.clone(), HealthStatus {
                    healthy: true,
                    last_check: Instant::now(),
                    latency_ms: 0,
                    consecutive_failures: 0,
                });
            });
        }

        Self { upstreams, client }
    }

    pub async fn register(&self, name: &str) {
        let mut map = self.upstreams.write().await;
        map.insert(name.to_string(), HealthStatus {
            healthy: true,
            last_check: Instant::now(),
            latency_ms: 0,
            consecutive_failures: 0,
        });
    }

    pub async fn is_healthy(&self, name: &str) -> bool {
        let map = self.upstreams.read().await;
        map.get(name).map(|s| s.healthy).unwrap_or(true)
    }

    pub async fn all_healthy(&self) -> Vec<String> {
        let map = self.upstreams.read().await;
        map.iter()
            .filter(|(_, v)| v.healthy)
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub async fn start_background_checks(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(10));
            loop {
                ticker.tick().await;
                let names: Vec<String> = {
                    let map = self.upstreams.read().await;
                    map.keys().cloned().collect()
                };
                for name in names {
                    let url = format!("{}/healthz", name.trim_end_matches('/'));
                    let start = Instant::now();
                    match self.client.get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let mut map = self.upstreams.write().await;
                            if let Some(status) = map.get_mut(&name) {
                                status.healthy = true;
                                status.latency_ms = start.elapsed().as_millis() as u64;
                                status.consecutive_failures = 0;
                            }
                        }
                        _ => {
                            let mut map = self.upstreams.write().await;
                            if let Some(status) = map.get_mut(&name) {
                                status.consecutive_failures += 1;
                                if status.consecutive_failures >= 3 {
                                    if status.healthy {
                                        warn!("upstream {} marked unhealthy", name);
                                    }
                                    status.healthy = false;
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}