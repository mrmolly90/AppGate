use std::time::Duration;
use moka::future::Cache;
use tracing::debug;

pub struct DistributedRateLimiter {
    local_cache: Cache<String, bool>,
}

impl DistributedRateLimiter {
    pub async fn new(_redis_url: String) -> anyhow::Result<Self> {
        let cache = Cache::builder()
            .time_to_live(Duration::from_millis(100))
            .max_capacity(100_000)
            .build();
        Ok(Self { local_cache: cache })
    }
    
    pub async fn check(&self, key: &str, _policy_limits: Option<&crate::policy::RateLimits>) -> anyhow::Result<bool> {
        let cache_key = format!("rl:{}", key);
        if self.local_cache.get(&cache_key).await == Some(false) {
            return Ok(false);
        }
        self.local_cache.insert(cache_key, true).await;
        debug!("Rate limit check passed for {}", key);
        Ok(true)
    }
}