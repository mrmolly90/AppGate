// =============================================================================
// AppGate Gateway — Distributed Rate Limiter (Production)
// =============================================================================

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

pub struct DistributedRateLimiter {
    redis: Option<redis::aio::ConnectionManager>,
    local_fallback: moka::future::Cache<String, u32>,
}

impl DistributedRateLimiter {
    pub async fn new(redis_url: Option<String>) -> anyhow::Result<Self> {
        let redis = match redis_url {
            Some(url) => match redis::Client::open(url) {
                Ok(client) => match redis::aio::ConnectionManager::new(client).await {
                    Ok(conn) => {
                        debug!("Connected to Redis for distributed rate limiting");
                        Some(conn)
                    }
                    Err(e) => {
                        warn!("Redis ConnectionManager failed: {}. Using local fallback.", e);
                        None
                    }
                },
                Err(e) => {
                    warn!("Invalid Redis URL: {}. Using local fallback.", e);
                    None
                }
            },
            None => {
                warn!("No Redis URL configured. Using local fallback rate limiting.");
                None
            }
        };

        let local_fallback = moka::future::Cache::builder()
            .time_to_live(Duration::from_secs(60))
            .max_capacity(100_000)
            .build();

        Ok(Self { redis, local_fallback })
    }

    pub async fn check(
        &self,
        identity: &str,
        policy_limits: Option<&crate::policy::RateLimits>,
    ) -> anyhow::Result<(bool, u64, u64)> {
        let limit = policy_limits.map(|p| p.requests_per_minute).unwrap_or(100) as u64;
        let window = 60u64;

        match &self.redis {
            Some(conn) => self.check_redis(conn, identity, limit, window).await,
            None => self.check_local(identity, limit, window).await,
        }
    }

    async fn check_redis(
        &self,
        conn: &redis::aio::ConnectionManager,
        identity: &str,
        limit: u64,
        window: u64,
    ) -> anyhow::Result<(bool, u64, u64)> {
        let key = format!("ratelimit:{}", identity);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("ZREMRANGEBYSCORE").arg(&key).arg(0i64).arg((now - window) as i64)
            .cmd("ZCARD").arg(&key)
            .cmd("ZADD").arg(&key).arg(now as f64).arg(now as i64)
            .cmd("EXPIRE").arg(&key).arg(window as i64);

        let mut conn_clone = conn.clone();
        let results: Vec<redis::Value> = pipe.query_async(&mut conn_clone).await?;

        let count = match &results.get(1) {
            Some(redis::Value::Int(c)) => *c as u64,
            _ => 0,
        };

        let allowed = count < limit;
        let remaining = if allowed { limit - count } else { 0 };
        let reset = now + window;

        debug!(
            target: "appgate::ratelimit",
            identity = %identity,
            count = %count,
            limit = %limit,
            allowed = %allowed,
            "Rate limit check"
        );

        Ok((allowed, remaining, reset))
    }

    async fn check_local(
        &self,
        identity: &str,
        limit: u64,
        _window: u64,
    ) -> anyhow::Result<(bool, u64, u64)> {
        let key = format!("{}:{}", identity, Self::current_minute());
        let count = self.local_fallback.get(&key).await.unwrap_or(0);

        let allowed = (count as u64) < limit;
        let remaining = if allowed { limit - count as u64 } else { 0 };
        let reset = Self::next_minute();

        if allowed {
            self.local_fallback.insert(key, count + 1).await;
        }

        Ok((allowed, remaining, reset))
    }

    fn current_minute() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 60
    }

    fn next_minute() -> u64 {
        (Self::current_minute() + 1) * 60
    }
}