//! AppGate Gateway — Distributed & Local Rate Limiting
//!
//! Uses Redis sorted sets for sliding-window distributed rate limiting,
//! with governor as local fallback.

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

pub struct RateLimiterService {
    redis: Option<redis::aio::ConnectionManager>,
    local: Option<Arc<DefaultDirectRateLimiter>>,
}

impl RateLimiterService {
    pub async fn new(redis_url: Option<&str>) -> anyhow::Result<Self> {
        match redis_url {
            Some(url) if !url.is_empty() => {
                let client = redis::Client::open(url)?;
                let conn = client.get_connection_manager().await?;
                Ok(Self {
                    redis: Some(conn),
                    local: None,
                })
            }
            _ => {
                Ok(Self::new_local())
            }
        }
    }

    /// Create a local-only rate limiter (no Redis dependency).
    pub fn new_local() -> Self {
        let quota = Quota::per_second(NonZeroU32::new(1000).unwrap());
        let local = RateLimiter::direct(quota);
        Self {
            redis: None,
            local: Some(Arc::new(local)),
        }
    }

    pub async fn check(&self, identity: &str, limit: u64, window: u64) -> anyhow::Result<bool> {
        match &self.redis {
            Some(conn) => {
                self.check_redis(conn.clone(), identity, limit, window).await
            }
            None => self.check_local(identity, limit, window).await,
        }
    }

    async fn check_redis(
        &self,
        mut conn: redis::aio::ConnectionManager,
        identity: &str,
        limit: u64,
        window: u64,
    ) -> anyhow::Result<bool> {
        let key = format!("ratelimit:{}", identity);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let window_start = now.saturating_sub(window * 1000);

        // Use raw commands for compatibility with redis 0.27
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(&key)
            .arg(0i64)
            .arg(window_start as i64)
            .query_async(&mut conn)
            .await?;

        let count: i64 = redis::cmd("ZCARD")
            .arg(&key)
            .query_async(&mut conn)
            .await?;

        if count >= limit as i64 {
            debug!(identity = %identity, count = count, limit = limit, "Rate limit exceeded");
            return Ok(false);
        }

        let _: () = redis::cmd("ZADD")
            .arg(&key)
            .arg(now as f64)
            .arg(format!("{}:{}", now, uuid::Uuid::new_v4()))
            .query_async(&mut conn)
            .await?;

        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(window as i64)
            .query_async(&mut conn)
            .await?;

        Ok(true)
    }

    async fn check_local(
        &self,
        _identity: &str,
        _limit: u64,
        _window: u64,
    ) -> anyhow::Result<bool> {
        if let Some(limiter) = &self.local {
            match limiter.check() {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(true)
        }
    }
}