use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    config: crate::config::RateLimitConfig,
    redis: Option<redis::aio::ConnectionManager>,
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    capacity: f64,
    rate_per_sec: f64,
}

impl TokenBucket {
    fn new(capacity: f64, rate_per_sec: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            capacity,
            rate_per_sec,
        }
    }

    fn consume(&mut self, amount: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
        self.last_update = now;

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

impl RateLimiter {
    pub async fn new(config: &crate::config::RateLimitConfig) -> Self {
        let redis = if let Ok(url) = std::env::var("APPGATE_REDIS_URL") {
            match redis::Client::open(url.clone()) {
                Ok(client) => match client.get_connection_manager().await {
                    Ok(conn) => Some(conn),
                    Err(e) => {
                        tracing::warn!("Redis connection failed: {}", e);
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("Redis client creation failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
            redis,
        }
    }

    pub async fn check(&self, key: &str, provider: &str, model: &str) -> bool {
        if !self.config.enabled {
            return true;
        }

        // Distributed check via Redis if available
        if let Some(ref redis_conn) = self.redis {
            let composite_key = format!("ratelimit:{}:{}:{}", key, provider, model);
            return self.check_redis(redis_conn, &composite_key).await;
        }

        // Local fallback
        let mut buckets = self.buckets.write().await;
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(
                self.config.burst_size as f64,
                self.config.requests_per_second as f64,
            )
        });
        bucket.consume(1.0)
    }

    async fn check_redis(&self, redis: &redis::aio::ConnectionManager, key: &str) -> bool {
        let mut conn = redis.clone();
        let script = redis::Script::new(r#"
            local current = redis.call('GET', KEYS[1])
            if current == false then
                redis.call('SET', KEYS[1], 1, 'EX', ARGV[1])
                return 1
            end
            local val = tonumber(current)
            if val >= tonumber(ARGV[2]) then
                return 0
            end
            redis.call('INCR', KEYS[1])
            return 1
        "#);
        let result: Result<i64, redis::RedisError> = script
            .key(key)
            .arg(self.config.window_secs)
            .arg(self.config.requests_per_second)
            .invoke_async(&mut conn)
            .await;
        match result {
            Ok(1) => true,
            Ok(0) => false,
            Ok(_) => true,
            Err(e) => {
                tracing::warn!("Redis rate limit script failed: {}", e);
                true // Fail open
            }
        }
    }

    pub async fn cleanup_old_buckets(&self) {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_update) < Duration::from_secs(self.config.window_secs * 2)
        });
    }
}