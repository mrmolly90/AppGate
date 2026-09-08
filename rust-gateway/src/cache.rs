//! AppGate Gateway — Response Cache
//!
//! Production-grade, lock-free response caching with Moka.

use bytes::Bytes;
use moka::future::Cache;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

pub struct ResponseCache {
    inner: Option<Cache<String, CachedResponse>>,
    ttl: Duration,
    max_size: u64,
    enabled: bool,
}

impl ResponseCache {
    pub fn new(config: &crate::config::GatewayConfig) -> Self {
        let cache_cfg = &config.cache;
        let ttl = Duration::from_secs(cache_cfg.ttl_secs.unwrap_or(60));
        let max_size = cache_cfg.max_size.unwrap_or(10_000);

        let inner = if cache_cfg.enabled {
            Some(Cache::builder()
                .time_to_live(ttl)
                .max_capacity(max_size)
                .weigher(|_key, value: &CachedResponse| {
                    (value.body.len() + value.headers.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()) as u32
                })
                .build())
        } else {
            None
        };

        Self {
            inner,
            ttl,
            max_size,
            enabled: cache_cfg.enabled,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn get(&self, key: &str) -> Option<CachedResponse> {
        match &self.inner {
            Some(cache) => cache.get(key).await,
            None => None,
        }
    }

    pub async fn set(&self, key: String, response: CachedResponse) {
        if let Some(cache) = &self.inner {
            cache.insert(key, response).await;
        }
    }

    pub async fn invalidate(&self, key: &str) {
        if let Some(cache) = &self.inner {
            cache.invalidate(key).await;
        }
    }

    pub async fn clear(&self) {
        if let Some(cache) = &self.inner {
            cache.invalidate_all();
        }
    }

    pub fn entry_count(&self) -> u64 {
        match &self.inner {
            Some(cache) => cache.entry_count(),
            None => 0,
        }
    }
}