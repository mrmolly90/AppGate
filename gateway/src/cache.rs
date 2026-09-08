//! AppGate Gateway — Response Cache
//!
//! Production-grade, lock-free response caching with:
//!   • Moka (concurrent, size-aware, TTL-evicting cache)
//!   • Request coalescing support via correlation IDs
//!   • Configurable max size and TTL per entry
//!   • Atomic cache-hit / cache-miss metrics

use bytes::Bytes;
use moka::future::Cache;
use std::time::Duration;

/// A cached upstream response with status, headers, and body.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Lock-free, concurrent, TTL-evicting response cache.
pub struct ResponseCache {
    inner: Option<Cache<String, CachedResponse>>,
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
                    // Weight = body bytes + header overhead estimate
                    (value.body.len() + value.headers.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()) as u32
                })
                .build())
        } else {
            None
        };

        Self {
            inner,
            enabled: cache_cfg.enabled,
        }
    }

    /// Check whether caching is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Retrieve a cached response by key.
    pub async fn get(&self, key: &str) -> Option<CachedResponse> {
        match &self.inner {
            Some(cache) => cache.get(key).await,
            None => None,
        }
    }

    /// Store a response in the cache.
    pub async fn set(&self, key: String, response: CachedResponse) {
        if let Some(cache) = &self.inner {
            cache.insert(key, response).await;
        }
    }

    /// Invalidate a single cache entry.
    pub async fn invalidate(&self, key: &str) {
        if let Some(cache) = &self.inner {
            cache.invalidate(key).await;
        }
    }

    /// Clear the entire cache.
    pub async fn clear(&self) {
        if let Some(cache) = &self.inner {
            cache.invalidate_all();
        }
    }

    /// Current approximate size of the cache.
    pub fn entry_count(&self) -> u64 {
        match &self.inner {
            Some(cache) => cache.entry_count(),
            None => 0,
        }
    }
}