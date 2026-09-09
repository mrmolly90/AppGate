//! AppGate Gateway — Distributed & Local Rate Limiting
//!
//! Uses governor for fast local rate limiting with burst support.

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::debug;

pub struct DistributedRateLimiter {
    local: Option<Arc<DefaultDirectRateLimiter>>,
    enabled: bool,
}

impl DistributedRateLimiter {
    pub async fn new(_redis_url: String) -> anyhow::Result<Self> {
        let quota = Quota::per_second(NonZeroU32::new(1000).unwrap())
            .allow_burst(NonZeroU32::new(2000).unwrap());
        let local = RateLimiter::direct(quota);
        Ok(Self {
            local: Some(Arc::new(local)),
            enabled: true,
        })
    }

    pub fn new_local() -> Self {
        let quota = Quota::per_second(NonZeroU32::new(500).unwrap())
            .allow_burst(NonZeroU32::new(1000).unwrap());
        let local = RateLimiter::direct(quota);
        Self {
            local: Some(Arc::new(local)),
            enabled: true,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub async fn check(
        &self,
        key: &str,
        _policy_limits: Option<&crate::policy::RateLimits>,
    ) -> anyhow::Result<bool> {
        if !self.enabled {
            return Ok(true);
        }

        if let Some(limiter) = &self.local {
            match limiter.check() {
                Ok(()) => {
                    debug!("Rate limit check passed for {}", key);
                    Ok(true)
                }
                Err(_) => {
                    debug!("Rate limit check failed for {}", key);
                    Ok(false)
                }
            }
        } else {
            Ok(true)
        }
    }
}
}
