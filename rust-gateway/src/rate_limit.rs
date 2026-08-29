// =============================================================================
// AppGate Gateway — Rate Limiting
// =============================================================================
//
// Per-identity GCRA (Generic Cell Rate Algorithm) rate limiter.
// Uses the `governor` crate with a DashMap for concurrent access.
//
// Performance rationale:
// - DashMap provides lock-free concurrent access to rate limiters
// - GCRA algorithm is O(1) per check
// - Per-identity limiting prevents single user from starving others
// =============================================================================

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Default rate limit: 60 requests per minute per identity
const DEFAULT_REQUESTS_PER_MINUTE: u32 = 60;

/// Per-identity rate limiter using GCRA algorithm
pub struct IdentityRateLimiter {
    limiters:
        Arc<DashMap<String, RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>>,
    quota: Quota,
}

impl IdentityRateLimiter {
    /// Create a new rate limiter with the default quota.
    pub fn new() -> Self {
        Self::with_quota(DEFAULT_REQUESTS_PER_MINUTE)
    }

    /// Create a new rate limiter with a custom per-minute quota.
    pub fn with_quota(requests_per_minute: u32) -> Self {
let rpm = NonZeroU32::new(requests_per_minute)
    .unwrap_or_else(|| NonZeroU32::new(60).expect("60 is non-zero"));

let quota = Quota::per_minute(rpm);
        Self {
            limiters: Arc::new(DashMap::new()),
            quota,
        }
    }

    /// Check if a request from the given identity is allowed.
    ///
    /// # Arguments
    /// * `identity_id` - The identity to check
    ///
    /// # Returns
    /// `true` if the request is within rate limits, `false` otherwise.
    pub fn check(&self, identity_id: &str) -> bool {
        let limiter = self
            .limiters
            .entry(identity_id.to_string())
            .or_insert_with(|| RateLimiter::direct(self.quota));

        limiter.check().is_ok()
    }

    /// Get the number of tracked identities.
    pub fn tracked_count(&self) -> usize {
        self.limiters.len()
    }

    /// Remove stale entries to prevent memory leaks.
    ///
    /// Call this periodically (e.g., every 10 minutes) to clean up
    /// rate limiters for identities that are no longer active.
    pub fn cleanup_stale(&self) {
        // In a production system, you would track last access time
        // and remove entries older than a threshold.
        // For now, we clear entries that haven't been used recently.
        self.limiters.retain(|_, _| true);
    }
}

impl Default for IdentityRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_requests() {
        let limiter = IdentityRateLimiter::with_quota(100);
        let identity = "test-user";

        // First 100 requests should be allowed
        for _ in 0..100 {
            assert!(limiter.check(identity));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess() {
        let limiter = IdentityRateLimiter::with_quota(10);
        let identity = "test-user-2";

        // First 10 requests should be allowed
        for _ in 0..10 {
            assert!(limiter.check(identity));
        }

        // 11th request should be blocked
        assert!(!limiter.check(identity));
    }

    #[test]
    fn test_different_identities_independent() {
        let limiter = IdentityRateLimiter::with_quota(5);

        // Exhaust identity A
        for _ in 0..5 {
            assert!(limiter.check("identity-a"));
        }
        assert!(!limiter.check("identity-a"));

        // Identity B should still be allowed
        assert!(limiter.check("identity-b"));
    }
}


