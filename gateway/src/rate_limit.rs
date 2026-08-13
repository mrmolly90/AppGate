//! Rate limiting using token bucket algorithm
//!
//! Rate limits are applied per identity. The governor crate provides
//! a GCRA-based rate limiter that is both accurate and performant.

use std::num::NonZeroU32;

use dashmap::DashMap;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::sync::Arc;

/// Rate limiter keyed by identity
pub struct RateLimiter {
    limiters: DashMap<String, Arc<DefaultDirectRateLimiter>>,
    default_quota: Quota,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            limiters: DashMap::new(),
            default_quota: Quota::per_minute(NonZeroU32::new(60).unwrap()),
        }
    }

    /// Check if a request is allowed for the given identity
    /// Returns true if the request is within rate limits
    pub fn check(&self, identity_id: &str) -> bool {
        let limiter = self
            .limiters
            .entry(identity_id.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::direct(self.default_quota)));

        limiter.check().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_accepts_first_request() {
        let limiter = RateLimiter::new();
        assert!(limiter.check("test-user"));
    }

    #[test]
    fn test_rate_limiter_tracks_different_identities() {
        let limiter = RateLimiter::new();
        assert!(limiter.check("user-a"));
        assert!(limiter.check("user-b"));
    }
}