// =============================================================================
// AppGate Control Plane — Token Bucket Rate Limiter
// =============================================================================
//
// Token bucket algorithm for rate limiting API requests.
// Thread-safe with atomic operations for high concurrency.
// =============================================================================

package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket implements a token bucket rate limiter.
type TokenBucket struct {
	mu         sync.Mutex
	rate       int     // tokens per second
	burst      int     // max tokens
	tokens     float64 // current tokens
	lastRefill time.Time
}

// NewTokenBucket creates a new token bucket rate limiter.
func NewTokenBucket(rate, burst int) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed. Returns true if within rate limits.
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN checks if N tokens can be consumed. Returns true if within rate limits.
func (tb *TokenBucket) AllowN(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}
	return false
}

// refill adds tokens based on elapsed time since last refill.
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tb.lastRefill = now

	// Add tokens proportional to elapsed time
	tokensToAdd := elapsed.Seconds() * float64(tb.rate)
	tb.tokens += tokensToAdd

	// Cap at burst
	if tb.tokens > float64(tb.burst) {
		tb.tokens = float64(tb.burst)
	}
}

// Remaining returns the approximate number of tokens remaining.
func (tb *TokenBucket) Remaining() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return tb.tokens
}

// Rate returns the configured rate (tokens per second).
func (tb *TokenBucket) Rate() int {
	return tb.rate
}

// Burst returns the configured burst size.
func (tb *TokenBucket) Burst() int {
	return tb.burst
}
