package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// tokenBucket is a simple in-memory token bucket rate limiter.
type tokenBucket struct {
	capacity float64
	tokens   float64
	refill   float64 // tokens per second
	last     time.Time
}

func newTokenBucket(capacity float64, refillPerSec float64) *tokenBucket {
	return &tokenBucket{
		capacity: capacity,
		tokens:   capacity,
		refill:   refillPerSec,
		last:     time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(b.capacity, b.tokens+elapsed*b.refill)
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ipRateLimiter tracks per-IP token buckets.
type ipRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	capacity float64
	refill   float64
	// cleanup
	lastCleanup time.Time
}

// NewIPRateLimiter creates a new per-IP rate limiter.
func NewIPRateLimiter(capacity, refillPerSec float64) *ipRateLimiter {
	return newIPRateLimiter(capacity, refillPerSec)
}

// RateLimitMiddleware wraps a handler with per-IP rate limiting.
func RateLimitMiddleware(limiter *ipRateLimiter, next http.HandlerFunc) http.Handler {
	return rateLimitMiddleware(limiter)(next)
}

func newIPRateLimiter(capacity, refillPerSec float64) *ipRateLimiter {
	return &ipRateLimiter{
		buckets:     make(map[string]*tokenBucket),
		capacity:    capacity,
		refill:      refillPerSec,
		lastCleanup: time.Now(),
	}
}

// rateLimitMiddleware returns a middleware that limits requests per IP.
func rateLimitMiddleware(limiter *ipRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)

			limiter.mu.Lock()
			// Opportunistic cleanup of idle buckets (every 10 minutes)
			if time.Since(limiter.lastCleanup) > 10*time.Minute {
				for k, b := range limiter.buckets {
					if time.Since(b.last) > 10*time.Minute {
						delete(limiter.buckets, k)
					}
				}
				limiter.lastCleanup = time.Now()
			}

			bucket, ok := limiter.buckets[ip]
			if !ok {
				bucket = newTokenBucket(limiter.capacity, limiter.refill)
				limiter.buckets[ip] = bucket
			}
			allowed := bucket.allow()
			limiter.mu.Unlock()

			if !allowed {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	// Prefer X-Forwarded-For first entry (set by trusted proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := indexByte(xff, ','); idx != -1 {
			return trimSpace(xff[:idx])
		}
		return trimSpace(xff)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
