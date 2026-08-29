// =============================================================================
// AppGate Control Plane — Distributed Rate Limiter (Production)
// =============================================================================

package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RedisRateLimiter implements distributed sliding window rate limiting
type RedisRateLimiter struct {
	client *redis.Client
	logger *zap.Logger
}

// NewRedisRateLimiter creates a new Redis-backed rate limiter
func NewRedisRateLimiter(ctx context.Context, redisURL string) (*RedisRateLimiter, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}

	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return &RedisRateLimiter{
		client: client,
		logger: zap.NewNop(),
	}, nil
}

// Middleware returns HTTP middleware that enforces rate limits
func (r *RedisRateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			apiKey := req.Header.Get("X-API-Key")
			if apiKey == "" {
				http.Error(w, `{"error":"missing_api_key"}`, http.StatusUnauthorized)
				return
			}

			allowed, remaining, reset, err := r.check(req.Context(), apiKey)
			if err != nil {
				r.logger.Error("Rate limit check failed", zap.Error(err))
				// Fail open: allow request on Redis error
				next.ServeHTTP(w, req)
				return
			}

			w.Header().Set("RateLimit-Limit", "100")
			w.Header().Set("RateLimit-Remaining", strconv.Itoa(int(remaining)))
			w.Header().Set("RateLimit-Reset", strconv.FormatInt(reset, 10))

			if !allowed {
				http.Error(w, `{"error":"rate_limit_exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, req)
		})
	}
}

func (r *RedisRateLimiter) check(ctx context.Context, key string) (bool, int64, int64, error) {
	now := time.Now().Unix()
	window := int64(60) // 1 minute window

	// Sliding window using sorted set
	pipe := r.client.Pipeline()
	countCmd := pipe.ZCard(ctx, "ratelimit:"+key)
	pipe.ZRemRangeByScore(ctx, "ratelimit:"+key, "0", strconv.FormatInt(now-window, 10))
	pipe.ZAdd(ctx, "ratelimit:"+key, redis.Z{Score: float64(now), Member: now})
	pipe.Expire(ctx, "ratelimit:"+key, time.Duration(window)*time.Second)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, 0, err
	}

	count := countCmd.Val()
	limit := int64(100) // 100 req/min

	allowed := count < limit
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	reset := now + window

	return allowed, remaining, reset, nil
}

// TokenBucket remains for local fallback
type TokenBucket struct {
	// ... existing implementation unchanged
}
