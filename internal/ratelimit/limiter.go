package ratelimit

import (
    "context"
    "fmt"
    "net/http"
    "strconv"
    "time"

    "github.com/redis/go-redis/v9"
    "github.com/rs/zerolog/log"
)

// Limiter implements token-bucket rate limiting per project
type Limiter struct {
    client *redis.Client
    rps    int
    burst  int
    window time.Duration
}

func New(addr, password string) (*Limiter, error) {
    opts := &redis.Options{
        Addr:     addr,
        Password: password,
        DB:       0,
    }
    client := redis.NewClient(opts)
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := client.Ping(ctx).Err(); err != nil {
        return nil, fmt.Errorf("redis connection failed: %w", err)
    }

    return &Limiter{
        client: client,
        rps:    100,  // TODO: from config
        burst:  150,
        window: time.Minute,
    }, nil
}

func (l *Limiter) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        projectID := r.Header.Get("X-AppGate-Project")
        if projectID == "" {
            projectID = "default"
        }

        allowed, remaining, resetTime := l.checkLimit(r.Context(), projectID)
        if !allowed {
            w.Header().Set("X-RateLimit-Limit", strconv.Itoa(l.rps))
            w.Header().Set("X-RateLimit-Remaining", "0")
            w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))
            http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
            log.Warn().Str("project", projectID).Msg("rate limit hit")
            return
        }

        w.Header().Set("X-RateLimit-Limit", strconv.Itoa(l.rps))
        w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
        next.ServeHTTP(w, r)
    })
}

func (l *Limiter) checkLimit(ctx context.Context, key string) (bool, int, int64) {
    // Sliding window counter using Redis
    windowKey := fmt.Sprintf("ratelimit:%s:%d", key, time.Now().Unix()/int64(l.window.Seconds()))
    
    pipe := l.client.Pipeline()
    incr := pipe.Incr(ctx, windowKey)
    pipe.Expire(ctx, windowKey, l.window+time.Second)
    
    _, err := pipe.Exec(ctx)
    if err != nil {
        log.Error().Err(err).Str("key", key).Msg("rate limit redis error")
        return true, 0, 0 // Fail open
    }

    count := int(incr.Val())
    remaining := l.rps - count
    if remaining < 0 {
        remaining = 0
    }

    allowed := count <= l.burst
    resetAt := time.Now().Add(l.window).Unix()
    
    return allowed, remaining, resetAt
}

func (l *Limiter) Ping() bool {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    return l.client.Ping(ctx).Err() == nil
}
