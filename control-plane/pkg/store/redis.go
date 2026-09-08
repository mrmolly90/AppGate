package store

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedis creates a Redis client with connection pooling for production throughput.
// Tuned for millions of requests: 100 pool connections, 10 min idle, keepalive.
func NewRedis(redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}

	// Production connection pool settings
	opts.PoolSize = 100                     // Max concurrent connections
	opts.MinIdleConns = 10                  // Keep warm connections ready
	opts.MaxIdleConns = 30                  // Maximum idle connections
	opts.ConnMaxLifetime = 30 * time.Minute // Rotate connections
	opts.ConnMaxIdleTime = 5 * time.Minute  // Close idle connections
	opts.PoolTimeout = 4 * time.Second      // Wait for connection from pool
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second
	opts.DialTimeout = 5 * time.Second

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return client, nil
}
