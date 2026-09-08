package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Handler manages proxy routing and backend health for the control plane.
type Handler struct {
	logger      *zap.SugaredLogger
	db          *sql.DB
	redisClient *redis.Client
	backends    map[string]*Backend
	mu          sync.RWMutex
	httpClient  *http.Client
	stopCh      chan struct{}
	stopped     bool
}

// Backend represents an upstream proxy backend.
type Backend struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Healthy   bool      `json:"healthy"`
	Weight    int       `json:"weight"`
	PoolID    string    `json:"pool_id"`
	LastCheck time.Time `json:"last_check"`
}

// NewHandler creates a new proxy handler.
func NewHandler(logger *zap.SugaredLogger, db *sql.DB, redisClient *redis.Client) *Handler {
	h := &Handler{
		logger:      logger,
		db:          db,
		redisClient: redisClient,
		backends:    make(map[string]*Backend),
		httpClient:  &http.Client{Timeout: 5 * time.Second},
		stopCh:      make(chan struct{}),
	}
	go h.healthCheckLoop()
	return h
}

// Close stops the health check loop, preventing goroutine leaks on shutdown.
func (h *Handler) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stopped {
		h.stopped = true
		close(h.stopCh)
	}
}

// HealthHandler returns the health status of all backends.
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	backends := make([]*Backend, 0, len(h.backends))
	for _, b := range h.backends {
		backends = append(backends, b)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"backends": backends,
		"count":    len(backends),
	})
}

// ConfigReloadHandler triggers a reload of proxy configuration.
func (h *Handler) ConfigReloadHandler(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Reload backends from database
	if h.db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		rows, err := h.db.QueryContext(ctx, `SELECT name, url, pool_id, weight FROM backends WHERE enabled = true`)
		if err == nil {
			defer rows.Close()
			h.backends = make(map[string]*Backend)
			for rows.Next() {
				var b Backend
				if err := rows.Scan(&b.Name, &b.URL, &b.PoolID, &b.Weight); err != nil {
					continue
				}
				b.Healthy = true
				b.LastCheck = time.Now()
				h.backends[b.Name] = &b
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded", "count": fmt.Sprintf("%d", len(h.backends))})
}

// SelectBackend picks a healthy backend for the given path using weighted selection.
func (h *Handler) SelectBackend(path string) (*Backend, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Collect healthy backends with their weights.
	type weighted struct {
		backend *Backend
		weight  int
	}
	var candidates []weighted
	totalWeight := 0
	for _, b := range h.backends {
		if b.Healthy {
			w := b.Weight
			if w <= 0 {
				w = 1
			}
			candidates = append(candidates, weighted{backend: b, weight: w})
			totalWeight += w
		}
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no healthy backends available")
	}

	// Weighted random selection via path hash for consistent routing.
	idx := int(hashString(path)) % totalWeight
	cumulative := 0
	for _, c := range candidates {
		cumulative += c.weight
		if idx < cumulative {
			return c.backend, nil
		}
	}

	// Fallback (should not happen): return last candidate.
	return candidates[len(candidates)-1].backend, nil
}

func (h *Handler) healthCheckLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			h.logger.Info("Health check loop stopped")
			return
		case <-ticker.C:
			h.checkAllBackends()
		}
	}
}

func (h *Handler) checkAllBackends() {
	h.mu.RLock()
	backends := make([]*Backend, 0, len(h.backends))
	for _, b := range h.backends {
		backends = append(backends, b)
	}
	h.mu.RUnlock()

	for _, b := range backends {
		// Build health check URL properly - handle trailing slashes
		healthURL := strings.TrimRight(b.URL, "/") + "/health"

		// Use a request with context to ensure proper timeout handling
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			cancel()
			h.mu.Lock()
			if existing, ok := h.backends[b.Name]; ok {
				existing.Healthy = false
				existing.LastCheck = time.Now()
			}
			h.mu.Unlock()
			continue
		}

		resp, err := h.httpClient.Do(req)
		cancel()
		healthy := err == nil && resp != nil && resp.StatusCode == http.StatusOK
		if resp != nil {
			resp.Body.Close()
		}

		h.mu.Lock()
		if existing, ok := h.backends[b.Name]; ok {
			existing.Healthy = healthy
			existing.LastCheck = time.Now()
		}
		h.mu.Unlock()
	}
}

func hashString(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
