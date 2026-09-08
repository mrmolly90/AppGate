package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Engine evaluates access policies for the control plane.
type Engine struct {
	logger *zap.SugaredLogger
	db     *sql.DB
	mu     sync.RWMutex
	cache  map[string]cachedPolicy
	// maxCacheSize bounds the cache to prevent unbounded memory growth
	// under high traffic with many unique identity/action/resource combos.
	maxCacheSize int
	stopCh       chan struct{}
	done         chan struct{}
}

type cachedPolicy struct {
	Policy    Policy
	ExpiresAt time.Time
}

// Policy represents an access control policy.
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Condition   string `json:"condition"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}

// EvaluationResult contains the result of a policy evaluation.
type EvaluationResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Policy  string `json:"policy,omitempty"`
}

// NewEngine creates a new policy engine.
func NewEngine(logger *zap.SugaredLogger, db *sql.DB) *Engine {
	e := &Engine{
		logger:       logger,
		db:           db,
		cache:        make(map[string]cachedPolicy),
		maxCacheSize: 100000, // ~100k entries; prevents unbounded growth
		stopCh:       make(chan struct{}),
		done:         make(chan struct{}),
	}
	go e.periodicRefresh()
	return e
}

// Close stops the periodic refresh goroutine, preventing goroutine leaks on shutdown.
func (e *Engine) Close() {
	close(e.stopCh)
	<-e.done
}

// Evaluate checks whether an identity is allowed to perform an action on a resource.
func (e *Engine) Evaluate(identity, action, resource string) EvaluationResult {
	// Build a cache key from identity + action + resource to prevent
	// cross-request cache poisoning (e.g., identity A's allow for resource X
	// being returned for identity A's request to resource Y).
	cacheKey := fmt.Sprintf("%s:%s:%s", identity, action, resource)

	// Check cache first
	e.mu.RLock()
	if cached, ok := e.cache[cacheKey]; ok && time.Now().Before(cached.ExpiresAt) {
		e.mu.RUnlock()
		if cached.Policy.Action == "allow" {
			return EvaluationResult{Allowed: true, Reason: "cached allow", Policy: cached.Policy.Name}
		}
		return EvaluationResult{Allowed: false, Reason: "cached deny", Policy: cached.Policy.Name}
	}
	e.mu.RUnlock()

	// Query database for matching policies
	if e.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		rows, err := e.db.QueryContext(ctx,
			`SELECT id, name, description, action, condition, priority, enabled 
			 FROM policies WHERE enabled = true ORDER BY priority DESC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var p Policy
				if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Action, &p.Condition, &p.Priority, &p.Enabled); err != nil {
					continue
				}
				// Simple condition matching - extend for production
				if matchesCondition(p.Condition, identity, action, resource) {
					e.mu.Lock()
					e.cache[cacheKey] = cachedPolicy{Policy: p, ExpiresAt: time.Now().Add(30 * time.Second)}
					e.trimCacheLocked()
					e.mu.Unlock()
					if p.Action == "allow" {
						return EvaluationResult{Allowed: true, Reason: "policy matched", Policy: p.Name}
					}
					return EvaluationResult{Allowed: false, Reason: fmt.Sprintf("denied by policy: %s", p.Name), Policy: p.Name}
				}
			}
		}
	}

	// Default: deny if no policies match (default-deny security posture)
	return EvaluationResult{Allowed: false, Reason: "default deny: no matching policy"}
}

// EvaluateRequest evaluates a gateway proxy request against policies.
func (e *Engine) EvaluateRequest(identityID string, roles []string, provider, model string) EvaluationResult {
	resource := fmt.Sprintf("%s/%s", provider, model)
	return e.Evaluate(identityID, "llm_request", resource)
}

func matchesCondition(condition, identity, action, resource string) bool {
	var cond map[string]interface{}
	if err := json.Unmarshal([]byte(condition), &cond); err != nil {
		return false
	}
	// Simple condition matching
	if v, ok := cond["identity"]; ok && v != identity {
		return false
	}
	if v, ok := cond["action"]; ok && v != action {
		return false
	}
	if v, ok := cond["resource"]; ok {
		pattern := fmt.Sprintf("%v", v)
		if matched, _ := matchPattern(pattern, resource); !matched {
			return false
		}
	}
	return true
}

func matchPattern(pattern, value string) (bool, error) {
	if pattern == "*" || pattern == value {
		return true, nil
	}
	// Support glob-style wildcards: prefix*, *suffix, *contains*
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		contains := strings.Trim(pattern, "*")
		return strings.Contains(value, contains), nil
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(value, suffix), nil
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix), nil
	}
	return false, nil
}

func (e *Engine) periodicRefresh() {
	defer close(e.done)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.mu.Lock()
			for k, v := range e.cache {
				if time.Now().After(v.ExpiresAt) {
					delete(e.cache, k)
				}
			}
			e.mu.Unlock()
		}
	}
}

// trimCacheLocked evicts expired entries first; if still over the cap, removes
// the entries expiring soonest. Caller must hold e.mu (write lock).
func (e *Engine) trimCacheLocked() {
	if e.maxCacheSize <= 0 || len(e.cache) <= e.maxCacheSize {
		return
	}
	// Evict expired entries.
	now := time.Now()
	for k, v := range e.cache {
		if now.After(v.ExpiresAt) {
			delete(e.cache, k)
		}
	}
	// If still over the cap, delete arbitrary entries (map iteration order is
	// random; this is acceptable for a bounded cache under extreme load).
	over := len(e.cache) - e.maxCacheSize
	for k := range e.cache {
		if over <= 0 {
			break
		}
		delete(e.cache, k)
		over--
	}
}
