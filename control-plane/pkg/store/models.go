package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ── AuditLog ─────────────────────────────────────────────────────────────────

// AuditLog represents a single auditable event in the system.
type AuditLog struct {
	ID           string    `json:"id"`
	NodeID       string    `json:"node_id"`
	EventType    string    `json:"event_type"`
	Level        string    `json:"level"`
	ClientIP     string    `json:"client_ip"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	StatusCode   *int      `json:"status_code"`
	BackendHost  string    `json:"backend_host"`
	DurationMs   *int64    `json:"duration_ms"`
	ErrorMessage string    `json:"error_message"`
	CreatedAt    time.Time `json:"created_at"`
}

// ── Backend ──────────────────────────────────────────────────────────────────

// Backend represents an upstream service backend.
type Backend struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	URL        string                 `json:"url"`
	Weight     uint32                 `json:"weight"`
	PoolID     string                 `json:"pool_id"`
	HealthPath string                 `json:"health_path"`
	Metadata   map[string]interface{} `json:"metadata"`
	Enabled    bool                   `json:"enabled"`
	Healthy    bool                   `json:"healthy"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// ── BackendStore ─────────────────────────────────────────────────────────────

// BackendStore provides CRUD operations for backends using SQL.
type BackendStore struct {
	db *sql.DB
}

// NewBackendStore creates a new BackendStore.
func NewBackendStore(db *sql.DB) *BackendStore {
	return &BackendStore{db: db}
}

// List returns all backends, optionally filtered by pool_id.
func (s *BackendStore) List(ctx context.Context, poolID string) ([]Backend, error) {
	var query string
	var args []interface{}
	if poolID != "" {
		query = `SELECT id, name, url, weight, pool_id, health_path, metadata, enabled, healthy, created_at, updated_at 
				 FROM backends WHERE pool_id = $1 ORDER BY name`
		args = append(args, poolID)
	} else {
		query = `SELECT id, name, url, weight, pool_id, health_path, metadata, enabled, healthy, created_at, updated_at 
				 FROM backends ORDER BY name`
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list backends: %w", err)
	}
	defer rows.Close()

	var backends []Backend
	for rows.Next() {
		var b Backend
		var metadataRaw []byte
		if err := rows.Scan(&b.ID, &b.Name, &b.URL, &b.Weight, &b.PoolID, &b.HealthPath, &metadataRaw, &b.Enabled, &b.Healthy, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan backend: %w", err)
		}
		if len(metadataRaw) > 0 {
			_ = json.Unmarshal(metadataRaw, &b.Metadata)
		}
		backends = append(backends, b)
	}
	return backends, nil
}

// Get returns a single backend by ID.
func (s *BackendStore) Get(ctx context.Context, id string) (*Backend, error) {
	var b Backend
	var metadataRaw []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, url, weight, pool_id, health_path, metadata, enabled, healthy, created_at, updated_at 
		 FROM backends WHERE id = $1`, id).
		Scan(&b.ID, &b.Name, &b.URL, &b.Weight, &b.PoolID, &b.HealthPath, &metadataRaw, &b.Enabled, &b.Healthy, &b.CreatedAt, &b.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("backend not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("get backend: %w", err)
	}
	if len(metadataRaw) > 0 {
		_ = json.Unmarshal(metadataRaw, &b.Metadata)
	}
	return &b, nil
}

// Create inserts a new backend.
func (s *BackendStore) Create(ctx context.Context, backend *Backend) error {
	backend.ID = uuid.New().String()
	backend.CreatedAt = time.Now().UTC()
	backend.UpdatedAt = backend.CreatedAt

	metadataJSON, err := json.Marshal(backend.Metadata)
	if err != nil {
		return fmt.Errorf("marshal backend metadata: %w", err)
	}
	if string(metadataJSON) == "null" {
		metadataJSON = []byte("{}")
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO backends (id, name, url, weight, pool_id, health_path, metadata, enabled, healthy, created_at, updated_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		backend.ID, backend.Name, backend.URL, backend.Weight, backend.PoolID,
		backend.HealthPath, metadataJSON, backend.Enabled, backend.Healthy, backend.CreatedAt, backend.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create backend: %w", err)
	}
	return nil
}

// Update modifies a backend. Only columns in the allowlist can be updated.
func (s *BackendStore) Update(ctx context.Context, id string, updates map[string]interface{}) error {
	allowedColumns := map[string]bool{
		"name": true, "url": true, "weight": true, "pool_id": true,
		"health_path": true, "metadata": true, "enabled": true,
		"healthy": true, "updated_at": true,
	}
	updates["updated_at"] = time.Now().UTC()
	var setClauses []string
	var args []interface{}
	argIdx := 1
	for k, v := range updates {
		if !allowedColumns[k] {
			continue // silently skip unallowed columns — prevents SQL injection
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", k, argIdx))
		args = append(args, v)
		argIdx++
	}
	if len(setClauses) == 0 {
		return fmt.Errorf("no valid columns to update for backend %s", id)
	}
	args = append(args, id)
	query := fmt.Sprintf("UPDATE backends SET %s WHERE id = $%d", strings.Join(setClauses, ", "), argIdx)
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update backend: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update backend rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("backend not found: %s", id)
	}
	return nil
}

// Delete removes a backend.
func (s *BackendStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM backends WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete backend: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete backend rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("backend not found: %s", id)
	}
	return nil
}

// HealthCheck performs an actual HTTP health check against a backend.
// Uses a shared HTTP client for efficiency at scale.
var healthCheckClient = &http.Client{Timeout: 10 * time.Second}

func (s *BackendStore) HealthCheck(ctx context.Context, id string) error {
	backend, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	if !backend.Enabled {
		return fmt.Errorf("backend %s is disabled, skipping health check", id)
	}

	healthURL := backend.URL
	if backend.HealthPath != "" {
		healthURL = strings.TrimRight(backend.URL, "/") + "/" + strings.TrimLeft(backend.HealthPath, "/")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		_ = s.Update(ctx, id, map[string]interface{}{"healthy": false})
		return fmt.Errorf("health check create request: %w", err)
	}
	resp, err := healthCheckClient.Do(req)
	if err != nil {
		_ = s.Update(ctx, id, map[string]interface{}{"healthy": false})
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	healthy := resp.StatusCode == http.StatusOK
	if err := s.Update(ctx, id, map[string]interface{}{"healthy": healthy}); err != nil {
		return fmt.Errorf("health check update status: %w", err)
	}
	return nil
}

// ── Route ────────────────────────────────────────────────────────────────────

// Route maps incoming requests to backend pools.
type Route struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Host        string                 `json:"host"`
	PathPrefix  string                 `json:"path_prefix"`
	BackendPool string                 `json:"backend_pool"`
	Methods     []string               `json:"methods"`
	Headers     map[string]interface{} `json:"headers"`
	StripPrefix bool                   `json:"strip_prefix"`
	Priority    int32                  `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// ── RouteStore ───────────────────────────────────────────────────────────────

// RouteStore provides CRUD operations for routes using SQL.
type RouteStore struct {
	db *sql.DB
}

// NewRouteStore creates a new RouteStore.
func NewRouteStore(db *sql.DB) *RouteStore {
	return &RouteStore{db: db}
}

// List returns all enabled routes.
func (s *RouteStore) List(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, host, path_prefix, backend_pool, methods, headers, strip_prefix, priority, enabled, created_at, updated_at 
		 FROM routes WHERE enabled = true ORDER BY priority DESC`)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	defer rows.Close()

	var routes []Route
	for rows.Next() {
		var r Route
		var headersRaw []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.Host, &r.PathPrefix, &r.BackendPool, &r.Methods, &headersRaw, &r.StripPrefix, &r.Priority, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan route: %w", err)
		}
		if len(headersRaw) > 0 {
			_ = json.Unmarshal(headersRaw, &r.Headers)
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// Get returns a single route by ID.
func (s *RouteStore) Get(ctx context.Context, id string) (*Route, error) {
	var r Route
	var headersRaw []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, host, path_prefix, backend_pool, methods, headers, strip_prefix, priority, enabled, created_at, updated_at 
		 FROM routes WHERE id = $1`, id).
		Scan(&r.ID, &r.Name, &r.Host, &r.PathPrefix, &r.BackendPool, &r.Methods, &headersRaw, &r.StripPrefix, &r.Priority, &r.Enabled, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("route not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("get route: %w", err)
	}
	if len(headersRaw) > 0 {
		_ = json.Unmarshal(headersRaw, &r.Headers)
	}
	return &r, nil
}

// Create inserts a new route.
func (s *RouteStore) Create(ctx context.Context, route *Route) error {
	route.ID = uuid.New().String()
	route.CreatedAt = time.Now().UTC()
	route.UpdatedAt = route.CreatedAt

	headersJSON, err := json.Marshal(route.Headers)
	if err != nil {
		return fmt.Errorf("marshal route headers: %w", err)
	}
	if string(headersJSON) == "null" {
		headersJSON = []byte("{}")
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO routes (id, name, host, path_prefix, backend_pool, methods, headers, strip_prefix, priority, enabled, created_at, updated_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		route.ID, route.Name, route.Host, route.PathPrefix, route.BackendPool,
		route.Methods, headersJSON, route.StripPrefix, route.Priority, route.Enabled, route.CreatedAt, route.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create route: %w", err)
	}
	return nil
}

// Update modifies a route. Only columns in the allowlist can be updated.
func (s *RouteStore) Update(ctx context.Context, id string, updates map[string]interface{}) error {
	allowedColumns := map[string]bool{
		"name": true, "host": true, "path_prefix": true, "backend_pool": true,
		"methods": true, "headers": true, "strip_prefix": true,
		"priority": true, "enabled": true, "updated_at": true,
	}
	updates["updated_at"] = time.Now().UTC()
	var setClauses []string
	var args []interface{}
	argIdx := 1
	for k, v := range updates {
		if !allowedColumns[k] {
			continue // silently skip unallowed columns — prevents SQL injection
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", k, argIdx))
		args = append(args, v)
		argIdx++
	}
	if len(setClauses) == 0 {
		return fmt.Errorf("no valid columns to update for route %s", id)
	}
	args = append(args, id)
	query := fmt.Sprintf("UPDATE routes SET %s WHERE id = $%d", strings.Join(setClauses, ", "), argIdx)
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update route: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update route rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("route not found: %s", id)
	}
	return nil
}

// Delete removes a route.
func (s *RouteStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM routes WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete route: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete route rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("route not found: %s", id)
	}
	return nil
}

// ── APIKey ───────────────────────────────────────────────────────────────────

// APIKey represents a hashed API key for programmatic access.
type APIKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	KeyHash   string     `json:"-"`
	Scopes    []string   `json:"scopes"`
	Routes    []string   `json:"routes"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// ── APIKeyStore ──────────────────────────────────────────────────────────────

// APIKeyStore provides CRUD operations for API keys using SQL.
type APIKeyStore struct {
	db *sql.DB
}

// NewAPIKeyStore creates a new APIKeyStore.
func NewAPIKeyStore(db *sql.DB) *APIKeyStore {
	return &APIKeyStore{db: db}
}

// List returns all API keys (without hashes).
func (s *APIKeyStore) List(ctx context.Context) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, scopes, routes, enabled, expires_at, created_at, updated_at 
		 FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.Name, &k.Scopes, &k.Routes, &k.Enabled, &k.ExpiresAt, &k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Create generates a new API key and returns it with the plaintext value.
func (s *APIKeyStore) Create(ctx context.Context, name string, scopes, routes []string, expiresAt *time.Time) (*APIKey, string, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}
	plaintext := "ak_" + hex.EncodeToString(keyBytes)
	hash := sha256.Sum256([]byte(plaintext))

	key := &APIKey{
		ID:        uuid.New().String(),
		Name:      name,
		KeyHash:   hex.EncodeToString(hash[:]),
		Scopes:    scopes,
		Routes:    routes,
		Enabled:   true,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, name, key_hash, scopes, routes, enabled, expires_at, created_at, updated_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		key.ID, key.Name, key.KeyHash, key.Scopes, key.Routes, key.Enabled, key.ExpiresAt, key.CreatedAt, key.UpdatedAt)
	if err != nil {
		return nil, "", fmt.Errorf("create api key: %w", err)
	}

	return key, plaintext, nil
}

// Revoke disables an API key.
func (s *APIKeyStore) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET enabled = false, updated_at = $1 WHERE id = $2`, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke api key rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("api key not found: %s", id)
	}
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────
