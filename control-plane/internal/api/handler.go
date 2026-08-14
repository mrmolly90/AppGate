package api

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	"appgate-control-plane/internal/auth"
	"appgate-control-plane/internal/database"
	"appgate-control-plane/internal/policy"
)

// Handler holds dependencies for API handlers.
type Handler struct {
	db         *database.Postgres
	jwtService *auth.JWTService
}

// NewHandler creates a new API handler.
func NewHandler(db *database.Postgres, jwtService *auth.JWTService) *Handler {
	return &Handler{
		db:         db,
		jwtService: jwtService,
	}
}

// CreateToken handles POST /v1/auth/token
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate client credentials against database
	var storedSecret string
	var roles []string
	err := h.db.DB().QueryRow(
		"SELECT client_secret, roles FROM identities WHERE id = $1 AND enabled = true",
		req.ClientID,
	).Scan(&storedSecret, &roles)

	if err == sql.ErrNoRows {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		log.Error().Err(err).Str("client_id", req.ClientID).Msg("failed to query identity")
		respondError(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(req.ClientSecret), []byte(storedSecret)) != 1 {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := h.jwtService.CreateToken(req.ClientID, roles, req.Scope, 1*time.Hour)
	if err != nil {
		log.Error().Err(err).Msg("failed to create token")
		respondError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// ListPolicies handles GET /v1/policies
func (h *Handler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.DB().Query(`
		SELECT id, name, version, spec, created_at, updated_at, created_by
		FROM policies ORDER BY created_at DESC
	`)
	if err != nil {
		log.Error().Err(err).Msg("failed to query policies")
		respondError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}
	defer rows.Close()

	var policies []policy.Policy
	for rows.Next() {
		var p policy.Policy
		var specJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Version, &specJSON, &p.CreatedAt, &p.UpdatedAt, &p.CreatedBy); err != nil {
			log.Error().Err(err).Msg("failed to scan policy row")
			continue
		}
		if err := json.Unmarshal(specJSON, &p.Spec); err != nil {
			log.Error().Err(err).Str("policy_id", p.ID).Msg("failed to unmarshal policy spec")
			continue
		}
		policies = append(policies, p)
	}

	if policies == nil {
		policies = []policy.Policy{}
	}

	respondJSON(w, http.StatusOK, policies)
}

// CreatePolicy handles POST /v1/policies
func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.PolicySpec
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		respondError(w, http.StatusBadRequest, "invalid policy spec")
		return
	}

	if err := p.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusForbidden, "unauthorized")
		return
	}

	id := uuid.New().String()
	specJSON, err := json.Marshal(p)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal policy spec")
		respondError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	_, err = h.db.DB().Exec(`
		INSERT INTO policies (id, name, version, spec, created_by)
		VALUES ($1, $2, 1, $3, $4)
	`, id, p.Name, specJSON, claims.Subject)
	if err != nil {
		log.Error().Err(err).Msg("failed to insert policy")
		respondError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{
		"id":     id,
		"status": "created",
	})
}

// GetPolicy handles GET /v1/policies/{id}
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var p policy.Policy
	var specJSON []byte
	err := h.db.DB().QueryRow(`
		SELECT id, name, version, spec, created_at, updated_at, created_by
		FROM policies WHERE id = $1
	`, id).Scan(&p.ID, &p.Name, &p.Version, &specJSON, &p.CreatedAt, &p.UpdatedAt, &p.CreatedBy)

	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "policy not found")
		return
	}
	if err != nil {
		log.Error().Err(err).Str("policy_id", id).Msg("failed to query policy")
		respondError(w, http.StatusInternalServerError, "failed to get policy")
		return
	}

	if err := json.Unmarshal(specJSON, &p.Spec); err != nil {
		log.Error().Err(err).Str("policy_id", id).Msg("failed to unmarshal policy spec")
		respondError(w, http.StatusInternalServerError, "failed to read policy")
		return
	}

	respondJSON(w, http.StatusOK, p)
}

// UpdatePolicy handles PUT /v1/policies/{id}
func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var p policy.PolicySpec
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		respondError(w, http.StatusBadRequest, "invalid policy spec")
		return
	}

	if err := p.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	specJSON, err := json.Marshal(p)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal policy spec")
		respondError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}

	result, err := h.db.DB().Exec(`
		UPDATE policies SET spec = $1, version = version + 1, updated_at = NOW()
		WHERE id = $2
	`, specJSON, id)
	if err != nil {
		log.Error().Err(err).Str("policy_id", id).Msg("failed to update policy")
		respondError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "policy not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// DeletePolicy handles DELETE /v1/policies/{id}
func (h *Handler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	result, err := h.db.DB().Exec(`DELETE FROM policies WHERE id = $1`, id)
	if err != nil {
		log.Error().Err(err).Str("policy_id", id).Msg("failed to delete policy")
		respondError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "policy not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListGateways handles GET /v1/gateways
func (h *Handler) ListGateways(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.DB().Query(`
		SELECT id, name, version, status, last_seen_at, registered_at, metadata
		FROM gateways ORDER BY registered_at DESC
	`)
	if err != nil {
		log.Error().Err(err).Msg("failed to query gateways")
		respondError(w, http.StatusInternalServerError, "failed to list gateways")
		return
	}
	defer rows.Close()

	type Gateway struct {
		ID           string     `json:"id"`
		Name         string     `json:"name"`
		Version      string     `json:"version"`
		Status       string     `json:"status"`
		LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
		RegisteredAt time.Time  `json:"registered_at"`
	}

	var gateways []Gateway
	for rows.Next() {
		var g Gateway
		if err := rows.Scan(&g.ID, &g.Name, &g.Version, &g.Status, &g.LastSeenAt, &g.RegisteredAt); err != nil {
			log.Error().Err(err).Msg("failed to scan gateway row")
			continue
		}
		gateways = append(gateways, g)
	}

	if gateways == nil {
		gateways = []Gateway{}
	}

	respondJSON(w, http.StatusOK, gateways)
}

// GetGateway handles GET /v1/gateways/{id}
func (h *Handler) GetGateway(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	type Gateway struct {
		ID           string     `json:"id"`
		Name         string     `json:"name"`
		Version      string     `json:"version"`
		PublicKey    string     `json:"public_key"`
		Status       string     `json:"status"`
		LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
		RegisteredAt time.Time  `json:"registered_at"`
	}

	var g Gateway
	err := h.db.DB().QueryRow(`
		SELECT id, name, version, public_key, status, last_seen_at, registered_at
		FROM gateways WHERE id = $1
	`, id).Scan(&g.ID, &g.Name, &g.Version, &g.PublicKey, &g.Status, &g.LastSeenAt, &g.RegisteredAt)

	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "gateway not found")
		return
	}
	if err != nil {
		log.Error().Err(err).Str("gateway_id", id).Msg("failed to query gateway")
		respondError(w, http.StatusInternalServerError, "failed to get gateway")
		return
	}

	respondJSON(w, http.StatusOK, g)
}

// RegisterGateway handles POST /v1/gateways/register
func (h *Handler) RegisterGateway(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		PublicKey string `json:"public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.Name == "" || req.PublicKey == "" {
		respondError(w, http.StatusBadRequest, "name and public_key are required")
		return
	}

	id := uuid.New().String()
	_, err := h.db.DB().Exec(`
		INSERT INTO gateways (id, name, version, public_key, status, last_seen_at)
		VALUES ($1, $2, $3, $4, 'active', NOW())
	`, id, req.Name, req.Version, req.PublicKey)
	if err != nil {
		log.Error().Err(err).Msg("failed to register gateway")
		respondError(w, http.StatusInternalServerError, "failed to register gateway")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{
		"gateway_id": id,
		"status":     "registered",
	})
}

// EvaluatePolicy handles POST /v1/policies/evaluate
func (h *Handler) EvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IdentityID string   `json:"identity_id"`
		Roles      []string `json:"roles"`
		Provider   string   `json:"provider"`
		Model      string   `json:"model"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Fetch all policies from database and evaluate
	rows, err := h.db.DB().Query(`
		SELECT id, name, spec FROM policies ORDER BY created_at ASC
	`)
	if err != nil {
		log.Error().Err(err).Msg("failed to query policies for evaluation")
		respondError(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}
	defer rows.Close()

	for rows.Next() {
		var p policy.Policy
		var specJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &specJSON); err != nil {
			log.Error().Err(err).Msg("failed to scan policy for evaluation")
			continue
		}
		if err := json.Unmarshal(specJSON, &p.Spec); err != nil {
			log.Error().Err(err).Str("policy_id", p.ID).Msg("failed to unmarshal policy spec")
			continue
		}

		result := p.Evaluate(req.IdentityID, req.Roles, req.Provider, req.Model)
		if result != nil && result.Allowed {
			respondJSON(w, http.StatusOK, result)
			return
		}
	}

	// Fail closed: deny if no matching policy allows the request
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"allowed": false,
		"reason":  "no matching policy",
	})
}

// ListAuditEvents handles GET /v1/audit
func (h *Handler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.DB().Query(`
		SELECT id, timestamp, event_type, actor_id, actor_ip, action, resource, result, correlation_id, metadata, source
		FROM audit_events ORDER BY timestamp DESC LIMIT 100
	`)
	if err != nil {
		log.Error().Err(err).Msg("failed to query audit events")
		respondError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}
	defer rows.Close()

	type AuditEvent struct {
		ID            string            `json:"id"`
		Timestamp     time.Time         `json:"timestamp"`
		EventType     string            `json:"event_type"`
		ActorID       string            `json:"actor_id"`
		ActorIP       *string           `json:"actor_ip,omitempty"`
		Action        string            `json:"action"`
		Resource      *string           `json:"resource,omitempty"`
		Result        string            `json:"result"`
		CorrelationID *string           `json:"correlation_id,omitempty"`
		Metadata      map[string]string `json:"metadata,omitempty"`
		Source        *string           `json:"source,omitempty"`
	}

	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var metadataJSON []byte
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.ActorID, &e.ActorIP, &e.Action, &e.Resource, &e.Result, &e.CorrelationID, &metadataJSON, &e.Source); err != nil {
			log.Error().Err(err).Msg("failed to scan audit event row")
			continue
		}
		if len(metadataJSON) > 0 {
			json.Unmarshal(metadataJSON, &e.Metadata)
		}
		events = append(events, e)
	}

	if events == nil {
		events = []AuditEvent{}
	}

	respondJSON(w, http.StatusOK, events)
}

// CreateAuditEvent handles POST /v1/audit — used by the gateway to record audit events
func (h *Handler) CreateAuditEvent(w http.ResponseWriter, r *http.Request) {
	var event struct {
		EventType     string            `json:"event_type"`
		ActorID       string            `json:"actor_id"`
		ActorIP       *string           `json:"actor_ip,omitempty"`
		Action        string            `json:"action"`
		Resource      *string           `json:"resource,omitempty"`
		Result        string            `json:"result"`
		CorrelationID *string           `json:"correlation_id,omitempty"`
		Metadata      map[string]string `json:"metadata,omitempty"`
		Source        *string           `json:"source,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if event.EventType == "" || event.ActorID == "" || event.Action == "" || event.Result == "" {
		respondError(w, http.StatusBadRequest, "event_type, actor_id, action, and result are required")
		return
	}

	id := uuid.New().String()
	metadataJSON, _ := json.Marshal(event.Metadata)
	if metadataJSON == nil {
		metadataJSON = []byte("{}")
	}

	_, err := h.db.DB().Exec(`
		INSERT INTO audit_events (id, event_type, actor_id, actor_ip, action, resource, result, correlation_id, metadata, source)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, id, event.EventType, event.ActorID, event.ActorIP, event.Action, event.Resource, event.Result, event.CorrelationID, metadataJSON, event.Source)
	if err != nil {
		log.Error().Err(err).Msg("failed to insert audit event")
		respondError(w, http.StatusInternalServerError, "failed to record audit event")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "recorded"})
}

// ListProviders handles GET /v1/providers — used by the gateway to discover LLM providers
func (h *Handler) ListProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.DB().Query(`
		SELECT id, name, base_url, auth_type, models, enabled, created_at
		FROM providers WHERE enabled = true ORDER BY name ASC
	`)
	if err != nil {
		log.Error().Err(err).Msg("failed to query providers")
		respondError(w, http.StatusInternalServerError, "failed to list providers")
		return
	}
	defer rows.Close()

	type Provider struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		BaseURL   string   `json:"base_url"`
		AuthType  string   `json:"auth_type"`
		Models    []string `json:"models"`
		Enabled   bool     `json:"enabled"`
		CreatedAt string   `json:"created_at"`
	}

	var providers []Provider
	for rows.Next() {
		var p Provider
		var createdAt time.Time
		if err := rows.Scan(&p.ID, &p.Name, &p.BaseURL, &p.AuthType, &p.Models, &p.Enabled, &createdAt); err != nil {
			log.Error().Err(err).Msg("failed to scan provider row")
			continue
		}
		p.CreatedAt = createdAt.Format(time.RFC3339)
		providers = append(providers, p)
	}

	if providers == nil {
		providers = []Provider{}
	}

	respondJSON(w, http.StatusOK, providers)
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}