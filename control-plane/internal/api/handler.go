package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	"appgate-control-plane/internal/auth"
	"appgate-control-plane/internal/database"
	"appgate-control-plane/internal/policy"
)

// Handler holds dependencies for API handlers.
type Handler struct {
	db        *database.Postgres
	jwtService *auth.JWTService
}

// NewHandler creates a new API handler.
func NewHandler(db *database.Postgres, jwtService *auth.JWTService) *Handler {
	return &Handler{
		db:        db,
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

	// In production, validate client_id and client_secret against database
	// For now, accept valid-looking requests
	if req.ClientID == "" {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Determine roles from identity
	roles := []string{"gateway"}
	token, err := h.jwtService.CreateToken(req.ClientID, roles, req.Scope, 1*time.Hour)
	if err != nil {
		log.Error().Err(err).Msg("failed to create token")
		respondError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   "3600",
	})
}

// ListPolicies handles GET /v1/policies
func (h *Handler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	// In production, query database
	respondJSON(w, http.StatusOK, []policy.Policy{})
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

	// In production, persist to database
	respondJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

// GetPolicy handles GET /v1/policies/{id}
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	_ = vars["id"]
	respondError(w, http.StatusNotFound, "policy not found")
}

// UpdatePolicy handles PUT /v1/policies/{id}
func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	respondError(w, http.StatusNotImplemented, "not implemented")
}

// DeletePolicy handles DELETE /v1/policies/{id}
func (h *Handler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	respondError(w, http.StatusNotImplemented, "not implemented")
}

// ListGateways handles GET /v1/gateways
func (h *Handler) ListGateways(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, []map[string]string{})
}

// GetGateway handles GET /v1/gateways/{id}
func (h *Handler) GetGateway(w http.ResponseWriter, r *http.Request) {
	respondError(w, http.StatusNotFound, "gateway not found")
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

	respondJSON(w, http.StatusCreated, map[string]string{
		"gateway_id": uuid.New().String(),
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

	// In production, fetch policies from database and evaluate
	// For now, allow by default
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"allowed": true,
		"reason":  "default allow",
	})
}

// ListAuditEvents handles GET /v1/audit
func (h *Handler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, []map[string]string{})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}