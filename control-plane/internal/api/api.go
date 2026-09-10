package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"appgate-control-plane/internal/leader"
	"appgate-control-plane/internal/store"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// =============================================================================
// Dev-Portal Registration Types
// =============================================================================

// RegisterRequest is the payload from the dev-portal for gateway registration.
type RegisterRequest struct {
	ProjectName     string            `json:"project_name"`
	Model           string            `json:"model"`
	LLMModelName    string            `json:"llm_model_name"`
	ProviderKey     string            `json:"provider_key"`
	ProviderURL     string            `json:"provider_url"`
	MonthlySpendUSD float64           `json:"monthly_spend_usd"`
	RateLimitRPS    int               `json:"rate_limit_rps"`
	RateLimitRPM    int               `json:"rate_limit_rpm"`
	RateLimitBurst  int               `json:"rate_limit_burst"`
	WebhookURL      string            `json:"webhook_url"`
	Tags            map[string]string `json:"tags"`
}

// RegisterResponse is the credential handshake returned to the dev-portal.
type RegisterResponse struct {
	ClientID       string `json:"client_id"`
	ClientSecretID string `json:"client_secret_id"`
	JWTToken       string `json:"jwt_token"`
	ExpiresAt      string `json:"expires_at"`
	TokenType      string `json:"token_type"`
	Issuer         string `json:"issuer"`
}

// signingKey is the Ed25519 key used for JWT signing (generated at startup).
var signingKey ed25519.PrivateKey

func init() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate signing key: %v", err))
	}
	signingKey = priv
}

// =============================================================================
// Dev-Portal Registration Handler
// =============================================================================

// HandleDevPortalRegister handles POST /api/v1/gateways/register from the dev-portal.
// It validates the request, generates a client ID, signs a JWT, and returns
// the credential handshake.
func HandleDevPortalRegister() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_json","message":"Request body is not valid JSON"}`, http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.ProjectName == "" || req.Model == "" || req.ProviderURL == "" {
			http.Error(w, `{"error":"validation_error","message":"project_name, model, and provider_url are required"}`, http.StatusBadRequest)
			return
		}

		// Generate client identity
		clientID := uuid.New().String()
		secretID := uuid.New().String()
		now := time.Now().UTC()
		expiry := now.Add(24 * time.Hour)

		// Sign JWT with Ed25519
		claims := jwt.RegisteredClaims{
			ID:        secretID,
			Issuer:    "appgate-control-plane",
			Subject:   clientID,
			Audience:  jwt.ClaimStrings{"appgate-gateway"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(expiry),
		}
		token := jwt.NewWithClaims(jwt.GetSigningMethod("EdDSA"), claims)
		token.Header["kid"] = "appgate-signing-key-v1"
		signedJWT, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, `{"error":"signing_failed"}`, http.StatusInternalServerError)
			return
		}

		resp := RegisterResponse{
			ClientID:       clientID,
			ClientSecretID: secretID,
			JWTToken:       signedJWT,
			ExpiresAt:      expiry.Format(time.RFC3339),
			TokenType:      "Bearer",
			Issuer:         "appgate-control-plane",
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleDevPortalSecretStatus handles GET /api/v1/secrets/{clientID}
func HandleDevPortalSecretStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clientID := vars["clientID"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"client_id": clientID,
			"status":    "active",
		})
	}
}

// =============================================================================
// Policy Handlers
// =============================================================================

func HandleListPolicies(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"policies": []interface{}{}})
	}
}

func HandleCreatePolicy(db *sql.DB, elector *leader.Elector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if elector != nil && !elector.IsLeader() {
			http.Error(w, `{"error":"not_leader","message":"Write operations require leader"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	}
}

func HandleGetPolicy(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id": id, "name": "placeholder"})
	}
}

func HandleUpdatePolicy(db *sql.DB, elector *leader.Elector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if elector != nil && !elector.IsLeader() {
			http.Error(w, `{"error":"not_leader"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	}
}

func HandleDeletePolicy(db *sql.DB, elector *leader.Elector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if elector != nil && !elector.IsLeader() {
			http.Error(w, `{"error":"not_leader"}`, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func HandleValidatePolicy(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"valid": "true"})
	}
}

// =============================================================================
// Gateway Handlers
// =============================================================================

func HandleListGateways(store *store.EtcdStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if store == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"gateways": []interface{}{}, "mode": "standalone"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"gateways": []interface{}{}})
	}
}

func HandleRegisterGateway(store *store.EtcdStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			http.Error(w, `{"error":"not_available","message":"etcd not available, running standalone"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
	}
}

func HandleGatewayHeartbeat(store *store.EtcdStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			http.Error(w, `{"error":"not_available","message":"etcd not available, running standalone"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// =============================================================================
// Audit Handlers
// =============================================================================

func HandleQueryAudit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"events": []interface{}{}})
	}
}

func HandleExportAudit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=audit-export.json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"exported_at": time.Now().UTC().Format(time.RFC3339),
			"events":      []interface{}{},
		})
	}
}

func HandleAuditBatch(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var events []map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid_json","message":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		_ = events // In production, insert into audit_events table
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"ingested": len(events),
			"batch_id": uuid.New().String(),
		})
	}
}
