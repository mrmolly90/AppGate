package api

import (
	"encoding/json"
	"net/http"
	"time"

	"appgate-control-plane/pkg/store"

	"github.com/gorilla/mux"
)

// ListAPIKeys returns all API keys (without hashes)
func ListAPIKeys(s *store.APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys, err := s.List(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": keys})
	}
}

// CreateAPIKey generates a new API key
func CreateAPIKey(s *store.APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name      string   `json:"name"`
			Scopes    []string `json:"scopes"`
			Routes    []string `json:"routes"`
			ExpiresIn *int     `json:"expires_in_hours"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.Name == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "name is required")
			return
		}

		var expiresAt *time.Time
		if req.ExpiresIn != nil {
			t := time.Now().UTC().Add(time.Duration(*req.ExpiresIn) * time.Hour)
			expiresAt = &t
		}

		key, plaintext, err := s.Create(r.Context(), req.Name, req.Scopes, req.Routes, expiresAt)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": key,
			"key":  plaintext,
		})
	}
}

// RevokeAPIKey disables an API key
func RevokeAPIKey(s *store.APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		if err := s.Revoke(r.Context(), id); err != nil {
			writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "revoked"})
	}
}
