package api

import (
	"encoding/json"
	"net/http"

	"appgate-control-plane/pkg/store"

	"github.com/gorilla/mux"
)

// ListBackends returns all configured backends
func ListBackends(s *store.BackendStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		poolID := r.URL.Query().Get("pool_id")
		backends, err := s.List(r.Context(), poolID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": backends})
	}
}

// GetBackend returns a single backend
func GetBackend(s *store.BackendStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		backend, err := s.Get(r.Context(), id)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": backend})
	}
}

// CreateBackend adds a new backend
func CreateBackend(s *store.BackendStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name       string                 `json:"name"`
			URL        string                 `json:"url"`
			Weight     uint32                 `json:"weight"`
			PoolID     string                 `json:"pool_id"`
			HealthPath string                 `json:"health_path"`
			Metadata   map[string]interface{} `json:"metadata"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.Name == "" || req.URL == "" || req.PoolID == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "name, url, and pool_id are required")
			return
		}

		backend := &store.Backend{
			Name:       req.Name,
			URL:        req.URL,
			Weight:     req.Weight,
			PoolID:     req.PoolID,
			HealthPath: req.HealthPath,
			Metadata:   req.Metadata,
			Enabled:    true,
			Healthy:    true,
		}

		if err := s.Create(r.Context(), backend); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"data": backend})
	}
}

// UpdateBackend modifies a backend
func UpdateBackend(s *store.BackendStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if err := s.Update(r.Context(), id, updates); err != nil {
			writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "updated"})
	}
}

// DeleteBackend removes a backend
func DeleteBackend(s *store.BackendStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		if err := s.Delete(r.Context(), id); err != nil {
			writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// TriggerHealthCheck forces a health check
func TriggerHealthCheck(s *store.BackendStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		if err := s.HealthCheck(r.Context(), id); err != nil {
			writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "health check triggered"})
	}
}
