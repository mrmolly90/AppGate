package api

import (
	"encoding/json"
	"net/http"

	"appgate-control-plane/pkg/store"

	"github.com/gorilla/mux"
)

// ListRoutes returns all routes
func ListRoutes(s *store.RouteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		routes, err := s.List(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": routes})
	}
}

// GetRoute returns a single route
func GetRoute(s *store.RouteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		route, err := s.Get(r.Context(), id)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": route})
	}
}

// CreateRoute adds a new route
func CreateRoute(s *store.RouteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name        string                 `json:"name"`
			Host        string                 `json:"host"`
			PathPrefix  string                 `json:"path_prefix"`
			BackendPool string                 `json:"backend_pool"`
			Methods     []string               `json:"methods"`
			Headers     map[string]interface{} `json:"headers"`
			StripPrefix bool                   `json:"strip_prefix"`
			Priority    int32                  `json:"priority"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.Name == "" || req.PathPrefix == "" || req.BackendPool == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "name, path_prefix, and backend_pool are required")
			return
		}

		route := &store.Route{
			Name:        req.Name,
			Host:        req.Host,
			PathPrefix:  req.PathPrefix,
			BackendPool: req.BackendPool,
			Methods:     req.Methods,
			Headers:     req.Headers,
			StripPrefix: req.StripPrefix,
			Priority:    req.Priority,
			Enabled:     true,
		}

		if err := s.Create(r.Context(), route); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"data": route})
	}
}

// UpdateRoute modifies a route
func UpdateRoute(s *store.RouteStore) http.HandlerFunc {
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

// DeleteRoute removes a route
func DeleteRoute(s *store.RouteStore) http.HandlerFunc {
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
