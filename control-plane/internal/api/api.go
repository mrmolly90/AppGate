// =============================================================================
// AppGate Control Plane — API Handlers (Production)
// =============================================================================

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"appgate-control-plane/internal/leader"
	"appgate-control-plane/internal/store"

	"github.com/gorilla/mux"
)

func HandleListPolicies(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"policies": []interface{}{}})
	}
}

func HandleCreatePolicy(db *sql.DB, elector *leader.Elector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !elector.IsLeader() {
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
		if !elector.IsLeader() {
			http.Error(w, `{"error":"not_leader"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	}
}

func HandleDeletePolicy(db *sql.DB, elector *leader.Elector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !elector.IsLeader() {
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

func HandleListGateways(store *store.EtcdStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"gateways": []interface{}{}})
	}
}

func HandleRegisterGateway(store *store.EtcdStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
	}
}

func HandleGatewayHeartbeat(store *store.EtcdStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

func HandleQueryAudit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"events": []interface{}{}})
	}
}

func HandleExportAudit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "exporting"})
	}
}

func HandleAuditBatch(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
	}
}
