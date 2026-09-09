package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"appgate-control-plane/internal/leader"
	"appgate-control-plane/internal/store"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

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
