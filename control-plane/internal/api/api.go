package api

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
)

// ── Helper ──────────────────────────────────────────────────────────────────

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

// WriteJSONError is the exported version of writeJSONError, usable from other
// packages (e.g. cmd/server) that need consistent error responses.
func WriteJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSONError(w, status, code, message)
}

// ── Policy ──────────────────────────────────────────────────────────────────

type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Action      string    `json:"action"`
	Condition   string    `json:"condition"`
	Priority    int       `json:"priority"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func HandleListPolicies(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		rows, err := db.QueryContext(ctx,
			`SELECT id, name, description, action, condition, priority, enabled, created_at, updated_at 
			 FROM policies WHERE enabled = true ORDER BY priority DESC`)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		defer rows.Close()

		var policies []Policy
		for rows.Next() {
			var p Policy
			if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Action, &p.Condition, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "scan_error", err.Error())
				return
			}
			policies = append(policies, p)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"policies": policies})
	}
}

func HandleCreatePolicy(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

		var p Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if p.Name == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "name is required")
			return
		}
		// Validate action against DB CHECK constraint
		validActions := map[string]bool{"allow": true, "deny": true, "rate_limit": true}
		if !validActions[p.Action] {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "action must be one of: allow, deny, rate_limit")
			return
		}

		p.ID = uuid.New().String()
		p.CreatedAt = time.Now().UTC()
		p.UpdatedAt = p.CreatedAt

		_, err := db.ExecContext(r.Context(),
			`INSERT INTO policies (id, name, description, action, condition, priority, enabled, created_at, updated_at) 
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			p.ID, p.Name, p.Description, p.Action, p.Condition, p.Priority, p.Enabled, p.CreatedAt, p.UpdatedAt)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(p)
	}
}

func HandleGetPolicy(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		var p Policy
		err := db.QueryRowContext(r.Context(),
			`SELECT id, name, description, action, condition, priority, enabled, created_at, updated_at 
			 FROM policies WHERE id = $1`, id).Scan(
			&p.ID, &p.Name, &p.Description, &p.Action, &p.Condition, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		} else if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	}
}

func HandleUpdatePolicy(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

		var p Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		// Validate action if provided
		if p.Action != "" {
			validActions := map[string]bool{"allow": true, "deny": true, "rate_limit": true}
			if !validActions[p.Action] {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "action must be one of: allow, deny, rate_limit")
				return
			}
		}

		p.UpdatedAt = time.Now().UTC()

		res, err := db.ExecContext(r.Context(),
			`UPDATE policies SET name=$1, description=$2, action=$3, condition=$4, priority=$5, enabled=$6, updated_at=$7 
			 WHERE id=$8`,
			p.Name, p.Description, p.Action, p.Condition, p.Priority, p.Enabled, p.UpdatedAt, id)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}

		rowsAffected, err := res.RowsAffected()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		if rowsAffected == 0 {
			writeJSONError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "updated", "id": id})
	}
}

func HandleDeletePolicy(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		res, err := db.ExecContext(r.Context(), `DELETE FROM policies WHERE id = $1`, id)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		if rowsAffected == 0 {
			writeJSONError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func HandleValidatePolicy(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		var exists bool
		err := db.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM policies WHERE id = $1 AND enabled = true)`, id).Scan(&exists)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if exists {
			json.NewEncoder(w).Encode(map[string]string{"status": "valid", "id": id})
		} else {
			writeJSONError(w, http.StatusNotFound, "not_found", "policy not found or disabled")
		}
	}
}

// ── Gateway handlers — Redis-backed ─────────────────────────────────────────

func HandleListGateways(redisClient *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Use SCAN instead of KEYS for production safety (KEYS is O(N) and blocks)
		var result []map[string]string
		var cursor uint64
		for {
			keys, nextCursor, err := redisClient.Scan(ctx, cursor, "gateway:*", 100).Result()
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
				return
			}
			for _, key := range keys {
				data, err := redisClient.HGetAll(ctx, key).Result()
				if err != nil {
					continue
				}
				data["id"] = key
				result = append(result, data)
			}
			cursor = nextCursor
			if cursor == 0 {
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"gateways": result})
	}
}

// Audit handlers — production implementation
func HandleQueryAudit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
			if limit > 1000 {
				limit = 1000
			}
		}

		rows, err := db.QueryContext(r.Context(),
			`SELECT id, timestamp, event_type, actor_id, action, resource, result, correlation_id, source, metadata::text
			 FROM audit_events ORDER BY timestamp DESC LIMIT $1`, limit)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		defer rows.Close()

		var events []map[string]interface{}
		for rows.Next() {
			var id, eventType, actorID, action, resource, result, correlationID, source string
			var timestamp time.Time
			var metadataStr string
			if err := rows.Scan(&id, &timestamp, &eventType, &actorID, &action, &resource, &result, &correlationID, &source, &metadataStr); err != nil {
				continue
			}
			entry := map[string]interface{}{
				"id": id, "timestamp": timestamp, "event_type": eventType,
				"actor_id": actorID, "action": action, "resource": resource,
				"result": result, "correlation_id": correlationID, "source": source,
			}
			var metadata map[string]interface{}
			if json.Unmarshal([]byte(metadataStr), &metadata) == nil {
				entry["metadata"] = metadata
			}
			events = append(events, entry)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"events": events})
	}
}

func HandleExportAudit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="audit-export.csv"`)

		// Bound the export to prevent OOM: 100k rows max, streamed row by row.
		limit := 100000
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000000 {
				limit = parsed
			}
		}

		rows, err := db.QueryContext(r.Context(),
			`SELECT id, timestamp, event_type, actor_id, action, resource, result, correlation_id, source, metadata::text
			 FROM audit_events ORDER BY timestamp DESC LIMIT $1`, limit)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		defer rows.Close()

		writer := csv.NewWriter(w)
		defer writer.Flush()

		writer.Write([]string{"id", "timestamp", "event_type", "actor_id", "action", "resource", "result", "correlation_id", "source", "metadata"})
		for rows.Next() {
			var id, eventType, actorID, action, resource, result, correlationID, source, metadataStr string
			var timestamp time.Time
			if err := rows.Scan(&id, &timestamp, &eventType, &actorID, &action, &resource, &result, &correlationID, &source, &metadataStr); err != nil {
				continue
			}
			writer.Write([]string{id, timestamp.Format(time.RFC3339), eventType, actorID, action, resource, result, correlationID, source, metadataStr})
		}
	}
}

func HandleAuditBatch(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var events []map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		committed := false
		defer func() {
			if !committed {
				tx.Rollback()
			}
		}()

		stmt, err := tx.PrepareContext(r.Context(),
			`INSERT INTO audit_events (id, event_type, actor_id, action, resource, result, correlation_id, source, metadata) 
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		defer stmt.Close()

		// Cap batch size to bound memory and transaction duration.
		if len(events) > 10000 {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "batch exceeds maximum of 10000 events")
			return
		}

		for _, ev := range events {
			metaRaw := ev["metadata"]
			metaJSON := []byte("{}")
			if metaRaw != nil {
				metaJSON, _ = json.Marshal(metaRaw)
			}
			_, err := stmt.ExecContext(r.Context(),
				uuid.New().String(), ev["event_type"], ev["actor_id"], ev["action"], ev["resource"], ev["result"], ev["correlation_id"], ev["source"], metaJSON)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
				return
			}
		}

		if err := tx.Commit(); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "database_error", err.Error())
			return
		}
		committed = true

		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "count": fmt.Sprintf("%d", len(events))})
	}
}

// ── gRPC Server ──────────────────────────────────────────────────────────────
// NOTE: GRPCServer is defined in pkg/api/grpc.go to avoid duplicate symbol.
// Import and use from that package.
