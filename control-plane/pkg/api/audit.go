package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"appgate-control-plane/pkg/store"
)

// ListAuditLogs returns paginated audit logs
func ListAuditLogs(s *store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filters := make(map[string]interface{})

		if t := r.URL.Query().Get("event_type"); t != "" {
			filters["event_type"] = t
		}
		if l := r.URL.Query().Get("level"); l != "" {
			filters["level"] = l
		}
		if node := r.URL.Query().Get("node_id"); node != "" {
			filters["node_id"] = node
		}
		if from := r.URL.Query().Get("from"); from != "" {
			filters["from"] = from
		}
		if to := r.URL.Query().Get("to"); to != "" {
			filters["to"] = to
		}

		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 50
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

		logs, total, err := s.List(r.Context(), filters, limit, offset)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":   logs,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
	}
}

// AuditSummary returns aggregated stats
func AuditSummary(s *store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
		if hours <= 0 {
			hours = 24
		}
		summary, err := s.Summary(r.Context(), hours)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": summary})
	}
}
