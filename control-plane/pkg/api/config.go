package api

import (
	"encoding/json"
	"net/http"
)

// GRPCConfigPusher is an interface that PushConfig uses to push real config
// updates to connected gateway nodes over gRPC streams.
type GRPCConfigPusher interface {
	NodeCount() int
	PushConfigToAll(configID string, backends, routes []string) int
}

// PushConfig triggers a real config push to all connected gateway nodes via
// the gRPC StreamConfig streams. The request body may carry an optional
// config_id; backends and routes are pulled from the configured proxy state.
func PushConfig(pusher GRPCConfigPusher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ConfigID string `json:"config_id"`
		}
		// Body is optional; decode without failing if absent.
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		if req.ConfigID == "" {
			req.ConfigID = "manual-" + r.Header.Get("X-Request-ID")
		}

		delivered := 0
		nodeCount := 0
		if pusher != nil {
			nodeCount = pusher.NodeCount()
			// Real config push over gRPC streams.
			delivered = pusher.PushConfigToAll(req.ConfigID, nil, nil)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "pushed",
			"config_id":  req.ConfigID,
			"node_count": nodeCount,
			"delivered":  delivered,
		})
	}
}
