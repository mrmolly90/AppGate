package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
)

// ListNodes returns connected gateway nodes from Redis
func ListNodes(redisClient *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var nodes []map[string]string
		var cursor uint64
		for {
			keys, nextCursor, err := redisClient.Scan(ctx, cursor, "node:*", 100).Result()
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
				nodes = append(nodes, data)
			}
			cursor = nextCursor
			if cursor == 0 {
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": nodes})
	}
}

// DrainNode sends drain command to a gateway node via Redis list.
// Using RPUSH (not HSet) so multiple commands can be queued without overwriting.
func DrainNode(redisClient *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		nodeID := vars["id"]
		ctx := r.Context()

		cmd := map[string]string{
			"command":   "drain",
			"issued_at": time.Now().UTC().Format(time.RFC3339),
		}
		cmdJSON, err := json.Marshal(cmd)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "marshal_error", err.Error())
			return
		}

		err = redisClient.RPush(ctx, "node:"+nodeID+":commands", cmdJSON).Err()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "drain command issued"})
	}
}

// ReloadNode sends config reload command via Redis list.
func ReloadNode(redisClient *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		nodeID := vars["id"]
		ctx := r.Context()

		cmd := map[string]string{
			"command":   "reload",
			"issued_at": time.Now().UTC().Format(time.RFC3339),
		}
		cmdJSON, err := json.Marshal(cmd)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "marshal_error", err.Error())
			return
		}

		err = redisClient.RPush(ctx, "node:"+nodeID+":commands", cmdJSON).Err()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "reload command issued"})
	}
}
