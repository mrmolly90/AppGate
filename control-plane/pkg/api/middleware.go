package api

import (
	"net/http"
	"time"

	"go.uber.org/zap"
)

// LoggerMiddleware provides structured logging for admin API
func LoggerMiddleware(logger *zap.SugaredLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			path := r.URL.Path
			raw := r.URL.RawQuery

			next.ServeHTTP(w, r)

			latency := time.Since(start)
			clientIP := r.RemoteAddr
			method := r.Method

			if raw != "" {
				path = path + "?" + raw
			}

			logger.Infow("admin-api",
				"client_ip", clientIP,
				"method", method,
				"path", path,
				"latency_ms", latency.Milliseconds(),
			)
		})
	}
}
