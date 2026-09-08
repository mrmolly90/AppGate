// AppGate Control Plane — Metrics Collector
// Provides Prometheus-compatible metrics for the control plane.

package metrics

import (
	"fmt"
	"net/http"
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "appgate_control_plane_requests_total",
		Help: "Total HTTP requests processed",
	}, []string{"method", "path", "status"})

	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "appgate_control_plane_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "appgate_control_plane_active_connections",
		Help: "Number of active connections",
	})

	leaderStatus = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "appgate_control_plane_leader_status",
		Help: "1 if this instance is the leader, 0 otherwise",
	})

	policyViolations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "appgate_control_plane_policy_violations_total",
		Help: "Total policy violations by project and type",
	}, []string{"project", "violation_type"})

	upstreamErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "appgate_control_plane_upstream_errors_total",
		Help: "Total upstream errors by project, upstream, and error type",
	}, []string{"project", "upstream", "error_type"})

	upstreamRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "appgate_control_plane_upstream_request_duration_seconds",
		Help:    "Upstream request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"project", "upstream", "model"})
)

func init() {
	prometheus.MustRegister(requestsTotal, requestDuration, activeConnections,
		leaderStatus, policyViolations, upstreamErrors, upstreamRequestDuration)
}

// Handler returns the Prometheus metrics HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// RecordRequest records an HTTP request metric with upstream context.
func RecordRequest(project, upstream, model string, statusCode int, duration float64, inputTokens, outputTokens int) {
	requestsTotal.WithLabelValues("POST", "/v1/chat/completions", fmt.Sprintf("%d", statusCode)).Inc()
	upstreamRequestDuration.WithLabelValues(project, upstream, model).Observe(duration)
}

// RecordPolicyViolation records a policy violation.
func RecordPolicyViolation(project, violationType string) {
	policyViolations.WithLabelValues(project, violationType).Inc()
}

// RecordUpstreamError records an upstream error.
func RecordUpstreamError(project, upstream, errorType string) {
	upstreamErrors.WithLabelValues(project, upstream, errorType).Inc()
}

// SetLeaderStatus sets the leader status gauge.
func SetLeaderStatus(isLeader bool) {
	if isLeader {
		leaderStatus.Set(1)
	} else {
		leaderStatus.Set(0)
	}
}

// GetGoMetrics returns Go runtime metrics.
func GetGoMetrics() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]interface{}{
		"goroutines": runtime.NumGoroutine(),
		"heap_alloc": m.HeapAlloc,
		"heap_sys":   m.HeapSys,
		"gc_count":   m.NumGC,
	}
}
