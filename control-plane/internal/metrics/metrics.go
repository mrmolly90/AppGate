// Package metrics exposes Prometheus metrics for the AppGate control plane.
package metrics

import (
    "net/http"
    "strconv"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_requests_total",
        Help: "Total LLM proxy requests",
    }, []string{"project", "upstream", "model", "status"})

    requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "appgate_request_duration_seconds",
        Help:    "Request latency distribution",
        Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
    }, []string{"project", "upstream"})

    tokensInput = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_tokens_input_total",
        Help: "Input tokens consumed",
    }, []string{"project", "model"})

    tokensOutput = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_tokens_output_total",
        Help: "Output tokens consumed",
    }, []string{"project", "model"})

    violationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_violations_total",
        Help: "Security policy violations",
    }, []string{"project", "violation_type"})

    rateLimitHits = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_rate_limit_hits_total",
        Help: "Rate limit rejections",
    }, []string{"project"})

    upstreamErrors = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_upstream_errors_total",
        Help: "Upstream LLM provider errors",
    }, []string{"project", "upstream", "error_type"})

    activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "appgate_active_connections",
        Help: "Current active connections",
    })
)

func Handler() http.Handler {
    return promhttp.Handler()
}

func RecordRequest(project, upstream, model string, status int, duration float64, inputTokens, outputTokens int) {
    statusStr := strconv.Itoa(status)
    requestsTotal.WithLabelValues(project, upstream, model, statusStr).Inc()
    requestDuration.WithLabelValues(project, upstream).Observe(duration)
    tokensInput.WithLabelValues(project, model).Add(float64(inputTokens))
    tokensOutput.WithLabelValues(project, model).Add(float64(outputTokens))
}

func RecordTokenUsage(project, model string, inputTokens, outputTokens int) {
    tokensInput.WithLabelValues(project, model).Add(float64(inputTokens))
    tokensOutput.WithLabelValues(project, model).Add(float64(outputTokens))
}

func RecordViolation(project, violationType string) {
    violationsTotal.WithLabelValues(project, violationType).Inc()
}

func RecordRateLimitHit(project string) {
    rateLimitHits.WithLabelValues(project).Inc()
}

func RecordUpstreamError(project, upstream, errorType string) {
    upstreamErrors.WithLabelValues(project, upstream, errorType).Inc()
}

func IncActiveConnections() {
    activeConnections.Inc()
}

func DecActiveConnections() {
    activeConnections.Dec()
}
