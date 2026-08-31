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
        Help: "Total requests processed",
    }, []string{"project", "upstream", "model", "status"})

    requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "appgate_request_duration_seconds",
        Help:    "Request latency",
        Buckets: prometheus.DefBuckets,
    }, []string{"project", "upstream"})

    tokensConsumed = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_tokens_consumed_total",
        Help: "Total tokens consumed",
    }, []string{"project", "model", "token_type"})

    policyViolations = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_policy_violations_total",
        Help: "Security policy violations",
    }, []string{"project", "violation_type"})

    rateLimitHits = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_rate_limit_hits_total",
        Help: "Rate limit hits",
    }, []string{"project"})

    upstreamErrors = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "appgate_upstream_errors_total",
        Help: "Upstream LLM errors",
    }, []string{"project", "upstream", "error_type"})
)

func Handler() http.Handler {
    return promhttp.Handler()
}

func RecordRequest(project, upstream, model string, status int, duration float64, inputTokens, outputTokens int) {
    statusStr := strconv.Itoa(status)
    requestsTotal.WithLabelValues(project, upstream, model, statusStr).Inc()
    requestDuration.WithLabelValues(project, upstream).Observe(duration)
    tokensConsumed.WithLabelValues(project, model, "input").Add(float64(inputTokens))
    tokensConsumed.WithLabelValues(project, model, "output").Add(float64(outputTokens))
}

func RecordPolicyViolation(project, violationType string) {
    policyViolations.WithLabelValues(project, violationType).Inc()
}

func RecordRateLimitHit(project string) {
    rateLimitHits.WithLabelValues(project).Inc()
}

func RecordUpstreamError(project, upstream, errorType string) {
    upstreamErrors.WithLabelValues(project, upstream, errorType).Inc()
}
