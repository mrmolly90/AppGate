package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RequestsTotal counts all HTTP requests by status code and path.
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "appgate_control_plane_requests_total",
			Help: "Total HTTP requests to the control plane",
		},
		[]string{"status", "path"},
	)

	// RequestDuration tracks request latency in seconds.
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "appgate_control_plane_request_duration_seconds",
			Help:    "Request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"path"},
	)

	// ActiveConnections tracks the number of active connections.
	ActiveConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "appgate_control_plane_active_connections",
			Help: "Current number of active connections",
		},
	)

	// PolicyEvaluations counts policy evaluation results.
	PolicyEvaluations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "appgate_control_plane_policy_evaluations_total",
			Help: "Total policy evaluations by result",
		},
		[]string{"result"},
	)

	// AuditEvents counts audit events by type.
	AuditEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "appgate_control_plane_audit_events_total",
			Help: "Total audit events by type",
		},
		[]string{"event_type"},
	)

	// GatewayRegistrations counts gateway node registrations.
	GatewayRegistrations = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "appgate_control_plane_gateway_registrations_total",
			Help: "Total gateway node registrations",
		},
	)

	// DatabaseErrors counts database operation errors.
	DatabaseErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "appgate_control_plane_database_errors_total",
			Help: "Total database errors by operation",
		},
		[]string{"operation"},
	)
)