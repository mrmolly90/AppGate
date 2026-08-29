package audit

import (
	"time"
)

// EventType represents the type of audit event.
type EventType string

const (
	EventAuthenticationSuccess EventType = "authentication.success"
	EventAuthenticationFailure EventType = "authentication.failure"
	EventAuthorizationDenial   EventType = "authorization.denial"
	EventAuthorizationSuccess  EventType = "authorization.success"
	EventPolicyCreated         EventType = "policy.created"
	EventPolicyModified        EventType = "policy.modified"
	EventPolicyDeleted         EventType = "policy.deleted"
	EventGatewayRegistered     EventType = "gateway.registered"
	EventGatewayConfigChange   EventType = "gateway.config_changed"
	EventAdminAction           EventType = "admin.action"
	EventSecurityConfigChange  EventType = "security.config_changed"
)

// Event represents a security audit event.
type Event struct {
	ID            string            `json:"id"`
	Timestamp     time.Time         `json:"timestamp"`
	EventType     EventType         `json:"event_type"`
	ActorID       string            `json:"actor_id"`
	ActorIP       string            `json:"actor_ip,omitempty"`
	Action        string            `json:"action"`
	Resource      string            `json:"resource,omitempty"`
	Result        string            `json:"result"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Source        string            `json:"source,omitempty"`
}

// Store defines the interface for audit event storage.
type Store interface {
	Record(event *Event) error
	Query(filter EventFilter) ([]*Event, error)
}

// EventFilter defines query parameters for audit events.
type EventFilter struct {
	EventTypes []EventType `json:"event_types,omitempty"`
	Since      *time.Time  `json:"since,omitempty"`
	Until      *time.Time  `json:"until,omitempty"`
	ActorID    string      `json:"actor_id,omitempty"`
	Limit      int         `json:"limit,omitempty"`
	Offset     int         `json:"offset,omitempty"`
}