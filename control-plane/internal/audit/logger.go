package audit

import (
	"go.uber.org/zap"
)

// Logger provides structured audit logging for the control plane.
type Logger struct {
	logger *zap.SugaredLogger
}

// NewLogger creates a new audit logger.
func NewLogger(logger *zap.SugaredLogger) *Logger {
	return &Logger{logger: logger}
}

// Record writes an audit event to the log.
func (l *Logger) Record(eventType, actorID, action, resource, result, correlationID, source string, metadata map[string]string) {
	fields := []interface{}{
		"event_type", eventType,
		"actor_id", actorID,
		"action", action,
		"resource", resource,
		"result", result,
		"correlation_id", correlationID,
		"source", source,
	}
	for k, v := range metadata {
		fields = append(fields, k, v)
	}
	l.logger.Infow("audit", fields...)
}

// RecordBatch writes multiple audit events in a single log call.
func (l *Logger) RecordBatch(events []map[string]interface{}) {
	for _, event := range events {
		fields := make([]interface{}, 0, len(event)*2)
		for k, v := range event {
			fields = append(fields, k, v)
		}
		l.logger.Infow("audit", fields...)
	}
}