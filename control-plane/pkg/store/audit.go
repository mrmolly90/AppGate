package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AuditStore manages audit log queries using SQL.
type AuditStore struct {
	db *sql.DB
}

// NewAuditStore creates a new audit store.
func NewAuditStore(db *sql.DB) *AuditStore {
	return &AuditStore{db: db}
}

// List returns paginated audit logs with filtering.
func (s *AuditStore) List(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]AuditLog, int64, error) {
	whereClause := "WHERE 1=1"
	var args []interface{}
	argIdx := 1

	if eventType, ok := filters["event_type"].(string); ok && eventType != "" {
		whereClause += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, eventType)
		argIdx++
	}
	if level, ok := filters["level"].(string); ok && level != "" {
		whereClause += fmt.Sprintf(" AND level = $%d", argIdx)
		args = append(args, level)
		argIdx++
	}
	if nodeID, ok := filters["node_id"].(string); ok && nodeID != "" {
		whereClause += fmt.Sprintf(" AND node_id = $%d", argIdx)
		args = append(args, nodeID)
		argIdx++
	}
	if from, ok := filters["from"].(string); ok && from != "" {
		whereClause += fmt.Sprintf(" AND created_at >= $%d", argIdx)
		args = append(args, from)
		argIdx++
	}
	if to, ok := filters["to"].(string); ok && to != "" {
		whereClause += fmt.Sprintf(" AND created_at <= $%d", argIdx)
		args = append(args, to)
		argIdx++
	}

	// Count
	var total int64
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_logs %s", whereClause)
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	// List
	query := fmt.Sprintf(
		`SELECT id, node_id, event_type, level, client_ip, method, path, status_code, backend_host, duration_ms, error_message, created_at 
		 FROM audit_logs %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		whereClause, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.NodeID, &l.EventType, &l.Level, &l.ClientIP, &l.Method, &l.Path, &l.StatusCode, &l.BackendHost, &l.DurationMs, &l.ErrorMessage, &l.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit log: %w", err)
		}
		logs = append(logs, l)
	}

	return logs, total, nil
}

// Summary returns aggregated statistics.
func (s *AuditStore) Summary(ctx context.Context, hours int) (map[string]interface{}, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	rows, err := s.db.QueryContext(ctx,
		`SELECT event_type, COUNT(*) as count FROM audit_logs WHERE created_at >= $1 GROUP BY event_type`, since)
	if err != nil {
		return nil, fmt.Errorf("audit summary: %w", err)
	}
	defer rows.Close()

	summary := make(map[string]interface{})
	for rows.Next() {
		var eventType string
		var count int64
		if err := rows.Scan(&eventType, &count); err != nil {
			continue
		}
		summary[eventType] = count
	}
	return summary, nil
}

// InsertBatch bulk inserts audit events.
func (s *AuditStore) InsertBatch(ctx context.Context, logs []AuditLog) error {
	if len(logs) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO audit_logs (id, node_id, event_type, level, client_ip, method, path, status_code, backend_host, duration_ms, error_message, created_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`)
	if err != nil {
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	for _, l := range logs {
		if l.ID == "" {
			l.ID = uuid.New().String()
		}
		if l.CreatedAt.IsZero() {
			l.CreatedAt = time.Now().UTC()
		}
		if _, err := stmt.ExecContext(ctx, l.ID, l.NodeID, l.EventType, l.Level, l.ClientIP, l.Method, l.Path, l.StatusCode, l.BackendHost, l.DurationMs, l.ErrorMessage, l.CreatedAt); err != nil {
			return fmt.Errorf("insert audit log: %w", err)
		}
	}

	return tx.Commit()
}
