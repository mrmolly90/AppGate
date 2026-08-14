package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Postgres wraps a PostgreSQL connection.
type Postgres struct {
	db *sql.DB
}

// NewPostgres creates a new PostgreSQL connection.
func NewPostgres(databaseURL string) (*Postgres, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Postgres{db: db}, nil
}

// Ping checks database connectivity.
func (p *Postgres) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.db.PingContext(ctx)
}

// Close closes the database connection.
func (p *Postgres) Close() error {
	return p.db.Close()
}

// DB returns the underlying sql.DB.
func (p *Postgres) DB() *sql.DB {
	return p.db
}

// Migrate runs database migrations.
func (p *Postgres) Migrate() error {
	migrations := []string{
		createIdentitiesTable,
		createPoliciesTable,
		createPolicyVersionsTable,
		createGatewaysTable,
		createProvidersTable,
		createRoutesTable,
		createAuditEventsTable,
	}

	for i, m := range migrations {
		if _, err := p.db.Exec(m); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}

	return nil
}

const createIdentitiesTable = `
CREATE TABLE IF NOT EXISTS identities (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    client_secret TEXT NOT NULL DEFAULT '',
    roles         TEXT[] NOT NULL DEFAULT '{}',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`

const createPoliciesTable = `
CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    spec        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  TEXT NOT NULL REFERENCES identities(id)
);
`

const createPolicyVersionsTable = `
CREATE TABLE IF NOT EXISTS policy_versions (
    id          TEXT PRIMARY KEY,
    policy_id   TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    spec        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  TEXT NOT NULL,
    UNIQUE(policy_id, version)
);
`

const createGatewaysTable = `
CREATE TABLE IF NOT EXISTS gateways (
    id              TEXT PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    version         TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    last_seen_at    TIMESTAMPTZ,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata        JSONB NOT NULL DEFAULT '{}'
);
`

const createProvidersTable = `
CREATE TABLE IF NOT EXISTS providers (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    base_url    TEXT NOT NULL,
    auth_type   TEXT NOT NULL DEFAULT 'api_key',
    models      TEXT[] NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`

const createRoutesTable = `
CREATE TABLE IF NOT EXISTS routes (
    id          TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    methods     TEXT[] NOT NULL DEFAULT '{"POST"}',
    rate_limit  INTEGER NOT NULL DEFAULT 60,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(provider_id, path)
);
`

const createAuditEventsTable = `
CREATE TABLE IF NOT EXISTS audit_events (
    id              TEXT PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type      TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    actor_ip        TEXT,
    action          TEXT NOT NULL,
    resource        TEXT,
    result          TEXT NOT NULL,
    correlation_id  TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    source          TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_id ON audit_events(actor_id);
`