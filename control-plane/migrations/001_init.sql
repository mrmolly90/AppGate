-- AppGate Control Plane — Database Schema
-- PostgreSQL 15+ required
-- =============================================================================
-- This migration creates all tables needed by the control plane.
-- =============================================================================

-- ── Extensions ──────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Policies ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(128) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    action      VARCHAR(16) NOT NULL CHECK (action IN ('allow', 'deny', 'rate_limit')),
    condition   JSONB NOT NULL DEFAULT '{}',
    priority    INTEGER NOT NULL DEFAULT 0,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_enabled_priority ON policies (enabled, priority DESC);
CREATE INDEX idx_policies_name ON policies (name);

-- ── Audit Events ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type      VARCHAR(64) NOT NULL,
    actor_id        VARCHAR(128) NOT NULL DEFAULT '',
    action          VARCHAR(64) NOT NULL DEFAULT '',
    resource        VARCHAR(256) NOT NULL DEFAULT '',
    result          VARCHAR(16) NOT NULL DEFAULT 'allowed',
    correlation_id  VARCHAR(64) NOT NULL DEFAULT '',
    source          VARCHAR(64) NOT NULL DEFAULT 'gateway',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_events_timestamp ON audit_events (timestamp DESC);
CREATE INDEX idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX idx_audit_events_actor ON audit_events (actor_id);
CREATE INDEX idx_audit_events_correlation ON audit_events (correlation_id);

-- ── Audit Logs (for pkg/store/audit.go) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         VARCHAR(64) NOT NULL DEFAULT '',
    event_type      VARCHAR(64) NOT NULL,
    level           VARCHAR(16) NOT NULL DEFAULT 'info',
    client_ip       VARCHAR(45) NOT NULL DEFAULT '',
    method          VARCHAR(10) NOT NULL DEFAULT '',
    path            TEXT NOT NULL DEFAULT '',
    status_code     SMALLINT,
    backend_host    VARCHAR(255) NOT NULL DEFAULT '',
    duration_ms     BIGINT,
    error_message   TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
CREATE INDEX idx_audit_logs_node ON audit_logs (node_id);

-- ── Backends ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS backends (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(128) NOT NULL,
    url         TEXT NOT NULL,
    weight      INTEGER NOT NULL DEFAULT 1,
    pool_id     VARCHAR(64) NOT NULL DEFAULT 'default',
    health_path VARCHAR(255) NOT NULL DEFAULT '/health',
    metadata    JSONB NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    healthy     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backends_pool ON backends (pool_id);
CREATE INDEX idx_backends_enabled ON backends (enabled);

-- ── Routes ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS routes (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(128) NOT NULL,
    host          VARCHAR(255) NOT NULL DEFAULT '',
    path_prefix   VARCHAR(255) NOT NULL,
    backend_pool  VARCHAR(64) NOT NULL,
    methods       TEXT[] NOT NULL DEFAULT '{}',
    headers       JSONB NOT NULL DEFAULT '{}',
    strip_prefix  BOOLEAN NOT NULL DEFAULT false,
    priority      INTEGER NOT NULL DEFAULT 0,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_routes_enabled_priority ON routes (enabled, priority DESC);
CREATE INDEX idx_routes_path ON routes (path_prefix);

-- ── API Keys ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(128) NOT NULL,
    key_hash    VARCHAR(255) NOT NULL,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    routes      TEXT[] NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_enabled ON api_keys (enabled);
CREATE INDEX idx_api_keys_expires ON api_keys (expires_at) WHERE expires_at IS NOT NULL;

-- ── Gateway Nodes (Redis-backed, but keep a registry table) ─────────────────
CREATE TABLE IF NOT EXISTS gateway_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         VARCHAR(128) NOT NULL UNIQUE,
    version         VARCHAR(32) NOT NULL DEFAULT '',
    region          VARCHAR(64) NOT NULL DEFAULT '',
    hostname        VARCHAR(255) NOT NULL DEFAULT '',
    ip_address      VARCHAR(45) NOT NULL DEFAULT '',
    status          VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'draining', 'inactive')),
    last_heartbeat  TIMESTAMPTZ,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gateway_nodes_status ON gateway_nodes (status);
CREATE INDEX idx_gateway_nodes_heartbeat ON gateway_nodes (last_heartbeat);

-- ── Seed Data ───────────────────────────────────────────────────────────────
INSERT INTO policies (name, description, action, condition, priority, enabled)
VALUES 
    ('allow-all', 'Default allow all traffic', 'allow', '{}', 0, true)
ON CONFLICT DO NOTHING;