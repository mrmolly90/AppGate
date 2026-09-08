-- AppGate Database Schema

CREATE TYPE audit_level AS ENUM ('info', 'warning', 'error', 'critical');
CREATE TYPE audit_event_type AS ENUM (
    'request_received',
    'request_forwarded',
    'request_blocked',
    'rate_limit_exceeded',
    'circuit_breaker_opened',
    'circuit_breaker_closed',
    'auth_success',
    'auth_failure',
    'ssrf_blocked',
    'upstream_error',
    'timeout'
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type audit_event_type NOT NULL,
    level audit_level NOT NULL,
    client_ip INET,
    method VARCHAR(10),
    path TEXT,
    user_agent TEXT,
    status_code INTEGER,
    backend_host TEXT,
    duration_ms BIGINT,
    details JSONB,
    error_message TEXT
);

CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_level ON audit_logs(level);
CREATE INDEX idx_audit_client_ip ON audit_logs(client_ip);

-- API keys table (optional, for key-based auth)
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true
);