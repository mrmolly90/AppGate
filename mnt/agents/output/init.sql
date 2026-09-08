-- =============================================================================
-- AppGate Production Database Bootstrap
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Identities (admin users)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identities (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    client_secret TEXT NOT NULL DEFAULT '',
    roles         TEXT[] NOT NULL DEFAULT '{}',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- Clients (OAuth2-style API clients)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clients (
    client_id          TEXT PRIMARY KEY,
    client_secret_hash TEXT NOT NULL,
    roles              TEXT[] NOT NULL DEFAULT '{}',
    active             BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_clients_active ON clients(active);

-- -----------------------------------------------------------------------------
-- Policies
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    spec        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  TEXT NOT NULL REFERENCES identities(id)
);

-- -----------------------------------------------------------------------------
-- Policy Versions
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_versions (
    id          TEXT PRIMARY KEY,
    policy_id   TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    spec        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  TEXT NOT NULL,
    UNIQUE(policy_id, version)
);

-- -----------------------------------------------------------------------------
-- Gateways
-- -----------------------------------------------------------------------------
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

-- -----------------------------------------------------------------------------
-- Providers (LLM upstreams)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS providers (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    base_url    TEXT NOT NULL,
    auth_type   TEXT NOT NULL DEFAULT 'api_key',
    models      TEXT[] NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- Routes
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS routes (
    id          TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    methods     TEXT[] NOT NULL DEFAULT '{"POST"}',
    rate_limit  INTEGER NOT NULL DEFAULT 60,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(provider_id, path)
);

-- -----------------------------------------------------------------------------
-- Audit Events
-- -----------------------------------------------------------------------------
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

-- -----------------------------------------------------------------------------
-- Revoked Tokens
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_jti    TEXT PRIMARY KEY,
    revoked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- =============================================================================
-- Seed Data
-- =============================================================================

INSERT INTO identities (id, email, roles, enabled)
VALUES ('admin-1', 'admin@appgate.local', '{"admin","policy:write","gateway:read"}', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO clients (client_id, client_secret_hash, roles, active)
VALUES (
    'appgate-gateway-1',
    '$2a$12$fakehashforgatewayclientsecretreplaceinprod',
    '{"gateway:access","audit:read"}',
    true
)
ON CONFLICT (client_id) DO NOTHING;

INSERT INTO providers (id, name, base_url, auth_type, models, enabled)
VALUES 
    ('openai-1', 'OpenAI', 'https://api.openai.com', 'bearer', '{"gpt-4","gpt-4o","gpt-3.5-turbo"}', true),
    ('anthropic-1', 'Anthropic', 'https://api.anthropic.com', 'bearer', '{"claude-3-opus","claude-3-sonnet"}', true)
ON CONFLICT (id) DO NOTHING;