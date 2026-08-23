CREATE TABLE tenants (
    tenant_id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    disabled_at INTEGER
) STRICT;

INSERT INTO tenants (tenant_id, name, created_at)
VALUES ('local', 'Local CLI', unixepoch());

CREATE TABLE users (
    user_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    created_at INTEGER NOT NULL,
    disabled_at INTEGER,
    UNIQUE (tenant_id, username)
) STRICT;

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    csrf_token_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
) STRICT;

CREATE TABLE api_tokens (
    token_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash BLOB NOT NULL UNIQUE,
    scopes_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
) STRICT;

CREATE TABLE tenant_targets (
    target_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    normalized_target TEXT NOT NULL,
    display_target TEXT NOT NULL,
    authorization_attested_at INTEGER NOT NULL,
    authorization_actor_id TEXT REFERENCES users(user_id),
    created_at INTEGER NOT NULL,
    UNIQUE (tenant_id, normalized_target)
) STRICT;

ALTER TABLE scans ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'local' REFERENCES tenants(tenant_id);
ALTER TABLE audit_events ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'local' REFERENCES tenants(tenant_id);
ALTER TABLE audit_events ADD COLUMN actor_id TEXT;
ALTER TABLE audit_events ADD COLUMN actor_kind TEXT NOT NULL DEFAULT 'local_cli';
ALTER TABLE audit_events ADD COLUMN request_id TEXT;

CREATE INDEX scans_tenant_started_idx
    ON scans(tenant_id, started_at DESC, scan_id DESC);
CREATE INDEX scans_tenant_target_started_idx
    ON scans(tenant_id, normalized_target, started_at DESC, scan_id DESC);
CREATE INDEX audit_events_tenant_occurred_idx
    ON audit_events(tenant_id, occurred_at DESC, event_id DESC);
CREATE INDEX sessions_token_idx ON sessions(token_hash);
CREATE INDEX api_tokens_token_idx ON api_tokens(token_hash);

CREATE TRIGGER scans_tenant_immutable
BEFORE UPDATE OF tenant_id ON scans
BEGIN
    SELECT RAISE(ABORT, 'historical scan tenant ownership is immutable');
END;
