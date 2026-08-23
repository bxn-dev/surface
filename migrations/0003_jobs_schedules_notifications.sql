CREATE TABLE scan_jobs (
    job_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    creator_id TEXT NOT NULL,
    target TEXT NOT NULL,
    configuration_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at INTEGER NOT NULL,
    lease_owner TEXT,
    lease_expires_at INTEGER,
    scan_id TEXT REFERENCES scans(scan_id),
    error_text TEXT,
    idempotency_key TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
) STRICT;
CREATE INDEX scan_jobs_claim_idx ON scan_jobs(state, available_at, created_at, job_id);
CREATE INDEX scan_jobs_tenant_idx ON scan_jobs(tenant_id, created_at DESC, job_id DESC);

CREATE TABLE schedules (
    schedule_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    creator_id TEXT NOT NULL,
    target TEXT NOT NULL,
    configuration_json TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL CHECK (interval_seconds >= 300),
    next_run_at INTEGER NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    last_job_id TEXT REFERENCES scan_jobs(job_id),
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX schedules_due_idx ON schedules(enabled, next_run_at, schedule_id);

CREATE TABLE notification_endpoints (
    endpoint_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    url TEXT NOT NULL,
    event_mask TEXT NOT NULL,
    secret BLOB NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE notification_deliveries (
    delivery_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    endpoint_id TEXT NOT NULL REFERENCES notification_endpoints(endpoint_id) ON DELETE CASCADE,
    job_id TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'delivering', 'succeeded', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at INTEGER NOT NULL,
    lease_owner TEXT,
    lease_expires_at INTEGER,
    response_status INTEGER,
    error_text TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (endpoint_id, job_id)
) STRICT;
CREATE INDEX deliveries_claim_idx ON notification_deliveries(state, available_at, created_at, delivery_id);
