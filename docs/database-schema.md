# Database schema

Surface uses SQLite schema version 3 through numbered migrations: scan history, identity/tenancy, and durable jobs/schedules/notifications.

## Migration rules

- `surface_schema_migrations` records each committed migration.
- Migrations run transactionally when `surface-storage` opens a database.
- `PRAGMA foreign_keys = ON` is enabled for every connection.
- Startup code does not create product tables outside numbered migrations.

## Tables

### `scans`

One immutable row per scan. It stores the scan ID, original and normalized target, scanner/report versions, UTC Unix timestamps, lifecycle status, finding counts, origin, and complete serialized report. The `scans_report_immutable` trigger rejects updates to `report_json`.

### `scan_findings`

Queryable finding metadata keyed by scan and deterministic report order. Foreign-key deletion cascades from `scans`.

### Identity and tenancy

`tenants`, `users`, `sessions`, `api_tokens`, and `tenant_targets` hold tenant ownership, Argon2id password hashes, opaque-token SHA-256 hashes, roles/scopes, expiry/revocation state, and explicit target-authorization attestations. Managed scan/audit queries always include tenant identity; a trigger makes persisted scan ownership immutable. Existing local records migrate to the reserved `local` tenant.

### `audit_events`

Immutable tenant-scoped records include action, outcome, resource, actor kind/ID, request ID, and bounded metadata.

### Durable execution

`scan_jobs` uses deterministic claim ordering, idempotency keys, bounded attempts, and expiring worker leases. `schedules` use fixed intervals and atomically materialize at most one due job per pass. `notification_endpoints` and `notification_deliveries` hold HTTPS webhook configuration and leased retry state.

## Retention

`history prune` supports age and per-target count policies, optional preservation of high/critical scans, and dry-run selection. Multiple supplied retention constraints are combined conservatively: a scan is deleted only when every supplied deletion condition matches. Selection and deletion order are deterministic.

All timestamps are UTC Unix seconds. IDs are UUIDs serialized as canonical text. Historical reports retain their original schema version and are deserialized through the public `ScanReport` model.

Backups use SQLite `VACUUM INTO`, integrity/schema validation, restrictive permissions, and atomic publication. Restore validates before replacement and preserves the current database until the replacement passes validation. Stop `surface-server` before restore.
