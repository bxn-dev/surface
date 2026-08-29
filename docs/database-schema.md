# Database schema

Surface uses SQLite schema version 3 through committed numbered migrations. Version 2 and 3 retain legacy hosted tables solely so existing databases remain compatible.

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

### Legacy compatibility tables

Migrations 2 and 3 created identity, tenancy, job, schedule, and notification tables for the removed hosted server. They remain unused and are not dropped because committed migration history and existing version-3 databases must stay readable. Local scans use the reserved `local` tenant value.

### `audit_events`

Local history deletion records immutable audit events.

## Retention

`history prune` supports age and per-target count policies, optional preservation of high/critical scans, and dry-run selection. Multiple supplied retention constraints are combined conservatively: a scan is deleted only when every supplied deletion condition matches. Selection and deletion order are deterministic.

All timestamps are UTC Unix seconds. IDs are UUIDs serialized as canonical text. Historical reports retain their original schema version and are deserialized through the public `ScanReport` model.

Backups use SQLite `VACUUM INTO`, integrity/schema validation, restrictive permissions, and atomic publication. Restore validates before replacement and preserves the current database until the replacement passes validation. Close processes using the database before restore.
