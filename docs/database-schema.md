# Database schema

Surface Phase 7 uses SQLite schema version 1 from `migrations/0001_scan_history.sql`.

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

### `audit_events`

Minimal immutable records for explicit scan deletion and retention deletion. Managed-mode actor, tenant, and request context will extend this table through later migrations.

## Retention

`history prune` supports age and per-target count policies, optional preservation of high/critical scans, and dry-run selection. Multiple supplied retention constraints are combined conservatively: a scan is deleted only when every supplied deletion condition matches. Selection and deletion order are deterministic.

All timestamps are UTC Unix seconds. IDs are UUIDs serialized as canonical text. Historical reports retain their original schema version and are deserialized through the public `ScanReport` model.
