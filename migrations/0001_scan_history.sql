CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY NOT NULL,
    original_target TEXT NOT NULL,
    normalized_target TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    report_schema_version TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    status TEXT NOT NULL,
    interrupted INTEGER NOT NULL CHECK (interrupted IN (0, 1)),
    finding_info_count INTEGER NOT NULL DEFAULT 0,
    finding_low_count INTEGER NOT NULL DEFAULT 0,
    finding_medium_count INTEGER NOT NULL DEFAULT 0,
    finding_high_count INTEGER NOT NULL DEFAULT 0,
    finding_critical_count INTEGER NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'cli',
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE scan_findings (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_index INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_index)
) STRICT;

CREATE INDEX scans_target_started_idx
    ON scans(normalized_target, started_at DESC, scan_id DESC);
CREATE INDEX scans_status_started_idx
    ON scans(status, started_at DESC, scan_id DESC);
CREATE INDEX scan_findings_severity_idx
    ON scan_findings(severity, scan_id);

CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    occurred_at INTEGER NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    outcome TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX audit_events_occurred_idx
    ON audit_events(occurred_at DESC, event_id DESC);

CREATE TRIGGER scans_report_immutable
BEFORE UPDATE OF report_json ON scans
BEGIN
    SELECT RAISE(ABORT, 'historical scan reports are immutable');
END;
