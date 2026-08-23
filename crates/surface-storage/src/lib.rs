//! Persists immutable Surface reports and queryable scan history in `SQLite`.

mod backup;
mod identity;
mod jobs;
mod scheduling;

pub use backup::{backup_database, restore_database, verify_database};
pub use identity::{
    ActorContext, AuditEvent, AuditFilter, AuthenticatedActor, Role, TenantId, UserRecord,
};
pub use jobs::{JobState, ScanJob};
pub use scheduling::NotificationDelivery;

use std::fmt;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use surface_core::{ScanReport, ScanStatus, Severity};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

// Rust guideline compliant 2026-02-21

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../../../migrations/0001_scan_history.sql")),
    (
        2,
        include_str!("../../../migrations/0002_identity_tenancy.sql"),
    ),
    (
        3,
        include_str!("../../../migrations/0003_jobs_schedules_notifications.sql"),
    ),
];
const DEFAULT_PAGE_SIZE: u32 = 50;
const MAX_PAGE_SIZE: u32 = 500;

/// Reports a storage or serialized-report failure.
#[derive(Debug)]
pub struct Error {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    fn with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// A compact persisted-scan summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanSummary {
    /// Unique scan identifier.
    pub scan_id: Uuid,
    /// Original target supplied by the operator.
    pub original_target: String,
    /// Canonical hostname or IP address.
    pub normalized_target: String,
    /// Report lifecycle status.
    pub status: String,
    /// Scan start time as a Unix timestamp.
    pub started_at: i64,
    /// Completion time as a Unix timestamp.
    pub completed_at: Option<i64>,
    /// Number of high-severity findings.
    pub high_findings: u32,
    /// Number of critical findings.
    pub critical_findings: u32,
    /// Scan origin.
    pub origin: String,
}

/// Filters deterministic history listings.
#[derive(Debug, Clone, Default)]
pub struct HistoryFilter {
    /// Exact normalized target match.
    pub target: Option<String>,
    /// Exact serialized status match.
    pub status: Option<String>,
    /// Minimum finding severity required.
    pub minimum_severity: Option<Severity>,
    /// Include scans started at or after this Unix timestamp.
    pub started_after: Option<i64>,
    /// Include scans started at or before this Unix timestamp.
    pub started_before: Option<i64>,
    /// Zero-based result offset.
    pub offset: u32,
    /// Requested page size, capped at 500.
    pub limit: u32,
}

/// Configures transactional history retention.
#[derive(Debug, Clone, Default)]
pub struct RetentionPolicy {
    /// Retain this many newest scans per target.
    pub keep_last: Option<u32>,
    /// Delete scans older than this duration.
    pub older_than: Option<Duration>,
    /// Preserve scans containing high or critical findings.
    pub preserve_high: bool,
    /// Report candidates without deleting them.
    pub dry_run: bool,
}

/// Result of retention candidate selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetentionResult {
    /// Scan identifiers selected by the policy.
    pub scan_ids: Vec<Uuid>,
    /// Whether rows were actually deleted.
    pub deleted: bool,
}

/// SQLite-backed immutable scan history.
#[derive(Debug)]
pub struct Storage {
    connection: Connection,
}

impl Storage {
    /// Opens a database and applies committed migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot open or migrate the database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let mut connection = Connection::open(path)
            .map_err(|error| Error::with_source("could not open Surface database", error))?;
        secure_database(path)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(|error| Error::with_source("could not enable SQLite foreign keys", error))?;
        apply_migrations(&mut connection)?;
        Ok(Self { connection })
    }

    /// Stores a complete immutable report and normalized finding metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for serialization failures or duplicate scan identifiers.
    pub fn persist_report(&mut self, report: &ScanReport, origin: &str) -> Result<(), Error> {
        self.persist_report_for_tenant("local", report, origin)
    }

    fn persist_report_for_tenant(
        &mut self,
        tenant_id: &str,
        report: &ScanReport,
        origin: &str,
    ) -> Result<(), Error> {
        let report_json = serde_json::to_string(report)
            .map_err(|error| Error::with_source("could not serialize scan report", error))?;
        let normalized_target = normalized_target(report);
        let counts = finding_counts(report);
        let transaction = self.connection.transaction().map_err(|error| {
            Error::with_source("could not start report persistence transaction", error)
        })?;
        transaction
            .execute(
                "INSERT INTO scans (
                    scan_id, original_target, normalized_target, scanner_version,
                    report_schema_version, started_at, completed_at, status, interrupted,
                    finding_info_count, finding_low_count, finding_medium_count,
                    finding_high_count, finding_critical_count, report_json, origin, created_at,
                    tenant_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    report.scan_id.to_string(),
                    report.target.original,
                    normalized_target,
                    report.scanner_version,
                    report.schema_version,
                    report.started_at.unix_timestamp(),
                    report.completed_at.map(OffsetDateTime::unix_timestamp),
                    status_name(report.status),
                    i64::from(report.status == ScanStatus::Interrupted),
                    counts[0], counts[1], counts[2], counts[3], counts[4],
                    report_json,
                    origin,
                    OffsetDateTime::now_utc().unix_timestamp(),
                    tenant_id,
                ],
            )
            .map_err(|error| Error::with_source("could not persist scan report", error))?;
        for (index, finding) in report.findings.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO scan_findings
                     (scan_id, finding_index, rule_id, severity, target, title)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        report.scan_id.to_string(),
                        index,
                        finding.id,
                        severity_name(finding.severity),
                        finding.target,
                        finding.title,
                    ],
                )
                .map_err(|error| Error::with_source("could not persist scan findings", error))?;
        }
        transaction
            .commit()
            .map_err(|error| Error::with_source("could not commit scan report", error))
    }

    /// Loads a complete historical report by scan identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the query or report deserialization fails.
    pub fn report(&self, scan_id: Uuid) -> Result<Option<ScanReport>, Error> {
        let json = self
            .connection
            .query_row(
                "SELECT report_json FROM scans WHERE scan_id = ?1",
                [scan_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| Error::with_source("could not retrieve scan report", error))?;
        json.map(|json| {
            serde_json::from_str(&json)
                .map_err(|error| Error::with_source("stored scan report is invalid", error))
        })
        .transpose()
    }

    /// Lists persisted scans in deterministic newest-first order.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot execute or decode the query.
    pub fn history(&self, filter: &HistoryFilter) -> Result<Vec<ScanSummary>, Error> {
        let limit = if filter.limit == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            filter.limit.min(MAX_PAGE_SIZE)
        };
        let minimum_severity = filter.minimum_severity.map(severity_rank);
        let mut statement = self
            .connection
            .prepare(
                "SELECT scan_id, original_target, normalized_target, status, started_at,
                        completed_at, finding_high_count, finding_critical_count, origin
                 FROM scans
                 WHERE (?1 IS NULL OR normalized_target = ?1)
                   AND (?2 IS NULL OR status = ?2)
                   AND (?3 IS NULL OR started_at >= ?3)
                   AND (?4 IS NULL OR started_at <= ?4)
                   AND (?5 IS NULL OR
                        (?5 <= 0 AND finding_info_count > 0) OR
                        (?5 <= 1 AND finding_low_count > 0) OR
                        (?5 <= 2 AND finding_medium_count > 0) OR
                        (?5 <= 3 AND finding_high_count > 0) OR
                        (?5 <= 4 AND finding_critical_count > 0))
                 ORDER BY started_at DESC, scan_id DESC
                 LIMIT ?6 OFFSET ?7",
            )
            .map_err(|error| Error::with_source("could not prepare history query", error))?;
        let rows = statement
            .query_map(
                params![
                    filter.target,
                    filter.status,
                    filter.started_after,
                    filter.started_before,
                    minimum_severity,
                    limit,
                    filter.offset,
                ],
                scan_summary,
            )
            .map_err(|error| Error::with_source("could not query scan history", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| Error::with_source("could not decode scan history", error))
    }

    /// Deletes one historical scan and its dependent rows transactionally.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot perform the deletion.
    pub fn delete_scan(&mut self, scan_id: Uuid) -> Result<bool, Error> {
        let transaction = self.connection.transaction().map_err(|error| {
            Error::with_source("could not start scan deletion transaction", error)
        })?;
        let deleted = transaction
            .execute(
                "DELETE FROM scans WHERE scan_id = ?1",
                [scan_id.to_string()],
            )
            .map_err(|error| Error::with_source("could not delete scan", error))?
            == 1;
        if deleted {
            record_audit(&transaction, "scan.delete", Some(scan_id))?;
        }
        transaction
            .commit()
            .map_err(|error| Error::with_source("could not commit scan deletion", error))?;
        Ok(deleted)
    }

    /// Applies retention selection and optional transactional deletion.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy or `SQLite` failures.
    pub fn prune(&mut self, policy: &RetentionPolicy) -> Result<RetentionResult, Error> {
        if policy.keep_last.is_none() && policy.older_than.is_none() {
            return Err(Error::new("retention requires --keep-last or --older-than"));
        }
        let now = OffsetDateTime::now_utc();
        let cutoff = policy
            .older_than
            .map(|duration| {
                now.checked_sub(duration)
                    .map(OffsetDateTime::unix_timestamp)
                    .ok_or_else(|| Error::new("retention duration is outside the supported range"))
            })
            .transpose()?;
        let keep_last = policy.keep_last.map(i64::from);
        let mut statement = self
            .connection
            .prepare(
                "WITH ranked AS (
                    SELECT scan_id, started_at, finding_high_count, finding_critical_count,
                           ROW_NUMBER() OVER (
                               PARTITION BY normalized_target
                               ORDER BY started_at DESC, scan_id DESC
                           ) AS target_rank
                    FROM scans
                 )
                 SELECT scan_id FROM ranked
                 WHERE (?1 IS NULL OR started_at < ?1)
                   AND (?2 IS NULL OR target_rank > ?2)
                   AND (?3 = 0 OR (finding_high_count = 0 AND finding_critical_count = 0))
                 ORDER BY started_at ASC, scan_id ASC",
            )
            .map_err(|error| Error::with_source("could not prepare retention query", error))?;
        let ids = statement
            .query_map(params![cutoff, keep_last, policy.preserve_high], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| Error::with_source("could not select retention candidates", error))?
            .map(|row| {
                row.and_then(|id| {
                    Uuid::parse_str(&id).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                })
            })
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| Error::with_source("could not decode retention candidates", error))?;
        drop(statement);
        if !policy.dry_run && !ids.is_empty() {
            let transaction = self.connection.transaction().map_err(|error| {
                Error::with_source("could not start retention transaction", error)
            })?;
            for id in &ids {
                transaction
                    .execute("DELETE FROM scans WHERE scan_id = ?1", [id.to_string()])
                    .map_err(|error| Error::with_source("could not prune scan", error))?;
                record_audit(&transaction, "retention.delete", Some(*id))?;
            }
            transaction
                .commit()
                .map_err(|error| Error::with_source("could not commit retention", error))?;
        }
        Ok(RetentionResult {
            scan_ids: ids,
            deleted: !policy.dry_run,
        })
    }
}

#[cfg(unix)]
fn secure_database(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    if path != Path::new(":memory:") {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| Error::with_source("could not restrict Surface database permissions", error),
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_database(_path: &Path) -> Result<(), Error> {
    Ok(())
}

fn record_audit(
    transaction: &rusqlite::Transaction<'_>,
    action: &str,
    resource_id: Option<Uuid>,
) -> Result<(), Error> {
    transaction
        .execute(
            "INSERT INTO audit_events
             (event_id, occurred_at, action, resource_type, resource_id, outcome)
             VALUES (?1, ?2, ?3, 'scan', ?4, 'success')",
            params![
                Uuid::new_v4().to_string(),
                OffsetDateTime::now_utc().unix_timestamp(),
                action,
                resource_id.map(|id| id.to_string()),
            ],
        )
        .map_err(|error| Error::with_source("could not record audit event", error))?;
    Ok(())
}

fn apply_migrations(connection: &mut Connection) -> Result<(), Error> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS surface_schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL,
                applied_at INTEGER NOT NULL
             ) STRICT;",
        )
        .map_err(|error| Error::with_source("could not initialize migrations", error))?;
    let latest_supported = MIGRATIONS.last().map_or(0, |(version, _)| *version);
    let latest_applied = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM surface_schema_migrations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| Error::with_source("could not inspect migration version", error))?;
    if latest_applied > latest_supported {
        return Err(Error::new(format!(
            "database schema version {latest_applied} is newer than supported version {latest_supported}"
        )));
    }
    for &(version, sql) in MIGRATIONS {
        let applied = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM surface_schema_migrations WHERE version = ?1)",
                [version],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| Error::with_source("could not inspect migration state", error))?;
        if applied {
            continue;
        }
        let transaction = connection
            .transaction()
            .map_err(|error| Error::with_source("could not start migration", error))?;
        transaction
            .execute_batch(sql)
            .map_err(|error| Error::with_source(format!("migration {version} failed"), error))?;
        transaction
            .execute(
                "INSERT INTO surface_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![version, OffsetDateTime::now_utc().unix_timestamp()],
            )
            .map_err(|error| Error::with_source("could not record migration", error))?;
        transaction
            .commit()
            .map_err(|error| Error::with_source("could not commit migration", error))?;
    }
    Ok(())
}

fn normalized_target(report: &ScanReport) -> String {
    report.target.identity()
}

fn finding_counts(report: &ScanReport) -> [i64; 5] {
    let mut counts = [0; 5];
    for finding in &report.findings {
        let index = match finding.severity {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };
        counts[index] += 1;
    }
    counts
}

const fn severity_rank(severity: Severity) -> i64 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

const fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

const fn status_name(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::NotStarted => "not_started",
        ScanStatus::Completed => "completed",
        ScanStatus::Partial => "partial",
        ScanStatus::Interrupted => "interrupted",
        ScanStatus::Failed => "failed",
    }
}

fn scan_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanSummary> {
    let id: String = row.get(0)?;
    let scan_id = Uuid::parse_str(&id).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ScanSummary {
        scan_id,
        original_target: row.get(1)?,
        normalized_target: row.get(2)?,
        status: row.get(3)?,
        started_at: row.get(4)?,
        completed_at: row.get(5)?,
        high_findings: row.get(6)?,
        critical_findings: row.get(7)?,
        origin: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use surface_core::{normalize_target, ScanConfiguration, ScanReport, ScanStatus};
    use tempfile::tempdir;

    use super::{HistoryFilter, RetentionPolicy, Storage};

    fn report(target: &str) -> ScanReport {
        let mut report = ScanReport::not_started(
            normalize_target(target).unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![80],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
        );
        report.status = ScanStatus::Completed;
        report.completed_at = Some(time::OffsetDateTime::now_utc());
        report
    }

    #[test]
    fn migrates_and_round_trips_immutable_reports() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("surface.db");
        let mut storage = Storage::open(&path).unwrap_or_else(|error| panic!("{error}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(&path)
                    .unwrap_or_else(|error| panic!("{error}"))
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(
            storage
                .connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0)),
            Ok(true)
        );
        assert_eq!(
            storage.connection.query_row(
                "SELECT COUNT(*) FROM surface_schema_migrations",
                [],
                |row| row.get::<_, i64>(0)
            ),
            Ok(3)
        );
        let report = report("example.com");
        storage
            .persist_report(&report, "cli")
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            storage
                .report(report.scan_id)
                .unwrap_or_else(|error| panic!("{error}")),
            Some(report.clone())
        );
        assert_eq!(
            storage
                .history(&HistoryFilter::default())
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        assert!(storage.persist_report(&report, "cli").is_err());
    }

    #[test]
    fn rejects_newer_database_schema() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("future.db");
        let connection =
            rusqlite::Connection::open(&path).unwrap_or_else(|error| panic!("{error}"));
        connection
            .execute_batch(
                "CREATE TABLE surface_schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL,
                    applied_at INTEGER NOT NULL
                 ) STRICT;
                 INSERT INTO surface_schema_migrations VALUES (4, 0);",
            )
            .unwrap_or_else(|error| panic!("{error}"));
        drop(connection);

        let error = Storage::open(&path).expect_err("future schema must be rejected");
        assert!(error.to_string().contains("newer than supported"));
    }

    #[test]
    fn retention_dry_run_preserves_data() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));
        let report = report("example.com");
        storage
            .persist_report(&report, "cli")
            .unwrap_or_else(|error| panic!("{error}"));
        let result = storage
            .prune(&RetentionPolicy {
                keep_last: Some(0),
                dry_run: true,
                ..RetentionPolicy::default()
            })
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(result.scan_ids, vec![report.scan_id]);
        assert!(storage.report(report.scan_id).unwrap_or(None).is_some());
    }

    #[test]
    fn rejects_retention_duration_outside_timestamp_range() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(storage
            .prune(&RetentionPolicy {
                older_than: Some(time::Duration::seconds(i64::MAX)),
                ..RetentionPolicy::default()
            })
            .is_err());
    }

    #[test]
    fn foreign_keys_delete_dependent_findings() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));
        let report = report("example.com");
        storage
            .persist_report(&report, "cli")
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(storage.delete_scan(report.scan_id).unwrap_or(false));
        assert!(storage.report(report.scan_id).unwrap_or(None).is_none());
        assert_eq!(
            storage.connection.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'scan.delete'",
                [],
                |row| row.get::<_, i64>(0)
            ),
            Ok(1)
        );
    }
}
