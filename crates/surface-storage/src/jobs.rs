use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use surface_core::ScanConfiguration;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Error, Storage, TenantId};

const MAX_ATTEMPTS: i64 = 3;
const MAX_ERROR_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobState {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(Error::new("stored job state is invalid")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanJob {
    pub job_id: Uuid,
    pub tenant_id: TenantId,
    pub creator_id: String,
    pub target: String,
    pub configuration: ScanConfiguration,
    pub state: JobState,
    pub attempt_count: u32,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<i64>,
    pub scan_id: Option<Uuid>,
    pub error_text: Option<String>,
}

impl Storage {
    /// Enqueues one idempotent tenant-scoped scan job.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, serialization, or database failures.
    pub fn enqueue_scan_job(
        &mut self,
        tenant_id: &TenantId,
        creator_id: &str,
        target: &str,
        configuration: &ScanConfiguration,
        idempotency_key: Option<&str>,
        available_at: i64,
    ) -> Result<Uuid, Error> {
        if target.is_empty()
            || target.len() > 2_048
            || creator_id.is_empty()
            || creator_id.len() > 200
        {
            return Err(Error::new("invalid scan job fields"));
        }
        if idempotency_key.is_some_and(|key| key.is_empty() || key.len() > 200) {
            return Err(Error::new("invalid idempotency key"));
        }
        let configuration = serde_json::to_string(configuration)
            .map_err(|error| Error::with_source("could not serialize job configuration", error))?;
        let job_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.connection
            .execute(
                "INSERT INTO scan_jobs
             (job_id, tenant_id, creator_id, target, configuration_json, state,
              available_at, idempotency_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, ?7, ?8, ?8)
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
                params![
                    job_id.to_string(),
                    tenant_id.as_str(),
                    creator_id,
                    target,
                    configuration,
                    available_at,
                    idempotency_key,
                    now
                ],
            )
            .map_err(|error| Error::with_source("could not enqueue scan job", error))?;
        if let Some(key) = idempotency_key {
            let existing = self
                .connection
                .query_row(
                    "SELECT job_id FROM scan_jobs WHERE tenant_id = ?1 AND idempotency_key = ?2",
                    params![tenant_id.as_str(), key],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|error| {
                    Error::with_source("could not resolve idempotent scan job", error)
                })?;
            return Uuid::parse_str(&existing)
                .map_err(|error| Error::with_source("stored job ID is invalid", error));
        }
        Ok(job_id)
    }

    /// Claims one eligible job using a bounded lease.
    ///
    /// # Errors
    ///
    /// Returns an error when lease input or transactional database work fails.
    pub fn claim_scan_job(
        &mut self,
        worker_id: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<ScanJob>, Error> {
        if worker_id.is_empty()
            || worker_id.len() > 200
            || lease_seconds <= 0
            || lease_seconds > 3_600
        {
            return Err(Error::new("invalid worker lease"));
        }
        let lease_expires_at = now
            .checked_add(lease_seconds)
            .ok_or_else(|| Error::new("lease expiry is out of range"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| Error::with_source("could not start job claim", error))?;
        let job_id = transaction
            .query_row(
                "SELECT job_id FROM scan_jobs
             WHERE attempt_count < ?1 AND available_at <= ?2
               AND (state = 'queued' OR (state = 'running' AND lease_expires_at <= ?2))
             ORDER BY available_at, created_at, job_id LIMIT 1",
                params![MAX_ATTEMPTS, now],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| Error::with_source("could not select scan job", error))?;
        let Some(job_id) = job_id else {
            transaction
                .commit()
                .map_err(|error| Error::with_source("could not finish empty job claim", error))?;
            return Ok(None);
        };
        let changed = transaction
            .execute(
                "UPDATE scan_jobs SET state = 'running', lease_owner = ?1, lease_expires_at = ?2,
                    attempt_count = attempt_count + 1, updated_at = ?3
             WHERE job_id = ?4 AND attempt_count < ?5
               AND (state = 'queued' OR (state = 'running' AND lease_expires_at <= ?3))",
                params![worker_id, lease_expires_at, now, job_id, MAX_ATTEMPTS],
            )
            .map_err(|error| Error::with_source("could not claim scan job", error))?;
        if changed != 1 {
            return Err(Error::new("scan job claim lost transactional ownership"));
        }
        let job = transaction
            .query_row(
                "SELECT job_id, tenant_id, creator_id, target, configuration_json, state,
                    attempt_count, lease_owner, lease_expires_at, scan_id, error_text
             FROM scan_jobs WHERE job_id = ?1",
                [&job_id],
                decode_job,
            )
            .map_err(|error| Error::with_source("could not decode claimed scan job", error))?;
        transaction
            .commit()
            .map_err(|error| Error::with_source("could not commit scan job claim", error))?;
        Ok(Some(job))
    }

    /// Completes a leased scan job.
    ///
    /// # Errors
    ///
    /// Returns an error unless the named worker owns the active lease.
    pub fn complete_scan_job(
        &mut self,
        job_id: Uuid,
        worker_id: &str,
        scan_id: Uuid,
        now: i64,
    ) -> Result<(), Error> {
        let changed = self.connection.execute(
            "UPDATE scan_jobs SET state = 'succeeded', scan_id = ?1, lease_owner = NULL,
                    lease_expires_at = NULL, error_text = NULL, updated_at = ?2
             WHERE job_id = ?3 AND state = 'running' AND lease_owner = ?4 AND lease_expires_at > ?2",
            params![scan_id.to_string(), now, job_id.to_string(), worker_id],
        ).map_err(|error| Error::with_source("could not complete scan job", error))?;
        if changed != 1 {
            return Err(Error::new("worker does not own an active scan job lease"));
        }
        Ok(())
    }

    /// Records a bounded failure for a leased scan job.
    ///
    /// # Errors
    ///
    /// Returns an error unless the named worker owns the job.
    pub fn fail_scan_job(
        &mut self,
        job_id: Uuid,
        worker_id: &str,
        error_text: &str,
        now: i64,
    ) -> Result<(), Error> {
        let error_text = error_text.chars().take(MAX_ERROR_BYTES).collect::<String>();
        let changed = self.connection.execute(
            "UPDATE scan_jobs SET state = CASE WHEN attempt_count >= ?1 THEN 'failed' ELSE 'queued' END,
                    available_at = ?2, lease_owner = NULL, lease_expires_at = NULL,
                    error_text = ?3, updated_at = ?4
             WHERE job_id = ?5 AND state = 'running' AND lease_owner = ?6",
            params![MAX_ATTEMPTS, now.saturating_add(30), error_text, now, job_id.to_string(), worker_id],
        ).map_err(|error| Error::with_source("could not fail scan job", error))?;
        if changed != 1 {
            return Err(Error::new("worker does not own the scan job"));
        }
        Ok(())
    }
}

fn decode_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanJob> {
    let job_id: String = row.get(0)?;
    let tenant_id: String = row.get(1)?;
    let configuration: String = row.get(4)?;
    let state: String = row.get(5)?;
    let scan_id: Option<String> = row.get(9)?;
    Ok(ScanJob {
        job_id: Uuid::parse_str(&job_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        tenant_id: TenantId::new(tenant_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        creator_id: row.get(2)?,
        target: row.get(3)?,
        configuration: serde_json::from_str(&configuration).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        state: JobState::parse(&state).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        attempt_count: row.get(6)?,
        lease_owner: row.get(7)?,
        lease_expires_at: row.get(8)?,
        scan_id: scan_id
            .map(|value| Uuid::parse_str(&value))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
        error_text: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use surface_core::ScanConfiguration;
    use tempfile::tempdir;

    use crate::Storage;

    fn configuration() -> ScanConfiguration {
        ScanConfiguration {
            ports: vec![443],
            concurrency: 1,
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            global_timeout_ms: 1_000,
            ipv4_only: false,
            ipv6_only: false,
            authorization_acknowledged: true,
        }
    }

    #[test]
    fn idempotency_and_leases_prevent_duplicate_claims() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));
        let tenant = storage
            .create_tenant("Jobs")
            .unwrap_or_else(|error| panic!("{error}"));
        let first = storage
            .enqueue_scan_job(
                &tenant,
                "operator",
                "example.com",
                &configuration(),
                Some("same"),
                0,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let duplicate = storage
            .enqueue_scan_job(
                &tenant,
                "operator",
                "example.com",
                &configuration(),
                Some("same"),
                0,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first, duplicate);
        let claimed = storage
            .claim_scan_job("worker-a", 10, 30)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("job required"));
        assert_eq!(claimed.job_id, first);
        assert!(
            storage
                .claim_scan_job("worker-b", 20, 30)
                .unwrap_or_default()
                .is_none()
        );
        let recovered = storage
            .claim_scan_job("worker-b", 41, 30)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("expired lease must recover"));
        assert_eq!(recovered.job_id, first);
        assert!(
            storage
                .complete_scan_job(first, "worker-a", uuid::Uuid::new_v4(), 42)
                .is_err()
        );
    }
}
