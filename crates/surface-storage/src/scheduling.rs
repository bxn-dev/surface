use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use surface_core::ScanConfiguration;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Error, Storage, TenantId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotificationDelivery {
    pub delivery_id: Uuid,
    pub tenant_id: TenantId,
    pub endpoint_id: Uuid,
    pub url: String,
    pub secret: Vec<u8>,
    pub payload_json: String,
    pub attempt_count: u32,
}

impl Storage {
    /// Creates a fixed-interval scan schedule.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input or database failure.
    pub fn create_schedule(
        &mut self,
        tenant_id: &TenantId,
        creator_id: &str,
        target: &str,
        configuration: &ScanConfiguration,
        interval_seconds: i64,
        next_run_at: i64,
    ) -> Result<Uuid, Error> {
        if interval_seconds < 300 || target.is_empty() || target.len() > 2_048 {
            return Err(Error::new("invalid schedule"));
        }
        let id = Uuid::new_v4();
        let configuration = serde_json::to_string(configuration).map_err(|error| {
            Error::with_source("could not serialize schedule configuration", error)
        })?;
        self.connection
            .execute(
                "INSERT INTO schedules
             (schedule_id, tenant_id, creator_id, target, configuration_json,
              interval_seconds, next_run_at, enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                params![
                    id.to_string(),
                    tenant_id.as_str(),
                    creator_id,
                    target,
                    configuration,
                    interval_seconds,
                    next_run_at,
                    OffsetDateTime::now_utc().unix_timestamp()
                ],
            )
            .map_err(|error| Error::with_source("could not create schedule", error))?;
        Ok(id)
    }

    /// Materializes each due schedule into at most one queued job.
    ///
    /// # Errors
    ///
    /// Returns an error when transactional scheduling fails.
    pub fn materialize_due_schedules(&mut self, now: i64) -> Result<Vec<Uuid>, Error> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                Error::with_source("could not start schedule materialization", error)
            })?;
        let due = {
            let mut statement = transaction.prepare(
                "SELECT schedule_id, tenant_id, creator_id, target, configuration_json, interval_seconds
                 FROM schedules WHERE enabled = 1 AND next_run_at <= ?1
                 ORDER BY next_run_at, schedule_id",
            ).map_err(|error| Error::with_source("could not prepare due schedules", error))?;
            statement
                .query_map([now], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .map_err(|error| Error::with_source("could not query due schedules", error))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|error| Error::with_source("could not decode due schedules", error))?
        };
        let mut jobs = Vec::with_capacity(due.len());
        for (schedule_id, tenant_id, creator_id, target, configuration, interval) in due {
            let job_id = Uuid::new_v4();
            transaction
                .execute(
                    "INSERT INTO scan_jobs
                 (job_id, tenant_id, creator_id, target, configuration_json, state,
                  available_at, idempotency_key, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, ?7, ?6, ?6)
                 ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
                    params![
                        job_id.to_string(),
                        tenant_id,
                        creator_id,
                        target,
                        configuration,
                        now,
                        format!("schedule:{schedule_id}:{now}")
                    ],
                )
                .map_err(|error| {
                    Error::with_source("could not materialize scheduled job", error)
                })?;
            let next = now
                .checked_add(interval)
                .ok_or_else(|| Error::new("schedule timestamp overflow"))?;
            transaction.execute(
                "UPDATE schedules SET next_run_at = ?1, last_job_id = ?2 WHERE schedule_id = ?3",
                params![next, job_id.to_string(), schedule_id],
            ).map_err(|error| Error::with_source("could not advance schedule", error))?;
            jobs.push(job_id);
        }
        transaction
            .commit()
            .map_err(|error| Error::with_source("could not commit schedules", error))?;
        Ok(jobs)
    }

    /// Registers a signed HTTPS notification endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid values or database failure.
    pub fn create_notification_endpoint(
        &mut self,
        tenant_id: &TenantId,
        url: &str,
        secret: &[u8],
    ) -> Result<Uuid, Error> {
        if !url.starts_with("https://")
            || url.len() > 2_048
            || secret.len() < 32
            || secret.len() > 128
        {
            return Err(Error::new(
                "notification endpoint requires HTTPS and a 32-128 byte secret",
            ));
        }
        let id = Uuid::new_v4();
        self.connection
            .execute(
                "INSERT INTO notification_endpoints
             (endpoint_id, tenant_id, url, event_mask, secret, enabled, created_at)
             VALUES (?1, ?2, ?3, 'scan.completed', ?4, 1, ?5)",
                params![
                    id.to_string(),
                    tenant_id.as_str(),
                    url,
                    secret,
                    OffsetDateTime::now_utc().unix_timestamp()
                ],
            )
            .map_err(|error| Error::with_source("could not create notification endpoint", error))?;
        Ok(id)
    }

    /// Enqueues completion notifications for a successful job.
    ///
    /// # Errors
    ///
    /// Returns an error when database work fails.
    pub fn enqueue_completion_notifications(
        &mut self,
        tenant_id: &TenantId,
        job_id: Uuid,
        scan_id: Uuid,
        now: i64,
    ) -> Result<(), Error> {
        let payload = serde_json::json!({
            "event": "scan.completed", "job_id": job_id, "scan_id": scan_id,
        })
        .to_string();
        self.connection
            .execute(
                "INSERT INTO notification_deliveries
             (delivery_id, tenant_id, endpoint_id, job_id, payload_json, state,
              available_at, created_at, updated_at)
             SELECT lower(hex(randomblob(16))), tenant_id, endpoint_id, ?1, ?2, 'queued', ?3, ?3, ?3
             FROM notification_endpoints WHERE tenant_id = ?4 AND enabled = 1
             ON CONFLICT (endpoint_id, job_id) DO NOTHING",
                params![job_id.to_string(), payload, now, tenant_id.as_str()],
            )
            .map_err(|error| {
                Error::with_source("could not enqueue notification deliveries", error)
            })?;
        Ok(())
    }

    /// Claims one due notification delivery.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid lease input or database failure.
    pub fn claim_notification(
        &mut self,
        worker_id: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<NotificationDelivery>, Error> {
        if worker_id.is_empty() || lease_seconds <= 0 || lease_seconds > 600 {
            return Err(Error::new("invalid notification lease"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| Error::with_source("could not start notification claim", error))?;
        let id = transaction
            .query_row(
                "SELECT delivery_id FROM notification_deliveries
             WHERE attempt_count < 5 AND available_at <= ?1
               AND (state = 'queued' OR (state = 'delivering' AND lease_expires_at <= ?1))
             ORDER BY available_at, created_at, delivery_id LIMIT 1",
                [now],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| Error::with_source("could not select notification", error))?;
        let Some(id) = id else {
            transaction.commit().map_err(|error| {
                Error::with_source("could not finish empty notification claim", error)
            })?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE notification_deliveries SET state = 'delivering', attempt_count = attempt_count + 1,
                    lease_owner = ?1, lease_expires_at = ?2, updated_at = ?3 WHERE delivery_id = ?4",
            params![worker_id, now.saturating_add(lease_seconds), now, id],
        ).map_err(|error| Error::with_source("could not claim notification", error))?;
        let delivery = transaction
            .query_row(
                "SELECT d.delivery_id, d.tenant_id, d.endpoint_id, e.url, e.secret,
                    d.payload_json, d.attempt_count
             FROM notification_deliveries d JOIN notification_endpoints e
               ON e.endpoint_id = d.endpoint_id AND e.tenant_id = d.tenant_id
             WHERE d.delivery_id = ?1",
                [&id],
                decode_delivery,
            )
            .map_err(|error| Error::with_source("could not decode notification", error))?;
        transaction
            .commit()
            .map_err(|error| Error::with_source("could not commit notification claim", error))?;
        Ok(Some(delivery))
    }

    /// Completes or reschedules one owned notification delivery.
    ///
    /// # Errors
    ///
    /// Returns an error unless the worker owns the delivery.
    pub fn finish_notification(
        &mut self,
        delivery_id: Uuid,
        worker_id: &str,
        success: bool,
        status: Option<u16>,
        error: Option<&str>,
        now: i64,
    ) -> Result<(), Error> {
        let error = error.map(|value| value.chars().take(1_024).collect::<String>());
        let changed = self.connection.execute(
            "UPDATE notification_deliveries SET
               state = CASE WHEN ?1 THEN 'succeeded' WHEN attempt_count >= 5 THEN 'failed' ELSE 'queued' END,
               available_at = ?2, lease_owner = NULL, lease_expires_at = NULL,
               response_status = ?3, error_text = ?4, updated_at = ?5
             WHERE delivery_id = ?6 AND state = 'delivering' AND lease_owner = ?7",
            params![success, now.saturating_add(30_i64.saturating_mul(1_i64 << 4)), status, error,
                now, delivery_id.to_string(), worker_id],
        ).map_err(|error| Error::with_source("could not finish notification", error))?;
        if changed != 1 {
            return Err(Error::new("worker does not own notification delivery"));
        }
        Ok(())
    }
}

fn decode_delivery(row: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationDelivery> {
    let delivery: String = row.get(0)?;
    let tenant: String = row.get(1)?;
    let endpoint: String = row.get(2)?;
    Ok(NotificationDelivery {
        delivery_id: Uuid::parse_str(&delivery).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        tenant_id: TenantId::new(tenant).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        endpoint_id: Uuid::parse_str(&endpoint).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        url: row.get(3)?,
        secret: row.get(4)?,
        payload_json: row.get(5)?,
        attempt_count: row.get(6)?,
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
    fn due_schedule_materializes_once_and_webhooks_require_https() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));
        let tenant = storage
            .create_tenant("Schedules")
            .unwrap_or_else(|error| panic!("{error}"));
        storage
            .create_schedule(
                &tenant,
                "operator",
                "example.com",
                &configuration(),
                300,
                10,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            storage
                .materialize_due_schedules(10)
                .unwrap_or_default()
                .len(),
            1
        );
        assert!(
            storage
                .materialize_due_schedules(10)
                .unwrap_or_default()
                .is_empty()
        );
        assert!(
            storage
                .claim_scan_job("worker", 10, 30)
                .unwrap_or_default()
                .is_some()
        );
        assert!(
            storage
                .create_notification_endpoint(&tenant, "http://127.0.0.1/hook", &[1; 32])
                .is_err()
        );
        assert!(
            storage
                .create_notification_endpoint(&tenant, "https://example.com/hook", &[1; 31])
                .is_err()
        );
    }
}
