use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use surface_core::ScanReport;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Error, HistoryFilter, ScanSummary, Storage, scan_summary};

const MAX_AUDIT_PAGE: u32 = 500;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(String);

impl TenantId {
    /// Validates a tenant identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for empty or oversized identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(Error::new("tenant ID must contain 1 to 128 bytes"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn local() -> Self {
        Self("local".to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "viewer" => Ok(Self::Viewer),
            _ => Err(Error::new("stored user role is invalid")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorContext {
    pub tenant_id: TenantId,
    pub actor_id: String,
    pub actor_kind: String,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub user_id: String,
    pub tenant_id: TenantId,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedActor {
    pub user_id: String,
    pub tenant_id: TenantId,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub occurred_at: i64,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub actor_id: Option<String>,
    pub actor_kind: String,
    pub request_id: Option<String>,
    pub metadata_json: String,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub action: Option<String>,
    pub offset: u32,
    pub limit: u32,
}

#[expect(
    clippy::missing_errors_doc,
    reason = "all managed storage methods return the crate's documented storage Error contract"
)]
impl Storage {
    pub fn create_tenant(&mut self, name: &str) -> Result<TenantId, Error> {
        if name.trim().is_empty() || name.len() > 200 {
            return Err(Error::new("tenant name must contain 1 to 200 bytes"));
        }
        let tenant_id = TenantId::new(Uuid::new_v4().to_string())?;
        self.connection
            .execute(
                "INSERT INTO tenants (tenant_id, name, created_at) VALUES (?1, ?2, ?3)",
                params![
                    tenant_id.as_str(),
                    name,
                    OffsetDateTime::now_utc().unix_timestamp()
                ],
            )
            .map_err(|error| Error::with_source("could not create tenant", error))?;
        Ok(tenant_id)
    }

    pub fn create_user(
        &mut self,
        tenant_id: &TenantId,
        username: &str,
        password_hash: &str,
        role: Role,
    ) -> Result<String, Error> {
        if username.trim().is_empty() || username.len() > 200 || password_hash.len() > 1_024 {
            return Err(Error::new("invalid user fields"));
        }
        let user_id = Uuid::new_v4().to_string();
        self.connection
            .execute(
                "INSERT INTO users
                 (user_id, tenant_id, username, password_hash, role, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    user_id,
                    tenant_id.as_str(),
                    username,
                    password_hash,
                    role.as_str(),
                    OffsetDateTime::now_utc().unix_timestamp(),
                ],
            )
            .map_err(|error| Error::with_source("could not create user", error))?;
        Ok(user_id)
    }

    pub fn user_by_username(
        &self,
        tenant_id: &TenantId,
        username: &str,
    ) -> Result<Option<UserRecord>, Error> {
        self.connection
            .query_row(
                "SELECT user_id, password_hash, role FROM users
                 WHERE tenant_id = ?1 AND username = ?2 AND disabled_at IS NULL",
                params![tenant_id.as_str(), username],
                |row| {
                    let role: String = row.get(2)?;
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, role))
                },
            )
            .optional()
            .map_err(|error| Error::with_source("could not retrieve user", error))?
            .map(|(user_id, password_hash, role)| {
                Ok(UserRecord {
                    user_id,
                    tenant_id: tenant_id.clone(),
                    username: username.to_owned(),
                    password_hash,
                    role: Role::parse(&role)?,
                })
            })
            .transpose()
    }

    pub fn create_session(
        &mut self,
        actor: &AuthenticatedActor,
        token_hash: &[u8],
        csrf_hash: &[u8],
        expires_at: i64,
    ) -> Result<String, Error> {
        if token_hash.len() != 32 || csrf_hash.len() != 32 {
            return Err(Error::new("session hashes must be SHA-256 values"));
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if expires_at <= now {
            return Err(Error::new("session expiry must be in the future"));
        }
        let session_id = Uuid::new_v4().to_string();
        self.connection
            .execute(
                "INSERT INTO sessions
                 (session_id, tenant_id, user_id, token_hash, csrf_token_hash, created_at, expires_at, last_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6)",
                params![session_id, actor.tenant_id.as_str(), actor.user_id, token_hash, csrf_hash, now, expires_at],
            )
            .map_err(|error| Error::with_source("could not create session", error))?;
        Ok(session_id)
    }

    pub fn authenticate_session(
        &self,
        token_hash: &[u8],
        now: i64,
    ) -> Result<Option<AuthenticatedActor>, Error> {
        self.authenticate_session_with_csrf(token_hash, None, now)
    }

    pub fn authenticate_session_with_csrf(
        &self,
        token_hash: &[u8],
        csrf_hash: Option<&[u8]>,
        now: i64,
    ) -> Result<Option<AuthenticatedActor>, Error> {
        self.connection
            .query_row(
                "SELECT u.user_id, u.tenant_id, u.role
                 FROM sessions s JOIN users u ON u.user_id = s.user_id AND u.tenant_id = s.tenant_id
                 JOIN tenants t ON t.tenant_id = s.tenant_id
                 WHERE s.token_hash = ?1 AND s.expires_at > ?2
                   AND (?3 IS NULL OR s.csrf_token_hash = ?3)
                   AND u.disabled_at IS NULL AND t.disabled_at IS NULL",
                params![token_hash, now, csrf_hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| Error::with_source("could not authenticate session", error))?
            .map(|(user_id, tenant_id, role)| {
                Ok(AuthenticatedActor {
                    user_id,
                    tenant_id: TenantId::new(tenant_id)?,
                    role: Role::parse(&role)?,
                })
            })
            .transpose()
    }

    pub fn create_api_token(
        &mut self,
        actor: &AuthenticatedActor,
        name: &str,
        token_hash: &[u8],
        scopes: &[String],
        expires_at: Option<i64>,
    ) -> Result<String, Error> {
        if name.is_empty() || name.len() > 200 || token_hash.len() != 32 || scopes.len() > 32 {
            return Err(Error::new("invalid API token fields"));
        }
        let scopes_json = serde_json::to_string(scopes)
            .map_err(|error| Error::with_source("could not serialize API token scopes", error))?;
        let token_id = Uuid::new_v4().to_string();
        self.connection
            .execute(
                "INSERT INTO api_tokens
             (token_id, tenant_id, user_id, name, token_hash, scopes_json, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    token_id,
                    actor.tenant_id.as_str(),
                    actor.user_id,
                    name,
                    token_hash,
                    scopes_json,
                    OffsetDateTime::now_utc().unix_timestamp(),
                    expires_at
                ],
            )
            .map_err(|error| Error::with_source("could not create API token", error))?;
        Ok(token_id)
    }

    pub fn authenticate_api_token(
        &self,
        token_hash: &[u8],
        now: i64,
    ) -> Result<Option<(AuthenticatedActor, Vec<String>)>, Error> {
        self.connection
            .query_row(
                "SELECT u.user_id, u.tenant_id, u.role, a.scopes_json
             FROM api_tokens a JOIN users u ON u.user_id = a.user_id AND u.tenant_id = a.tenant_id
             JOIN tenants t ON t.tenant_id = a.tenant_id
             WHERE a.token_hash = ?1 AND a.revoked_at IS NULL
               AND (a.expires_at IS NULL OR a.expires_at > ?2)
               AND u.disabled_at IS NULL AND t.disabled_at IS NULL",
                params![token_hash, now],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| Error::with_source("could not authenticate API token", error))?
            .map(|(user_id, tenant_id, role, scopes)| {
                Ok((
                    AuthenticatedActor {
                        user_id,
                        tenant_id: TenantId::new(tenant_id)?,
                        role: Role::parse(&role)?,
                    },
                    serde_json::from_str(&scopes).map_err(|error| {
                        Error::with_source("stored API token scopes are invalid", error)
                    })?,
                ))
            })
            .transpose()
    }

    pub fn delete_session(&mut self, token_hash: &[u8]) -> Result<bool, Error> {
        self.connection
            .execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])
            .map(|count| count == 1)
            .map_err(|error| Error::with_source("could not delete session", error))
    }

    pub fn attest_target(
        &mut self,
        actor: &ActorContext,
        normalized_target: &str,
        display_target: &str,
    ) -> Result<(), Error> {
        if normalized_target.is_empty()
            || normalized_target.len() > 2_048
            || display_target.len() > 2_048
        {
            return Err(Error::new("invalid target attestation"));
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.connection
            .execute(
                "INSERT INTO tenant_targets
             (target_id, tenant_id, normalized_target, display_target, authorization_attested_at,
              authorization_actor_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5)
             ON CONFLICT (tenant_id, normalized_target) DO UPDATE SET
                display_target = excluded.display_target,
                authorization_attested_at = excluded.authorization_attested_at,
                authorization_actor_id = excluded.authorization_actor_id",
                params![
                    Uuid::new_v4().to_string(),
                    actor.tenant_id.as_str(),
                    normalized_target,
                    display_target,
                    now,
                    actor.actor_id
                ],
            )
            .map_err(|error| Error::with_source("could not attest target authorization", error))?;
        Ok(())
    }

    pub fn target_is_attested(
        &self,
        tenant_id: &TenantId,
        normalized_target: &str,
    ) -> Result<bool, Error> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tenant_targets
             WHERE tenant_id = ?1 AND normalized_target = ?2)",
                params![tenant_id.as_str(), normalized_target],
                |row| row.get(0),
            )
            .map_err(|error| Error::with_source("could not inspect target authorization", error))
    }

    pub fn persist_report_for(
        &mut self,
        actor: &ActorContext,
        report: &ScanReport,
        origin: &str,
    ) -> Result<(), Error> {
        self.persist_report_for_tenant(actor.tenant_id.as_str(), report, origin)
    }

    pub fn report_for(
        &self,
        tenant_id: &TenantId,
        scan_id: Uuid,
    ) -> Result<Option<ScanReport>, Error> {
        let json = self
            .connection
            .query_row(
                "SELECT report_json FROM scans WHERE tenant_id = ?1 AND scan_id = ?2",
                params![tenant_id.as_str(), scan_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| Error::with_source("could not retrieve tenant scan report", error))?;
        json.map(|json| {
            serde_json::from_str(&json)
                .map_err(|error| Error::with_source("stored scan report is invalid", error))
        })
        .transpose()
    }

    pub fn history_for(
        &self,
        tenant_id: &TenantId,
        filter: &HistoryFilter,
    ) -> Result<Vec<ScanSummary>, Error> {
        let limit = if filter.limit == 0 {
            50
        } else {
            filter.limit.min(500)
        };
        let mut statement = self
            .connection
            .prepare(
                "SELECT scan_id, original_target, normalized_target, status, started_at,
                    completed_at, finding_high_count, finding_critical_count, origin
             FROM scans
             WHERE tenant_id = ?1 AND (?2 IS NULL OR normalized_target = ?2)
               AND (?3 IS NULL OR status = ?3) AND (?4 IS NULL OR started_at >= ?4)
               AND (?5 IS NULL OR started_at <= ?5)
             ORDER BY started_at DESC, scan_id DESC LIMIT ?6 OFFSET ?7",
            )
            .map_err(|error| Error::with_source("could not prepare tenant history query", error))?;
        let rows = statement
            .query_map(
                params![
                    tenant_id.as_str(),
                    filter.target,
                    filter.status,
                    filter.started_after,
                    filter.started_before,
                    limit,
                    filter.offset
                ],
                scan_summary,
            )
            .map_err(|error| Error::with_source("could not query tenant scan history", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| Error::with_source("could not decode tenant scan history", error))
    }

    pub fn delete_scan_for(&mut self, actor: &ActorContext, scan_id: Uuid) -> Result<bool, Error> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| Error::with_source("could not start tenant scan deletion", error))?;
        let deleted = transaction
            .execute(
                "DELETE FROM scans WHERE tenant_id = ?1 AND scan_id = ?2",
                params![actor.tenant_id.as_str(), scan_id.to_string()],
            )
            .map_err(|error| Error::with_source("could not delete tenant scan", error))?
            == 1;
        transaction
            .execute(
                "INSERT INTO audit_events
             (event_id, occurred_at, action, resource_type, resource_id, outcome, metadata_json,
              tenant_id, actor_id, actor_kind, request_id)
             VALUES (?1, ?2, 'scan.delete', 'scan', ?3, ?4, '{}', ?5, ?6, ?7, ?8)",
                params![
                    Uuid::new_v4().to_string(),
                    OffsetDateTime::now_utc().unix_timestamp(),
                    scan_id.to_string(),
                    if deleted { "success" } else { "not_found" },
                    actor.tenant_id.as_str(),
                    actor.actor_id,
                    actor.actor_kind,
                    actor.request_id
                ],
            )
            .map_err(|error| Error::with_source("could not record tenant audit event", error))?;
        transaction
            .commit()
            .map_err(|error| Error::with_source("could not commit tenant scan deletion", error))?;
        Ok(deleted)
    }

    pub fn audit_events_for(
        &self,
        tenant_id: &TenantId,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEvent>, Error> {
        let limit = if filter.limit == 0 {
            50
        } else {
            filter.limit.min(MAX_AUDIT_PAGE)
        };
        let mut statement = self
            .connection
            .prepare(
                "SELECT event_id, occurred_at, action, resource_type, resource_id, outcome,
                    actor_id, actor_kind, request_id, metadata_json
             FROM audit_events WHERE tenant_id = ?1 AND (?2 IS NULL OR action = ?2)
             ORDER BY occurred_at DESC, event_id DESC LIMIT ?3 OFFSET ?4",
            )
            .map_err(|error| Error::with_source("could not prepare audit query", error))?;
        let rows = statement
            .query_map(
                params![tenant_id.as_str(), filter.action, limit, filter.offset],
                |row| {
                    Ok(AuditEvent {
                        event_id: row.get(0)?,
                        occurred_at: row.get(1)?,
                        action: row.get(2)?,
                        resource_type: row.get(3)?,
                        resource_id: row.get(4)?,
                        outcome: row.get(5)?,
                        actor_id: row.get(6)?,
                        actor_kind: row.get(7)?,
                        request_id: row.get(8)?,
                        metadata_json: row.get(9)?,
                    })
                },
            )
            .map_err(|error| Error::with_source("could not query audit events", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| Error::with_source("could not decode audit events", error))
    }
}

#[cfg(test)]
mod tests {
    use surface_core::{ScanConfiguration, ScanReport, normalize_target};
    use tempfile::tempdir;

    use super::{ActorContext, AuditFilter, AuthenticatedActor, Role, TenantId};
    use crate::{HistoryFilter, Storage};

    fn report(target: &str) -> ScanReport {
        ScanReport::not_started(
            normalize_target(target).unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![443],
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
        )
    }

    #[test]
    fn sessions_store_hashes_and_expire() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));
        let tenant = storage
            .create_tenant("Acme")
            .unwrap_or_else(|error| panic!("{error}"));
        let user_id = storage
            .create_user(&tenant, "admin", "$argon2id$stored", Role::Admin)
            .unwrap_or_else(|error| panic!("{error}"));
        let user = storage
            .user_by_username(&tenant, "admin")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("user required"));
        assert_eq!(user.password_hash, "$argon2id$stored");
        let actor = AuthenticatedActor {
            user_id,
            tenant_id: tenant,
            role: Role::Admin,
        };
        storage
            .create_session(&actor, &[1; 32], &[2; 32], i64::MAX)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            storage
                .authenticate_session(&[1; 32], 0)
                .unwrap_or_default()
                .is_some()
        );
        assert!(
            storage
                .authenticate_session(&[1; 32], i64::MAX)
                .unwrap_or_default()
                .is_none()
        );
        assert!(storage.delete_session(&[1; 32]).unwrap_or(false));
    }

    #[test]
    fn managed_reports_are_tenant_scoped() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));
        let tenant = storage
            .create_tenant("Acme")
            .unwrap_or_else(|error| panic!("{error}"));
        let other = storage
            .create_tenant("Other")
            .unwrap_or_else(|error| panic!("{error}"));
        let actor = ActorContext {
            tenant_id: tenant.clone(),
            actor_id: "operator".to_owned(),
            actor_kind: "user".to_owned(),
            request_id: "request".to_owned(),
        };
        let report = report("example.com");
        storage
            .persist_report_for(&actor, &report, "api")
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            storage
                .report_for(&tenant, report.scan_id)
                .unwrap_or_default()
                .is_some()
        );
        assert!(
            storage
                .report_for(&other, report.scan_id)
                .unwrap_or_default()
                .is_none()
        );
        assert_eq!(
            storage
                .history_for(&tenant, &HistoryFilter::default())
                .unwrap_or_default()
                .len(),
            1
        );
        assert!(
            storage
                .history_for(&other, &HistoryFilter::default())
                .unwrap_or_default()
                .is_empty()
        );
        assert!(
            !storage
                .delete_scan_for(
                    &ActorContext {
                        tenant_id: other.clone(),
                        ..actor.clone()
                    },
                    report.scan_id
                )
                .unwrap_or(true)
        );
        assert!(
            storage
                .delete_scan_for(&actor, report.scan_id)
                .unwrap_or(false)
        );
        assert_eq!(
            storage
                .audit_events_for(&tenant, &AuditFilter::default())
                .unwrap_or_default()
                .len(),
            1
        );
        assert_eq!(
            storage
                .audit_events_for(&other, &AuditFilter::default())
                .unwrap_or_default()
                .len(),
            1
        );
        assert_ne!(tenant, TenantId::local());
    }
}
