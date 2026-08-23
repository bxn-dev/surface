#![forbid(unsafe_code)]

mod metrics;

pub use metrics::Metrics;

use std::sync::{Arc, Mutex};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use hmac::{Hmac, Mac as _};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use surface_core::{
    NormalizedTarget, ScanConfiguration, ScanStatus, normalize_target, run_hosted_scan,
};
use surface_storage::{
    ActorContext, AuditFilter, AuthenticatedActor, HistoryFilter, Role, Storage, TenantId,
};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SESSION_COOKIE: &str = "surface_session";
const MAX_PAGE: u32 = 200;

#[derive(Clone)]
pub struct AppState {
    storage: Arc<Mutex<Storage>>,
    public_origin: String,
    secure_cookies: bool,
    session_lifetime: Duration,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("public_origin", &self.public_origin)
            .field("secure_cookies", &self.secure_cookies)
            .field("session_lifetime", &self.session_lifetime)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Creates server state around an already-migrated database.
    ///
    /// # Errors
    ///
    /// Returns an error unless the origin is absolute HTTP(S), with HTTPS required for non-loopback hosts.
    pub fn new(
        storage: Storage,
        public_origin: &str,
        session_lifetime: Duration,
    ) -> Result<Self, String> {
        let origin =
            url::Url::parse(public_origin).map_err(|_| "public origin must be an absolute URL")?;
        if !matches!(origin.scheme(), "http" | "https") || origin.host_str().is_none() {
            return Err("public origin must use HTTP or HTTPS".to_owned());
        }
        let loopback = matches!(
            origin.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if origin.scheme() != "https" && !loopback {
            return Err("non-loopback public origin must use HTTPS".to_owned());
        }
        if session_lifetime <= Duration::ZERO {
            return Err("session lifetime must be positive".to_owned());
        }
        Ok(Self {
            storage: Arc::new(Mutex::new(storage)),
            public_origin: public_origin.trim_end_matches('/').to_owned(),
            secure_cookies: origin.scheme() == "https",
            session_lifetime,
            metrics: Arc::new(Metrics::default()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    ViewScans,
    DeleteScans,
    ViewAudit,
    SubmitScan,
    ManageTargets,
}

const fn authorize(role: Role, action: Action) -> bool {
    match action {
        Action::ViewScans => true,
        Action::SubmitScan => matches!(role, Role::Admin | Role::Operator),
        Action::DeleteScans | Action::ViewAudit | Action::ManageTargets => {
            matches!(role, Role::Admin)
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: &'static str,
    message: &'static str,
    request_id: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = Uuid::new_v4().to_string();
        let mut response = (
            self.status,
            Json(ApiErrorBody {
                error: self.code,
                message: self.message,
                request_id: request_id.clone(),
            }),
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            response.headers_mut().insert("x-request-id", value);
        }
        security_headers(response)
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    tenant_id: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct LoginResponse {
    csrf_token: String,
    role: Role,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    offset: Option<u32>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct FormatQuery {
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    target: String,
    configuration: ScanConfiguration,
    idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanRequestResponse {
    job_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct TargetAttestationRequest {
    target: String,
}

#[derive(Debug, Deserialize)]
struct ApiTokenRequest {
    name: String,
    expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ApiTokenResponse {
    token: String,
}

/// Builds the hosted API and minimal web interface.
pub fn metrics_app(state: AppState) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            let metrics = Arc::clone(&state.metrics);
            async move { metrics.render() }
        }),
    )
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/v1/session", post(login).delete(logout))
        .route("/api/v1/scans", get(scans))
        .route("/api/v1/scan-requests", post(submit_scan))
        .route("/api/v1/target-attestations", post(attest_target))
        .route("/api/v1/api-tokens", post(create_api_token))
        .route("/api/v1/scans/{id}", get(scan).delete(delete_scan))
        .route("/api/v1/scans/{id}/report", get(report))
        .route("/api/v1/audit", get(audit))
        .route("/", get(web_index))
        .route("/web/scans", get(web_scans))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

async fn login(
    State(state): State<AppState>,
    Json(input): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    if input.username.len() > 200 || input.password.len() > 1_024 || input.tenant_id.len() > 128 {
        return Err(invalid_credentials());
    }
    let tenant = TenantId::new(input.tenant_id).map_err(|_| invalid_credentials())?;
    let user = state
        .storage
        .lock()
        .map_err(|_| internal())?
        .user_by_username(&tenant, &input.username)
        .map_err(|_| internal())?
        .ok_or_else(invalid_credentials)?;
    let parsed = PasswordHash::new(&user.password_hash).map_err(|_| invalid_credentials())?;
    Argon2::default()
        .verify_password(input.password.as_bytes(), &parsed)
        .map_err(|_| invalid_credentials())?;

    let token = random_token();
    let csrf = random_token();
    let token_hash = hash_secret(&token);
    let csrf_hash = hash_secret(&csrf);
    let actor = AuthenticatedActor {
        user_id: user.user_id,
        tenant_id: tenant,
        role: user.role,
    };
    let expires = (OffsetDateTime::now_utc() + state.session_lifetime).unix_timestamp();
    state
        .storage
        .lock()
        .map_err(|_| internal())?
        .create_session(&actor, &token_hash, &csrf_hash, expires)
        .map_err(|_| internal())?;

    let mut response = Json(LoginResponse {
        csrf_token: hex(&csrf),
        role: user.role,
    })
    .into_response();
    let mut cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax",
        hex(&token)
    );
    if state.secure_cookies {
        cookie.push_str("; Secure");
    }
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| internal())?,
    );
    Ok(security_headers(response))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let (actor, token_hash) = authenticate(&state, &headers, true)?;
    if !authorize(actor.role, Action::ViewScans) {
        return Err(forbidden());
    }
    state
        .storage
        .lock()
        .map_err(|_| internal())?
        .delete_session(&token_hash)
        .map_err(|_| internal())?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("surface_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    Ok(security_headers(response))
}

async fn submit_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<ScanRequest>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, true)?;
    if !authorize(actor.role, Action::SubmitScan) {
        return Err(forbidden());
    }
    validate_hosted_configuration(&input.configuration)?;
    input.configuration.authorization_acknowledged = true;
    let target = normalize_target(&input.target).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "target is invalid",
        )
    })?;
    let normalized = normalized_target(&target);
    let mut storage = state.storage.lock().map_err(|_| internal())?;
    if !storage
        .target_is_attested(&actor.tenant_id, &normalized)
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "target_not_attested",
            "target authorization is not attested",
        ));
    }
    let job_id = storage
        .enqueue_scan_job(
            &actor.tenant_id,
            &actor.user_id,
            &input.target,
            &input.configuration,
            input.idempotency_key.as_deref(),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|_| internal())?;
    Ok(security_headers(
        (StatusCode::ACCEPTED, Json(ScanRequestResponse { job_id })).into_response(),
    ))
}

async fn attest_target(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TargetAttestationRequest>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, true)?;
    if !authorize(actor.role, Action::ManageTargets) {
        return Err(forbidden());
    }
    let target = normalize_target(&input.target).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "target is invalid",
        )
    })?;
    let context = ActorContext {
        tenant_id: actor.tenant_id,
        actor_id: actor.user_id,
        actor_kind: "user".to_owned(),
        request_id: Uuid::new_v4().to_string(),
    };
    state
        .storage
        .lock()
        .map_err(|_| internal())?
        .attest_target(&context, &normalized_target(&target), &input.target)
        .map_err(|_| internal())?;
    Ok(security_headers(StatusCode::NO_CONTENT.into_response()))
}

async fn create_api_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ApiTokenRequest>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, true)?;
    if !authorize(actor.role, Action::ManageTargets) {
        return Err(forbidden());
    }
    let token = random_token();
    let token_hash = hash_secret(&token);
    state
        .storage
        .lock()
        .map_err(|_| internal())?
        .create_api_token(
            &actor,
            &input.name,
            &token_hash,
            &["all".to_owned()],
            input.expires_at,
        )
        .map_err(|_| internal())?;
    Ok(security_headers(
        (
            StatusCode::CREATED,
            Json(ApiTokenResponse { token: hex(&token) }),
        )
            .into_response(),
    ))
}

async fn scans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, false)?;
    if !authorize(actor.role, Action::ViewScans) {
        return Err(forbidden());
    }
    let rows = state
        .storage
        .lock()
        .map_err(|_| internal())?
        .history_for(
            &actor.tenant_id,
            &HistoryFilter {
                offset: page.offset.unwrap_or(0),
                limit: page.limit.unwrap_or(50).min(MAX_PAGE),
                ..HistoryFilter::default()
            },
        )
        .map_err(|_| internal())?;
    Ok(security_headers(Json(rows).into_response()))
}

async fn scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, false)?;
    if !authorize(actor.role, Action::ViewScans) {
        return Err(forbidden());
    }
    let report = state
        .storage
        .lock()
        .map_err(|_| internal())?
        .report_for(&actor.tenant_id, id)
        .map_err(|_| internal())?
        .ok_or_else(not_found)?;
    Ok(security_headers(Json(report).into_response()))
}

async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<FormatQuery>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, false)?;
    let report = state
        .storage
        .lock()
        .map_err(|_| internal())?
        .report_for(&actor.tenant_id, id)
        .map_err(|_| internal())?
        .ok_or_else(not_found)?;
    let format = query.format.as_deref().unwrap_or("json");
    let (content_type, body) = match format {
        "json" => (
            "application/json",
            surface_report::render_json(&report).map_err(|_| internal())?,
        ),
        "html" => (
            "text/html; charset=utf-8",
            surface_report::render_html(&report),
        ),
        "sarif" => (
            "application/sarif+json",
            surface_report::render_sarif(&report).map_err(|_| internal())?,
        ),
        "cyclonedx-json" => (
            "application/vnd.cyclonedx+json",
            surface_report::render_cyclonedx(&report).map_err(|_| internal())?,
        ),
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_format",
                "unsupported report format",
            ));
        }
    };
    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    Ok(security_headers(response))
}

async fn delete_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, true)?;
    if !authorize(actor.role, Action::DeleteScans) {
        return Err(forbidden());
    }
    let context = ActorContext {
        tenant_id: actor.tenant_id,
        actor_id: actor.user_id,
        actor_kind: "user".to_owned(),
        request_id: Uuid::new_v4().to_string(),
    };
    let deleted = state
        .storage
        .lock()
        .map_err(|_| internal())?
        .delete_scan_for(&context, id)
        .map_err(|_| internal())?;
    if !deleted {
        return Err(not_found());
    }
    Ok(security_headers(StatusCode::NO_CONTENT.into_response()))
}

async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, false)?;
    if !authorize(actor.role, Action::ViewAudit) {
        return Err(forbidden());
    }
    let events = state
        .storage
        .lock()
        .map_err(|_| internal())?
        .audit_events_for(
            &actor.tenant_id,
            &AuditFilter {
                offset: page.offset.unwrap_or(0),
                limit: page.limit.unwrap_or(50).min(MAX_PAGE),
                action: None,
            },
        )
        .map_err(|_| internal())?;
    Ok(security_headers(Json(events).into_response()))
}

async fn web_index() -> Response {
    security_headers(Html("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Surface</title><h1>Surface</h1><p>Use <code>POST /api/v1/session</code> to sign in.</p></html>").into_response())
}

async fn web_scans(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (actor, _) = authenticate(&state, &headers, false)?;
    let rows = state
        .storage
        .lock()
        .map_err(|_| internal())?
        .history_for(&actor.tenant_id, &HistoryFilter::default())
        .map_err(|_| internal())?;
    let mut body = String::from(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Surface scans</title><h1>Scans</h1><ul>",
    );
    for row in rows {
        body.push_str("<li><code>");
        body.push_str(&surface_report::escape_html(&row.scan_id.to_string()));
        body.push_str("</code> ");
        body.push_str(&surface_report::escape_html(&row.original_target));
        body.push_str("</li>");
    }
    body.push_str("</ul></html>");
    Ok(security_headers(Html(body).into_response()))
}

/// Runs one durable hosted scan worker until cancellation.
pub async fn run_worker(state: AppState, worker_id: String, cancellation: CancellationToken) {
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let job = state.storage.lock().ok().and_then(|mut storage| {
            let _ = storage.materialize_due_schedules(now);
            storage
                .claim_scan_job(&worker_id, now, 1_200)
                .ok()
                .flatten()
        });
        let Some(job) = job else {
            tokio::select! {
                () = cancellation.cancelled() => return,
                () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
            }
            continue;
        };
        let Ok(target) = normalize_target(&job.target) else {
            if let Ok(mut storage) = state.storage.lock() {
                let _ =
                    storage.fail_scan_job(job.job_id, &worker_id, "stored target is invalid", now);
            }
            continue;
        };
        let report = run_hosted_scan(target, job.configuration, cancellation.child_token()).await;
        let actor = ActorContext {
            tenant_id: job.tenant_id,
            actor_id: job.creator_id,
            actor_kind: "worker".to_owned(),
            request_id: job.job_id.to_string(),
        };
        if let Ok(mut storage) = state.storage.lock() {
            let completed_at = OffsetDateTime::now_utc().unix_timestamp();
            let scan_succeeded = report.status == ScanStatus::Completed;
            let result = storage
                .persist_report_for(&actor, &report, "hosted-worker")
                .and_then(|()| {
                    if scan_succeeded {
                        storage.complete_scan_job(
                            job.job_id,
                            &worker_id,
                            report.scan_id,
                            completed_at,
                        )?;
                        storage.enqueue_completion_notifications(
                            &actor.tenant_id,
                            job.job_id,
                            report.scan_id,
                            completed_at,
                        )
                    } else {
                        storage.fail_scan_job(job.job_id, &worker_id, &report.message, completed_at)
                    }
                });
            if result.is_err() {
                Metrics::increment(&state.metrics.jobs_failed);
                let _ = storage.fail_scan_job(
                    job.job_id,
                    &worker_id,
                    "scan persistence failed",
                    OffsetDateTime::now_utc().unix_timestamp(),
                );
            } else if scan_succeeded {
                Metrics::increment(&state.metrics.jobs_completed);
            } else {
                Metrics::increment(&state.metrics.jobs_failed);
            }
        }
    }
}

/// Runs signed HTTPS notification delivery until cancellation.
pub async fn run_notification_worker(
    state: AppState,
    worker_id: String,
    cancellation: CancellationToken,
) {
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let delivery = state.storage.lock().ok().and_then(|mut storage| {
            storage
                .claim_notification(&worker_id, now, 60)
                .ok()
                .flatten()
        });
        let Some(delivery) = delivery else {
            tokio::select! {
                () = cancellation.cancelled() => return,
                () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
            continue;
        };
        Metrics::increment(&state.metrics.notification_attempts);
        let result =
            deliver_notification(&delivery.url, &delivery.secret, &delivery.payload_json, now)
                .await;
        if let Ok(mut storage) = state.storage.lock() {
            let (success, status, error) = match &result {
                Ok(status) => (status.is_success(), Some(status.as_u16()), None),
                Err(error) => {
                    Metrics::increment(&state.metrics.notification_failures);
                    (false, None, Some(error.as_str()))
                }
            };
            let _ = storage.finish_notification(
                delivery.delivery_id,
                &worker_id,
                success,
                status,
                error,
                OffsetDateTime::now_utc().unix_timestamp(),
            );
        }
    }
}

async fn deliver_notification(
    url: &str,
    secret: &[u8],
    payload: &str,
    timestamp: i64,
) -> Result<StatusCode, String> {
    let parsed = url::Url::parse(url).map_err(|_| "notification URL is invalid".to_owned())?;
    if parsed.scheme() != "https" {
        return Err("notification URL must use HTTPS".to_owned());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "notification host is missing".to_owned())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "notification port is missing".to_owned())?;
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "notification DNS lookup failed".to_owned())?
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !surface_core::is_global_unicast(address.ip()))
    {
        return Err("notification destination is not globally routable".to_owned());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| "notification secret is invalid".to_owned())?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload.as_bytes());
    let signature = hex(&mac.finalize().into_bytes());
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .resolve(host, addresses[0])
        .build()
        .map_err(|_| "notification client could not be built".to_owned())?;
    client
        .post(parsed)
        .header("content-type", "application/json")
        .header("x-surface-timestamp", timestamp)
        .header("x-surface-signature", signature)
        .body(payload.to_owned())
        .send()
        .await
        .map(|response| response.status())
        .map_err(|_| "notification request failed".to_owned())
}

fn normalized_target(target: &NormalizedTarget) -> String {
    target
        .hostname
        .clone()
        .or_else(|| target.explicit_ip.map(|address| address.to_string()))
        .unwrap_or_else(|| target.original.clone())
}

fn validate_hosted_configuration(configuration: &ScanConfiguration) -> Result<(), ApiError> {
    if configuration.ports.is_empty()
        || configuration.ports.len() > 1_024
        || configuration.concurrency == 0
        || configuration.concurrency > 64
        || configuration.connect_timeout_ms == 0
        || configuration.connect_timeout_ms > 10_000
        || configuration.request_timeout_ms == 0
        || configuration.request_timeout_ms > 30_000
        || configuration.global_timeout_ms == 0
        || configuration.global_timeout_ms > 900_000
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_configuration",
            "scan configuration exceeds hosted limits",
        ));
    }
    Ok(())
}

fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    require_csrf: bool,
) -> Result<(AuthenticatedActor, [u8; 32]), ApiError> {
    if let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(decode_hex_32)
    {
        let token_hash = hash_secret(&token);
        let authenticated = state
            .storage
            .lock()
            .map_err(|_| internal())?
            .authenticate_api_token(&token_hash, OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| internal())?
            .filter(|(_, scopes)| scopes.iter().any(|scope| scope == "all"))
            .map(|(actor, _)| actor)
            .ok_or_else(unauthorized)?;
        return Ok((authenticated, token_hash));
    }
    let token = cookie(headers, SESSION_COOKIE)
        .and_then(|value| decode_hex_32(&value))
        .ok_or_else(unauthorized)?;
    let token_hash = hash_secret(&token);
    let csrf_hash = if require_csrf {
        let origin = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(forbidden)?;
        if origin.trim_end_matches('/') != state.public_origin {
            return Err(forbidden());
        }
        let csrf = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .and_then(decode_hex_32)
            .ok_or_else(forbidden)?;
        Some(hash_secret(&csrf))
    } else {
        None
    };
    let actor = state
        .storage
        .lock()
        .map_err(|_| internal())?
        .authenticate_session_with_csrf(
            &token_hash,
            csrf_hash.as_ref().map(<[u8; 32]>::as_slice),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|_| internal())?
        .ok_or_else(unauthorized)?;
    Ok((actor, token_hash))
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
}

/// Hashes a password using Argon2id and a fresh random salt.
///
/// # Errors
///
/// Returns an error when salt encoding or password hashing fails.
pub fn hash_password(password: &[u8]) -> Result<String, String> {
    let salt_bytes = rand::rng().random::<[u8; 16]>();
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|error| error.to_string())?;
    Argon2::default()
        .hash_password(password, &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| error.to_string())
}

fn random_token() -> [u8; 32] {
    rand::rng().random()
}

fn hash_secret(secret: &[u8]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(output)
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

const fn invalid_credentials() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "invalid credentials",
    )
}
const fn unauthorized() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "authentication required",
    )
}
const fn forbidden() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden",
        "action is not permitted",
    )
}
const fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "resource not found")
}
const fn internal() -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "request could not be completed",
    )
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt as _;
    use surface_core::{ScanConfiguration, ScanReport, normalize_target};
    use surface_storage::{ActorContext, Role, Storage};
    use tempfile::tempdir;
    use time::Duration;
    use tower::ServiceExt as _;

    use super::{AppState, LoginResponse, app, hash_password};

    fn report() -> ScanReport {
        ScanReport::not_started(
            normalize_target("example.com").unwrap_or_else(|error| panic!("{error}")),
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

    async fn login(router: axum::Router, tenant: &str) -> (String, LoginResponse) {
        let request = Request::post("/api/v1/session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"tenant_id":"{tenant}","username":"viewer","password":"correct horse battery"}}"#)))
            .unwrap_or_else(|error| panic!("{error}"));
        let response = router
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or_else(|| panic!("session cookie required"))
            .to_owned();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let login = serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        (cookie, login)
    }

    #[tokio::test]
    async fn tenant_scope_and_role_boundary_return_safe_statuses() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));
        let tenant = storage
            .create_tenant("Viewer tenant")
            .unwrap_or_else(|error| panic!("{error}"));
        let other = storage
            .create_tenant("Other tenant")
            .unwrap_or_else(|error| panic!("{error}"));
        let hash =
            hash_password(b"correct horse battery").unwrap_or_else(|error| panic!("{error}"));
        storage
            .create_user(&tenant, "viewer", &hash, Role::Viewer)
            .unwrap_or_else(|error| panic!("{error}"));
        let report = report();
        storage
            .persist_report_for(
                &ActorContext {
                    tenant_id: other,
                    actor_id: "seed".to_owned(),
                    actor_kind: "test".to_owned(),
                    request_id: "seed".to_owned(),
                },
                &report,
                "test",
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let router = app(
            AppState::new(storage, "http://127.0.0.1:8080", Duration::hours(1))
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let (cookie, login) = login(router.clone(), tenant.as_str()).await;

        let response = router
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/scans/{}", report.scan_id))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = router
            .oneshot(
                Request::delete(format!("/api/v1/scans/{}", report.scan_id))
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header("x-csrf-token", login.csrf_token)
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get("x-frame-options")
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
    }

    #[test]
    fn rejects_insecure_non_loopback_origin() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let storage = Storage::open(directory.path().join("surface.db"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(AppState::new(storage, "http://example.com", Duration::hours(1)).is_err());
    }
}
