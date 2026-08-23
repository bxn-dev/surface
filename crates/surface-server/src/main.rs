use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand};
use surface_server::{AppState, hash_password};
use surface_storage::{Role, Storage, TenantId};
use time::Duration;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "surface-server", version, about = "Hosted Surface API")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        database: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        public_origin: String,
        #[arg(long, default_value_t = 12)]
        session_hours: i64,
        #[arg(long, default_value = "127.0.0.1:9090")]
        metrics_bind: SocketAddr,
    },
    BootstrapAdmin {
        #[arg(long)]
        database: PathBuf,
        #[arg(long, default_value = "local")]
        tenant: String,
        #[arg(long)]
        username: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let result = run(Cli::parse()).await;
    if let Err(error) = result {
        eprintln!("surface-server: {error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Serve {
            database,
            bind,
            public_origin,
            session_hours,
            metrics_bind,
        } => {
            let storage = Storage::open(database).map_err(|error| error.to_string())?;
            let state = AppState::new(storage, &public_origin, Duration::hours(session_hours))?;
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .map_err(|error| error.to_string())?;
            let metrics_listener = tokio::net::TcpListener::bind(metrics_bind)
                .await
                .map_err(|error| error.to_string())?;
            let cancellation = CancellationToken::new();
            let worker_id = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4());
            let notification_worker_id = format!("notify-{worker_id}");
            tracing::info!(%bind, "Surface server listening");
            let server = axum::serve(listener, surface_server::app(state.clone()))
                .with_graceful_shutdown(shutdown(cancellation.clone()));
            let metrics = axum::serve(metrics_listener, surface_server::metrics_app(state.clone()))
                .with_graceful_shutdown(cancellation.clone().cancelled_owned());
            let worker =
                surface_server::run_worker(state.clone(), worker_id, cancellation.child_token());
            let notifications = surface_server::run_notification_worker(
                state,
                notification_worker_id,
                cancellation.child_token(),
            );
            let (result, metrics_result, (), ()) =
                tokio::join!(server, metrics, worker, notifications);
            result
                .and(metrics_result)
                .map_err(|error| error.to_string())
        }
        Command::BootstrapAdmin {
            database,
            tenant,
            username,
        } => {
            let password = std::env::var("SURFACE_BOOTSTRAP_PASSWORD")
                .map_err(|_| "SURFACE_BOOTSTRAP_PASSWORD is required".to_owned())?;
            if password.len() < 12 || password.len() > 1_024 {
                return Err("bootstrap password must contain 12 to 1024 bytes".to_owned());
            }
            let mut storage = Storage::open(database).map_err(|error| error.to_string())?;
            let tenant = TenantId::new(tenant).map_err(|error| error.to_string())?;
            let password_hash = hash_password(password.as_bytes())?;
            storage
                .create_user(&tenant, &username, &password_hash, Role::Admin)
                .map_err(|error| error.to_string())?;
            println!("admin user created for tenant {}", tenant.as_str());
            Ok(())
        }
    }
}

async fn shutdown(cancellation: CancellationToken) {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "could not install shutdown signal");
    }
    cancellation.cancel();
}
