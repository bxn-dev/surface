use std::fmt;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use clap_complete::Shell;
use indicatif::{ProgressBar, ProgressDrawTarget};
use surface_core::{
    IntelligenceObservation, ScanConfiguration, ScanProgress, ScanReport, ScanSelection, ScanStage,
    ScanStatus, Severity, SkippedCheck, analyze_certificate_transparency, analyze_intelligence,
    analyze_network_registrations, analyze_related_domains, calculate_exposure, normalize_target,
    parse_bundle, parse_ports, parse_udp_ports, run_scan_selected_until_with_progress,
};
use surface_report::{
    decode_key, diff_reports, render_cyclonedx, render_diff_html, render_diff_json,
    render_diff_terminal, render_html, render_json, render_sarif, render_terminal, sign_bytes,
    verify_bytes,
};
use surface_storage::{
    HistoryFilter, RetentionPolicy, Storage, backup_database, restore_database, verify_database,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

// Rust guideline compliant 2026-02-21

const AUTHORIZED_USE_NOTICE: &str =
    "Use Surface only on systems you own or are explicitly authorized to assess.";
const EXIT_INVALID_INPUT: u8 = 1;
const EXIT_HIGH_FINDINGS: u8 = 2;
const EXIT_SCAN_FAILED: u8 = 3;

/// Analyzes externally observable services and security-related configuration.
#[derive(Debug, Parser)]
#[command(name = "surface", version, propagate_version = true, after_help = AUTHORIZED_USE_NOTICE)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Runs an authorized external exposure assessment.
    Scan(ScanArgs),
    /// Compares two report files or persisted scans.
    Diff(DiffArgs),
    /// Lists, retrieves, deletes, or prunes persisted scans.
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    /// Signs or verifies exact report bytes.
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Backs up, verifies, or restores a Surface database.
    Database {
        #[command(subcommand)]
        command: DatabaseCommand,
    },
    /// Prints the Surface version.
    Version,
    /// Generates a shell-completion script on stdout.
    Completion {
        /// Shell receiving the completion script.
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent CLI flags map directly to user choices"
)]
struct ScanArgs {
    /// Domain, hostname, HTTP(S) URL, or IP address to assess.
    target: String,
    /// TCP preset (`common` or `all`), comma-separated ports, or ranges.
    #[arg(long, default_value = "common")]
    ports: String,
    /// UDP preset (`common` or `all`), comma-separated ports, or ranges.
    #[arg(long, default_value = "common")]
    udp_ports: String,
    /// Maximum simultaneous network probes.
    #[arg(long, default_value_t = 64)]
    concurrency: usize,
    /// Per-connection timeout, such as 1500ms or 2s.
    #[arg(long, default_value = "1500ms", value_parser = parse_duration)]
    connect_timeout: Duration,
    /// Per-request timeout, such as 5s.
    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    request_timeout: Duration,
    /// Whole-scan timeout, such as 5m.
    #[arg(long, default_value = "5m", value_parser = parse_duration)]
    global_timeout: Duration,
    /// Report format.
    #[arg(long, value_enum, default_value_t = ReportFormat::Terminal)]
    format: ReportFormat,
    /// Writes the report to a file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Enables diagnostic logging in later scanning phases.
    #[arg(long, conflicts_with = "quiet")]
    verbose: bool,
    /// Suppresses non-report diagnostics.
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,
    /// Restricts future address discovery to IPv4.
    #[arg(long, conflicts_with = "ipv6_only")]
    ipv4_only: bool,
    /// Restricts future address discovery to IPv6.
    #[arg(long, conflicts_with = "ipv4_only")]
    ipv6_only: bool,
    /// `SQLite` database path used when persistence is enabled.
    #[arg(long, requires = "persist")]
    database: Option<PathBuf>,
    /// Persists the complete immutable report after scanning.
    #[arg(long)]
    persist: bool,
    /// Passively observes an explicitly supplied child subdomain (repeatable).
    #[arg(long = "subdomain")]
    subdomains: Vec<String>,
    /// Queries an explicitly supplied DKIM selector (repeatable).
    #[arg(long = "dkim-selector")]
    dkim_selectors: Vec<String>,
    /// Optional bounded offline network/CVE intelligence bundle.
    #[arg(long)]
    intelligence_bundle: Option<PathBuf>,
    /// Restricts the default full scan to selected groups (repeatable or comma-separated).
    #[arg(long, value_enum, value_delimiter = ',')]
    only: Vec<ScanPart>,
}

#[derive(Debug, clap::Args)]
struct DiffArgs {
    /// Earlier report file or scan identifier.
    old: String,
    /// Later report file or scan identifier.
    new: String,
    /// Loads both arguments as scan identifiers from this `SQLite` database.
    #[arg(long)]
    database: Option<PathBuf>,
    /// Diff output format.
    #[arg(long, value_enum, default_value_t = DiffFormat::Terminal)]
    format: DiffFormat,
    /// Writes the diff to a file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    /// Creates a detached Ed25519 signature.
    Sign {
        report: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        signature: PathBuf,
    },
    /// Verifies a detached Ed25519 signature.
    Verify {
        report: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DatabaseCommand {
    /// Creates an integrity-checked online backup.
    Backup {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Runs integrity and schema checks.
    Verify {
        #[arg(long)]
        database: PathBuf,
    },
    /// Atomically restores a verified backup while no process uses the database.
    Restore {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    /// Lists persisted scans newest first.
    List {
        /// `SQLite` database path.
        #[arg(long)]
        database: PathBuf,
        /// Exact normalized target filter.
        #[arg(long)]
        target: Option<String>,
        /// Exact scan status filter.
        #[arg(long)]
        status: Option<String>,
        /// Minimum finding severity filter.
        #[arg(long, value_enum)]
        severity: Option<SeverityFilter>,
        /// Include scans started at or after this Unix timestamp.
        #[arg(long)]
        started_after: Option<i64>,
        /// Include scans started at or before this Unix timestamp.
        #[arg(long)]
        started_before: Option<i64>,
        /// Maximum records returned.
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Zero-based record offset.
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Emits machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Shows one complete persisted report.
    Show {
        /// Persisted scan identifier.
        scan_id: Uuid,
        /// `SQLite` database path.
        #[arg(long)]
        database: PathBuf,
        /// Report format.
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },
    /// Deletes one persisted report and dependent metadata.
    Delete {
        /// Persisted scan identifier.
        scan_id: Uuid,
        /// `SQLite` database path.
        #[arg(long)]
        database: PathBuf,
    },
    /// Applies retention to persisted reports.
    Prune {
        /// `SQLite` database path.
        #[arg(long)]
        database: PathBuf,
        /// Retains this many newest scans for each target.
        #[arg(long)]
        keep_last: Option<u32>,
        /// Deletes scans older than this duration, such as 180d.
        #[arg(long, value_parser = parse_retention_duration)]
        older_than: Option<time::Duration>,
        /// Preserves scans containing high or critical findings.
        #[arg(long)]
        preserve_high: bool,
        /// Reports candidates without deleting them.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityFilter> for Severity {
    fn from(value: SeverityFilter) -> Self {
        match value {
            SeverityFilter::Info => Self::Info,
            SeverityFilter::Low => Self::Low,
            SeverityFilter::Medium => Self::Medium,
            SeverityFilter::High => Self::High,
            SeverityFilter::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ScanPart {
    Dns,
    Ports,
    Services,
    Http,
    Tls,
    Intelligence,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormat {
    Terminal,
    Json,
    Html,
    Sarif,
    CyclonedxJson,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DiffFormat {
    Terminal,
    Json,
    Html,
}

#[derive(Debug)]
struct AppError {
    message: String,
    exit_code: u8,
}

impl AppError {
    fn new(message: impl Into<String>, exit_code: u8) -> Self {
        Self {
            message: message.into(),
            exit_code,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let _ = error.print();
            return ExitCode::from(if informational { 0 } else { EXIT_INVALID_INPUT });
        }
    };

    init_logging(&cli.command);
    match run(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("surface: {error}");
            ExitCode::from(error.exit_code)
        }
    }
}

async fn run(command: Command) -> Result<(), AppError> {
    match command {
        Command::Scan(arguments) => run_scan_command(arguments).await,
        Command::Diff(arguments) => run_diff_command(arguments).await,
        Command::History { command } => run_history_command(command),
        Command::Report { command } => run_report_command(command).await,
        Command::Database { command } => run_database_command(command),
        Command::Version => {
            println!("surface {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Completion { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "surface", &mut io::stdout());
            Ok(())
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "linear CLI orchestration preserves cancellation, intelligence, and output ordering"
)]
async fn run_scan_command(arguments: ScanArgs) -> Result<(), AppError> {
    let scan_deadline = tokio::time::Instant::now() + arguments.global_timeout;
    let target = normalize_target(&arguments.target)
        .map_err(|error| AppError::new(error.to_string(), EXIT_INVALID_INPUT))?;
    let full_scan = arguments.only.is_empty();
    let intelligence_selected = full_scan || arguments.only.contains(&ScanPart::Intelligence);
    let selected_stages = arguments
        .only
        .iter()
        .filter_map(|part| match part {
            ScanPart::Dns | ScanPart::Intelligence => None,
            ScanPart::Ports => Some(ScanStage::Ports),
            ScanPart::Services => Some(ScanStage::Services),
            ScanPart::Http => Some(ScanStage::Http),
            ScanPart::Tls => Some(ScanStage::Tls),
        })
        .collect::<Vec<_>>();
    let selection = if full_scan {
        ScanSelection::all()
    } else {
        ScanSelection::only(&selected_stages)
    };
    let reverse_ns_api_key = intelligence_selected
        .then(|| std::env::var("SURFACE_WHOISXML_API_KEY").ok())
        .flatten()
        .filter(|value| !value.trim().is_empty());
    if target.explicit_ip.is_some_and(|ip| {
        (arguments.ipv4_only && ip.is_ipv6()) || (arguments.ipv6_only && ip.is_ipv4())
    }) {
        return Err(AppError::new(
            "explicit IP conflicts with the selected address family",
            EXIT_INVALID_INPUT,
        ));
    }
    if arguments.concurrency == 0 || arguments.concurrency > 4_096 {
        return Err(AppError::new(
            "concurrency must be between 1 and 4096",
            EXIT_INVALID_INPUT,
        ));
    }
    let ports = parse_ports(&arguments.ports)
        .map_err(|error| AppError::new(error.to_string(), EXIT_INVALID_INPUT))?;
    let udp_ports = parse_udp_ports(&arguments.udp_ports)
        .map_err(|error| AppError::new(error.to_string(), EXIT_INVALID_INPUT))?;
    let configuration = ScanConfiguration {
        ports: ports.as_slice().to_vec(),
        udp_ports: udp_ports.as_slice().to_vec(),
        concurrency: arguments.concurrency,
        connect_timeout_ms: duration_millis(arguments.connect_timeout)?,
        request_timeout_ms: duration_millis(arguments.request_timeout)?,
        global_timeout_ms: duration_millis(arguments.global_timeout)?,
        ipv4_only: arguments.ipv4_only,
        ipv6_only: arguments.ipv6_only,
        authorization_acknowledged: true,
    };
    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancellation.cancel();
        }
    });
    let progress = progress_bar(arguments.quiet);
    let scan_progress = progress.clone();
    let mut report = run_scan_selected_until_with_progress(
        target,
        configuration,
        cancellation.clone(),
        selection,
        scan_deadline,
        move |event| match event {
            ScanProgress::Started(stage) => scan_progress.set_message(format!("{stage:?}")),
            ScanProgress::Completed {
                stage,
                observations,
            } => scan_progress.set_message(format!("{stage:?}: {observations}")),
        },
    )
    .await;
    progress.finish_and_clear();
    if intelligence_selected
        && (!arguments.subdomains.is_empty()
            || !arguments.dkim_selectors.is_empty()
            || arguments.intelligence_bundle.is_some())
    {
        let explicit_intelligence = tokio::select! {
            biased;
            () = cancellation.cancelled() => None,
            result = tokio::time::timeout_at(scan_deadline, async {
                let bundle = if let Some(path) = &arguments.intelligence_bundle {
                    let bytes = read_bounded(path, 16 * 1024 * 1024).await?;
                    Some(parse_bundle(&bytes).map_err(|error| {
                        AppError::new(error, EXIT_INVALID_INPUT)
                    })?)
                } else {
                    None
                };
                analyze_intelligence(
                    &report,
                    &arguments.subdomains,
                    &arguments.dkim_selectors,
                    bundle.as_ref(),
                    arguments.request_timeout,
                )
                .await
                .map_err(|error| AppError::new(error, EXIT_INVALID_INPUT))
            }) => result.ok(),
        };
        if let Some(result) = explicit_intelligence {
            match result {
                Ok(observation) => {
                    if !observation.complete {
                        mark_intelligence_partial(&mut report);
                    }
                    report.intelligence = Some(observation);
                }
                Err(error) => {
                    signal_task.abort();
                    return Err(error);
                }
            }
        } else {
            mark_intelligence_stopped(
                &mut report,
                cancellation.is_cancelled(),
                &[
                    ("subdomain_dns", !arguments.subdomains.is_empty()),
                    ("dkim", !arguments.dkim_selectors.is_empty()),
                    (
                        "offline_network_metadata",
                        arguments.intelligence_bundle.is_some(),
                    ),
                    (
                        "offline_cve_correlation",
                        arguments.intelligence_bundle.is_some(),
                    ),
                ],
            );
        }
    }
    if intelligence_selected {
        analyze_network_registrations(
            &mut report,
            arguments.request_timeout,
            scan_deadline,
            &cancellation,
        )
        .await;
    }
    let related_configured = reverse_ns_api_key.is_some();
    let ct_applicable = intelligence_selected && report.target.hostname.is_some();
    let certspotter_api_key = std::env::var("SURFACE_CERTSPOTTER_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let passive_results = if ct_applicable || related_configured {
        let passive_progress = progress_bar(arguments.quiet);
        passive_progress.set_message("Passive intelligence");
        let results = tokio::select! {
            biased;
            () = cancellation.cancelled() => None,
            result = tokio::time::timeout_at(scan_deadline, async {
                tokio::join!(
                    async {
                        if ct_applicable {
                            Some(
                                analyze_certificate_transparency(
                                    &report,
                                    certspotter_api_key.as_deref(),
                                    arguments.request_timeout,
                                )
                                .await,
                            )
                        } else {
                            None
                        }
                    },
                    async {
                        if let Some(api_key) = reverse_ns_api_key.as_deref() {
                            Some(
                                analyze_related_domains(
                                    &report,
                                    api_key,
                                    arguments.request_timeout,
                                )
                                .await,
                            )
                        } else {
                            None
                        }
                    }
                )
            }) => result.ok(),
        };
        passive_progress.finish_and_clear();
        results
    } else {
        Some((None, None))
    };
    if let Some((certificate_transparency, related_domains)) = passive_results {
        if let Some(result) = certificate_transparency {
            match result {
                Ok(observation) => {
                    let intelligence =
                        report
                            .intelligence
                            .get_or_insert_with(|| IntelligenceObservation {
                                complete: true,
                                ..IntelligenceObservation::default()
                            });
                    let complete = observation.complete;
                    intelligence.complete &= complete;
                    intelligence.certificate_transparency = Some(observation);
                    if !complete {
                        mark_intelligence_partial(&mut report);
                    }
                }
                Err(reason) => {
                    report.skipped_checks.push(SkippedCheck {
                        check: "certificate_transparency".to_owned(),
                        reason,
                    });
                    mark_intelligence_partial(&mut report);
                }
            }
        }
        if let Some(result) = related_domains {
            match result {
                Ok(related) => {
                    let intelligence =
                        report
                            .intelligence
                            .get_or_insert_with(|| IntelligenceObservation {
                                complete: true,
                                ..IntelligenceObservation::default()
                            });
                    let complete = related.complete;
                    intelligence.complete &= complete;
                    intelligence.related_domains = Some(related);
                    if !complete {
                        mark_intelligence_partial(&mut report);
                    }
                }
                Err(reason) => {
                    report.skipped_checks.push(SkippedCheck {
                        check: "related_domains".to_owned(),
                        reason,
                    });
                    mark_intelligence_partial(&mut report);
                }
            }
        }
    } else {
        mark_intelligence_stopped(
            &mut report,
            cancellation.is_cancelled(),
            &[
                ("certificate_transparency", ct_applicable),
                ("related_domains", related_configured),
            ],
        );
    }
    if intelligence_selected && !ct_applicable {
        report.skipped_checks.push(SkippedCheck {
            check: "certificate_transparency".to_owned(),
            reason: "certificate transparency discovery requires a hostname target".to_owned(),
        });
    }
    record_intelligence_skips(
        &mut report,
        &arguments,
        intelligence_selected,
        related_configured,
    );
    refresh_exposure_score(&mut report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
    signal_task.abort();
    if arguments.persist {
        let database = arguments.database.as_ref().ok_or_else(|| {
            AppError::new("--database is required with --persist", EXIT_INVALID_INPUT)
        })?;
        let mut storage = open_storage(database)?;
        storage
            .persist_report(&report, "cli")
            .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))?;
    }
    tracing::info!(
        name: "surface.scan.completed",
        scan_id = %report.scan_id,
        scan_status = ?report.status,
        finding_count = report.findings.len(),
        "scan completed"
    );
    let rendered = render_report(&report, arguments.format)?;

    if let Some(path) = arguments.output {
        tokio::fs::write(&path, rendered).await.map_err(|error| {
            AppError::new(
                format!("could not write '{}': {error}", path.display()),
                EXIT_SCAN_FAILED,
            )
        })?;
    } else {
        print!("{rendered}");
        let html_path = PathBuf::from(format!("surface-{}.html", report.scan_id));
        tokio::fs::write(&html_path, render_html(&report))
            .await
            .map_err(|error| {
                AppError::new(
                    format!("could not write '{}': {error}", html_path.display()),
                    EXIT_SCAN_FAILED,
                )
            })?;
        if !arguments.quiet {
            eprintln!("HTML report: {}", html_path.display());
        }
    }

    let _ = arguments.verbose;
    if let Some(error) = report_exit_error(&report) {
        return Err(error);
    }
    Ok(())
}

async fn run_report_command(command: ReportCommand) -> Result<(), AppError> {
    match command {
        ReportCommand::Sign {
            report,
            key,
            signature,
        } => {
            ensure_private_key_permissions(&key)?;
            let report_bytes = read_bounded(&report, 16 * 1024 * 1024).await?;
            let key_bytes = read_bounded(&key, 4_096).await?;
            let key = decode_key::<32>(&key_bytes).ok_or_else(|| {
                AppError::new(
                    "private key must be 32 raw bytes encoded as hexadecimal",
                    EXIT_INVALID_INPUT,
                )
            })?;
            let envelope = sign_bytes(&report_bytes, &key)
                .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))?;
            tokio::fs::write(&signature, envelope)
                .await
                .map_err(|error| {
                    AppError::new(
                        format!("could not write '{}': {error}", signature.display()),
                        EXIT_SCAN_FAILED,
                    )
                })
        }
        ReportCommand::Verify {
            report,
            signature,
            public_key,
        } => {
            let report_bytes = read_bounded(&report, 16 * 1024 * 1024).await?;
            let envelope = read_bounded(&signature, 64 * 1024).await?;
            let key_bytes = read_bounded(&public_key, 4_096).await?;
            let key = decode_key::<32>(&key_bytes).ok_or_else(|| {
                AppError::new(
                    "public key must be 32 raw bytes encoded as hexadecimal",
                    EXIT_INVALID_INPUT,
                )
            })?;
            verify_bytes(&report_bytes, &envelope, &key)
                .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))?;
            println!("signature valid");
            Ok(())
        }
    }
}

fn run_database_command(command: DatabaseCommand) -> Result<(), AppError> {
    match command {
        DatabaseCommand::Backup { database, output } => backup_database(&database, &output),
        DatabaseCommand::Verify { database } => verify_database(&database),
        DatabaseCommand::Restore { database, input } => restore_database(&database, &input),
    }
    .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))
}

async fn read_bounded(path: &PathBuf, maximum: u64) -> Result<Vec<u8>, AppError> {
    let metadata = tokio::fs::metadata(path).await.map_err(|error| {
        AppError::new(
            format!("could not inspect '{}': {error}", path.display()),
            EXIT_INVALID_INPUT,
        )
    })?;
    if metadata.len() > maximum {
        return Err(AppError::new(
            format!("'{}' exceeds the {} byte limit", path.display(), maximum),
            EXIT_INVALID_INPUT,
        ));
    }
    tokio::fs::read(path).await.map_err(|error| {
        AppError::new(
            format!("could not read '{}': {error}", path.display()),
            EXIT_INVALID_INPUT,
        )
    })
}

#[cfg(unix)]
fn ensure_private_key_permissions(path: &PathBuf) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .map_err(|error| {
            AppError::new(
                format!("could not inspect '{}': {error}", path.display()),
                EXIT_INVALID_INPUT,
            )
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(AppError::new(
            "private key permissions must not grant group or other access",
            EXIT_INVALID_INPUT,
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn ensure_private_key_permissions(_path: &PathBuf) -> Result<(), AppError> {
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one match keeps each history subcommand's linear CLI behavior together"
)]
fn run_history_command(command: HistoryCommand) -> Result<(), AppError> {
    match command {
        HistoryCommand::List {
            database,
            target,
            status,
            severity,
            started_after,
            started_before,
            limit,
            offset,
            json,
        } => {
            let storage = open_storage(&database)?;
            let history = storage
                .history(&HistoryFilter {
                    target,
                    status,
                    minimum_severity: severity.map(Into::into),
                    started_after,
                    started_before,
                    offset,
                    limit,
                })
                .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&history).map_err(|error| AppError::new(
                        format!("could not serialize history: {error}"),
                        EXIT_SCAN_FAILED,
                    ))?
                );
            } else {
                for scan in history {
                    println!(
                        "{}  {}  {}  {}  high={} critical={}",
                        scan.scan_id,
                        scan.started_at,
                        scan.status,
                        scan.normalized_target,
                        scan.high_findings,
                        scan.critical_findings
                    );
                }
            }
            Ok(())
        }
        HistoryCommand::Show {
            scan_id,
            database,
            format,
        } => {
            let storage = open_storage(&database)?;
            let report = storage
                .report(scan_id)
                .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))?
                .ok_or_else(|| {
                    AppError::new(format!("scan {scan_id} was not found"), EXIT_INVALID_INPUT)
                })?;
            let rendered = render_report(&report, format)?;
            print!("{rendered}");
            Ok(())
        }
        HistoryCommand::Delete { scan_id, database } => {
            let mut storage = open_storage(&database)?;
            if !storage
                .delete_scan(scan_id)
                .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))?
            {
                return Err(AppError::new(
                    format!("scan {scan_id} was not found"),
                    EXIT_INVALID_INPUT,
                ));
            }
            println!("deleted {scan_id}");
            Ok(())
        }
        HistoryCommand::Prune {
            database,
            keep_last,
            older_than,
            preserve_high,
            dry_run,
        } => {
            let mut storage = open_storage(&database)?;
            let result = storage
                .prune(&RetentionPolicy {
                    keep_last,
                    older_than,
                    preserve_high,
                    dry_run,
                })
                .map_err(|error| AppError::new(error.to_string(), EXIT_INVALID_INPUT))?;
            for scan_id in &result.scan_ids {
                println!("{scan_id}");
            }
            eprintln!(
                "surface: {} {} scan(s)",
                if result.deleted {
                    "deleted"
                } else {
                    "would delete"
                },
                result.scan_ids.len()
            );
            Ok(())
        }
    }
}

async fn run_diff_command(arguments: DiffArgs) -> Result<(), AppError> {
    let (old, new) = if let Some(database) = &arguments.database {
        let old_id = Uuid::parse_str(&arguments.old)
            .map_err(|_| AppError::new("old scan ID is invalid", EXIT_INVALID_INPUT))?;
        let new_id = Uuid::parse_str(&arguments.new)
            .map_err(|_| AppError::new("new scan ID is invalid", EXIT_INVALID_INPUT))?;
        let storage = open_storage(database)?;
        let old = storage
            .report(old_id)
            .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))?
            .ok_or_else(|| {
                AppError::new(format!("scan {old_id} was not found"), EXIT_INVALID_INPUT)
            })?;
        let new = storage
            .report(new_id)
            .map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))?
            .ok_or_else(|| {
                AppError::new(format!("scan {new_id} was not found"), EXIT_INVALID_INPUT)
            })?;
        (old, new)
    } else {
        (
            load_report_file(PathBuf::from(&arguments.old)).await?,
            load_report_file(PathBuf::from(&arguments.new)).await?,
        )
    };
    let diff = diff_reports(&old, &new)
        .map_err(|error| AppError::new(error.to_string(), EXIT_INVALID_INPUT))?;
    let rendered = match arguments.format {
        DiffFormat::Terminal => render_diff_terminal(&diff),
        DiffFormat::Json => render_diff_json(&diff).map_err(|error| {
            AppError::new(
                format!("could not serialize diff: {error}"),
                EXIT_SCAN_FAILED,
            )
        })?,
        DiffFormat::Html => render_diff_html(&diff),
    };
    if let Some(path) = arguments.output {
        tokio::fs::write(&path, rendered).await.map_err(|error| {
            AppError::new(
                format!("could not write '{}': {error}", path.display()),
                EXIT_SCAN_FAILED,
            )
        })?;
    } else {
        print!("{rendered}");
    }
    Ok(())
}

async fn load_report_file(path: PathBuf) -> Result<ScanReport, AppError> {
    const MAX_REPORT_BYTES: u64 = 16 * 1_024 * 1_024;
    let metadata = tokio::fs::metadata(&path).await.map_err(|error| {
        AppError::new(
            format!("could not inspect '{}': {error}", path.display()),
            EXIT_SCAN_FAILED,
        )
    })?;
    if metadata.len() > MAX_REPORT_BYTES {
        return Err(AppError::new(
            format!("report '{}' exceeds 16 MiB", path.display()),
            EXIT_INVALID_INPUT,
        ));
    }
    let bytes = tokio::fs::read(&path).await.map_err(|error| {
        AppError::new(
            format!("could not read '{}': {error}", path.display()),
            EXIT_SCAN_FAILED,
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        AppError::new(
            format!("report '{}' is invalid: {error}", path.display()),
            EXIT_INVALID_INPUT,
        )
    })
}

fn render_report(report: &ScanReport, format: ReportFormat) -> Result<String, AppError> {
    match format {
        ReportFormat::Terminal => Ok(render_terminal(report)),
        ReportFormat::Json => render_json(report),
        ReportFormat::Html => Ok(render_html(report)),
        ReportFormat::Sarif => render_sarif(report),
        ReportFormat::CyclonedxJson => render_cyclonedx(report),
    }
    .map_err(|error| {
        AppError::new(
            format!("could not serialize report: {error}"),
            EXIT_SCAN_FAILED,
        )
    })
}

fn open_storage(path: &PathBuf) -> Result<Storage, AppError> {
    Storage::open(path).map_err(|error| AppError::new(error.to_string(), EXIT_SCAN_FAILED))
}

fn report_exit_error(report: &ScanReport) -> Option<AppError> {
    if report.status != ScanStatus::Completed {
        return Some(AppError::new(
            "scan incomplete; inspect the partial report",
            EXIT_SCAN_FAILED,
        ));
    }
    report
        .findings
        .iter()
        .any(|finding| finding.severity >= Severity::High)
        .then(|| {
            AppError::new(
                "scan completed with high-severity findings",
                EXIT_HIGH_FINDINGS,
            )
        })
}

fn refresh_exposure_score(report: &mut ScanReport) {
    report.exposure_score = Some(calculate_exposure(report));
}

fn mark_intelligence_partial(report: &mut ScanReport) {
    if report.status == ScanStatus::Completed {
        report.status = ScanStatus::Partial;
        "Scan completed with incomplete intelligence.".clone_into(&mut report.message);
    }
}

fn mark_intelligence_stopped(report: &mut ScanReport, cancelled: bool, checks: &[(&str, bool)]) {
    let reason = if cancelled {
        report.status = ScanStatus::Interrupted;
        "scan interrupted"
    } else {
        if report.status != ScanStatus::Interrupted {
            report.status = ScanStatus::Partial;
        }
        "global timeout expired"
    };
    reason.clone_into(&mut report.message);
    for (check, applicable) in checks {
        if *applicable
            && !report
                .skipped_checks
                .iter()
                .any(|skipped| skipped.check == *check)
        {
            report.skipped_checks.push(SkippedCheck {
                check: (*check).to_owned(),
                reason: reason.to_owned(),
            });
        }
    }
}

fn record_intelligence_skips(
    report: &mut ScanReport,
    arguments: &ScanArgs,
    intelligence_selected: bool,
    related_configured: bool,
) {
    let mut skip = |check: &str, reason: &str| {
        report.skipped_checks.push(SkippedCheck {
            check: check.to_owned(),
            reason: reason.to_owned(),
        });
    };
    if !intelligence_selected {
        skip("intelligence", "excluded by --only");
        return;
    }
    if arguments.subdomains.is_empty() {
        skip("subdomain_dns", "no child domains supplied");
    }
    if arguments.dkim_selectors.is_empty() {
        skip("dkim", "no selectors supplied");
    }
    if arguments.intelligence_bundle.is_none() {
        skip(
            "offline_network_metadata",
            "no intelligence bundle supplied",
        );
        skip("offline_cve_correlation", "no intelligence bundle supplied");
    }
    if !related_configured {
        skip(
            "related_domains",
            "SURFACE_WHOISXML_API_KEY is not configured",
        );
    }
}

fn progress_bar(quiet: bool) -> ProgressBar {
    let draw_target = if !quiet && io::stderr().is_terminal() {
        ProgressDrawTarget::stderr_with_hz(15)
    } else {
        ProgressDrawTarget::hidden()
    };
    let progress = ProgressBar::with_draw_target(None, draw_target);
    progress.enable_steady_tick(Duration::from_millis(100));
    progress
}

fn init_logging(command: &Command) {
    let level = match command {
        Command::Scan(arguments) if arguments.quiet => tracing_subscriber::filter::LevelFilter::OFF,
        Command::Scan(arguments) if arguments.verbose => {
            tracing_subscriber::filter::LevelFilter::DEBUG
        }
        _ => tracing_subscriber::filter::LevelFilter::ERROR,
    };
    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_target(false)
        .try_init();
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else {
        return Err("duration must end in ms, s, or m".to_owned());
    };
    let amount = number
        .parse::<u64>()
        .map_err(|_| "duration must contain a positive integer".to_owned())?;
    let milliseconds = amount
        .checked_mul(multiplier)
        .filter(|milliseconds| *milliseconds > 0)
        .ok_or_else(|| "duration must be positive and within range".to_owned())?;
    Ok(Duration::from_millis(milliseconds))
}

fn parse_retention_duration(value: &str) -> Result<time::Duration, String> {
    let days = value
        .strip_suffix('d')
        .ok_or_else(|| "retention duration must end in d".to_owned())?
        .parse::<i64>()
        .map_err(|_| "retention duration must contain a positive integer".to_owned())?;
    let seconds = days
        .checked_mul(86_400)
        .filter(|_| days > 0)
        .ok_or_else(|| "retention duration must be positive and within range".to_owned())?;
    Ok(time::Duration::seconds(seconds))
}

fn duration_millis(duration: Duration) -> Result<u64, AppError> {
    u64::try_from(duration.as_millis())
        .map_err(|_| AppError::new("duration is too large", EXIT_INVALID_INPUT))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;

    use super::{
        Cli, Command, EXIT_INVALID_INPUT, EXIT_SCAN_FAILED, ScanPart, mark_intelligence_partial,
        mark_intelligence_stopped, parse_duration, parse_retention_duration,
        refresh_exposure_score, report_exit_error, run,
    };

    #[test]
    fn parses_phase_one_scan_options() {
        let cli = Cli::try_parse_from([
            "surface",
            "scan",
            "example.com",
            "--ports",
            "22,80,443",
            "--format",
            "json",
            "--only",
            "dns,http",
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        let Command::Scan(arguments) = cli.command else {
            panic!("expected scan command");
        };
        assert_eq!(arguments.only, vec![ScanPart::Dns, ScanPart::Http]);
    }

    #[test]
    fn parses_diff_and_integration_formats() {
        for format in ["sarif", "cyclonedx-json"] {
            let cli = Cli::try_parse_from(["surface", "scan", "127.0.0.1", "--format", format])
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(matches!(cli.command, Command::Scan(_)));
        }
        let files = Cli::try_parse_from([
            "surface", "diff", "old.json", "new.json", "--format", "json",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(files.command, Command::Diff(_)));
        let database = Cli::try_parse_from([
            "surface",
            "diff",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "--database",
            "surface.db",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(database.command, Command::Diff(_)));
    }

    #[test]
    fn parses_bounded_duration_units() {
        assert_eq!(parse_duration("1500ms"), Ok(Duration::from_millis(1_500)));
        assert_eq!(parse_duration("5s"), Ok(Duration::from_secs(5)));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("1h").is_err());
        assert!(parse_retention_duration("9223372036854775807d").is_err());
    }

    #[test]
    fn stopped_intelligence_records_timeout_or_cancellation() {
        let mut report = surface_core::ScanReport::not_started(
            surface_core::normalize_target("example.com").unwrap_or_else(|error| panic!("{error}")),
            surface_core::ScanConfiguration {
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
        report.status = surface_core::ScanStatus::Completed;
        mark_intelligence_partial(&mut report);
        assert_eq!(report.status, surface_core::ScanStatus::Partial);
        report.status = surface_core::ScanStatus::Completed;

        mark_intelligence_stopped(&mut report, false, &[("certificate_transparency", true)]);
        assert_eq!(report.status, surface_core::ScanStatus::Partial);
        assert_eq!(report.skipped_checks[0].reason, "global timeout expired");

        mark_intelligence_stopped(&mut report, true, &[("related_domains", true)]);
        assert_eq!(report.status, surface_core::ScanStatus::Interrupted);
        assert_eq!(report.skipped_checks[1].reason, "scan interrupted");
    }

    #[tokio::test]
    async fn invalid_configuration_is_rejected_before_scanning() {
        let invalid = Cli::try_parse_from(["surface", "scan", "example.com", "--ports", "nope"])
            .unwrap_or_else(|error| panic!("{error}"));
        let invalid_error = run(invalid.command)
            .await
            .expect_err("invalid ports must fail");
        assert_eq!(invalid_error.exit_code, EXIT_INVALID_INPUT);

        let wrong_family = Cli::try_parse_from(["surface", "scan", "::1", "--ipv4-only"])
            .unwrap_or_else(|error| panic!("{error}"));
        let family_error = run(wrong_family.command)
            .await
            .expect_err("incompatible address family must fail");
        assert_eq!(family_error.exit_code, EXIT_INVALID_INPUT);
    }

    #[test]
    fn skipped_checks_mark_recalculated_score_incomplete() {
        let mut report = surface_core::ScanReport::not_started(
            surface_core::normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            surface_core::ScanConfiguration {
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
        report.status = surface_core::ScanStatus::Completed;
        report.skipped_checks.push(surface_core::SkippedCheck {
            check: "related_domains".to_owned(),
            reason: "credential unavailable".to_owned(),
        });

        refresh_exposure_score(&mut report);

        assert!(
            report
                .exposure_score
                .as_ref()
                .is_some_and(|score| score.incomplete)
        );
    }

    #[test]
    fn incomplete_reports_return_failure_exit_code() {
        let mut report = surface_core::ScanReport::not_started(
            surface_core::normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            surface_core::ScanConfiguration {
                ports: vec![80],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: false,
            },
        );
        report.status = surface_core::ScanStatus::Interrupted;
        let error = report_exit_error(&report).unwrap_or_else(|| panic!("exit error required"));
        assert_eq!(error.exit_code, EXIT_SCAN_FAILED);
    }
}
