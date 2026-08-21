use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use clap_complete::Shell;
use surface_core::{
    ScanConfiguration, ScanReport, ScanStatus, Severity, normalize_target, parse_ports, run_scan,
};
use surface_report::{render_html, render_json, render_terminal};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

// Rust guideline compliant 2026-02-21

const AUTHORIZED_USE_NOTICE: &str =
    "Use Surface only on systems you own or are explicitly authorized to assess.";
const EXIT_INVALID_INPUT: u8 = 1;
const EXIT_HIGH_FINDINGS: u8 = 2;
const EXIT_SCAN_FAILED: u8 = 3;
const EXIT_AUTHORIZATION_REQUIRED: u8 = 4;

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
    /// Named preset, comma-separated ports, or inclusive ranges.
    #[arg(long, default_value = "common")]
    ports: String,
    /// Maximum simultaneous TCP connections.
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
    /// Disables terminal colors.
    #[arg(long)]
    no_color: bool,
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
    /// Confirms authorization to actively assess the target.
    #[arg(long)]
    acknowledge_authorization: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormat {
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

async fn run_scan_command(arguments: ScanArgs) -> Result<(), AppError> {
    let target = normalize_target(&arguments.target)
        .map_err(|error| AppError::new(error.to_string(), EXIT_INVALID_INPUT))?;
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
    if !target.is_local() && !arguments.acknowledge_authorization {
        return Err(AppError::new(
            "active scanning requires --acknowledge-authorization for non-loopback targets",
            EXIT_AUTHORIZATION_REQUIRED,
        ));
    }
    let configuration = ScanConfiguration {
        ports: ports.as_slice().to_vec(),
        concurrency: arguments.concurrency,
        connect_timeout_ms: duration_millis(arguments.connect_timeout)?,
        request_timeout_ms: duration_millis(arguments.request_timeout)?,
        global_timeout_ms: duration_millis(arguments.global_timeout)?,
        ipv4_only: arguments.ipv4_only,
        ipv6_only: arguments.ipv6_only,
        authorization_acknowledged: arguments.acknowledge_authorization,
    };
    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancellation.cancel();
        }
    });
    let report = run_scan(target, configuration, cancellation).await;
    signal_task.abort();
    tracing::info!(
        name: "surface.scan.completed",
        scan_id = %report.scan_id,
        scan_status = ?report.status,
        finding_count = report.findings.len(),
        "scan completed"
    );
    let rendered = match arguments.format {
        ReportFormat::Terminal => render_terminal(&report),
        ReportFormat::Json => render_json(&report).map_err(|error| {
            AppError::new(
                format!("could not serialize report: {error}"),
                EXIT_SCAN_FAILED,
            )
        })?,
        ReportFormat::Html => render_html(&report),
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

    let _ = (arguments.no_color, arguments.verbose, arguments.quiet);
    if let Some(error) = report_exit_error(&report) {
        return Err(error);
    }
    Ok(())
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

fn duration_millis(duration: Duration) -> Result<u64, AppError> {
    u64::try_from(duration.as_millis())
        .map_err(|_| AppError::new("duration is too large", EXIT_INVALID_INPUT))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;

    use super::{
        Cli, Command, EXIT_AUTHORIZATION_REQUIRED, EXIT_INVALID_INPUT, EXIT_SCAN_FAILED,
        parse_duration, report_exit_error, run,
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
            "--acknowledge-authorization",
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(matches!(cli.command, Command::Scan(_)));
    }

    #[test]
    fn parses_bounded_duration_units() {
        assert_eq!(parse_duration("1500ms"), Ok(Duration::from_millis(1_500)));
        assert_eq!(parse_duration("5s"), Ok(Duration::from_secs(5)));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("1h").is_err());
    }

    #[tokio::test]
    async fn invalid_configuration_precedes_authorization_failure() {
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

        let unauthorized = Cli::try_parse_from(["surface", "scan", "example.com"])
            .unwrap_or_else(|error| panic!("{error}"));
        let authorization_error = run(unauthorized.command)
            .await
            .expect_err("authorization must fail");
        assert_eq!(authorization_error.exit_code, EXIT_AUTHORIZATION_REQUIRED);
    }

    #[test]
    fn incomplete_reports_return_failure_exit_code() {
        let mut report = surface_core::ScanReport::not_started(
            surface_core::normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            surface_core::ScanConfiguration {
                ports: vec![80],
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
