//! Scan-stage orchestration with global deadlines and cancellation.

use std::net::IpAddr;
use std::time::Duration;

use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::{
    NormalizedTarget, ScanConfiguration, ScanError, ScanErrorKind, ScanReport, ScanStage,
    ScanStatus, analyze_dns, analyze_http, analyze_tls, detect_services, generate_findings,
    scan_ports,
};

// Rust guideline compliant 2026-02-21

const MAX_ACTIVE_ENDPOINTS: usize = 64;

/// Runs implemented passive DNS and TCP stages.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "linear stages preserve partial observations and deadlines"
)]
pub async fn run_scan(
    target: NormalizedTarget,
    configuration: ScanConfiguration,
    cancellation: CancellationToken,
) -> ScanReport {
    let deadline = Instant::now() + Duration::from_millis(configuration.global_timeout_ms);
    let mut report = ScanReport::not_started(target, configuration);
    if incompatible_address_family(&report) {
        reject_before_scan(
            &mut report,
            ScanErrorKind::Other,
            "explicit IP conflicts with the selected address family",
        );
        return report;
    }
    let deferred_localhost = report.target.explicit_ip.is_none()
        && report.target.hostname.as_deref() == Some("localhost");
    let explicit_loopback = report.target.explicit_ip.is_some_and(|ip| ip.is_loopback());
    if !report.configuration.authorization_acknowledged && !explicit_loopback && !deferred_localhost
    {
        reject_before_scan(
            &mut report,
            ScanErrorKind::Authorization,
            "active scanning requires authorization acknowledgement",
        );
        return report;
    }
    "Scan started; unimplemented stages remain explicitly marked.".clone_into(&mut report.message);

    let dns_timeout = Duration::from_millis(report.configuration.request_timeout_ms);
    let dns_future = analyze_dns(
        &report.target,
        dns_timeout,
        report.configuration.ipv4_only,
        report.configuration.ipv6_only,
    );
    let dns = tokio::select! {
        () = cancellation.cancelled() => {
            interrupt(&mut report, "scan interrupted during DNS analysis");
            return report;
        }
        result = timeout_at(deadline, dns_future) => result,
    };
    match dns {
        Ok(Ok(observation)) => {
            report.errors.extend(observation.errors.clone());
            report.dns = Some(observation);
        }
        Ok(Err(message)) => report.errors.push(ScanError::new(
            ScanStage::Dns,
            report.target.hostname.clone(),
            ScanErrorKind::Dns,
            message,
            true,
        )),
        Err(_) => {
            fail_timeout(&mut report, "global timeout expired during DNS analysis");
            return report;
        }
    }

    let addresses = scan_addresses(&report);
    if !report.configuration.authorization_acknowledged
        && addresses.iter().any(|address| !address.is_loopback())
    {
        reject_before_scan(
            &mut report,
            ScanErrorKind::Authorization,
            "localhost resolved to a non-loopback address; authorization acknowledgement is required",
        );
        return report;
    }
    if addresses.is_empty() {
        report.status = ScanStatus::Partial;
        "DNS analysis completed, but no primary-host IP addresses were available."
            .clone_into(&mut report.message);
        complete_findings(&mut report);
        report.completed_at = Some(time::OffsetDateTime::now_utc());
        return report;
    }

    let ports_future = scan_ports(
        &addresses,
        &report.configuration.ports,
        report.configuration.concurrency,
        Duration::from_millis(report.configuration.connect_timeout_ms),
        &cancellation,
    );
    let hosts = tokio::select! {
        () = cancellation.cancelled() => {
            interrupt(&mut report, "scan interrupted during TCP connect scanning");
            return report;
        }
        result = timeout_at(deadline, ports_future) => result,
    };
    if let Ok(hosts) = hosts {
        report.hosts = hosts;
    } else {
        fail_timeout(
            &mut report,
            "global timeout expired during TCP connect scanning",
        );
        return report;
    }

    let open_endpoint_count = report
        .hosts
        .iter()
        .flat_map(|host| &host.ports)
        .filter(|port| port.state == crate::PortState::Open)
        .count();
    if open_endpoint_count > MAX_ACTIVE_ENDPOINTS {
        report.errors.push(ScanError::new(
            ScanStage::Services,
            report.target.hostname.clone(),
            ScanErrorKind::Other,
            format!("active endpoint analysis truncated at {MAX_ACTIVE_ENDPOINTS}"),
            true,
        ));
    }
    let services_future = detect_services(
        &report.hosts,
        report.target.hostname.as_deref(),
        report.configuration.concurrency.min(32),
        Duration::from_millis(report.configuration.request_timeout_ms),
        &cancellation,
    );
    let services = tokio::select! {
        () = cancellation.cancelled() => {
            interrupt(&mut report, "scan interrupted during service detection");
            return report;
        }
        result = timeout_at(deadline, services_future) => result,
    };
    if let Ok(services) = services {
        report.services = services;
    } else {
        fail_timeout(
            &mut report,
            "global timeout expired during service detection",
        );
        return report;
    }

    let http_future = analyze_http(
        &report.target,
        &report.services,
        report.configuration.concurrency.min(16),
        Duration::from_millis(report.configuration.request_timeout_ms),
        &cancellation,
    );
    let http = tokio::select! {
        () = cancellation.cancelled() => {
            interrupt(&mut report, "scan interrupted during HTTP analysis");
            return report;
        }
        result = timeout_at(deadline, http_future) => result,
    };
    if let Ok(http) = http {
        report.http = http;
    } else {
        fail_timeout(&mut report, "global timeout expired during HTTP analysis");
        return report;
    }

    if let Some(server_name) = report.target.hostname.as_deref() {
        let tls_future = analyze_tls(
            &report.services,
            server_name,
            report.configuration.concurrency.min(16),
            Duration::from_millis(report.configuration.request_timeout_ms),
            &cancellation,
        );
        let tls = tokio::select! {
            () = cancellation.cancelled() => {
                interrupt(&mut report, "scan interrupted during TLS analysis");
                return report;
            }
            result = timeout_at(deadline, tls_future) => result,
        };
        if let Ok(tls) = tls {
            report.tls = tls;
        } else {
            fail_timeout(&mut report, "global timeout expired during TLS analysis");
            return report;
        }
    }

    complete_findings(&mut report);
    report.status = if report.errors.is_empty() {
        ScanStatus::Completed
    } else {
        ScanStatus::Partial
    };
    "Surface analyzed externally observable services and security-related configuration."
        .clone_into(&mut report.message);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
    report
}

fn incompatible_address_family(report: &ScanReport) -> bool {
    report.target.explicit_ip.is_some_and(|ip| {
        (report.configuration.ipv4_only && ip.is_ipv6())
            || (report.configuration.ipv6_only && ip.is_ipv4())
    })
}

fn reject_before_scan(report: &mut ScanReport, kind: ScanErrorKind, message: &str) {
    report.status = ScanStatus::Failed;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        ScanStage::Ports,
        report.target.hostname.clone(),
        kind,
        message,
        false,
    ));
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn complete_findings(report: &mut ScanReport) {
    report.findings = generate_findings(
        report
            .target
            .hostname
            .as_deref()
            .unwrap_or(&report.target.original),
        report.dns.as_ref(),
        &report.hosts,
        &report.services,
        &report.http,
        &report.tls,
        time::OffsetDateTime::now_utc(),
    );
}

fn scan_addresses(report: &ScanReport) -> Vec<IpAddr> {
    report
        .dns
        .as_ref()
        .map(|dns| dns.resolved_hosts.iter().map(|host| host.ip).collect())
        .unwrap_or_default()
}

fn interrupt(report: &mut ScanReport, message: &str) {
    report.status = ScanStatus::Interrupted;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        ScanStage::Ports,
        report.target.hostname.clone(),
        ScanErrorKind::Cancelled,
        message,
        true,
    ));
    complete_findings(report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn fail_timeout(report: &mut ScanReport, message: &str) {
    report.status = ScanStatus::Partial;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        ScanStage::Ports,
        report.target.hostname.clone(),
        ScanErrorKind::Timeout,
        message,
        true,
    ));
    complete_findings(report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio_util::sync::CancellationToken;

    use super::run_scan;
    use crate::{ScanConfiguration, ScanStatus, normalize_target};

    #[tokio::test]
    async fn scans_only_explicit_loopback_without_dns() {
        let target = normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}"));
        let report = run_scan(
            target,
            ScanConfiguration {
                ports: vec![9],
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: false,
            },
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(
            report.status,
            ScanStatus::Completed | ScanStatus::Partial
        ));
        assert_eq!(report.hosts[0].ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn preserves_interrupted_status() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let report = run_scan(
            normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![9],
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: false,
            },
            cancellation,
        )
        .await;
        assert_eq!(report.status, ScanStatus::Interrupted);
    }

    #[tokio::test]
    async fn core_rejects_unauthorized_non_loopback_before_network_io() {
        let report = run_scan(
            normalize_target("192.0.2.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![80],
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: false,
            },
            CancellationToken::new(),
        )
        .await;
        assert_eq!(report.status, ScanStatus::Failed);
        assert!(report.hosts.is_empty());
    }

    #[tokio::test]
    async fn rejects_incompatible_explicit_address_family() {
        let report = run_scan(
            normalize_target("::1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![80],
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: true,
                ipv6_only: false,
                authorization_acknowledged: false,
            },
            CancellationToken::new(),
        )
        .await;
        assert_eq!(report.status, ScanStatus::Failed);
        assert!(report.hosts.is_empty());
    }
}
