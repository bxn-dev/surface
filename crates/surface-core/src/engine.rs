//! Scan-stage orchestration with global deadlines and cancellation.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::{
    AxfrOutcome, DanglingCnameStatus, DnssecObservation, DnssecStatus, HostObservation,
    NormalizedTarget, ScanConfiguration, ScanError, ScanErrorKind, ScanProgress, ScanReport,
    ScanSelection, ScanStage, ScanStatus, SkippedCheck, WildcardDnsStatus, analyze_http,
    analyze_tls, calculate_exposure, detect_services, generate_findings, scan_ports,
    scan_udp_ports,
};

// Rust guideline compliant 2026-02-21

const MAX_ACTIVE_ENDPOINTS: usize = 256;

/// Runs implemented passive DNS, TCP, and UDP stages.
#[must_use]
pub async fn run_scan(
    target: NormalizedTarget,
    configuration: ScanConfiguration,
    cancellation: CancellationToken,
) -> ScanReport {
    run_scan_with_progress(target, configuration, cancellation, |_| {}).await
}

/// Runs a scan and reports stage transitions synchronously.
#[must_use]
pub async fn run_scan_with_progress(
    target: NormalizedTarget,
    configuration: ScanConfiguration,
    cancellation: CancellationToken,
    progress: impl Fn(ScanProgress),
) -> ScanReport {
    run_scan_selected_with_progress(
        target,
        configuration,
        cancellation,
        ScanSelection::all(),
        progress,
    )
    .await
}

/// Runs selected stages and reports transitions synchronously.
#[must_use]
pub async fn run_scan_selected_with_progress(
    target: NormalizedTarget,
    configuration: ScanConfiguration,
    cancellation: CancellationToken,
    selection: ScanSelection,
    progress: impl Fn(ScanProgress),
) -> ScanReport {
    let deadline = Instant::now() + Duration::from_millis(configuration.global_timeout_ms);
    run_scan_selected_until_with_progress(
        target,
        configuration,
        cancellation,
        selection,
        deadline,
        progress,
    )
    .await
}

/// Runs selected stages against a caller-owned whole-scan deadline.
#[must_use]
pub async fn run_scan_selected_until_with_progress(
    target: NormalizedTarget,
    configuration: ScanConfiguration,
    cancellation: CancellationToken,
    selection: ScanSelection,
    deadline: Instant,
    progress: impl Fn(ScanProgress),
) -> ScanReport {
    run_scan_inner(
        target,
        configuration,
        cancellation,
        selection,
        deadline,
        &progress,
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "linear stages preserve partial observations and deadlines"
)]
async fn run_scan_inner(
    target: NormalizedTarget,
    configuration: ScanConfiguration,
    cancellation: CancellationToken,
    selection: ScanSelection,
    deadline: Instant,
    progress: &impl Fn(ScanProgress),
) -> ScanReport {
    let mut configuration = configuration;
    configuration.authorization_acknowledged = true;
    let mut report = ScanReport::not_started(target, configuration);
    record_selection_skips(&mut report, selection);
    if incompatible_address_family(&report) {
        reject_before_scan(
            &mut report,
            ScanErrorKind::Other,
            "explicit IP conflicts with the selected address family",
        );
        return report;
    }
    "Scan started.".clone_into(&mut report.message);

    if Instant::now() >= deadline {
        fail_timeout(
            &mut report,
            ScanStage::Dns,
            selection,
            "global timeout expired before DNS analysis",
        );
        return report;
    }
    progress(ScanProgress::Started(ScanStage::Dns));
    let dns_timeout = Duration::from_millis(report.configuration.request_timeout_ms);
    let dns_future = crate::dns::analyze_dns_baseline_for_scan(
        &report.target,
        dns_timeout,
        report.configuration.ipv4_only,
        report.configuration.ipv6_only,
        true,
    );
    let dns = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            interrupt(&mut report, ScanStage::Dns, selection, "scan interrupted during DNS analysis");
            return report;
        }
        result = timeout_at(deadline, dns_future) => result,
    };
    let authority = match dns {
        Ok(Ok(baseline)) => {
            report.errors.extend(baseline.observation.errors.clone());
            report.dns = Some(baseline.observation);
            baseline.authority
        }
        Ok(Err(message)) => {
            report.errors.push(ScanError::new(
                ScanStage::Dns,
                report.target.hostname.clone(),
                ScanErrorKind::Dns,
                message,
                true,
            ));
            None
        }
        Err(_) => {
            fail_timeout(
                &mut report,
                ScanStage::Dns,
                selection,
                "global timeout expired during DNS analysis",
            );
            return report;
        }
    };

    if report.target.explicit_ip.is_some() || report.target.hostname.is_none() {
        add_skipped_check(
            &mut report,
            "dnssec_validation",
            "not applicable: target has no hostname",
        );
    } else {
        let dnssec_future = crate::dns::analyze_dnssec(
            &report.target,
            dns_timeout,
            report.configuration.ipv4_only,
            report.configuration.ipv6_only,
        );
        let dnssec = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                stop_after_dnssec(
                    &mut report,
                    selection,
                    ScanErrorKind::Cancelled,
                    ScanStatus::Interrupted,
                    "scan interrupted during DNSSEC validation",
                );
                return report;
            }
            result = timeout_at(deadline, dnssec_future) => result,
        };
        let Ok(observation) = dnssec else {
            stop_after_dnssec(
                &mut report,
                selection,
                ScanErrorKind::Timeout,
                ScanStatus::Partial,
                "global timeout expired during DNSSEC validation",
            );
            return report;
        };
        if matches!(
            observation.status,
            DnssecStatus::Indeterminate | DnssecStatus::NotApplicable
        ) {
            add_skipped_check(
                &mut report,
                "dnssec_validation",
                if observation.status == DnssecStatus::Indeterminate {
                    "DNSSEC validation was indeterminate; see DNSSEC errors"
                } else {
                    "no address RRset was selected for DNSSEC validation"
                },
            );
        }
        if let Some(dns) = report.dns.as_mut() {
            dns.dnssec = Some(observation);
        }
    }

    if report.target.explicit_ip.is_some() || report.target.hostname.is_none() {
        add_skipped_check(
            &mut report,
            "authoritative_axfr",
            "not applicable: target has no hostname",
        );
    } else if let Some(authority) = authority {
        let check =
            crate::dns::analyze_authoritative_axfr(authority, dns_timeout, deadline, &cancellation)
                .await;
        if let Some(observation) = check.observation {
            if check.state == crate::dns::AxfrCheckState::Completed {
                for attempt in &observation.attempts {
                    let kind = match attempt.outcome {
                        AxfrOutcome::Incomplete | AxfrOutcome::LimitExceeded => {
                            Some(ScanErrorKind::Dns)
                        }
                        AxfrOutcome::Unreachable => Some(ScanErrorKind::Network),
                        AxfrOutcome::Timeout => Some(ScanErrorKind::Timeout),
                        AxfrOutcome::Allowed
                        | AxfrOutcome::Refused
                        | AxfrOutcome::NotAuthoritative
                        | AxfrOutcome::Cancelled => None,
                    };
                    if let Some(kind) = kind {
                        report.errors.push(ScanError::new(
                            ScanStage::Dns,
                            Some(format!("{} ({})", attempt.server, attempt.endpoint)),
                            kind,
                            attempt
                                .error
                                .as_deref()
                                .unwrap_or("AXFR attempt was incomplete"),
                            true,
                        ));
                    }
                }
            }
            if let Some(dns) = report.dns.as_mut() {
                dns.authoritative_axfr = Some(observation);
            }
        }
        match check.state {
            crate::dns::AxfrCheckState::Completed => {}
            crate::dns::AxfrCheckState::Skipped(reason) => {
                add_skipped_check(&mut report, "authoritative_axfr", reason);
            }
            crate::dns::AxfrCheckState::TimedOut => {
                stop_after_axfr(
                    &mut report,
                    selection,
                    ScanErrorKind::Timeout,
                    ScanStatus::Partial,
                    "global timeout expired during authoritative AXFR checking",
                );
                return report;
            }
            crate::dns::AxfrCheckState::Cancelled => {
                stop_after_axfr(
                    &mut report,
                    selection,
                    ScanErrorKind::Cancelled,
                    ScanStatus::Interrupted,
                    "scan interrupted during authoritative AXFR checking",
                );
                return report;
            }
        }
    } else {
        add_skipped_check(
            &mut report,
            "authoritative_axfr",
            "exact zone origin could not be established from primary-host SOA and matching NS evidence",
        );
    }

    if report.target.explicit_ip.is_some() || report.target.hostname.is_none() {
        add_skipped_check(
            &mut report,
            "wildcard_dns",
            "not applicable: target has no hostname",
        );
    } else if report.dns.is_none() {
        add_skipped_check(
            &mut report,
            "wildcard_dns",
            "baseline DNS observation was unavailable",
        );
    } else {
        let check = crate::dns::analyze_wildcard_dns(
            &report.target,
            dns_timeout,
            deadline,
            &cancellation,
            report.configuration.ipv4_only,
            report.configuration.ipv6_only,
        )
        .await;
        let status = check.observation.status;
        if let Some(dns) = report.dns.as_mut() {
            dns.wildcard_dns = Some(check.observation);
        }
        match check.state {
            crate::dns::WildcardDnsCheckState::Completed => {
                if status == WildcardDnsStatus::Indeterminate {
                    add_skipped_check(
                        &mut report,
                        "wildcard_dns",
                        "wildcard DNS detection was indeterminate; see DNS limitations",
                    );
                }
            }
            crate::dns::WildcardDnsCheckState::TimedOut => {
                stop_after_wildcard_dns(
                    &mut report,
                    selection,
                    ScanErrorKind::Timeout,
                    ScanStatus::Partial,
                    "global timeout expired during wildcard DNS detection",
                );
                return report;
            }
            crate::dns::WildcardDnsCheckState::Cancelled => {
                stop_after_wildcard_dns(
                    &mut report,
                    selection,
                    ScanErrorKind::Cancelled,
                    ScanStatus::Interrupted,
                    "scan interrupted during wildcard DNS detection",
                );
                return report;
            }
        }
    }

    if report.target.explicit_ip.is_some() || report.target.hostname.is_none() {
        add_skipped_check(
            &mut report,
            "dangling_cname",
            "not applicable: target has no hostname",
        );
    } else {
        let cname_chain = report
            .dns
            .as_ref()
            .map(|dns| dns.cname_chain.clone())
            .unwrap_or_default();
        if cname_chain.is_empty() {
            add_skipped_check(
                &mut report,
                "dangling_cname",
                "no primary-target CNAME destination was directly observed",
            );
        } else {
            let check = crate::dns::analyze_dangling_cnames(
                &cname_chain,
                dns_timeout,
                deadline,
                &cancellation,
                report.configuration.ipv4_only,
                report.configuration.ipv6_only,
            )
            .await;
            let indeterminate = check
                .observations
                .iter()
                .any(|observation| observation.status == DanglingCnameStatus::Indeterminate);
            if let Some(dns) = report.dns.as_mut() {
                dns.dangling_cnames = check.observations;
            }
            match check.state {
                crate::dns::DanglingCnameCheckState::Completed => {
                    if indeterminate {
                        add_skipped_check(
                            &mut report,
                            "dangling_cname",
                            "CNAME destination status was indeterminate; see DNS limitations",
                        );
                    }
                }
                crate::dns::DanglingCnameCheckState::TimedOut => {
                    stop_after_dangling_cname(
                        &mut report,
                        selection,
                        ScanErrorKind::Timeout,
                        ScanStatus::Partial,
                        "global timeout expired during CNAME destination checking",
                    );
                    return report;
                }
                crate::dns::DanglingCnameCheckState::Cancelled => {
                    stop_after_dangling_cname(
                        &mut report,
                        selection,
                        ScanErrorKind::Cancelled,
                        ScanStatus::Interrupted,
                        "scan interrupted during CNAME destination checking",
                    );
                    return report;
                }
            }
        }
    }

    let addresses = scan_addresses(&report);
    progress(ScanProgress::Completed {
        stage: ScanStage::Dns,
        observations: addresses.len(),
    });
    if addresses.is_empty() {
        report.status = ScanStatus::Partial;
        "DNS analysis completed, but no primary-host IP addresses were available."
            .clone_into(&mut report.message);
        return finish_selected_report(
            report,
            &cancellation,
            selection,
            Some(ScanStage::Ports),
            progress,
        );
    }

    if !selection.ports {
        return finish_selected_report(report, &cancellation, selection, None, progress);
    }
    if Instant::now() >= deadline {
        fail_timeout(
            &mut report,
            ScanStage::Ports,
            selection,
            "global timeout expired before port scanning",
        );
        return report;
    }

    progress(ScanProgress::Started(ScanStage::Ports));
    let probe_concurrency = report.configuration.concurrency.div_ceil(2).max(1);
    let ports_future = async {
        let (tcp, udp) = tokio::join!(
            scan_ports(
                &addresses,
                &report.configuration.ports,
                probe_concurrency,
                Duration::from_millis(report.configuration.connect_timeout_ms),
                &cancellation,
            ),
            scan_udp_ports(
                &addresses,
                &report.configuration.udp_ports,
                probe_concurrency,
                Duration::from_millis(report.configuration.connect_timeout_ms),
                &cancellation,
            )
        );
        merge_hosts(tcp, udp)
    };
    let hosts = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            interrupt(&mut report, ScanStage::Ports, selection, "scan interrupted during port scanning");
            return report;
        }
        result = timeout_at(deadline, ports_future) => result,
    };
    if let Ok(hosts) = hosts {
        report.hosts = hosts;
        progress(ScanProgress::Completed {
            stage: ScanStage::Ports,
            observations: report.hosts.len(),
        });
    } else {
        fail_timeout(
            &mut report,
            ScanStage::Ports,
            selection,
            "global timeout expired during port scanning",
        );
        return report;
    }

    if !selection.services {
        return finish_selected_report(report, &cancellation, selection, None, progress);
    }
    if Instant::now() >= deadline {
        fail_timeout(
            &mut report,
            ScanStage::Services,
            selection,
            "global timeout expired before service detection",
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
            format!("active protocol probing truncated at {MAX_ACTIVE_ENDPOINTS} endpoints"),
            true,
        ));
    }
    progress(ScanProgress::Started(ScanStage::Services));
    let services_future = detect_services(
        &report.hosts,
        report.target.hostname.as_deref(),
        report.configuration.concurrency.min(32),
        Duration::from_millis(report.configuration.request_timeout_ms),
        &cancellation,
    );
    let services = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            interrupt(&mut report, ScanStage::Services, selection, "scan interrupted during service detection");
            return report;
        }
        result = timeout_at(deadline, services_future) => result,
    };
    if let Ok(services) = services {
        report.services = services;
        progress(ScanProgress::Completed {
            stage: ScanStage::Services,
            observations: report.services.len(),
        });
    } else {
        fail_timeout(
            &mut report,
            ScanStage::Services,
            selection,
            "global timeout expired during service detection",
        );
        return report;
    }

    if selection.http {
        if Instant::now() >= deadline {
            fail_timeout(
                &mut report,
                ScanStage::Http,
                selection,
                "global timeout expired before HTTP analysis",
            );
            return report;
        }
        progress(ScanProgress::Started(ScanStage::Http));
        let http_future = analyze_http(
            &report.target,
            &report.services,
            report.configuration.concurrency.min(16),
            Duration::from_millis(report.configuration.request_timeout_ms),
            &cancellation,
        );
        let http = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                interrupt(&mut report, ScanStage::Http, selection, "scan interrupted during HTTP analysis");
                return report;
            }
            result = timeout_at(deadline, http_future) => result,
        };
        if let Ok(http) = http {
            report.http = http;
            progress(ScanProgress::Completed {
                stage: ScanStage::Http,
                observations: report.http.len(),
            });
        } else {
            fail_timeout(
                &mut report,
                ScanStage::Http,
                selection,
                "global timeout expired during HTTP analysis",
            );
            return report;
        }
    }

    if selection.tls
        && let Some(server_name) = report.target.hostname.as_deref()
    {
        if Instant::now() >= deadline {
            fail_timeout(
                &mut report,
                ScanStage::Tls,
                selection,
                "global timeout expired before TLS analysis",
            );
            return report;
        }
        progress(ScanProgress::Started(ScanStage::Tls));
        let tls_future = analyze_tls(
            &report.services,
            server_name,
            report.configuration.concurrency.min(16),
            Duration::from_millis(report.configuration.request_timeout_ms),
            &cancellation,
        );
        let tls = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                interrupt(&mut report, ScanStage::Tls, selection, "scan interrupted during TLS analysis");
                return report;
            }
            result = timeout_at(deadline, tls_future) => result,
        };
        if let Ok(tls) = tls {
            report.tls = tls;
            progress(ScanProgress::Completed {
                stage: ScanStage::Tls,
                observations: report.tls.len(),
            });
        } else {
            fail_timeout(
                &mut report,
                ScanStage::Tls,
                selection,
                "global timeout expired during TLS analysis",
            );
            return report;
        }
    }

    finish_selected_report(report, &cancellation, selection, None, progress)
}

fn add_skipped_check(report: &mut ScanReport, check: &str, reason: &str) {
    if !report
        .skipped_checks
        .iter()
        .any(|skipped| skipped.check == check)
    {
        report.skipped_checks.push(SkippedCheck {
            check: check.to_owned(),
            reason: reason.to_owned(),
        });
    }
}

fn record_selection_skips(report: &mut ScanReport, selection: ScanSelection) {
    for (check, selected) in [
        ("ports", selection.ports),
        ("services", selection.services),
        ("http", selection.http),
        ("tls", selection.tls),
    ] {
        if !selected {
            report.skipped_checks.push(SkippedCheck {
                check: check.to_owned(),
                reason: "excluded by --only".to_owned(),
            });
        }
    }
}

fn finish_selected_report(
    mut report: ScanReport,
    cancellation: &CancellationToken,
    selection: ScanSelection,
    unfinished_stage: Option<ScanStage>,
    progress: &impl Fn(ScanProgress),
) -> ScanReport {
    if cancellation.is_cancelled() {
        let message = "scan interrupted before findings finalization";
        report.status = ScanStatus::Interrupted;
        message.clone_into(&mut report.message);
        report.errors.push(ScanError::new(
            ScanStage::Findings,
            report.target.hostname.clone(),
            ScanErrorKind::Cancelled,
            message,
            true,
        ));
        if let Some(stage) = unfinished_stage {
            record_unfinished_checks(&mut report, stage, selection, message);
        }
    } else if report.status != ScanStatus::Partial {
        let dnssec_indeterminate = report
            .dns
            .as_ref()
            .and_then(|dns| dns.dnssec.as_ref())
            .is_some_and(|dnssec| dnssec.status == DnssecStatus::Indeterminate);
        let wildcard_indeterminate = report
            .dns
            .as_ref()
            .and_then(|dns| dns.wildcard_dns.as_ref())
            .is_some_and(|wildcard| wildcard.status == WildcardDnsStatus::Indeterminate);
        let dangling_indeterminate = report.dns.as_ref().is_some_and(|dns| {
            dns.dangling_cnames
                .iter()
                .any(|observation| observation.status == DanglingCnameStatus::Indeterminate)
        });
        report.status = if report.errors.is_empty()
            && !dnssec_indeterminate
            && !wildcard_indeterminate
            && !dangling_indeterminate
        {
            ScanStatus::Completed
        } else {
            ScanStatus::Partial
        };
        "Surface analyzed externally observable services and security-related configuration."
            .clone_into(&mut report.message);
    }
    progress(ScanProgress::Started(ScanStage::Findings));
    complete_findings(&mut report);
    progress(ScanProgress::Completed {
        stage: ScanStage::Findings,
        observations: report.findings.len(),
    });
    report.completed_at = Some(time::OffsetDateTime::now_utc());
    report
}

fn merge_hosts(mut tcp: Vec<HostObservation>, udp: Vec<HostObservation>) -> Vec<HostObservation> {
    for udp_host in udp {
        if let Some(host) = tcp.iter_mut().find(|host| host.ip == udp_host.ip) {
            host.ports.extend(udp_host.ports);
            host.ports
                .sort_by_key(|port| (port.address.port(), port.transport));
        } else {
            tcp.push(udp_host);
        }
    }
    tcp.sort_by_key(|host| host.ip);
    tcp
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
    report.exposure_score = Some(calculate_exposure(report));
}

fn scan_addresses(report: &ScanReport) -> Vec<IpAddr> {
    report
        .dns
        .as_ref()
        .map(|dns| {
            dns.resolved_hosts
                .iter()
                .map(|host| host.ip)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default()
}

fn stop_after_dnssec(
    report: &mut ScanReport,
    selection: ScanSelection,
    kind: ScanErrorKind,
    status: ScanStatus,
    message: &str,
) {
    report.status = status;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        ScanStage::Dns,
        report.target.hostname.clone(),
        kind,
        message,
        true,
    ));
    if let Some(dns) = report.dns.as_mut() {
        dns.dnssec = Some(DnssecObservation {
            status: DnssecStatus::Indeterminate,
            limitations: vec![message.to_owned()],
            ..DnssecObservation::default()
        });
    }
    add_skipped_check(report, "dnssec_validation", message);
    add_skipped_check(report, "authoritative_axfr", message);
    add_skipped_check(report, "wildcard_dns", message);
    add_skipped_check(report, "dangling_cname", message);
    record_unfinished_checks(report, ScanStage::Ports, selection, message);
    complete_findings(report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn stop_after_axfr(
    report: &mut ScanReport,
    selection: ScanSelection,
    kind: ScanErrorKind,
    status: ScanStatus,
    message: &str,
) {
    report.status = status;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        ScanStage::Dns,
        report.target.hostname.clone(),
        kind,
        message,
        true,
    ));
    add_skipped_check(report, "authoritative_axfr", message);
    add_skipped_check(report, "wildcard_dns", message);
    add_skipped_check(report, "dangling_cname", message);
    record_unfinished_checks(report, ScanStage::Ports, selection, message);
    complete_findings(report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn stop_after_wildcard_dns(
    report: &mut ScanReport,
    selection: ScanSelection,
    kind: ScanErrorKind,
    status: ScanStatus,
    message: &str,
) {
    report.status = status;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        ScanStage::Dns,
        report.target.hostname.clone(),
        kind,
        message,
        true,
    ));
    add_skipped_check(report, "wildcard_dns", message);
    add_skipped_check(report, "dangling_cname", message);
    record_unfinished_checks(report, ScanStage::Ports, selection, message);
    complete_findings(report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn stop_after_dangling_cname(
    report: &mut ScanReport,
    selection: ScanSelection,
    kind: ScanErrorKind,
    status: ScanStatus,
    message: &str,
) {
    report.status = status;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        ScanStage::Dns,
        report.target.hostname.clone(),
        kind,
        message,
        true,
    ));
    add_skipped_check(report, "dangling_cname", message);
    record_unfinished_checks(report, ScanStage::Ports, selection, message);
    complete_findings(report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn interrupt(report: &mut ScanReport, stage: ScanStage, selection: ScanSelection, message: &str) {
    report.status = ScanStatus::Interrupted;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        stage,
        report.target.hostname.clone(),
        ScanErrorKind::Cancelled,
        message,
        true,
    ));
    record_unfinished_checks(report, stage, selection, message);
    complete_findings(report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn fail_timeout(
    report: &mut ScanReport,
    stage: ScanStage,
    selection: ScanSelection,
    message: &str,
) {
    report.status = ScanStatus::Partial;
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        stage,
        report.target.hostname.clone(),
        ScanErrorKind::Timeout,
        message,
        true,
    ));
    record_unfinished_checks(report, stage, selection, message);
    complete_findings(report);
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn record_unfinished_checks(
    report: &mut ScanReport,
    failed_stage: ScanStage,
    selection: ScanSelection,
    reason: &str,
) {
    let failed_rank = stage_rank(failed_stage);
    for (check, stage, selected) in [
        ("dns", ScanStage::Dns, true),
        ("dnssec_validation", ScanStage::Dns, true),
        ("authoritative_axfr", ScanStage::Dns, true),
        ("wildcard_dns", ScanStage::Dns, true),
        ("dangling_cname", ScanStage::Dns, true),
        ("ports", ScanStage::Ports, selection.ports),
        ("services", ScanStage::Services, selection.services),
        ("http", ScanStage::Http, selection.http),
        ("tls", ScanStage::Tls, selection.tls),
    ] {
        if selected
            && stage_rank(stage) >= failed_rank
            && !report
                .skipped_checks
                .iter()
                .any(|skipped| skipped.check == check)
        {
            report.skipped_checks.push(SkippedCheck {
                check: check.to_owned(),
                reason: reason.to_owned(),
            });
        }
    }
}

const fn stage_rank(stage: ScanStage) -> u8 {
    match stage {
        ScanStage::Dns => 0,
        ScanStage::Ports => 1,
        ScanStage::Services => 2,
        ScanStage::Http => 3,
        ScanStage::Tls => 4,
        ScanStage::Findings => 5,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use super::{
        run_scan, run_scan_selected_until_with_progress, run_scan_selected_with_progress,
        run_scan_with_progress,
    };
    use crate::{
        AddressSource, CnameHop, DanglingCnameObservation, DanglingCnameStatus, DnsObservation,
        MailObservation, ResolvedHost, ScanConfiguration, ScanProgress, ScanSelection, ScanStage,
        ScanStatus, SpfObservation, WildcardDnsObservation, WildcardDnsRecordType,
        WildcardDnsStatus, normalize_target,
    };

    #[tokio::test]
    async fn scans_only_explicit_loopback_without_dns() {
        let target = normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}"));
        let report = run_scan(
            target,
            ScanConfiguration {
                ports: vec![9],
                udp_ports: Vec::new(),
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
        assert!(report.configuration.authorization_acknowledged);
    }

    #[tokio::test]
    async fn preserves_interrupted_status() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let report = run_scan(
            normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![9],
                udp_ports: Vec::new(),
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
        assert_eq!(report.errors[0].stage, ScanStage::Dns);
        assert!(
            report
                .skipped_checks
                .iter()
                .any(|skipped| skipped.check == "dns")
        );
        assert!(
            report
                .skipped_checks
                .iter()
                .any(|skipped| skipped.check == "tls")
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "dnssec_validation")
                .count(),
            1
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "authoritative_axfr")
                .count(),
            1
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "wildcard_dns")
                .count(),
            1
        );
        assert_eq!(report.errors.len(), 1);
    }

    #[tokio::test]
    async fn caller_deadline_bounds_core_scan() {
        let report = run_scan_selected_until_with_progress(
            normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![9],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 60_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
            CancellationToken::new(),
            ScanSelection::all(),
            Instant::now() - Duration::from_millis(1),
            |_| {},
        )
        .await;

        assert_eq!(report.status, ScanStatus::Partial);
        assert_eq!(report.errors[0].stage, ScanStage::Dns);
        assert!(
            report
                .skipped_checks
                .iter()
                .any(|skipped| skipped.check == "dns")
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "dnssec_validation")
                .count(),
            1
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "authoritative_axfr")
                .count(),
            1
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "wildcard_dns")
                .count(),
            1
        );
        assert_eq!(report.errors.len(), 1);
    }

    #[tokio::test]
    async fn reports_scan_progress_in_stage_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let report = run_scan_with_progress(
            normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![9],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
            CancellationToken::new(),
            move |event| captured.lock().expect("progress lock").push(event),
        )
        .await;
        assert!(matches!(
            report.status,
            ScanStatus::Completed | ScanStatus::Partial
        ));
        let events = events.lock().expect("progress lock");
        assert_eq!(events.first(), Some(&ScanProgress::Started(ScanStage::Dns)));
        assert!(events.contains(&ScanProgress::Started(ScanStage::Findings)));
    }

    #[tokio::test]
    async fn dns_only_selection_skips_active_stages() {
        let report = run_scan_selected_with_progress(
            normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![9],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
            CancellationToken::new(),
            ScanSelection::only(&[]),
            |_| {},
        )
        .await;
        assert!(report.hosts.is_empty());
        assert_eq!(report.skipped_checks.len(), 8);
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "dangling_cname")
                .count(),
            1
        );
        assert_eq!(report.status, ScanStatus::Completed);
    }

    #[tokio::test]
    async fn dns_only_cancellation_after_dns_completion_interrupts_finalization() {
        let cancellation = CancellationToken::new();
        let cancel_after_dns = cancellation.clone();
        let report = run_scan_selected_with_progress(
            normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![9],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
            cancellation,
            ScanSelection::only(&[]),
            move |event| {
                if matches!(
                    event,
                    ScanProgress::Completed {
                        stage: ScanStage::Dns,
                        ..
                    }
                ) {
                    cancel_after_dns.cancel();
                }
            },
        )
        .await;

        assert_eq!(report.status, ScanStatus::Interrupted);
        assert_eq!(
            report.message,
            "scan interrupted before findings finalization"
        );
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].stage, ScanStage::Findings);
        assert_eq!(report.errors[0].kind, crate::ScanErrorKind::Cancelled);
        assert_eq!(
            report.dns.as_ref().map(|dns| dns.resolved_hosts.as_slice()),
            Some(
                [ResolvedHost {
                    hostname: None,
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    source: AddressSource::Explicit,
                }]
                .as_slice()
            )
        );
        assert!(report.findings.is_empty());
        assert!(report.exposure_score.is_some());
        assert!(report.completed_at.is_some());
        assert!(
            report
                .skipped_checks
                .iter()
                .all(|skipped| skipped.reason != report.message)
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .map(|skipped| skipped.check.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            report.skipped_checks.len()
        );
    }

    #[tokio::test]
    async fn no_address_cancellation_preserves_completed_dns_observations() {
        let target = normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}"));
        let mut report = crate::ScanReport::not_started(
            target.clone(),
            ScanConfiguration {
                ports: vec![9],
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
        report.status = ScanStatus::Partial;
        "DNS analysis completed, but no primary-host IP addresses were available."
            .clone_into(&mut report.message);
        let mut dns = crate::dns::analyze_dns_baseline_for_scan(
            &target,
            Duration::from_millis(100),
            false,
            false,
            false,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .observation;
        dns.resolved_hosts.clear();
        dns.dnssec = Some(crate::DnssecObservation {
            status: crate::DnssecStatus::Secure,
            ..crate::DnssecObservation::default()
        });
        dns.authoritative_axfr = Some(crate::AuthoritativeAxfrObservation {
            zone: "example.test".to_owned(),
            ..crate::AuthoritativeAxfrObservation::default()
        });
        dns.wildcard_dns = Some(WildcardDnsObservation {
            status: WildcardDnsStatus::Detected,
            probes_attempted: 2,
            ..WildcardDnsObservation::default()
        });
        dns.dangling_cnames = vec![DanglingCnameObservation {
            source_alias: "example.test".to_owned(),
            canonical_target: "origin.example.test".to_owned(),
            status: DanglingCnameStatus::Resolved,
            ..DanglingCnameObservation::default()
        }];
        report.dns = Some(dns);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let report = super::finish_selected_report(
            report,
            &cancellation,
            ScanSelection::all(),
            Some(ScanStage::Ports),
            &|_| {},
        );

        let dns = report.dns.as_ref().expect("DNS observation");
        assert_eq!(report.status, ScanStatus::Interrupted);
        assert_eq!(
            dns.dnssec.as_ref().map(|dnssec| dnssec.status),
            Some(crate::DnssecStatus::Secure)
        );
        assert_eq!(
            dns.authoritative_axfr
                .as_ref()
                .map(|axfr| axfr.zone.as_str()),
            Some("example.test")
        );
        assert_eq!(
            dns.wildcard_dns
                .as_ref()
                .map(|wildcard| wildcard.probes_attempted),
            Some(2)
        );
        assert_eq!(dns.dangling_cnames[0].status, DanglingCnameStatus::Resolved);
        assert!(report.exposure_score.is_some());
        assert!(report.completed_at.is_some());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].kind, crate::ScanErrorKind::Cancelled);
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .map(|skipped| skipped.check.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["ports", "services", "http", "tls"])
        );
        assert!(
            report
                .skipped_checks
                .iter()
                .all(|skipped| skipped.reason == report.message)
        );
    }

    #[tokio::test]
    async fn cancellation_after_findings_finalization_does_not_interrupt_report() {
        let cancellation = CancellationToken::new();
        let cancel_after_findings = cancellation.clone();
        let report = run_scan_selected_with_progress(
            normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![9],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
            cancellation,
            ScanSelection::only(&[]),
            move |event| {
                if matches!(
                    event,
                    ScanProgress::Completed {
                        stage: ScanStage::Findings,
                        ..
                    }
                ) {
                    cancel_after_findings.cancel();
                }
            },
        )
        .await;

        assert_eq!(report.status, ScanStatus::Completed);
        assert!(report.errors.is_empty());
        assert!(report.completed_at.is_some());
    }

    #[tokio::test]
    async fn dnssec_stop_preserves_baseline_and_records_one_skip() {
        let target = normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}"));
        let configuration = ScanConfiguration {
            ports: vec![9],
            udp_ports: Vec::new(),
            concurrency: 1,
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            global_timeout_ms: 1_000,
            ipv4_only: false,
            ipv6_only: false,
            authorization_acknowledged: true,
        };
        let mut report = crate::ScanReport::not_started(target.clone(), configuration);
        report.dns = Some(
            crate::dns::analyze_dns_baseline_for_scan(
                &target,
                Duration::from_millis(100),
                false,
                false,
                false,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .observation,
        );

        super::stop_after_dnssec(
            &mut report,
            ScanSelection::all(),
            crate::ScanErrorKind::Cancelled,
            ScanStatus::Interrupted,
            "scan interrupted during DNSSEC validation",
        );

        let dns = report.dns.as_ref().expect("baseline DNS observation");
        assert_eq!(dns.resolved_hosts.len(), 1);
        assert_eq!(
            dns.dnssec.as_ref().map(|dnssec| dnssec.status),
            Some(crate::DnssecStatus::Indeterminate)
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "dnssec_validation")
                .count(),
            1
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "authoritative_axfr")
                .count(),
            1
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "wildcard_dns")
                .count(),
            1
        );
        assert_eq!(report.errors.len(), 1);
    }

    #[tokio::test]
    async fn axfr_stop_preserves_dns_and_records_one_skip() {
        let target = normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}"));
        let configuration = ScanConfiguration {
            ports: vec![9],
            udp_ports: Vec::new(),
            concurrency: 1,
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            global_timeout_ms: 1_000,
            ipv4_only: false,
            ipv6_only: false,
            authorization_acknowledged: true,
        };
        let mut report = crate::ScanReport::not_started(target.clone(), configuration);
        let mut dns = crate::dns::analyze_dns_baseline_for_scan(
            &target,
            Duration::from_millis(100),
            false,
            false,
            false,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .observation;
        dns.dnssec = Some(crate::DnssecObservation {
            status: crate::DnssecStatus::Secure,
            ..crate::DnssecObservation::default()
        });
        dns.authoritative_axfr = Some(crate::AuthoritativeAxfrObservation {
            zone: "example.test".to_owned(),
            ..crate::AuthoritativeAxfrObservation::default()
        });
        report.dns = Some(dns);

        super::stop_after_axfr(
            &mut report,
            ScanSelection::all(),
            crate::ScanErrorKind::Timeout,
            ScanStatus::Partial,
            "global timeout expired during authoritative AXFR checking",
        );

        let dns = report.dns.as_ref().expect("baseline DNS observation");
        assert_eq!(dns.resolved_hosts.len(), 1);
        assert_eq!(
            dns.dnssec.as_ref().map(|dnssec| dnssec.status),
            Some(crate::DnssecStatus::Secure)
        );
        assert_eq!(
            dns.authoritative_axfr
                .as_ref()
                .map(|axfr| axfr.zone.as_str()),
            Some("example.test")
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "authoritative_axfr")
                .count(),
            1
        );
        assert!(
            report
                .skipped_checks
                .iter()
                .all(|skipped| skipped.check != "dnssec_validation")
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "wildcard_dns")
                .count(),
            1
        );
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.status, ScanStatus::Partial);
        assert!(report.completed_at.is_some());
    }

    #[tokio::test]
    async fn wildcard_stop_preserves_prior_dns_and_records_one_skip() {
        let target = normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}"));
        let configuration = ScanConfiguration {
            ports: vec![9],
            udp_ports: Vec::new(),
            concurrency: 1,
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            global_timeout_ms: 1_000,
            ipv4_only: false,
            ipv6_only: false,
            authorization_acknowledged: true,
        };
        let mut report = crate::ScanReport::not_started(target.clone(), configuration);
        let mut dns = crate::dns::analyze_dns_baseline_for_scan(
            &target,
            Duration::from_millis(100),
            false,
            false,
            false,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .observation;
        dns.dnssec = Some(crate::DnssecObservation {
            status: crate::DnssecStatus::Secure,
            ..crate::DnssecObservation::default()
        });
        dns.authoritative_axfr = Some(crate::AuthoritativeAxfrObservation {
            zone: "example.test".to_owned(),
            ..crate::AuthoritativeAxfrObservation::default()
        });
        dns.wildcard_dns = Some(WildcardDnsObservation {
            status: WildcardDnsStatus::Indeterminate,
            probes_attempted: 1,
            limitations: vec!["scan interrupted".to_owned()],
            ..WildcardDnsObservation::default()
        });
        report.dns = Some(dns);

        super::stop_after_wildcard_dns(
            &mut report,
            ScanSelection::all(),
            crate::ScanErrorKind::Cancelled,
            ScanStatus::Interrupted,
            "scan interrupted during wildcard DNS detection",
        );

        let dns = report.dns.as_ref().expect("DNS observation");
        assert_eq!(dns.resolved_hosts.len(), 1);
        assert_eq!(
            dns.dnssec.as_ref().map(|dnssec| dnssec.status),
            Some(crate::DnssecStatus::Secure)
        );
        assert_eq!(
            dns.authoritative_axfr
                .as_ref()
                .map(|axfr| axfr.zone.as_str()),
            Some("example.test")
        );
        assert_eq!(
            dns.wildcard_dns
                .as_ref()
                .map(|wildcard| wildcard.probes_attempted),
            Some(1)
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .filter(|skipped| skipped.check == "wildcard_dns")
                .count(),
            1
        );
        assert_eq!(report.status, ScanStatus::Interrupted);
        assert_eq!(report.errors.len(), 1);
    }

    #[tokio::test]
    async fn dangling_stop_preserves_prior_dns_for_timeout_and_cancellation() {
        let target = normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}"));
        let configuration = ScanConfiguration {
            ports: vec![9],
            udp_ports: Vec::new(),
            concurrency: 1,
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            global_timeout_ms: 1_000,
            ipv4_only: false,
            ipv6_only: false,
            authorization_acknowledged: true,
        };
        let mut dns = crate::dns::analyze_dns_baseline_for_scan(
            &target,
            Duration::from_millis(100),
            false,
            false,
            false,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .observation;
        dns.dnssec = Some(crate::DnssecObservation {
            status: crate::DnssecStatus::Secure,
            ..crate::DnssecObservation::default()
        });
        dns.authoritative_axfr = Some(crate::AuthoritativeAxfrObservation {
            zone: "example.test".to_owned(),
            ..crate::AuthoritativeAxfrObservation::default()
        });
        dns.wildcard_dns = Some(WildcardDnsObservation {
            status: WildcardDnsStatus::Detected,
            probes_attempted: 2,
            ..WildcardDnsObservation::default()
        });
        dns.dangling_cnames = vec![DanglingCnameObservation {
            source_alias: "alias.example.test".to_owned(),
            canonical_target: "destination.example.test".to_owned(),
            status: DanglingCnameStatus::Indeterminate,
            ..DanglingCnameObservation::default()
        }];

        for (kind, status, message) in [
            (
                crate::ScanErrorKind::Timeout,
                ScanStatus::Partial,
                "global timeout expired during CNAME destination checking",
            ),
            (
                crate::ScanErrorKind::Cancelled,
                ScanStatus::Interrupted,
                "scan interrupted during CNAME destination checking",
            ),
        ] {
            let mut report = crate::ScanReport::not_started(target.clone(), configuration.clone());
            report.dns = Some(dns.clone());
            super::stop_after_dangling_cname(
                &mut report,
                ScanSelection::all(),
                kind,
                status,
                message,
            );

            let retained = report.dns.as_ref().expect("DNS observation");
            assert_eq!(retained.resolved_hosts.len(), 1);
            assert_eq!(
                retained.dnssec.as_ref().map(|value| value.status),
                Some(crate::DnssecStatus::Secure)
            );
            assert_eq!(
                retained
                    .authoritative_axfr
                    .as_ref()
                    .map(|value| value.zone.as_str()),
                Some("example.test")
            );
            assert_eq!(
                retained.wildcard_dns.as_ref().map(|value| value.status),
                Some(WildcardDnsStatus::Detected)
            );
            assert_eq!(retained.dangling_cnames.len(), 1);
            assert_eq!(report.status, status);
            assert_eq!(
                report
                    .skipped_checks
                    .iter()
                    .filter(|skipped| skipped.check == "dangling_cname")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn wildcard_probe_answers_never_become_active_scan_addresses() {
        let target = normalize_target("example.test").unwrap_or_else(|error| panic!("{error}"));
        let mut report = crate::ScanReport::not_started(
            target,
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
        report.dns = Some(DnsObservation {
            queried_name: "example.test".to_owned(),
            records: Vec::new(),
            cname_chain: vec![CnameHop {
                from: "example.test".to_owned(),
                to: "missing.example".to_owned(),
            }],
            dangling_cnames: vec![DanglingCnameObservation {
                source_alias: "example.test".to_owned(),
                canonical_target: "missing.example".to_owned(),
                status: DanglingCnameStatus::NxDomain,
                ..DanglingCnameObservation::default()
            }],
            resolved_hosts: vec![ResolvedHost {
                hostname: Some("example.test".to_owned()),
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                source: AddressSource::ARecord,
            }],
            mail: MailObservation {
                mx_present: false,
                spf: SpfObservation {
                    records: Vec::new(),
                    terminal_policy: None,
                },
                dmarc: Vec::new(),
                mta_sts: Vec::new(),
                mta_sts_policy_available: None,
                tls_rpt: Vec::new(),
            },
            dnssec: None,
            authoritative_axfr: None,
            wildcard_dns: Some(WildcardDnsObservation {
                status: WildcardDnsStatus::Detected,
                probes_attempted: 2,
                answer_types: vec![WildcardDnsRecordType::A],
                answer_fingerprints: vec!["sha256:probe-answer-only".to_owned()],
                probe_answers_scanned: false,
                ..WildcardDnsObservation::default()
            }),
            errors: Vec::new(),
        });

        assert_eq!(
            super::scan_addresses(&report),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
        );
        let dns = report.dns.as_ref().expect("DNS observation");
        assert!(dns.records.is_empty());
        assert_eq!(dns.cname_chain.len(), 1);
        assert_eq!(dns.dangling_cnames.len(), 1);
        assert_eq!(dns.resolved_hosts.len(), 1);
        assert!(report.intelligence.is_none());
        assert!(report.hosts.is_empty());
        assert!(report.services.is_empty());
        assert!(report.http.is_empty());
        assert!(report.tls.is_empty());
    }

    #[tokio::test]
    async fn rejects_incompatible_explicit_address_family() {
        let report = run_scan(
            normalize_target("::1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![80],
                udp_ports: Vec::new(),
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
