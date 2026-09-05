//! Terminal scan-report lifecycle operations.

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::{
    DnssecStatus, ScanError, ScanErrorKind, ScanProgress, ScanReport, ScanSelection, ScanStage,
    ScanStatus, SkippedCheck, WildcardDnsStatus, calculate_exposure, generate_findings,
};

pub(crate) fn add_skipped_check(report: &mut ScanReport, check: &str, reason: &str) {
    if report
        .skipped_checks
        .iter()
        .all(|skipped| skipped.check != check)
    {
        report.skipped_checks.push(SkippedCheck {
            check: check.to_owned(),
            reason: reason.to_owned(),
        });
    }
}

pub(crate) fn record_selection_skips(report: &mut ScanReport, selection: ScanSelection) {
    for (check, selected) in [
        ("ports", selection.ports),
        ("services", selection.services),
        ("http", selection.http),
        ("tls", selection.tls),
    ] {
        if !selected {
            add_skipped_check(report, check, "excluded by --only");
        }
    }
}

pub(crate) fn terminate(
    report: &mut ScanReport,
    stage: ScanStage,
    selection: ScanSelection,
    kind: ScanErrorKind,
    message: &str,
) {
    if report.status == ScanStatus::Interrupted && kind == ScanErrorKind::Cancelled {
        return;
    }
    if report.status == ScanStatus::Failed && kind == ScanErrorKind::Timeout {
        return;
    }
    report.status = match kind {
        ScanErrorKind::Configuration => ScanStatus::Failed,
        ScanErrorKind::Cancelled => ScanStatus::Interrupted,
        ScanErrorKind::Timeout if !has_observations(report) => ScanStatus::Failed,
        _ => ScanStatus::Partial,
    };
    message.clone_into(&mut report.message);
    report.errors.push(ScanError::new(
        stage,
        report.target.hostname.clone(),
        kind,
        message,
        report.status != ScanStatus::Failed,
    ));
    record_unfinished_checks(report, stage, selection, message);
}

pub(crate) fn settle(report: &mut ScanReport) {
    if matches!(
        report.status,
        ScanStatus::Interrupted | ScanStatus::Failed | ScanStatus::Partial
    ) {
        return;
    }
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
            .any(|observation| observation.status == crate::DanglingCnameStatus::Indeterminate)
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

pub(crate) fn finalize(
    report: &mut ScanReport,
    cancellation: &CancellationToken,
    deadline: Instant,
    progress: &impl Fn(ScanProgress),
) {
    if report.completed_at.is_some() {
        return;
    }
    if report
        .errors
        .iter()
        .any(|error| error.stage == ScanStage::Preflight)
    {
        report.completed_at = Some(time::OffsetDateTime::now_utc());
        return;
    }
    if cancellation.is_cancelled() {
        terminate(
            report,
            ScanStage::Findings,
            ScanSelection::all(),
            ScanErrorKind::Cancelled,
            "scan interrupted during findings finalization",
        );
    } else if Instant::now() >= deadline {
        terminate(
            report,
            ScanStage::Findings,
            ScanSelection::all(),
            ScanErrorKind::Timeout,
            "global timeout expired during findings finalization",
        );
    } else {
        settle(report);
    }
    progress(ScanProgress::Started(ScanStage::Findings));
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
    progress(ScanProgress::Completed {
        stage: ScanStage::Findings,
        observations: report.findings.len(),
    });
    if cancellation.is_cancelled() {
        terminate(
            report,
            ScanStage::Findings,
            ScanSelection::all(),
            ScanErrorKind::Cancelled,
            "scan interrupted after findings finalization",
        );
    } else if Instant::now() >= deadline {
        terminate(
            report,
            ScanStage::Findings,
            ScanSelection::all(),
            ScanErrorKind::Timeout,
            "global timeout expired after findings finalization",
        );
    }
    report.completed_at = Some(time::OffsetDateTime::now_utc());
}

fn has_observations(report: &ScanReport) -> bool {
    report.dns.is_some()
        || !report.hosts.is_empty()
        || !report.services.is_empty()
        || !report.http.is_empty()
        || !report.tls.is_empty()
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
        if selected && stage_rank(stage) >= failed_rank {
            add_skipped_check(report, check, reason);
        }
    }
}

const fn stage_rank(stage: ScanStage) -> u8 {
    match stage {
        ScanStage::Preflight => 0,
        ScanStage::Dns => 1,
        ScanStage::Ports => 2,
        ScanStage::Services => 3,
        ScanStage::Http => 4,
        ScanStage::Tls => 5,
        ScanStage::Findings => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::{add_skipped_check, record_selection_skips, terminate};
    use crate::{
        ScanConfiguration, ScanErrorKind, ScanReport, ScanSelection, ScanStage, ScanStatus,
        normalize_target,
    };

    fn report() -> ScanReport {
        ScanReport::not_started(
            normalize_target("127.0.0.1").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![9],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 1,
                request_timeout_ms: 1,
                global_timeout_ms: 1,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
        )
    }

    #[test]
    fn unfinished_checks_are_deduplicated_in_stage_order() {
        let mut report = report();
        record_selection_skips(&mut report, ScanSelection::only(&[]));
        add_skipped_check(&mut report, "ports", "duplicate");
        terminate(
            &mut report,
            ScanStage::Dns,
            ScanSelection::all(),
            ScanErrorKind::Cancelled,
            "cancelled",
        );
        assert_eq!(
            report
                .skipped_checks
                .iter()
                .map(|check| check.check.as_str())
                .collect::<Vec<_>>(),
            vec![
                "ports",
                "services",
                "http",
                "tls",
                "dns",
                "dnssec_validation",
                "authoritative_axfr",
                "wildcard_dns",
                "dangling_cname"
            ],
        );
    }

    #[test]
    fn timeout_without_observations_fails() {
        let mut report = report();
        terminate(
            &mut report,
            ScanStage::Dns,
            ScanSelection::all(),
            ScanErrorKind::Timeout,
            "expired",
        );
        assert_eq!(report.status, ScanStatus::Failed);
    }
}
