//! Shared semantic projections for report renderers.

use surface_core::{
    HostObservation, PartialSshAlgorithmSelections, PortState, ScanReport, ScanStatus,
    ServiceObservation, SshAlgorithmSelections, SshPostureOutcome,
};

// Rust guideline compliant 2026-02-21

#[derive(Debug)]
pub(crate) struct SshProjection<'a> {
    pub(crate) protocol: Option<&'a str>,
    pub(crate) software: Option<&'a str>,
    pub(crate) status: &'static str,
    pub(crate) selections: PartialSshAlgorithmSelectionsRef<'a>,
    pub(crate) reason: Option<&'a str>,
}

#[derive(Debug, Default)]
pub(crate) struct PartialSshAlgorithmSelectionsRef<'a> {
    pub(crate) kex: Option<&'a str>,
    pub(crate) host_key: Option<&'a str>,
    pub(crate) cipher_c2s: Option<&'a str>,
    pub(crate) cipher_s2c: Option<&'a str>,
    pub(crate) mac_c2s: Option<&'a str>,
    pub(crate) mac_s2c: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LifecycleProjection {
    pub(crate) status: &'static str,
    pub(crate) successful: bool,
    pub(crate) partial: bool,
    pub(crate) errors: usize,
    pub(crate) score_incomplete: bool,
}

#[derive(Debug)]
pub(crate) struct PortProjection {
    pub(crate) number: u16,
    pub(crate) transport: &'static str,
    pub(crate) state: &'static str,
    pub(crate) service: String,
}

pub(crate) fn ports(report: &ScanReport, host: &HostObservation) -> Vec<PortProjection> {
    host.ports
        .iter()
        .filter_map(|port| {
            let service = report.services.iter().find(|service| {
                service.address == port.address && service.transport == port.transport
            });
            if port.state != PortState::Open
                && !(port.state == PortState::OpenFiltered && service.is_some())
            {
                return None;
            }
            Some(PortProjection {
                number: port.address.port(),
                transport: port.transport.as_str(),
                state: if port.state == PortState::Open {
                    "open"
                } else {
                    "open|filtered"
                },
                service: service
                    .map_or_else(|| "unknown".to_owned(), |value| value.service.to_string()),
            })
        })
        .collect()
}

pub(crate) fn lifecycle(report: &ScanReport) -> LifecycleProjection {
    LifecycleProjection {
        status: match report.status {
            ScanStatus::NotStarted => "not_started",
            ScanStatus::Completed => "completed",
            ScanStatus::Partial => "partial",
            ScanStatus::Interrupted => "interrupted",
            ScanStatus::Failed => "failed",
        },
        successful: report.status == ScanStatus::Completed,
        partial: report.status == ScanStatus::Partial,
        errors: report.errors.len(),
        score_incomplete: report
            .exposure_score
            .as_ref()
            .is_some_and(|score| score.incomplete),
    }
}

impl<'a> From<&'a SshAlgorithmSelections> for PartialSshAlgorithmSelectionsRef<'a> {
    fn from(value: &'a SshAlgorithmSelections) -> Self {
        Self {
            kex: Some(&value.kex),
            host_key: Some(&value.host_key),
            cipher_c2s: Some(&value.cipher_c2s),
            cipher_s2c: Some(&value.cipher_s2c),
            mac_c2s: Some(&value.mac_c2s),
            mac_s2c: Some(&value.mac_s2c),
        }
    }
}

impl<'a> From<&'a PartialSshAlgorithmSelections> for PartialSshAlgorithmSelectionsRef<'a> {
    fn from(value: &'a PartialSshAlgorithmSelections) -> Self {
        Self {
            kex: value.kex.as_deref(),
            host_key: value.host_key.as_deref(),
            cipher_c2s: value.cipher_c2s.as_deref(),
            cipher_s2c: value.cipher_s2c.as_deref(),
            mac_c2s: value.mac_c2s.as_deref(),
            mac_s2c: value.mac_s2c.as_deref(),
        }
    }
}

pub(crate) fn ssh(service: &ServiceObservation) -> Option<SshProjection<'_>> {
    let posture = service.ssh.as_ref()?;
    let (status, selections, reason) = match &posture.outcome {
        SshPostureOutcome::Complete { selections } => ("complete", selections.into(), None),
        SshPostureOutcome::Partial { selections, reason } => {
            ("partial", selections.into(), Some(reason.as_str()))
        }
        SshPostureOutcome::Indeterminate { reason } => (
            "indeterminate",
            PartialSshAlgorithmSelectionsRef::default(),
            Some(reason.as_str()),
        ),
    };
    Some(SshProjection {
        protocol: posture
            .identification
            .as_ref()
            .map(|identification| identification.protocol.as_str()),
        software: posture
            .identification
            .as_ref()
            .map(|identification| identification.software.as_str()),
        status,
        selections,
        reason,
    })
}
