//! SARIF and CycloneDX-compatible exposure exports.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use surface_core::{Finding, ScanReport, Severity, SshPosture, SshPostureOutcome};

use crate::projection;

// Rust guideline compliant 2026-02-21

/// Renders a SARIF 2.1.0 findings document.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn render_sarif(report: &ScanReport) -> Result<String, serde_json::Error> {
    let mut findings = report.findings.iter().collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.id.cmp(&right.id))
            .then(left.target.cmp(&right.target))
            .then_with(|| canonical_finding(left).cmp(&canonical_finding(right)))
    });
    let mut rules = BTreeMap::<String, &Finding>::new();
    for finding in &findings {
        rules.entry(finding.id.clone()).or_insert(finding);
    }
    let rules = rules
        .into_iter()
        .map(|(id, finding)| {
            json!({
                "id": id,
                "name": finding.title,
                "shortDescription": { "text": finding.title },
                "fullDescription": { "text": finding.description },
                "help": {
                    "text": finding.remediation.as_deref().unwrap_or("Review the supporting Surface evidence."),
                },
                "properties": {
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "security-severity": security_severity(finding.severity),
                }
            })
        })
        .collect::<Vec<_>>();
    let results = findings
        .into_iter()
        .map(|finding| {
            json!({
                "ruleId": finding.id,
                "level": sarif_level(finding.severity),
                "message": { "text": format!("{} — {}", finding.title, finding.description) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": synthetic_target_uri(report, &finding.target) }
                    }
                }],
                "properties": {
                    "target": finding.target,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                }
            })
        })
        .collect::<Vec<_>>();
    let lifecycle = projection::lifecycle(report);
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Surface",
                    "version": report.scanner_version,
                    "informationUri": "https://github.com/bxn-dev/surface",
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": lifecycle.successful,
                "properties": {
                    "scanId": report.scan_id,
                    "reportSchemaVersion": report.schema_version,
                    "scanStatus": report.status,
                    "partial": lifecycle.partial,
                }
            }],
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&document)
}

/// Renders a deterministic `CycloneDX` 1.6 observed-service inventory.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn render_cyclonedx(report: &ScanReport) -> Result<String, serde_json::Error> {
    let lifecycle = projection::lifecycle(report);
    let mut services = report.services.iter().collect::<Vec<_>>();
    services.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then(left.transport.cmp(&right.transport))
            .then_with(|| left.service.to_string().cmp(&right.service.to_string()))
            .then_with(|| format!("{:?}", left.confidence).cmp(&format!("{:?}", right.confidence)))
            .then(left.banner.cmp(&right.banner))
            .then(left.protocol_details.cmp(&right.protocol_details))
            .then_with(|| format!("{:?}", left.ssh).cmp(&format!("{:?}", right.ssh)))
    });
    let services = services
        .into_iter()
        .map(|service| {
            let service_name = service.service.to_string();
            let mut properties = vec![
                property(
                    "surface:detection-confidence",
                    &format!("{:?}", service.confidence).to_ascii_lowercase(),
                ),
                property("surface:evidence-source", "active-safe-probe"),
                property("surface:scan-id", &report.scan_id.to_string()),
                property("surface:report-schema-version", &report.schema_version),
            ];
            properties.extend(
                service
                    .protocol_details
                    .iter()
                    .map(|(name, value)| property(&format!("surface:protocol:{name}"), value)),
            );
            if let Some(posture) = &service.ssh {
                properties.extend(ssh_properties(posture));
            }
            json!({
                "bom-ref": service_ref(service.address, service.transport.as_str(), &service_name),
                "name": format!("Externally observed {service_name} service"),
                "endpoints": [format!("{}://{}", service.transport.as_str(), service.address)],
                "authenticated": false,
                "properties": properties,
            })
        })
        .collect::<Vec<_>>();
    let mut findings = report.findings.iter().collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then(left.target.cmp(&right.target))
            .then(left.severity.cmp(&right.severity))
            .then_with(|| canonical_finding(left).cmp(&canonical_finding(right)))
    });
    let vulnerabilities = findings
        .into_iter()
        .map(|finding| {
            json!({
                "id": finding.id,
                "source": { "name": "Surface" },
                "ratings": [{
                    "source": { "name": "Surface" },
                    "severity": cyclone_severity(finding.severity),
                    "method": "other",
                }],
                "description": finding.description,
                "recommendation": finding.remediation,
                "properties": [
                    property("surface:target", &finding.target),
                    property("surface:confidence", &format!("{:?}", finding.confidence).to_ascii_lowercase()),
                ],
            })
        })
        .collect::<Vec<_>>();
    let target = report.target.identity();
    let document = json!({
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": format!("surface-target:{target}"),
                "name": "Externally Observed Service Inventory",
                "properties": [
                    property("surface:target", &target),
                    property("surface:scan-id", &report.scan_id.to_string()),
                    property("surface:scan-status", lifecycle.status),
                ],
            },
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "Surface",
                    "version": report.scanner_version,
                }]
            }
        },
        "services": services,
        "vulnerabilities": vulnerabilities,
    });
    serde_json::to_string_pretty(&document)
}

fn ssh_properties(posture: &SshPosture) -> Vec<Value> {
    let mut properties = Vec::new();
    if let Some(identification) = &posture.identification {
        properties.push(property("surface:ssh:protocol", &identification.protocol));
        properties.push(property("surface:ssh:software", &identification.software));
    }
    let (outcome, selections, reason) = match &posture.outcome {
        SshPostureOutcome::Complete { selections } => (
            "complete",
            [
                ("kex", Some(selections.kex.as_str())),
                ("host-key", Some(selections.host_key.as_str())),
                ("cipher-c2s", Some(selections.cipher_c2s.as_str())),
                ("cipher-s2c", Some(selections.cipher_s2c.as_str())),
                ("mac-c2s", Some(selections.mac_c2s.as_str())),
                ("mac-s2c", Some(selections.mac_s2c.as_str())),
            ],
            None,
        ),
        SshPostureOutcome::Partial { selections, reason } => (
            "partial",
            [
                ("kex", selections.kex.as_deref()),
                ("host-key", selections.host_key.as_deref()),
                ("cipher-c2s", selections.cipher_c2s.as_deref()),
                ("cipher-s2c", selections.cipher_s2c.as_deref()),
                ("mac-c2s", selections.mac_c2s.as_deref()),
                ("mac-s2c", selections.mac_s2c.as_deref()),
            ],
            Some(reason.as_str()),
        ),
        SshPostureOutcome::Indeterminate { reason } => {
            ("indeterminate", [("", None); 6], Some(reason.as_str()))
        }
    };
    properties.push(property("surface:ssh:outcome", outcome));
    properties.extend(selections.into_iter().filter_map(|(name, value)| {
        value.map(|value| property(&format!("surface:ssh:{name}"), value))
    }));
    if let Some(reason) = reason {
        properties.push(property("surface:ssh:reason", reason));
    }
    properties
}

fn canonical_finding(finding: &Finding) -> String {
    serde_json::to_string(finding).unwrap_or_default()
}

fn synthetic_target_uri(report: &ScanReport, finding_target: &str) -> String {
    let host = report.target.hostname.as_deref().unwrap_or("target");
    let context = finding_target
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric()
                || matches!(character, '.' | '-' | '_' | ':' | '[' | ']')
            {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("surface://{host}/{context}")
}

fn service_ref(address: std::net::SocketAddr, transport: &str, service: &str) -> String {
    format!("surface-service:{transport}:{address}/{service}")
}

fn property(name: &str, value: &str) -> Value {
    json!({ "name": name, "value": value })
}

const fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

const fn cyclone_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

const fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "2.0",
        Severity::Info => "0.0",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use surface_core::{
        DetectionConfidence, Finding, FindingCategory, FindingConfidence, ScanConfiguration,
        ScanReport, ScanStatus, ServiceKind, ServiceObservation, Severity, SshAlgorithmSelections,
        SshPosture, SshPostureOutcome, TransportProtocol, normalize_target,
    };

    use super::{render_cyclonedx, render_sarif};

    fn report() -> ScanReport {
        ScanReport::not_started(
            normalize_target("example.com").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![443],
                udp_ports: Vec::new(),
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

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.to_owned(),
            title: id.to_owned(),
            severity: Severity::Medium,
            category: FindingCategory::Network,
            target: "example.com".to_owned(),
            description: "Observed exposure.".to_owned(),
            evidence: Vec::new(),
            remediation: None,
            references: Vec::new(),
            confidence: FindingConfidence::High,
        }
    }

    #[test]
    fn exports_ignore_finding_input_order_including_duplicate_keys() {
        let mut duplicate = finding("RULE-A");
        duplicate.description = "Different endpoint evidence.".to_owned();
        let mut forward = report();
        forward.findings = vec![finding("RULE-A"), duplicate, finding("RULE-B")];
        let mut reversed = forward.clone();
        reversed.findings.reverse();
        assert_eq!(
            render_cyclonedx(&forward).unwrap_or_default(),
            render_cyclonedx(&reversed).unwrap_or_default()
        );
        assert_eq!(
            render_sarif(&forward).unwrap_or_default(),
            render_sarif(&reversed).unwrap_or_default()
        );
    }

    #[test]
    fn exports_preserve_exact_scan_lifecycle() {
        for (status, partial) in [
            (ScanStatus::NotStarted, false),
            (ScanStatus::Completed, false),
            (ScanStatus::Partial, true),
            (ScanStatus::Interrupted, false),
            (ScanStatus::Failed, false),
        ] {
            let mut report = report();
            report.status = status;
            let sarif: Value = serde_json::from_str(
                &render_sarif(&report).unwrap_or_else(|error| panic!("{error}")),
            )
            .unwrap_or_else(|error| panic!("{error}"));
            let cyclonedx: Value = serde_json::from_str(
                &render_cyclonedx(&report).unwrap_or_else(|error| panic!("{error}")),
            )
            .unwrap_or_else(|error| panic!("{error}"));

            assert_eq!(
                sarif["runs"][0]["invocations"][0]["properties"]["partial"],
                partial
            );
            assert_eq!(
                cyclonedx["metadata"]["component"]["properties"][2]["name"],
                "surface:scan-status"
            );
            assert_eq!(
                cyclonedx["metadata"]["component"]["properties"][2]["value"],
                serde_json::to_value(status).unwrap_or_else(|error| panic!("{error}"))
            );
        }
    }

    #[test]
    fn typed_ssh_uses_stable_cyclonedx_properties() {
        let mut report = report();
        report.services.push(ServiceObservation {
            transport: TransportProtocol::Tcp,
            address: "192.0.2.1:22"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            service: ServiceKind::Ssh,
            confidence: DetectionConfidence::High,
            banner: Some("SSH-2.0-OpenSSH_9.9".to_owned()),
            protocol_details: std::collections::BTreeMap::new(),
            ssh: Some(SshPosture {
                identification: None,
                outcome: SshPostureOutcome::Complete {
                    selections: SshAlgorithmSelections {
                        kex: "curve25519-sha256".to_owned(),
                        host_key: "ssh-ed25519".to_owned(),
                        cipher_c2s: "aes256-ctr".to_owned(),
                        cipher_s2c: "aes256-ctr".to_owned(),
                        mac_c2s: "hmac-sha2-512".to_owned(),
                        mac_s2c: "hmac-sha2-512".to_owned(),
                    },
                },
            }),
        });

        let cyclonedx = render_cyclonedx(&report).unwrap_or_else(|error| panic!("{error}"));
        assert!(cyclonedx.contains("surface:ssh:outcome"));
        assert!(cyclonedx.contains("surface:ssh:kex"));
        let sarif = render_sarif(&report).unwrap_or_else(|error| panic!("{error}"));
        assert!(!sarif.contains("surface:ssh:outcome"));
        assert!(!sarif.contains("surface:ssh:kex"));
    }

    #[test]
    fn cyclonedx_ignores_equal_endpoint_service_input_order() {
        let mut forward = report();
        for service in [ServiceKind::Https, ServiceKind::Http] {
            forward.services.push(ServiceObservation {
                transport: TransportProtocol::Tcp,
                address: "192.0.2.1:443"
                    .parse()
                    .unwrap_or_else(|error| panic!("{error}")),
                service,
                confidence: DetectionConfidence::High,
                banner: None,
                protocol_details: std::collections::BTreeMap::new(),
                ssh: None,
            });
        }
        let mut reversed = forward.clone();
        reversed.services.reverse();

        assert_eq!(
            render_cyclonedx(&forward).unwrap_or_default(),
            render_cyclonedx(&reversed).unwrap_or_default()
        );
    }

    #[test]
    fn exports_are_valid_deterministic_json() {
        let report = report();
        let sarif = render_sarif(&report).unwrap_or_else(|error| panic!("{error}"));
        let cyclonedx = render_cyclonedx(&report).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(sarif, render_sarif(&report).unwrap_or_default());
        assert_eq!(cyclonedx, render_cyclonedx(&report).unwrap_or_default());
        assert_eq!(
            serde_json::from_str::<Value>(&sarif)
                .unwrap_or_default()
                .get("version"),
            Some(&Value::String("2.1.0".to_owned()))
        );
        assert_eq!(
            serde_json::from_str::<Value>(&cyclonedx)
                .unwrap_or_default()
                .get("specVersion"),
            Some(&Value::String("1.6".to_owned()))
        );
    }
}
