//! SARIF and CycloneDX-compatible exposure exports.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use surface_core::{Finding, ScanReport, Severity};

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
    let successful = matches!(report.status, surface_core::ScanStatus::Completed);
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
                "executionSuccessful": successful,
                "properties": {
                    "scanId": report.scan_id,
                    "reportSchemaVersion": report.schema_version,
                    "scanStatus": report.status,
                    "partial": !successful,
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
    let mut services = report.services.iter().collect::<Vec<_>>();
    services.sort_by_key(|service| (service.address, service.transport));
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
        normalize_target, Finding, FindingCategory, FindingConfidence, ScanConfiguration,
        ScanReport, Severity,
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
