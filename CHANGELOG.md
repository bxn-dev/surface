# Changelog

All notable changes are documented here.

## [Unreleased]

### Changed

- Removed the hosted server/control plane in favor of direct CLI scans and complete self-contained HTML reports.
- Removed the `--acknowledge-authorization` gate; operators remain responsible for scanning only authorized targets.
- Added `indicatif` stage progress, resolver-returned CNAME-chain evidence, default bounded CertSpotter Certificate Transparency discovery, optional passive exact-pair reverse-NS correlation, and truthful HTTP-to-HTTPS redirect rendering.
- Added bounded TCP and UDP scanning across `1-65535`, transport-aware reports, truthful UDP `open|filtered` states, and curated service hints for infrastructure, databases, VPNs, and game servers.
- Added precise encrypted-service names such as SMTPS, IMAPS, and POP3S; bumped report and crate versions to `0.3.0`.
- Existing safe checks now run by default; `--only` restricts scan groups and reports omitted or unavailable checks explicitly.
- Scans without `--output` now emit the selected stdout format and a self-contained `surface-<SCAN_ID>.html` report.
- Removed redundant scan-stage implementation flags in report schema `0.2.0`.
- Consolidated target identity, HTML escaping, service mapping, and change sorting.

### Added

- Default-on bounded SSH identification and KEXINIT posture analysis for already identified TCP SSH services, with one deduplicated reconnect, RFC client-first inferred algorithm selections, compact sanitized terminal and escaped self-contained HTML posture sections, semantic diff/export coverage through existing service properties, a Medium/medium-confidence finding only for `complete_inferred` exact legacy selections, a bounded strong-first fallback tail through group1, DSS, Arcfour, and HMAC-MD5, per-endpoint indeterminate reasons, and no key exchange or authentication.
- Additive bounded TLS evidence for negotiated successful handshakes and certificates rejected by the unchanged validating WebPKI verifier, including peer-chain length, lowercase SHA-256 leaf fingerprints, reliably parsed public-key bits, and normalized SANs; duplicate implicit-TLS endpoints receive one attempt. Exact direct evidence now produces Medium/high-confidence findings for RSA leaf keys below 2048 bits, RFC 3279 SHA-1 leaf-signature OIDs, and `TLSv1_0`/`TLSv1_1` observations.
- Default-on conservative dangling-CNAME indicators for at most 16 directly observed primary-chain destinations, with selected A/AAAA-only classification, no destination propagation, and a Medium finding only for conclusive NXDOMAIN.
- Default-on conservative wildcard-DNS detection for hostname scans using exactly two UUID-v4 child probes, selected A/AAAA plus CNAME lookups, hashed answer summaries, non-retention, and an informational finding only for identical non-empty answers.
- Exact-zone Hickory TCP AXFR checks from primary-host SOA/NS evidence, with strict endpoint/transfer bounds, counts-only non-retention, conservative outcomes, and a high-confidence finding only for complete allowed transfers.
- Default-on Hickory DNSSEC validation for bounded primary-host address RRsets, with conservative status reporting and a high-confidence finding only for cryptographically bogus proofs.
- Explicit passive subdomain/DKIM observations plus validated offline network metadata and conservative CVE candidates in report schema `0.1.2`.
- Exact-byte detached Ed25519 signatures and verified atomic SQLite backup/restore.
- Deterministic semantic scan diffs for report files and persisted scan IDs, with terminal, JSON, and escaped HTML output.
- Versioned exposure scoring with stable deductions and explicit incomplete-scan limitations.
- SARIF 2.1.0 and CycloneDX 1.6 JSON exports.
- Centralized bounded probes for FTP, IMAP, POP3, Redis, MySQL, and SMTP capabilities.
- Optional SQLite-backed immutable scan persistence with versioned migrations.
- Scan-history list, show, delete, and dry-run retention commands.
- Queryable scan/finding metadata and auditable transactional deletion.
- Cargo workspace with separated core, reporting, and CLI crates.
- Domain, URL, IPv4, and IPv6 scanning.
- Passive DNS and conservative mail-domain interpretation.
- Bounded asynchronous TCP connect scanner with cancellation and strict timeouts.
- Safe service, HTTP, and validating TLS observations.
- Evidence-backed finding engine.
- Terminal, versioned JSON, and self-contained escaped HTML reports.
- Local-only tests, pinned CI actions, documentation, and dependency-policy checks.
