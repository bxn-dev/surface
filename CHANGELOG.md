# Changelog

All notable changes are documented here.

## [Unreleased]

### Added

- Deterministic semantic scan diffs for report files and persisted scan IDs, with terminal, JSON, and escaped HTML output.
- Versioned exposure scoring with stable deductions and explicit incomplete-scan limitations.
- SARIF 2.1.0 and CycloneDX 1.6 JSON exports.
- Centralized bounded probes for FTP, IMAP, POP3, Redis, MySQL, and SMTP capabilities.
- Optional SQLite-backed immutable scan persistence with versioned migrations.
- Scan-history list, show, delete, and dry-run retention commands.
- Queryable scan/finding metadata and auditable transactional deletion.
- Cargo workspace with separated core, reporting, and CLI crates.
- Authorization-gated domain, URL, IPv4, and IPv6 scanning.
- Passive DNS and conservative mail-domain interpretation.
- Bounded asynchronous TCP connect scanner with cancellation and strict timeouts.
- Safe service, HTTP, and validating TLS observations.
- Evidence-backed finding engine.
- Terminal, versioned JSON, and self-contained escaped HTML reports.
- Local-only tests, pinned CI actions, documentation, and dependency-policy checks.
