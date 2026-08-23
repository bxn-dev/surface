# Surface implementation plan

- [x] Phase 0 — workspace, CLI bootstrap, report skeleton, CI, baseline documentation
- [x] Phase 1 — target normalization, scan configuration, port parser, authorization and exit codes
- [x] Phase 2 — passive DNS and mail-domain observations
- [x] Phase 3 — bounded TCP connect scanner, deadlines, cancellation, deterministic ordering
- [x] Phase 4 — safe service, bounded HTTP, and validating TLS analysis
- [x] Phase 5 — evidence-backed findings and terminal/JSON/self-contained HTML reports
- [x] Phase 6 — final hardening, release gates, and review

Automated tests use only deterministic data and loopback fixture servers. No test or CI job accesses public scan targets.

## Verified baseline — 2026-08-23

Phase 0–6 behavior and 30 tests were present. The pre-change quality gate produced:

- `cargo fmt --all --check` — **failed**: import ordering in `crates/surface-report/src/lib.rs:279`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed.
- `cargo test --workspace --all-features` — passed: 30 tests.
- `cargo doc --workspace --no-deps` — passed.
- `cargo deny check` — passed with existing duplicate-dependency warnings.
- `cargo build --release` — passed.

The reported Phase 6 completion was therefore not fully reproducible because formatting failed. Phase 7 applies `cargo fmt` and retains the other verified behavior.

## Post-MVP phases

- [x] Phase 7 — SQLite persistence, immutable report history, retrieval, deletion, retention, and audit foundation
- [x] Phase 8 — deterministic diffs, safe probes, exposure score, SARIF, and CycloneDX
- [ ] Phase 9 — API, web, authentication, tenancy, authorization, and audit access
- [ ] Phase 10 — durable jobs, schedules, notifications, and hosted egress policy
- [ ] Phase 11 — passive intelligence, supplied subdomains/DKIM, CVE correlation, and network metadata
- [ ] Phase 12 — metrics, signing, deployment, backup/restore, and final hardening

## Phase 7 verified — 2026-08-23

- Migration: `migrations/0001_scan_history.sql`.
- Storage: complete immutable report JSON plus indexed scan/finding metadata, foreign keys, transactional writes/deletes, future-schema rejection, restrictive Unix permissions, and deletion audit events.
- CLI: opt-in `scan --persist --database`, plus `history list/show/delete/prune`; ordinary one-shot scans remain database-free.
- Retention: age, per-target count, high/critical preservation, deterministic ordering, and dry-run.
- Tests: 35 passed, including temporary-database migration, round-trip, future-schema, retention-overflow, deletion/audit, and foreign-key behavior.
- Full gate: format, strict Clippy, workspace tests, docs, `cargo deny`, and release build passed. `cargo deny` retains pre-existing duplicate-version warnings.

## Phase 8 verified — 2026-08-23

- Diff: deterministic typed comparisons for network, services/HTTP, certificates, DNS/mail, findings, score, and completeness from files or persisted scan IDs; terminal, JSON, and escaped HTML output.
- Probes: centralized bounded behavior registry with passive or fixed read-only discovery for FTP, SMTP, POP3, IMAP, Redis, MySQL, HTTP, SSH, and TLS-wrapped service hints.
- Score: additive report schema `0.1.1`, exposure model `1.0`, stable deduplicated deductions, explicit incomplete state, terminal/HTML/JSON rendering, and documented rubric.
- Integrations: deterministic SARIF 2.1.0 findings and CycloneDX 1.6 observed-service inventory/vulnerabilities.
- Tests: 44 passed, including score stability/clamping, semantic-noise suppression, export ordering, CLI parsing, storage regressions, and local-only scanner fixtures.
- Full gate: format, strict Clippy, workspace tests, warning-free docs, `cargo deny`, and release build passed. `cargo deny` retains pre-existing duplicate-version warnings.
- Local smoke tests: persistence/history round-trip passed; database mode was `0600`; one-shot scan created no database.
- Review: all medium findings were fixed; no blocking findings remain.
