# Surface implementation plan

- [x] Phase 0 — workspace, CLI bootstrap, report skeleton, CI, baseline documentation
- [x] Phase 1 — target normalization, scan configuration, port parser, authorization and exit codes
- [x] Phase 2 — passive DNS and mail-domain observations
- [x] Phase 3 — bounded TCP connect scanner, deadlines, cancellation, deterministic ordering
- [x] Phase 4 — safe service, bounded HTTP, and validating TLS analysis
- [x] Phase 5 — evidence-backed findings and terminal/JSON/self-contained HTML reports
- [x] Phase 6 — final hardening, release gates, and review

Automated tests use only deterministic data and loopback fixture servers. No test or CI job accesses public scan targets.
