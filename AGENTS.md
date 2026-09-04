# Repository Guide

## Workspace

- This is a Rust 2024 workspace requiring Rust 1.85+. `rust-toolchain.toml` selects stable with `clippy` and `rustfmt`.
- `surface-core` owns scan models, target normalization, bounded network stages, and findings. Keep it independent of rendering, storage, and process behavior.
- `surface-report` owns deterministic terminal/JSON/HTML/SARIF/CycloneDX output, signing, scoring, and semantic diffs.
- `surface-storage` owns SQLite history, retention, audit, backup, and restore. `surface-cli` is the `surface` binary and orchestrates the other crates.
- Tests are colocated in each crate's `src/*.rs`; there are no separate integration-test directories.

## Safety Boundaries

- Keep changes within authorized defensive scanning. Do not add raw-packet, stealth, evasion, exploitation, credential, brute-force, crawling, or unrelated-target expansion behavior.
- Active scan targets are limited to explicit IPs and primary-target A/AAAA results. CNAMEs may reuse already-resolved addresses; MX/NS records, redirects, links, CT names, prefixes, and related domains must not expand the target set.
- Every active operation must retain bounded input/data, concurrency, timeouts, deadline propagation, and cancellation. Preserve useful partial observations on recoverable errors or cancellation.
- Tests and CI must use deterministic data, temporary SQLite databases, or loopback fixture servers; never scan public infrastructure.

## Verification

- Match CI order: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo doc --workspace --no-deps`, then `cargo deny check`.
- Run one crate with `cargo test -p surface-core`; filter one colocated test with `cargo test -p <crate> <test-name>`.
- Run `cargo build --release` for release-facing changes. The dependency policy in `deny.toml` rejects wildcards and unknown registries/git sources.

## Data And Reports

- SQLite persistence is opt-in: scans open no database unless both `--persist` and `--database PATH` are supplied.
- Database migrations are committed numbered SQL files, embedded in `crates/surface-storage/src/lib.rs`, and applied transactionally on open. Add new migrations; do not rewrite versions already recorded by existing databases.
- Schema versions 2 and 3 contain unused hosted-server tables retained solely for compatibility. `PLAN.md` is historical and does not describe the current executable architecture.
- Report output must remain deterministic and must escape target-controlled HTML. Without `--output`, a scan prints its selected format and also creates ignored `surface-<SCAN_ID>.html` in the current directory.
- Scan exit codes are meaningful: `2` means a report with high/critical findings; `3` means incomplete/interrupted output. Do not treat every nonzero scan exit as a process crash.
