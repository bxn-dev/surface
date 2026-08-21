# Contributing

Use stable Rust and keep changes within Surface's authorized defensive scope. Never add raw-packet, stealth, evasion, exploit, credential, brute-force, crawling, public-internet test, or unrelated-target expansion behavior.

## Standards

- clear typed Rust; no `unwrap`/`expect` in production paths
- bounded concurrency, I/O timeouts, and cancellation for every active operation
- observations separate from findings and presentation
- deterministic ordering and bounded untrusted data
- concise Rustdoc on public APIs
- local fixture tests for behavior and failure paths
- no new dependency when the standard library or an existing crate is sufficient

## Checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
cargo deny check
cargo build --release
```

CI must never scan external hosts. Report vulnerabilities through the private process in [`SECURITY.md`](SECURITY.md).
