# Surface

Surface is an asynchronous command-line scanner for the externally observable
services and security-related configuration of a domain, hostname, HTTP(S)
URL, or IP address.

It is a bounded exposure-assessment tool—not a complete vulnerability scanner,
penetration-testing framework, security certification, or proof that a target
is secure.

> [!WARNING]
> Use Surface only on systems you own or are explicitly authorized to assess.

## Quick start

Surface requires Rust 1.85 or newer.

```bash
git clone https://github.com/bxn-dev/surface.git surface-rs
cd surface-rs
cargo install --path crates/surface-cli
surface version
surface scan 127.0.0.1
```

The examples below use the loopback address, so they do not probe public
infrastructure. Replace it only with a system you own or are authorized to
assess. A typical scan uses the `common` TCP and UDP port presets:

```bash
surface scan 127.0.0.1 --only dns,http,tls
surface scan http://127.0.0.1/path --ports 80,443,8000-8100
surface scan 127.0.0.1 --ports 1-1000 --udp-ports 1-1000 --global-timeout 30s
```

## Preview

> [!NOTE]
> Future screenshots will be added here.

![Terminal scan report](docs/assets/screenshots/terminal-report.png)

![HTML scan report](docs/assets/screenshots/html-report.png)

## Features

- IDNA-aware normalization of domains, hostnames, HTTP(S) URLs, IPv4, and IPv6.
- DNS, mail-policy, DNSSEC, wildcard-DNS, dangling-CNAME, and bounded
  authoritative AXFR observations.
- Bounded TCP connect and UDP response scanning with selectable or complete
  port ranges and centralized service probes.
- Read-only HTTP analysis of same-origin, address-pinned endpoints, including
  selected headers, cookies, metadata, redirects, bodies, and well-known files.
- One normal validating TLS handshake per applicable implicit-TLS endpoint,
  with bounded certificate evidence.
- Bounded SSH identification and one KEXINIT exchange for already
  identified SSH services; no authentication or completed key exchange.
- Passive Certificate Transparency, supplied subdomain and DKIM observations,
  administrative RDAP evidence, RIPE RIS route evidence, and offline
  network/CVE correlations.
- Evidence-backed findings kept separate from raw observations, deterministic
  exposure scoring, and semantic report diffs.
- Terminal, versioned JSON, self-contained HTML, SARIF 2.1.0, and CycloneDX 1.6
  output, plus detached Ed25519 signatures.
- Optional immutable SQLite history with retention, audit events, and verified
  backup and restore.

Surface does not implement raw packets, stealth, evasion, brute force,
exploitation, crawling, directory enumeration, authentication, rate-limit
bypass, or unrelated-host discovery.

## Scanning

By default, Surface runs every applicable built-in check. `--only` restricts a
scan to selected groups; values are repeatable or comma-separated:
`dns`, `ports`, `services`, `http`, `tls`, and `intelligence`. Required
prerequisites are added automatically.

Useful scan options:

| Option | Description | Default |
| --- | --- | --- |
| `--ports` | `common`, `top-100`, `all`, comma-separated ports, or ranges | `common` |
| `--udp-ports` | `common`, `top-100`, `all`, comma-separated ports, or ranges | `common` |
| `--concurrency` | Maximum simultaneous network probes (`1`–`4096`) | `64` |
| `--connect-timeout` | Per-connection timeout, such as `1500ms` or `2s` | `1500ms` |
| `--request-timeout` | Per-request timeout | `5s` |
| `--global-timeout` | Whole-scan timeout | `5m` |
| `-o`, `--output` | Repeatable output path; format is inferred from its extension | — |
| `--ipv4-only` / `--ipv6-only` | Restrict future address discovery | — |
| `--quiet` / `--verbose` | Suppress diagnostics / enable later-phase debug logging | — |

`common` and `top-100` are supported names for the built-in preset for each
transport; they currently select the same bounded list.

Each active stage has bounded input, concurrency, timeouts, a shared deadline,
and cancellation support. Press `Ctrl+C` to stop a scan while preserving useful
partial observations.

UDP silence is reported as `open|filtered`, never definitively open. Port-based
service names are low-confidence hints until protocol evidence confirms them.

### Output behavior

Surface always prints the concise terminal report to stdout. Each `-o`/`--output`
path additionally receives its inferred report. With no explicit output, Surface
also writes a complete, self-contained HTML report using the local date:
`<safe-host-or-ip>-YYYY-MM-DD.html` for scans, `diff-YYYY-MM-DD.html` for diffs,
and `scan-<SCAN_ID>-YYYY-MM-DD.html` for history. Existing names receive a
`-2`, `-3`, and so on suffix. Progress is shown on stderr as an indeterminate
phase spinner only when stderr is a terminal; totals are intentionally not
shown, and `--quiet` disables it.
`RUST_LOG` can override the default log filter.

## Report formats and diffs

| Format | Use |
| --- | --- |
| `terminal` | Concise observations, open ports, findings, and counts |
| `json` | Complete transport-aware observations, findings, errors, and score; schema `0.4.0` |
| `html` | Self-contained, escaped, print-friendly report with no remote assets or scripts |
| `sarif` | SARIF 2.1.0 finding projection for code-scanning integrations |
| `cyclonedx-json` | CycloneDX 1.6 observed-service inventory and vulnerability projection |

SARIF and CycloneDX are intentionally lossy projections. Use Surface JSON when
complete observations and errors are required.

Output extensions are case-insensitive: `.html`/`.htm` selects HTML, `.json`
selects complete Surface JSON, `.sarif`/`.sarif.json` selects SARIF, and
`.cdx.json`, `.cyclonedx.json`, or `.cyclonedx` selects CycloneDX. A path with
no extension gets `.html` appended. An unrecognized extension writes HTML to
the requested path and emits a concise warning. `diff` supports only HTML and
JSON files; SARIF and CycloneDX output paths are rejected.

```bash
surface scan 127.0.0.1 -o report.json -o report.html
surface scan 127.0.0.1 -o report.sarif.json -o report.cdx.json

surface scan 127.0.0.1 -o old.json
surface scan 127.0.0.1 -o new.json
surface diff old.json new.json -o diff.html
surface diff <OLD_SCAN_ID> <NEW_SCAN_ID> --database ./surface.db
surface history show <SCAN_ID> --database ./surface.db -o show.json
```

`surface diff` compares report files or two persisted scan IDs. File inputs are
Surface JSON reports. Its terminal diff is always printed to stdout, while
explicit `.json` or `.html` paths receive additional diff output.

With an existing local report and 32-byte hexadecimal Ed25519 keys:

```bash
surface report sign report.json --key private-key.hex --signature report.sig.json
surface report verify report.json --signature report.sig.json --public-key public-key.hex
```

## Persistence and recovery

SQLite persistence is opt-in. A normal one-shot scan does not open or require a
database. Supply both `--persist` and `--database PATH` to store the complete
immutable report:

```bash
surface scan 127.0.0.1 --persist --database ./surface.db
surface history list --database ./surface.db
surface history show <SCAN_ID> --database ./surface.db
surface history prune --database ./surface.db --older-than 180d --dry-run
```

Replace the scan-ID placeholders with values from `history list`.
History also supports `delete`, retention by `--keep-last`, age-based
`--older-than`, `--preserve-high`, and `--dry-run`. Reports retain their
original schema version. Deletions record audit events, and foreign-key
dependent metadata is removed with the scan.

Back up, verify, and restore a database with the recovery commands:

```bash
surface database backup --database ./surface.db --output ./surface.backup.db
surface database verify --database ./surface.backup.db
surface database restore --database ./surface.db --input ./surface.backup.db
```

Backups are integrity-checked and published atomically. Close processes using a
database before restoring it.

## Optional intelligence inputs

The full scan includes bounded passive intelligence where applicable. Operators
can add explicitly supplied observations or an offline bundle:

The example uses the reserved `.test` domain as a placeholder; use an
authorized hostname for an actual intelligence run.

```bash
surface scan example.test \
  --subdomain child.example.test \
  --dkim-selector selector1 \
  --intelligence-bundle intelligence.json
```

`SURFACE_CERTSPOTTER_API_KEY` is optional and can provide a higher CertSpotter
API allowance. `SURFACE_WHOISXML_API_KEY` enables exact nameserver-pair reverse-
NS correlation. Passive intelligence sends the target hostname to the
configured third-party provider. Returned passive addresses and related names
do not become active scan targets.

## Exposure score

Reports use deterministic score model `1.0` on a `0–100` scale. The score starts
at 100 and deducts once for each unique finding rule ID and target:

| Severity | Deduction |
| --- | ---: |
| Informational | 0 |
| Low | 2 |
| Medium | 7 |
| High | 20 |
| Critical | 35 |

The result is clamped to `0–100` and classified as `Favorable` (85–100),
`Review` (65–84), `Elevated` (35–64), or `Critical` (0–34). A score is not
CVSS, a compromise probability, certification, or proof of security. Score
completeness is independent of the numeric value: partial, interrupted,
failed, and not-started scans are incomplete, and missing observations do not
create deductions.

## Safety boundaries and limitations

> [!IMPORTANT]
> Active targets are limited to explicit IPs and resolver-returned A/AAAA
> addresses for the primary target. Resolver-observed CNAME edges may be
> reported and already-resolved addresses may be deduplicated, but MX, NS, TXT,
> redirects, page links, Certificate Transparency names, prefixes, and related
> domains never expand the active target set.

> [!CAUTION]
> A clean report or a score of 100 does not prove that a target is secure.
> Timeouts, uncertain service identification, CDN/reverse-proxy edges, and
> application-context-dependent header recommendations require operator review.

Important limits include:

- DNSSEC uses local Hickory validation over selected primary-host A/AAAA
  RRsets. Only cryptographic `Proof::Bogus` produces the high-severity DNSSEC
  finding; resolver limitations and inconclusive results remain indeterminate.
- Dangling-CNAME checks query selected A/AAAA records for at most 16 directly
  observed primary-chain destinations. Only conclusive NXDOMAIN produces a
  potential indicator; ownership, claimability, and takeover feasibility are
  not tested.
- Wildcard-DNS detection uses exactly two UUID-v4 child probes. Probe names and
  raw answers are not retained or scanned, and detection is contextual routing
  evidence rather than automatically a vulnerability.
- AXFR is attempted only when primary-host SOA evidence and exact-owner NS
  records establish one unambiguous zone. Transferred names and records are
  never retained or scanned.
- SSH selections are inferred from one bounded KEXINIT exchange before
  completed key exchange. Surface performs no host-key retrieval,
  authentication, channels, commands, or banner-based CVE inference.
- TLS performs one normal validating handshake for each applicable implicit-TLS
  endpoint. Certificate evidence is bounded; rejected certificates remain
  rejected, and no broad cipher-weakness finding is inferred.
- Offline CVE matches require exact recognized product/version evidence and are
  candidates, not confirmed exploitable vulnerabilities. Surface does not
  provide complete vulnerability coverage.

See [`docs/limitations.md`](docs/limitations.md) for the full limitations and
evidence rules.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Command succeeded; a completed scan has no High or Critical findings |
| `1` | Invalid CLI usage, target, or configuration |
| `2` | Scan completed with a High or Critical finding |
| `3` | Scan is incomplete/interrupted, or a scan/report/database/output operation failed; inspect any report that was written |

Help and version output also exit with `0`.

## Project documentation

- [`docs/architecture.md`](docs/architecture.md) — crate responsibilities,
  data flow, and active/passive boundaries.
- [`docs/report-schema.md`](docs/report-schema.md) — JSON fields, schema
  compatibility, and integration projections.
- [`docs/scoring.md`](docs/scoring.md) — score calculation and completeness.
- [`docs/database-schema.md`](docs/database-schema.md) — SQLite migrations,
  history, retention, audit, backup, and restore behavior.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development standards and required
  checks.

## Development verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
cargo deny check
cargo build --release
```

Keep changes within Surface's authorized defensive scope. CI must never scan
external hosts; use deterministic local fixture servers and bounded test data.
