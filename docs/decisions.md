# Design decisions

## TCP connect only

Surface uses Tokio `TcpStream::connect`. Raw sockets, stealth scans, spoofing, evasion, exploitation, authentication, and brute force are out of scope.

## Explicit authorization gate

Non-loopback scans require `--acknowledge-authorization` before DNS or network activity. Local CLI mode permits explicitly supplied private addresses; no hosted mode exists.

## Primary-host scope

Only explicit targets and primary-host A/AAAA records feed the TCP scanner. Passive MX/NS/CNAME/TXT observations do not create scan targets. HTTP redirects are followed only on the original host.

## Observation before interpretation

Protocol modules emit typed observations. A pure finding engine produces stable IDs, severity, evidence, and remediation. Missing context-sensitive controls are not automatically labeled vulnerabilities.

## TLS validation

The primary TLS observation uses Rustls, Mozilla roots, SNI/identity validation, TLS 1.2/1.3, and no verification bypass. Failed validation is preserved as an error; Surface does not silently retry insecurely.

## Deterministic reports

Sorted vectors and ordered maps avoid hash-order instability. HTML is generated locally with explicit escaping and no script/template execution.

## Semantic diffs ignore execution noise

Diff keys come from typed observations and stable finding identities. Scan IDs, timestamps, latency, and transient error strings are excluded so repeated equivalent scans compare cleanly. Completeness changes remain explicit because missing evidence can change interpretation.

## Exposure scoring is versioned

The score is a deterministic projection of stable finding severity and target identity. Model version `1.0` is stored with every result; incomplete coverage is represented independently from the numeric value. Weight or interpretation changes require a new model version.

## Integration exports are projections

SARIF and CycloneDX are generated directly from the complete report with `serde_json`; no format-specific dependency or parallel data model is maintained. The Surface JSON report remains the lossless source of truth.

## Hosted execution reuses core scanning

The hosted API adds tenancy and durable leases but invokes the same scan engine. A hosted-only core entry point fails closed for explicit or resolved non-global addresses, preventing request-layer validation bypass. Target authorization attestations are durable tenant state.

## Authentication uses opaque revocable credentials

Passwords use Argon2id with random salts. Session and API credentials are random 256-bit values stored only as SHA-256 hashes. Cookie mutations require exact-origin plus per-session CSRF; bearer tokens require stored scopes. Role authorization is centralized.

## Passive intelligence is operator supplied

Subdomains and DKIM selectors are explicit bounded inputs. Network/CVE metadata is a local versioned JSON bundle, avoiding third-party credentials, nondeterministic APIs, and public-network tests. CVE output is labeled as correlation candidates and does not alter score model 1.0.

## Recovery and signatures preserve immutable reports

Detached Ed25519 signatures cover exact bytes. SQLite backup/restore operates on verified database snapshots and never updates historical `report_json`.

## SQLite history is optional and immutable

Local scans remain database-free by default. When persistence is requested, Surface uses bundled SQLite, committed numbered migrations, foreign keys, prepared statements, and transactions. It stores normalized query metadata plus the original complete report JSON. A database trigger rejects report-content updates; rescans always create new scan IDs.
