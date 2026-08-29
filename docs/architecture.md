# Architecture

```mermaid
flowchart TD
    A[Target Input] --> B[Target Normalization]
    B --> C[DNS Analysis]
    C --> D[Primary-host IP Discovery]
    D --> E[Bounded TCP Connect Scanner]
    E --> F[Safe Service Detection]
    F --> G[Bounded HTTP Analysis]
    F --> H[Validating TLS Analysis]
    F --> SSH[Bounded SSH Identification and KEXINIT Analysis]
    C --> I[Passive Mail Analysis]
    C --> S[Bounded CertSpotter CT Discovery]
    G --> J[Pure Finding Engine]
    H --> J
    SSH --> J
    I --> J
    J --> K[Versioned ScanReport]
    S --> K
    K --> L[Terminal]
    K --> M[JSON]
    K --> N[Escaped HTML]
    K --> O[Optional SQLite History]
    K --> P[SARIF / CycloneDX]
    K --> Q[Versioned Exposure Score]
    O --> R[Semantic Diff]
    K --> R
```

## Crates

- `surface-core` — typed target/configuration, observations, bounded Tokio orchestration, errors, and deterministic findings. It has no terminal rendering.
- `surface-report` — pure terminal/JSON/HTML, SARIF/CycloneDX, and semantic-diff rendering. HTML escapes all target-controlled data and loads no remote resources.
- `surface-cli` — Clap arguments, progress, tracing setup, Ctrl+C cancellation, files/stdout, persistence, intelligence, signing, recovery, and exit codes.
- `surface-storage` — versioned SQLite migrations, immutable local history, audit, retention, and verified recovery.

`surface-core` remains independent. `surface-report` and `surface-storage` consume its report model; `surface-cli` orchestrates both. No dependency cycle exists.

## Boundaries

Only explicit IPs and resolver-returned A/AAAA addresses for the primary target become active scan targets. Resolver-returned CNAME edges are reported and their already-resolved addresses are deduplicated; MX, NS, TXT, redirects to other hosts, and page links never expand scan scope. TCP uses ordinary `connect`; every active stage has a timeout and bounded concurrency. Completed observations survive recoverable stage errors and cancellation.

Persistence is opt-in. A one-shot scan opens no database unless `--persist --database PATH` is supplied. Report serialization and normalized finding writes share one transaction. Historical report JSON cannot be updated; deletion cascades dependent metadata and records an audit event in the same transaction.

Service probes are selected by a centralized port-to-behavior registry. Payloads are fixed, read-only discovery commands; banner bytes, endpoint count, time, and concurrency remain bounded. During the Services stage, only already identified TCP SSH observations receive one reconnect per deduplicated `SocketAddr`, capped at 16 concurrent requests under the caller deadline, cancellation, and request timeout. The SSH path accepts at most 50 CRLF pre-banner lines/4 KiB, a 255-byte identification, one 35,000-byte packet, and ten name-lists of at most 8 KiB/128 names; each algorithm name is at most 64 printable ASCII bytes. It sends one identification and one unencrypted KEXINIT, stores sanitized client-first intersections on the matching service, and closes before key exchange, NEWKEYS, host-key bytes, authentication, channels, or commands. These values are inferred, not completed negotiation, and cannot create or propagate endpoints. Diffing and scoring are pure functions over completed report data and perform no network I/O.

TLS performs one normal validating rustls handshake per deduplicated applicable implicit-TLS endpoint. It does not disable validation, brute-force protocols or ciphers, or reconnect to recover rejected certificate evidence.

HTTP remains address-pinned and same-origin. CertSpotter Certificate Transparency names, supplied subdomains, and DKIM selectors are passive and bounded; CT names are reported but never scanned automatically. CVE/network metadata comes only from a validated offline bundle; candidates are correlations, never exploit confirmation.
