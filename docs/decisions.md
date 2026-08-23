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

## SQLite history is optional and immutable

Local scans remain database-free by default. When persistence is requested, Surface uses bundled SQLite, committed numbered migrations, foreign keys, prepared statements, and transactions. It stores normalized query metadata plus the original complete report JSON. A database trigger rejects report-content updates; rescans always create new scan IDs.
