# Limitations

- A TCP timeout records only that the connection deadline elapsed; it does not prove firewall filtering.
- Service identification uses safe banners, fixed read-only protocol discovery exchanges, TLS success, and port hints. Results can remain uncertain; MySQL, PostgreSQL, MQTT, and generic TLS hints do not prove product identity.
- CDN and reverse-proxy addresses may represent edge infrastructure rather than an origin server.
- HTTP security-header and cookie recommendations depend on application context. Header presence alone does not prove quality.
- Surface does not crawl, brute-force directories, authenticate, fuzz, exploit, deliver payloads, evade controls, or test denial of service.
- Surface does not provide complete vulnerability coverage or infer CVEs solely from banners.
- DNSSEC is not cryptographically validated and is never reported as validated.
- DKIM availability cannot be determined generically without an explicitly supplied selector, which v0.1.0 does not accept.
- MTA-STS/TLS-RPT/SPF/DMARC record presence does not prove secure mail delivery.
- The validating TLS handshake cannot retain an invalid leaf certificate when Rustls rejects it; the validation error remains visible.
- HTTPS/header analysis uses a native HTTP client and does not execute JavaScript.
- The exposure score reflects only generated findings. Missing observations never deduct points; compare scores only when coverage and score-model versions are compatible.
- SARIF and CycloneDX are lossy integration projections; use Surface JSON for complete observations and errors.
- A clean report or score of 100 does not prove that a target is secure.
