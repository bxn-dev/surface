# Report schema

Surface JSON reports use schema version `0.3.0`. Reports from `0.1.x` and `0.2.0` remain readable. Version `0.3.0` adds UDP selections and transport-aware port and service observations.

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Serialized report contract version |
| `scanner_version` | Surface binary version |
| `scan_id` | UUID identifying this execution |
| `started_at`, `completed_at` | UTC execution timestamps |
| `target` | Original and normalized target metadata |
| `configuration` | Effective TCP/UDP ports, timeouts, concurrency, address-family and authorization settings |
| `status` | `not_started`, `completed`, `partial`, `interrupted`, or `failed` |
| `dns` | Raw DNS, primary-host addresses, passive mail interpretation, and DNS errors |
| `hosts` | Sorted transport-aware observations; UDP silence is `open_filtered`, never `open` |
| `services` | Sanitized/capped protocol evidence and explicitly low-confidence port hints |
| `http` | Bounded redirects, headers, cookies without values, metadata, and endpoint errors |
| `tls` | Validating handshake, negotiated protocol, and parsed leaf-certificate metadata |
| `findings` | Stable evidence-backed interpretations sorted by severity and ID |
| `errors` | Recoverable and fatal stage errors |
| `exposure_score` | Versioned deterministic score, deductions, classification, and completeness flag |
| `intelligence` | Optional explicitly supplied passive subdomain/DKIM and offline network/CVE correlations |
| `message` | Human-readable lifecycle summary |

No field contains ANSI escape sequences. Target-controlled banners, headers, bodies, errors, and HTML fields are capped or sanitized. Additive fields may appear within schema `0.1.x`; incompatible changes require a schema-version change.

Optional SQLite history stores this complete JSON unchanged alongside normalized query metadata. Retrieval returns the original report schema version; persistence does not reinterpret or update historical content.

`surface diff` accepts compatible `0.1.x` reports. It compares typed network, service, certificate, DNS/mail, finding, score, and completeness data while ignoring execution IDs, timestamps, latency, and transient error text. Reports with incompatible schema or score-model versions produce explicit warnings rather than fabricated comparisons.

SARIF 2.1.0 and CycloneDX 1.6 are integration projections, not replacements for the complete Surface JSON report. Unknown observations and partial status remain represented conservatively.

Detached signatures sign exact report bytes and therefore do not change this schema. Reformatting otherwise equivalent JSON invalidates its signature by design.
