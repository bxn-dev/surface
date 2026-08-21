# Report schema

Surface JSON reports use schema version `0.1.0`.

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Serialized report contract version |
| `scanner_version` | Surface binary version |
| `scan_id` | UUID identifying this execution |
| `started_at`, `completed_at` | UTC execution timestamps |
| `target` | Original and normalized target metadata |
| `configuration` | Effective ports, timeouts, concurrency, address-family and authorization settings |
| `status` | `not_started`, `completed`, `partial`, `interrupted`, or `failed` |
| `stages` | Explicit implementation state |
| `dns` | Raw DNS, primary-host addresses, passive mail interpretation, and DNS errors |
| `hosts` | Sorted TCP observations including conservative states |
| `services` | Sanitized/capped protocol evidence |
| `http` | Bounded redirects, headers, cookies without values, metadata, and endpoint errors |
| `tls` | Validating handshake, negotiated protocol, and parsed leaf-certificate metadata |
| `findings` | Stable evidence-backed interpretations sorted by severity and ID |
| `errors` | Recoverable and fatal stage errors |
| `message` | Human-readable lifecycle summary |

No field contains ANSI escape sequences. Target-controlled banners, headers, bodies, errors, and HTML fields are capped or sanitized. Additive fields may appear within schema `0.1.x`; incompatible changes require a schema-version change.
