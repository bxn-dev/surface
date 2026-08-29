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
| `configuration` | Effective TCP/UDP ports, timeouts, concurrency, address-family settings, and a compatibility-only authorization field that is always `true` for new scans |
| `status` | `not_started`, `completed`, `partial`, `interrupted`, or `failed` |
| `dns` | Raw DNS, at most 16 resolver-returned primary CNAME edges and conservative destination statuses, deduplicated primary-target addresses, passive mail interpretation, DNS errors, bounded primary-host DNSSEC validation, optional authoritative AXFR counts, and conservative wildcard-DNS status |
| `hosts` | Sorted transport-aware observations; UDP silence is `open_filtered`, never `open` |
| `services` | Sanitized/capped protocol evidence and explicitly low-confidence port hints |
| `http` | Bounded redirects, headers, cookies without values, metadata, and endpoint errors |
| `tls` | One validating handshake per deduplicated applicable implicit-TLS endpoint, negotiated protocol/cipher on success, and bounded parsed presented-certificate evidence on success or certificate rejection |
| `findings` | Stable evidence-backed interpretations sorted by severity and ID |
| `errors` | Recoverable and fatal stage errors |
| `exposure_score` | Versioned deterministic score, deductions, classification, and completeness flag |
| `intelligence` | Optional passive subdomain/DKIM, exact nameserver-pair related-domain candidates, and offline network/CVE correlations |
| `message` | Human-readable lifecycle summary |

`dns.dnssec` is additive and optional when reading older reports. New hostname scans report `secure`, `insecure`, `bogus`, `indeterminate`, or `not_applicable`, plus checked names/types, errors, and scope limitations. Hickory performs local validation with built-in trust anchors over selected primary-host A/AAAA RRsets. System or upstream resolver limitations, timeouts, transport failures, and unsupported or inconclusive proofs remain indeterminate; only cryptographic `Proof::Bogus` generates the high-severity `DNS-DNSSEC-BOGUS` finding.

`dns.authoritative_axfr` is also additive and optional for older reports. It appears only when primary-host SOA evidence and exact-owner NS records establish one zone and at least one NS endpoint resolves. It records the evidenced zone, up to 4 NS names, up to 2 addresses per NS, up to 8 deduplicated TCP endpoint attempts, outcomes, response codes, bounded counts, and applied limits. Outcomes are `allowed`, `refused`, `not_authoritative`, `incomplete`, `unreachable`, `timeout`, `cancelled`, or `limit_exceeded`. `allowed` requires a complete authoritative transfer with matching opening and closing SOA. Per endpoint, processing stops at 2 MiB, 4,096 answer records, 64 messages, cancellation, the request timeout, or the caller's absolute deadline. Transferred owner names and records are never retained or scanned; the three `transferred_*` booleans remain `false`. Only `allowed` produces the high-confidence High finding `DNS-AXFR-ALLOWED`.

`dns.dangling_cnames` is additive and defaults to an empty list in older reports. It contains only directly observed ordered primary-chain hops, each with `source_alias`, `canonical_target`, `status`, and bounded evidence, errors, and limitations. Selected A/AAAA lookups classify any address as `resolved`, uniformly authenticated NXDOMAIN as `nxdomain`, uniformly authenticated NOERROR/NODATA with SOA/NSEC/NSEC3 evidence as `no_address`, and all mixed, bogus, indeterminate, timed-out, or failed results as `indeterminate`. Destination answers are never added to resolved hosts or any downstream scan target. Only directly observed `nxdomain` produces the Medium/medium-confidence `DNS-CNAME-DANGLING-INDICATOR`; it reports a potential dangling CNAME and does not assert ownership, claimability, or takeover feasibility.

`dns.wildcard_dns` is additive and optional for older reports. New scans report `detected`, `not_detected`, `indeterminate`, or `not_applicable`, the number of probes attempted, selected answer types, SHA-256 answer fingerprints, bounded diagnostics, and `probe_answers_scanned: false`. Hostname scans use exactly two UUID-v4 child names and query only selected A/AAAA plus CNAME records under the request timeout, cancellation, and caller's absolute deadline. Probe names and raw answers are never retained or used as downstream targets. Only identical non-empty answer sets are `detected`; this produces the high-confidence informational finding `DNS-WILDCARD-DETECTED`, which is contextual routing evidence and not automatically a vulnerability.

`tls` observations add `cipher_suite`, `certificate_chain_length`, `leaf_certificate_sha256`, `public_key_bits`, and `subject_alt_names_truncated`. These fields default to `null`, `null`, `null`, `null`, and `false` when older JSON is read. Successful handshakes populate negotiated fields and validated certificate evidence. When the normal WebPKI verifier rejects a presented certificate, `handshake_succeeded` remains `false`, `certificate_trusted` and `hostname_matches` remain `null`, and the same bounded parsed certificate fields may still be populated; the validation error remains generic and sanitized. `leaf_certificate_sha256` is exactly 64 lowercase hexadecimal characters over the leaf DER; `public_key_bits` is present only when x509-parser reports a nonzero size. Surface records the peer-supplied chain length but inspects at most the first 16 certificates and at most 1,048,576 cumulative DER bytes. It retains at most 128 unique DNS SANs normalized to lowercase without a trailing root dot and canonical textual IPv4/IPv6 SANs. `subject_alt_names_truncated` is true when another unique supported SAN is omitted. Bound limitations appear in the observation's `errors`; certificate DER is dropped after parsing and never serialized, retained, or logged. Existing subject, issuer, serial, validity, public-key OID, and signature OID meanings are unchanged.

No field contains ANSI escape sequences. Target-controlled banners, headers, bodies, errors, and HTML fields are capped or sanitized. Additive fields may appear within schema `0.1.x`; incompatible changes require a schema-version change.

Optional SQLite history stores this complete JSON unchanged alongside normalized query metadata. Retrieval returns the original report schema version; persistence does not reinterpret or update historical content.

`surface diff` accepts compatible `0.1.x` reports. It compares typed network, service, certificate, DNS/mail, finding, score, and completeness data while ignoring execution IDs, timestamps, latency, and transient error text. Reports with incompatible schema or score-model versions produce explicit warnings rather than fabricated comparisons.

SARIF 2.1.0 and CycloneDX 1.6 are integration projections, not replacements for the complete Surface JSON report. Unknown observations and partial status remain represented conservatively.

Certificate Transparency entries are bounded passive CertSpotter candidates. Surface fetches at most three 1 MiB pages, keeps at most 1,000 in-scope names, reports pagination limits, and never scans discovered names automatically. `SURFACE_CERTSPOTTER_API_KEY` is optional.

Related-domain entries are bounded passive infrastructure-correlation candidates. They do not assert common ownership, and Surface does not automatically scan them. Reverse-NS correlation runs automatically when `SURFACE_WHOISXML_API_KEY` is configured and uses one result page per nameserver. `skipped_checks` records stages excluded by `--only` and checks lacking required inputs or credentials. Stable DNS check identifiers are `dnssec_validation`, `authoritative_axfr`, `wildcard_dns`, and `dangling_cname`.

Detached signatures sign exact report bytes and therefore do not change this schema. Reformatting otherwise equivalent JSON invalidates its signature by design.
