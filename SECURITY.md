# Security policy

Please report vulnerabilities privately through GitHub Security Advisories for this repository. Do not open a public issue containing exploit details or sensitive target data.

Include the affected version, impact, reproduction steps using local fixtures where possible, and a proposed mitigation. Maintainers will acknowledge a complete report as soon as practical.

Surface is for authorized assessment only. Reports about unauthorized scanning campaigns belong with the relevant service provider or authorities, not this project's vulnerability channel.

## Hosted deployment

Bind API and metrics to loopback behind a TLS reverse proxy. Protect the database, bootstrap environment, webhook secrets, and signing keys with least privilege and mode `0600`. Do not expose metrics publicly. Rotate/revoke sessions and API tokens after suspected disclosure.

Hosted scans require a tenant authorization attestation and reject non-global explicit or DNS-resolved destinations inside the core engine. Do not weaken this policy to reach internal assets; use the local authorized CLI instead. Stop the server before restore and verify every backup.
