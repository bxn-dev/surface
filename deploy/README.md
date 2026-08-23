# Single-host deployment

1. Install release binaries in `/usr/local/bin` and create an unprivileged `surface` user.
2. Copy `surface-server.service` to `/etc/systemd/system/` and the environment example to `/etc/surface/server.env` (`0600`, root-owned).
3. Bootstrap one admin with `SURFACE_BOOTSTRAP_PASSWORD`; unset it immediately.
4. Put Caddy or another TLS reverse proxy in front of loopback port 8080. Keep metrics port 9090 loopback-only.
5. Enable with `systemctl enable --now surface-server`.

The hosted service is intentionally single-host SQLite. Run one API process; job leases allow bounded worker recovery. Stop the service before restore. Use `surface database backup`, verify the resulting file, and separately back up environment secrets, webhook secrets, and signing keys. Database and private keys must be mode `0600`.

Monitor disk space and periodically checkpoint/backup SQLite. Graceful shutdown stops claims and cancels active scans; expired leases are recovered on restart.
