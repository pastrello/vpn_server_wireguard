# Changelog

## v0.4

- Operational Status screen with ONLINE / IDLE / OFFLINE / NEVER states.
- Dashboard peer-state counters and per-Site status indicators.
- Automatic status refresh every 30 seconds.
- WireGuard/nftables/firewalld/forwarding health indicators.
- Automatic reconcile service after boot.
- One active Gateway per Site, enforced by PostgreSQL partial unique index.
- Controlled Peer and Admin Peer rekey/regeneration.
- Admin Peer configurations now include the VPNHub server tunnel IP.
- Reconcile pre-validates nftables and rolls back WireGuard/routes/nftables on failure.
- firewalld integration is idempotent and reloads only when a permanent change is required.
- Flask-Migrate/Alembic schema management.
- Optional Caddy/HTTPS helper and secure-cookie mode.
- Basic controller/status tests.

## v0.3

- Active privileged controller.
- WireGuard state synchronization.
- nftables Site isolation.
- Managed routes using protocol 186.
- Handshake, endpoint and traffic telemetry.
