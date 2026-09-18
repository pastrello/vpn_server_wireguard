# Changelog

## v0.5

- Added internal VPNInstance abstraction; the existing wg0 becomes the default Principal instance.
- Sites and Admin Peers now belong to a VPN Instance.
- IPAM, client configuration and status are instance-aware.
- Address/name uniqueness is scoped to the Instance/Site, preparing future independent wgX trees.
- Multi-instance execution remains intentionally disabled; v0.5 operates one active Instance and rejects ambiguous states.
- Controller pins interface, port, server address, pool, private-key path and route protocol to root-owned environment configuration.
- Unix socket requests are checked with Linux SO_PEERCRED; only root and the configured portal user are accepted.
- Oversized controller requests no longer terminate the controller process.
- Controller client also limits response frames to 1 MiB.
- /run/vpnhub is now root-owned; only the ephemeral secrets subdirectory is writable by the portal.
- Application code and venv under /opt/vpnhub are root-owned and non-writable by the portal user.
- Ephemeral config tokens are validated and created atomically.
- Installer no longer copies the project over itself when already running from /opt/vpnhub.
- Added persistent light/dark theme toggle, including the login screen.
- Dashboard and Status identify the active VPN Instance.

## v0.4

- Operational Status screen with ONLINE / IDLE / OFFLINE / NEVER states.
- Dashboard peer-state counters and per-Site status indicators.
- Automatic status refresh every 30 seconds.
- WireGuard/nftables/firewalld/forwarding health indicators.
- Automatic reconcile service after boot.
- One active Gateway per Site.
- Controlled Peer and Admin Peer rekey/regeneration.
- Alembic schema management.

## v0.3

- Active privileged controller.
- WireGuard state synchronization.
- nftables Site isolation.
- Managed routes using protocol 186.
- Handshake, endpoint and traffic telemetry.
