# Changelog

## v0.6

- Enabled multiple WireGuard trunks (wg0, wg1, wg2, ...).
- Added root-owned controller registry at /etc/wireguard/vpnhub-instances.json.
- Each trunk has an independent server key, UDP port, VPN pool and server address.
- Portal can provision a new trunk without choosing the privileged interface name or key path.
- Controller automatically allocates the next wgN and generates /etc/wireguard/vpnhub-wgN.key.
- Server PublicKeys are bound to the root registry and validated during sync.
- Dashboard can switch between trunks; new Sites/Admin Peers are created in the selected trunk.
- Global Status screen shows all trunks and identifies each Peer's trunk.
- WireGuard, managed routes and nftables are reconciled across all registered Instances.
- nftables isolates traffic both between Sites and between trunks.
- Cross-trunk overlapping customer LANs remain intentionally blocked until VRF/policy routing is implemented.
- VPN pools must be non-overlapping.
- Hardened the v0.5 migration to support legacy UNIQUE INDEX or UNIQUE CONSTRAINT layouts.
- Added multi-instance controller, registry and portal smoke tests.

## v0.5

- Added internal VPNInstance abstraction; the existing wg0 becomes the default Principal instance.
- Sites and Admin Peers now belong to a VPN Instance.
- IPAM, client configuration and status are instance-aware.
- Address/name uniqueness is scoped to the Instance/Site, preparing future independent wgX trees.
- Controller privilege boundary hardened with SO_PEERCRED and root-owned configuration.
- Application code and venv under /opt/vpnhub are root-owned and non-writable by the portal user.
- Added persistent light/dark theme toggle.

## v0.4

- Operational Status screen with ONLINE / IDLE / OFFLINE / NEVER states.
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
