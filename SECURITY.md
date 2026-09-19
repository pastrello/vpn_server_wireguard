# Security

## Privilege boundary

The Flask/Gunicorn portal runs as the unprivileged vpnhub user.

The privileged controller runs as root because it manages WireGuard, routes,
nftables, the root-owned trunk registry and local firewalld integration.

Allowed controller actions are intentionally closed:

- health
- status
- sync
- provision_instance
- unprovision_instance

The last two actions operate only within the VPNHub WireGuard namespace and
the validated root-owned registry.

## Root-owned trunk registry

Multi-trunk authorization is stored in:

~~~text
/etc/wireguard/vpnhub-instances.json
~~~

The registry must be root:root mode 0600.

A portal sync cannot introduce arbitrary interfaces or key paths. Each
Instance supplied by the portal must match a registered record for:

- interface;
- UDP listen port;
- VPN pool;
- server address;
- PrivateKey path;
- PublicKey;
- route protocol.

Provisioning chooses the next wgN inside the controller. Private keys are
restricted to VPNHub-owned filenames directly under /etc/wireguard.

## Process/file protections

- /opt/vpnhub and its Python environment are root-owned and not writable by
  the portal user.
- /run/vpnhub is root:vpnhub.
- Only /run/vpnhub/secrets is writable by vpnhub.
- The Unix socket validates peer credentials with Linux SO_PEERCRED.
- Request and response frames are size-limited.

## Secrets

Never commit:

- the real /etc/vpnhub/vpnhub.env;
- /etc/wireguard/*.key;
- WireGuard private keys or PresharedKeys;
- generated client configs;
- database dumps containing secret material.

Client private keys are not stored in PostgreSQL. Generated client configs are
kept temporarily under /run/vpnhub/secrets.

PresharedKeys are stored encrypted using PSK_ENCRYPTION_KEY.
