# Security

## Privilege boundary

The Flask/Gunicorn portal runs as the unprivileged vpnhub user.

The privileged controller runs as root because it manages WireGuard, routes,
nftables and local firewalld integration. It accepts only health, status and
sync actions.

Starting with v0.5:

- /opt/vpnhub and its Python environment are root-owned and not writable by
  the portal user.
- /run/vpnhub is root:vpnhub; only /run/vpnhub/secrets is writable by vpnhub.
- The Unix socket validates peer credentials with Linux SO_PEERCRED.
- Interface, listen port, VPN pool, server address, route protocol and
  private-key path are pinned to root-owned environment configuration.
- Request and response frames are size-limited.

## Secrets

Never commit the real vpnhub.env, WireGuard private keys, PresharedKeys,
generated client configs, or database dumps containing secret material.

Client private keys are not stored in PostgreSQL. Generated configs are kept
temporarily under /run/vpnhub/secrets.

PresharedKeys are stored encrypted using PSK_ENCRYPTION_KEY.
