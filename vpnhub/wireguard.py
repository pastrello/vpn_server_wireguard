import ipaddress
import subprocess

from .models import Site


def _run_wg(args, input_text=None):
    proc = subprocess.run(
        ["wg", *args],
        input=input_text,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def generate_keypair():
    private_key = _run_wg(["genkey"])
    public_key = _run_wg(
        ["pubkey"],
        input_text=private_key + "\n",
    )
    return private_key, public_key


def generate_psk():
    return _run_wg(["genpsk"])


def _server_public_key(instance):
    key = instance.server_public_key.strip()

    if not key or key == "CHANGE_ME" or key.startswith("COLOQUE_"):
        raise RuntimeError(
            "PublicKey da VPN Instance ainda não foi configurada. "
            "Execute scripts/bootstrap-wireguard.sh e "
            "scripts/sync-default-instance.py."
        )

    return key


def _server_tunnel_ip(instance):
    address = ipaddress.ip_interface(instance.server_address)
    return f"{address.ip}/32"


def render_site_peer_config(peer, private_key, preshared_key):
    instance = peer.site.vpn_instance

    if peer.peer_type == "gateway":
        allowed = [instance.vpn_pool]
    else:
        allowed = [peer.site.vpn_cidr]
        allowed.extend(
            network.translated_cidr or network.cidr
            for network in peer.site.networks
        )

    return f"""[Interface]
PrivateKey = {private_key}
Address = {peer.assigned_ip}

[Peer]
PublicKey = {_server_public_key(instance)}
PresharedKey = {preshared_key}
Endpoint = {instance.endpoint}
AllowedIPs = {', '.join(allowed)}
PersistentKeepalive = 25
"""


def render_admin_peer_config(peer, private_key, preshared_key):
    instance = peer.vpn_instance
    allowed = [_server_tunnel_ip(instance)]

    for site in (
        Site.query
        .filter_by(
            enabled=True,
            vpn_instance_id=instance.id,
        )
        .order_by(Site.id)
        .all()
    ):
        allowed.append(site.vpn_cidr)
        allowed.extend(
            network.translated_cidr or network.cidr
            for network in site.networks
        )

    allowed = list(dict.fromkeys(allowed))

    return f"""[Interface]
PrivateKey = {private_key}
Address = {peer.assigned_ip}

[Peer]
PublicKey = {_server_public_key(instance)}
PresharedKey = {preshared_key}
Endpoint = {instance.endpoint}
AllowedIPs = {', '.join(allowed)}
PersistentKeepalive = 25
"""
