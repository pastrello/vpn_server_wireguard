import subprocess
from flask import current_app
from .models import Site


def _run_wg(args, input_text=None):
    proc = subprocess.run(["wg", *args], input=input_text, capture_output=True, text=True, check=True)
    return proc.stdout.strip()


def generate_keypair():
    private_key = _run_wg(["genkey"])
    public_key = _run_wg(["pubkey"], input_text=private_key + "\n")
    return private_key, public_key


def generate_psk():
    return _run_wg(["genpsk"])


def _server_public_key():
    key = current_app.config["VPN_SERVER_PUBLIC_KEY"].strip()
    if not key or key == "CHANGE_ME" or key.startswith("COLOQUE_"):
        raise RuntimeError("VPN_SERVER_PUBLIC_KEY ainda não foi configurada. Execute scripts/bootstrap-wireguard.sh.")
    return key


def render_site_peer_config(peer, private_key, preshared_key):
    if peer.peer_type == "gateway":
        allowed = [current_app.config["VPN_ADDRESS_POOL"]]
    else:
        allowed = [peer.site.vpn_cidr]
        allowed.extend(n.translated_cidr or n.cidr for n in peer.site.networks)
    return f"""[Interface]\nPrivateKey = {private_key}\nAddress = {peer.assigned_ip}\n\n[Peer]\nPublicKey = {_server_public_key()}\nPresharedKey = {preshared_key}\nEndpoint = {current_app.config['VPN_ENDPOINT']}\nAllowedIPs = {', '.join(allowed)}\nPersistentKeepalive = 25\n"""


def render_admin_peer_config(peer, private_key, preshared_key):
    allowed = []
    for site in Site.query.filter_by(enabled=True).order_by(Site.id).all():
        allowed.append(site.vpn_cidr)
        allowed.extend(n.translated_cidr or n.cidr for n in site.networks)
    return f"""[Interface]\nPrivateKey = {private_key}\nAddress = {peer.assigned_ip}\n\n[Peer]\nPublicKey = {_server_public_key()}\nPresharedKey = {preshared_key}\nEndpoint = {current_app.config['VPN_ENDPOINT']}\nAllowedIPs = {', '.join(allowed)}\nPersistentKeepalive = 25\n"""
