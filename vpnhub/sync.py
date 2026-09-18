from datetime import datetime, timezone

from flask import current_app

from .controller_client import ControllerError, controller_request
from .crypto import decrypt_psk
from .models import AdminPeer, Peer, Site, db

STATE_ORDER = {
    "offline": 0,
    "never": 1,
    "idle": 2,
    "online": 3,
}

STATE_LABELS = {
    "online": "ONLINE",
    "idle": "IDLE",
    "offline": "OFFLINE",
    "never": "NEVER",
}


def _peer_allowed_ips(peer: Peer) -> list[str]:
    allowed = [peer.assigned_ip]
    if peer.peer_type == "gateway":
        allowed.extend(
            net.translated_cidr or net.cidr
            for net in peer.site.networks
        )
    return allowed


def desired_state() -> dict:
    sites = (
        Site.query
        .filter_by(enabled=True)
        .order_by(Site.id)
        .all()
    )

    peers = []

    for peer in (
        Peer.query
        .filter_by(enabled=True)
        .order_by(Peer.id)
        .all()
    ):
        peers.append({
            "kind": "site",
            "site_id": peer.site_id,
            "name": peer.name,
            "public_key": peer.public_key,
            "preshared_key": decrypt_psk(peer.preshared_key_enc),
            "allowed_ips": _peer_allowed_ips(peer),
        })

    for peer in (
        AdminPeer.query
        .filter_by(enabled=True)
        .order_by(AdminPeer.id)
        .all()
    ):
        peers.append({
            "kind": "admin",
            "site_id": None,
            "name": peer.name,
            "public_key": peer.public_key,
            "preshared_key": decrypt_psk(peer.preshared_key_enc),
            "allowed_ips": [peer.assigned_ip],
        })

    site_defs = []
    routes = []

    for site in sites:
        ranges = [site.vpn_cidr]

        for net in site.networks:
            target = net.translated_cidr or net.cidr
            ranges.append(target)
            routes.append(target)

        site_defs.append({
            "id": site.id,
            "name": site.name,
            "ranges": ranges,
        })

    return {
        "interface": current_app.config["WG_INTERFACE"],
        "listen_port": current_app.config["WG_LISTEN_PORT"],
        "server_address": current_app.config["WG_SERVER_ADDRESS"],
        "private_key_path": current_app.config[
            "WG_SERVER_PRIVATE_KEY_PATH"
        ],
        "route_protocol": current_app.config["WG_ROUTE_PROTOCOL"],
        "vpn_pool": current_app.config["VPN_ADDRESS_POOL"],
        "peers": peers,
        "sites": site_defs,
        "admin_addresses": [
            p.assigned_ip
            for p in AdminPeer.query.filter_by(enabled=True).all()
        ],
        "routes": sorted(set(routes)),
    }


def reconcile() -> dict:
    return controller_request("sync", desired_state())


def controller_health() -> dict:
    try:
        return controller_request("health")
    except ControllerError as exc:
        return {
            "ok": False,
            "interface_up": False,
            "dry_run": None,
            "error": str(exc),
            "nft_table": False,
            "firewalld": None,
            "ip_forward": None,
            "route_count": 0,
            "peer_count": 0,
        }


def refresh_status() -> dict:
    try:
        response = controller_request("status")
    except ControllerError as exc:
        return {
            "ok": False,
            "interface_up": False,
            "dry_run": None,
            "error": str(exc),
            "peers": {},
        }

    by_key = response.get("peers", {})
    changed = False

    for model in (Peer, AdminPeer):
        for peer in model.query.all():
            state = by_key.get(peer.public_key)
            if not state:
                continue

            epoch = int(state.get("latest_handshake") or 0)
            peer.latest_handshake = (
                datetime.fromtimestamp(
                    epoch,
                    tz=timezone.utc,
                ).replace(tzinfo=None)
                if epoch
                else None
            )
            peer.endpoint = state.get("endpoint") or None
            peer.rx_bytes = int(state.get("rx_bytes") or 0)
            peer.tx_bytes = int(state.get("tx_bytes") or 0)
            changed = True

    if changed:
        db.session.commit()

    return response


def peer_state(peer) -> str:
    if not peer.latest_handshake:
        return "never"

    seconds = max(
        0,
        int((datetime.utcnow() - peer.latest_handshake).total_seconds()),
    )

    if seconds <= current_app.config["WG_ONLINE_SECONDS"]:
        return "online"

    if seconds <= current_app.config["WG_IDLE_SECONDS"]:
        return "idle"

    return "offline"


def peer_state_label(peer_or_state) -> str:
    state = (
        peer_or_state
        if isinstance(peer_or_state, str)
        else peer_state(peer_or_state)
    )
    return STATE_LABELS.get(state, state.upper())


def format_bytes(value: int | None) -> str:
    size = float(value or 0)

    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024

    return f"{size:.1f} TB"


def handshake_age(peer) -> str:
    if not peer.latest_handshake:
        return "Nunca"

    seconds = max(
        0,
        int((datetime.utcnow() - peer.latest_handshake).total_seconds()),
    )

    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}min"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def status_counts(peers) -> dict:
    counts = {
        "online": 0,
        "idle": 0,
        "offline": 0,
        "never": 0,
    }

    for peer in peers:
        counts[peer_state(peer)] += 1

    counts["total"] = sum(counts.values())
    return counts


def site_status_counts(site) -> dict:
    return status_counts(site.peers)


def status_snapshot() -> dict:
    refresh_status()
    health = controller_health()

    rows = []

    for peer in Peer.query.all():
        state = peer_state(peer)
        rows.append({
            "key": peer.public_key,
            "id": peer.id,
            "name": peer.name,
            "kind": peer.peer_type,
            "site": peer.site.name,
            "site_id": peer.site_id,
            "assigned_ip": peer.assigned_ip,
            "state": state,
            "state_label": peer_state_label(state),
            "endpoint": peer.endpoint or "—",
            "handshake": handshake_age(peer),
            "rx": format_bytes(peer.rx_bytes),
            "tx": format_bytes(peer.tx_bytes),
        })

    for peer in AdminPeer.query.all():
        state = peer_state(peer)
        rows.append({
            "key": peer.public_key,
            "id": peer.id,
            "name": peer.name,
            "kind": "admin",
            "site": "—",
            "site_id": None,
            "assigned_ip": peer.assigned_ip,
            "state": state,
            "state_label": peer_state_label(state),
            "endpoint": peer.endpoint or "—",
            "handshake": handshake_age(peer),
            "rx": format_bytes(peer.rx_bytes),
            "tx": format_bytes(peer.tx_bytes),
        })

    rows.sort(
        key=lambda row: (
            STATE_ORDER[row["state"]],
            row["site"],
            row["name"].lower(),
        )
    )

    counts = {
        "online": sum(1 for row in rows if row["state"] == "online"),
        "idle": sum(1 for row in rows if row["state"] == "idle"),
        "offline": sum(1 for row in rows if row["state"] == "offline"),
        "never": sum(1 for row in rows if row["state"] == "never"),
        "total": len(rows),
    }

    sites = {}
    for site in Site.query.order_by(Site.id).all():
        sites[str(site.id)] = site_status_counts(site)

    return {
        "health": health,
        "counts": counts,
        "sites": sites,
        "peers": rows,
    }
