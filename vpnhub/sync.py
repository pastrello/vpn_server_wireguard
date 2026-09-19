from datetime import datetime, timezone

from flask import current_app

from .controller_client import ControllerError, controller_request
from .crypto import decrypt_psk
from .instances import all_instances
from .models import AdminPeer, Peer, Site, VPNInstance, db

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
            network.translated_cidr or network.cidr
            for network in peer.site.networks
        )
    return allowed


def _instance_state(instance: VPNInstance) -> dict:
    sites = (
        Site.query
        .filter_by(
            vpn_instance_id=instance.id,
            enabled=True,
        )
        .order_by(Site.id)
        .all()
    )
    site_ids = [site.id for site in sites]

    site_peers = (
        Peer.query
        .filter(
            Peer.enabled.is_(True),
            Peer.site_id.in_(site_ids),
        )
        .order_by(Peer.id)
        .all()
        if site_ids else []
    )
    admin_peers = (
        AdminPeer.query
        .filter_by(
            vpn_instance_id=instance.id,
            enabled=True,
        )
        .order_by(AdminPeer.id)
        .all()
    )

    peers = []
    site_defs = []
    routes = []

    if instance.enabled:
        for peer in site_peers:
            peers.append({
                "kind": "site",
                "site_id": peer.site_id,
                "name": peer.name,
                "public_key": peer.public_key,
                "preshared_key": decrypt_psk(
                    peer.preshared_key_enc
                ),
                "allowed_ips": _peer_allowed_ips(peer),
            })

        for peer in admin_peers:
            peers.append({
                "kind": "admin",
                "site_id": None,
                "name": peer.name,
                "public_key": peer.public_key,
                "preshared_key": decrypt_psk(
                    peer.preshared_key_enc
                ),
                "allowed_ips": [peer.assigned_ip],
            })

        for site in sites:
            ranges = [site.vpn_cidr]
            for network in site.networks:
                target = (
                    network.translated_cidr
                    or network.cidr
                )
                ranges.append(target)
                routes.append(target)
            site_defs.append({
                "id": site.id,
                "name": site.name,
                "ranges": ranges,
            })

    return {
        "id": instance.id,
        "name": instance.name,
        "enabled": instance.enabled,
        "interface": instance.interface_name,
        "listen_port": instance.listen_port,
        "server_address": instance.server_address,
        "private_key_path": instance.private_key_path,
        "server_public_key": instance.server_public_key,
        "route_protocol": instance.route_protocol,
        "vpn_pool": instance.vpn_pool,
        "peers": peers,
        "sites": site_defs,
        "admin_addresses": (
            [peer.assigned_ip for peer in admin_peers]
            if instance.enabled else []
        ),
        "routes": sorted(set(routes)),
    }


def desired_state() -> dict:
    return {
        "instances": [
            _instance_state(instance)
            for instance in all_instances()
        ]
    }


def reconcile() -> dict:
    return controller_request("sync", desired_state())


def controller_status() -> dict:
    try:
        return controller_request("status")
    except ControllerError as exc:
        return {
            "ok": False,
            "dry_run": None,
            "error": str(exc),
            "instances": {},
        }


def controller_health() -> dict:
    try:
        return controller_request("health")
    except ControllerError as exc:
        return {
            "ok": False,
            "dry_run": None,
            "error": str(exc),
            "instances": {},
            "nft_table": False,
            "firewalld": None,
            "ip_forward": None,
            "route_count": 0,
        }


def refresh_status() -> dict:
    response = controller_status()
    if not response.get("ok"):
        return response

    by_key = {}
    for runtime in response.get("instances", {}).values():
        for public_key, state in (
            runtime.get("peers") or {}
        ).items():
            by_key[public_key] = state

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
                if epoch else None
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
        int(
            (
                datetime.utcnow()
                - peer.latest_handshake
            ).total_seconds()
        ),
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
        int(
            (
                datetime.utcnow()
                - peer.latest_handshake
            ).total_seconds()
        ),
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


def _instance_peers(instance: VPNInstance):
    sites = Site.query.filter_by(
        vpn_instance_id=instance.id
    ).all()
    site_ids = [site.id for site in sites]
    peers = (
        Peer.query.filter(
            Peer.site_id.in_(site_ids)
        ).all()
        if site_ids else []
    )
    admins = AdminPeer.query.filter_by(
        vpn_instance_id=instance.id
    ).all()
    return sites, peers, admins


def status_snapshot(
    instance: VPNInstance | None = None,
) -> dict:
    runtime = refresh_status()
    health = controller_health()
    instances = (
        [instance]
        if instance is not None
        else all_instances()
    )

    rows = []
    site_counts = {}

    for item in instances:
        sites, peers, admins = _instance_peers(item)

        for site in sites:
            site_counts[str(site.id)] = (
                site_status_counts(site)
            )

        for peer in peers:
            state = peer_state(peer)
            rows.append({
                "key": peer.public_key,
                "id": peer.id,
                "name": peer.name,
                "kind": peer.peer_type,
                "site": peer.site.name,
                "site_id": peer.site_id,
                "instance_id": item.id,
                "instance_name": item.name,
                "interface": item.interface_name,
                "assigned_ip": peer.assigned_ip,
                "state": state,
                "state_label": peer_state_label(state),
                "endpoint": peer.endpoint or "—",
                "handshake": handshake_age(peer),
                "rx": format_bytes(peer.rx_bytes),
                "tx": format_bytes(peer.tx_bytes),
            })

        for peer in admins:
            state = peer_state(peer)
            rows.append({
                "key": peer.public_key,
                "id": peer.id,
                "name": peer.name,
                "kind": "admin",
                "site": "—",
                "site_id": None,
                "instance_id": item.id,
                "instance_name": item.name,
                "interface": item.interface_name,
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
            row["instance_name"].lower(),
            row["site"],
            row["name"].lower(),
        )
    )

    counts = {
        state: sum(
            1 for row in rows
            if row["state"] == state
        )
        for state in (
            "online",
            "idle",
            "offline",
            "never",
        )
    }
    counts["total"] = len(rows)

    runtime_map = runtime.get("instances", {})
    instance_rows = []

    for item in all_instances():
        runtime_item = runtime_map.get(
            item.interface_name,
            {},
        )
        sites, peers, admins = _instance_peers(item)
        instance_rows.append({
            "id": item.id,
            "name": item.name,
            "interface_name": item.interface_name,
            "endpoint": item.endpoint,
            "listen_port": item.listen_port,
            "vpn_pool": item.vpn_pool,
            "server_address": item.server_address,
            "enabled": item.enabled,
            "is_default": item.is_default,
            "interface_up": bool(
                runtime_item.get("interface_up")
            ),
            "peer_count": len(peers) + len(admins),
            "site_count": len(sites),
            "runtime_peer_count": int(
                runtime_item.get("peer_count") or 0
            ),
        })

    selected_health = None
    if instance is not None:
        selected_health = dict(
            runtime_map.get(
                instance.interface_name,
                {
                    "interface": instance.interface_name,
                    "interface_up": False,
                    "listen_port": None,
                    "public_key": None,
                    "peer_count": 0,
                    "peers": {},
                },
            )
        )
        selected_health["dry_run"] = health.get("dry_run")

    return {
        "instance": (
            {
                "id": instance.id,
                "name": instance.name,
                "interface_name": instance.interface_name,
                "endpoint": instance.endpoint,
                "listen_port": instance.listen_port,
                "vpn_pool": instance.vpn_pool,
                "server_address": instance.server_address,
                "enabled": instance.enabled,
            }
            if instance is not None
            else None
        ),
        "instances": instance_rows,
        "instance_health": selected_health,
        "health": health,
        "counts": counts,
        "sites": site_counts,
        "peers": rows,
    }
