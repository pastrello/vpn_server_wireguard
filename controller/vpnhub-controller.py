#!/usr/bin/env python3
from __future__ import annotations

import base64
import ipaddress
import json
import os
import pwd
import shutil
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

SOCKET_PATH = os.getenv(
    "CONTROLLER_SOCKET",
    "/run/vpnhub/controller.sock",
)
DRY_RUN = os.getenv("WG_DRY_RUN", "true").lower() == "true"
DEFAULT_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
DEFAULT_LISTEN_PORT = int(os.getenv("WG_LISTEN_PORT", "51820"))
DEFAULT_SERVER_ADDRESS = os.getenv("WG_SERVER_ADDRESS", "10.250.0.1/16")
DEFAULT_VPN_POOL = os.getenv("VPN_ADDRESS_POOL", "10.250.0.0/16")
DEFAULT_PRIVATE_KEY = os.getenv(
    "WG_SERVER_PRIVATE_KEY_PATH",
    "/etc/wireguard/vpnhub-server.key",
)
DEFAULT_ROUTE_PROTOCOL = int(os.getenv("WG_ROUTE_PROTOCOL", "186"))
CONTROLLER_ALLOWED_USER = os.getenv("CONTROLLER_ALLOWED_USER", "vpnhub")
MAX_PAYLOAD_BYTES = 1024 * 1024


class ControllerFailure(RuntimeError):
    pass


def run(cmd, *, input_text=None, check=True):
    proc = subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )

    if check and proc.returncode != 0:
        raise ControllerFailure(
            f"{' '.join(cmd)}: "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )

    return proc


def interface_exists(interface: str) -> bool:
    return (
        run(
            ["ip", "link", "show", "dev", interface],
            check=False,
        ).returncode
        == 0
    )


def _validate_wg_key(value: str, label: str):
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ControllerFailure(f"{label} não é base64 válido.") from exc

    if len(decoded) != 32:
        raise ControllerFailure(f"{label} deve representar 32 bytes.")


def _require_runtime_value(label, supplied, expected):
    if supplied != expected:
        raise ControllerFailure(
            f"{label} não pertence à configuração autorizada do controller."
        )


def validate_state(payload: dict) -> dict:
    interface = str(payload.get("interface") or "")
    listen_port = int(payload.get("listen_port") or 0)
    server_address = str(payload.get("server_address") or "")
    vpn_pool_value = str(payload.get("vpn_pool") or "")
    private_key_path = str(payload.get("private_key_path") or "")
    route_protocol = int(payload.get("route_protocol") or 0)

    _require_runtime_value(
        "Interface WireGuard",
        interface,
        DEFAULT_INTERFACE,
    )
    _require_runtime_value(
        "Porta WireGuard",
        listen_port,
        DEFAULT_LISTEN_PORT,
    )
    _require_runtime_value(
        "Endereço do servidor",
        server_address,
        DEFAULT_SERVER_ADDRESS,
    )
    _require_runtime_value(
        "VPN pool",
        vpn_pool_value,
        DEFAULT_VPN_POOL,
    )
    _require_runtime_value(
        "Caminho da PrivateKey",
        private_key_path,
        DEFAULT_PRIVATE_KEY,
    )
    _require_runtime_value(
        "Routing protocol",
        route_protocol,
        DEFAULT_ROUTE_PROTOCOL,
    )

    server_iface = ipaddress.ip_interface(server_address)
    vpn_pool = ipaddress.ip_network(
        vpn_pool_value,
        strict=False,
    )

    if server_iface.version != 4 or server_iface.ip not in vpn_pool:
        raise ControllerFailure(
            "WG_SERVER_ADDRESS/VPN_ADDRESS_POOL inválidos."
        )

    peers = []
    public_keys = set()
    network_owners = []

    for raw in payload.get("peers") or []:
        public_key = str(raw.get("public_key") or "").strip()
        _validate_wg_key(public_key, "PublicKey")

        if public_key in public_keys:
            raise ControllerFailure("PublicKey duplicada.")

        public_keys.add(public_key)

        psk = str(raw.get("preshared_key") or "").strip() or None
        if psk:
            _validate_wg_key(psk, "PresharedKey")

        allowed_ips = []
        for item in raw.get("allowed_ips") or []:
            network = ipaddress.ip_network(str(item), strict=False)
            if network.version != 4:
                raise ControllerFailure("IPv6 ainda não é suportado.")
            allowed_ips.append(str(network))

            for previous, previous_key in network_owners:
                if network == previous and public_key != previous_key:
                    raise ControllerFailure(
                        f"AllowedIP {network} está atribuída a mais de um Peer."
                    )

            network_owners.append((network, public_key))

        peers.append({
            "kind": str(raw.get("kind") or "site"),
            "site_id": raw.get("site_id"),
            "name": str(raw.get("name") or ""),
            "public_key": public_key,
            "preshared_key": psk,
            "allowed_ips": allowed_ips,
        })

    sites = []
    for raw in payload.get("sites") or []:
        ranges = []

        for item in raw.get("ranges") or []:
            network = ipaddress.ip_network(str(item), strict=False)
            if network.version != 4:
                raise ControllerFailure("IPv6 ainda não é suportado.")
            ranges.append(str(network))

        sites.append({
            "id": int(raw["id"]),
            "name": str(raw.get("name") or ""),
            "ranges": ranges,
        })

    def normalize_networks(values):
        output = []
        for item in values or []:
            network = ipaddress.ip_network(str(item), strict=False)
            if network.version != 4:
                raise ControllerFailure("IPv6 ainda não é suportado.")
            output.append(str(network))
        return output

    return {
        "interface": interface,
        "listen_port": listen_port,
        "server_address": str(server_iface),
        "vpn_pool": str(vpn_pool),
        "private_key_path": DEFAULT_PRIVATE_KEY,
        "route_protocol": route_protocol,
        "peers": peers,
        "sites": sites,
        "admin_addresses": normalize_networks(
            payload.get("admin_addresses")
        ),
        "routes": sorted(
            set(normalize_networks(payload.get("routes")))
        ),
    }


def check_route_conflicts(state: dict):
    routes = json.loads(
        run(["ip", "-j", "route", "show"]).stdout or "[]"
    )
    protected = []

    for row in routes:
        dst = row.get("dst")
        dev = row.get("dev")
        protocol = str(row.get("protocol") or row.get("proto") or "")

        if not dst or dst == "default":
            continue

        if (
            dev == state["interface"]
            and protocol == str(state["route_protocol"])
        ):
            continue

        try:
            protected.append(
                (ipaddress.ip_network(dst, strict=False), dev or "?")
            )
        except ValueError:
            continue

    conflicts = []

    for desired in state["routes"]:
        wanted = ipaddress.ip_network(desired)

        for existing, dev in protected:
            if wanted.overlaps(existing):
                conflicts.append(
                    f"{wanted} conflita com rota local "
                    f"{existing} em {dev}"
                )

    if conflicts:
        raise ControllerFailure(
            "Conflito de rota detectado: " + "; ".join(conflicts)
        )


def ensure_kernel_state(state: dict):
    interface = state["interface"]

    if not interface_exists(interface):
        run([
            "ip",
            "link",
            "add",
            "dev",
            interface,
            "type",
            "wireguard",
        ])

    run([
        "ip",
        "address",
        "replace",
        state["server_address"],
        "dev",
        interface,
    ])
    run(["ip", "link", "set", "up", "dev", interface])
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])


def render_wg_config(state: dict) -> str:
    key_path = Path(state["private_key_path"])

    if not key_path.exists():
        raise ControllerFailure(
            f"Chave privada do servidor não existe em {key_path}. "
            "Execute scripts/bootstrap-wireguard.sh."
        )

    private_key = key_path.read_text(encoding="utf-8").strip()
    _validate_wg_key(private_key, "PrivateKey do servidor")

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"ListenPort = {state['listen_port']}",
        "",
    ]

    for peer in state["peers"]:
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['public_key']}")

        if peer["preshared_key"]:
            lines.append(
                f"PresharedKey = {peer['preshared_key']}"
            )

        if peer["allowed_ips"]:
            lines.append(
                "AllowedIPs = " + ", ".join(peer["allowed_ips"])
            )

        lines.append("")

    return "\n".join(lines)


def nft_set(name: str, values: list[str]) -> str:
    lines = [
        f"    set {name} {{",
        "        type ipv4_addr",
        "        flags interval",
    ]

    if values:
        lines.append(
            "        elements = { " + ", ".join(values) + " }"
        )

    lines.append("    }")
    return "\n".join(lines)


def render_nftables(state: dict, table_exists: bool) -> str:
    interface = state["interface"]
    all_sites = sorted(
        set(
            item
            for site in state["sites"]
            for item in site["ranges"]
        )
    )

    body = []

    if table_exists:
        body.extend([
            "delete table inet vpnhub",
            "",
        ])

    body.extend([
        "table inet vpnhub {",
        nft_set("admin_peers", state["admin_addresses"]),
        "",
        nft_set("all_sites", all_sites),
        "",
    ])

    for site in state["sites"]:
        body.extend([
            nft_set(
                f"site_{site['id']}",
                sorted(set(site["ranges"])),
            ),
            "",
        ])

    body.extend([
        "    chain input_guard {",
        "        type filter hook input priority -20; policy accept;",
        f'        iifname "{interface}" ip saddr @admin_peers accept',
        f'        iifname "{interface}" drop',
        "    }",
        "",
        "    chain forward_guard {",
        "        type filter hook forward priority -20; policy accept;",
        (
            f'        iifname "{interface}" oifname "{interface}" '
            "ip saddr @admin_peers ip daddr @all_sites accept"
        ),
        (
            f'        iifname "{interface}" oifname "{interface}" '
            "ip saddr @all_sites ip daddr @admin_peers "
            "ct state established,related accept"
        ),
    ])

    for site in state["sites"]:
        set_name = f"site_{site['id']}"
        body.append(
            f'        iifname "{interface}" oifname "{interface}" '
            f"ip saddr @{set_name} ip daddr @{set_name} accept"
        )

    body.extend([
        f'        iifname "{interface}" drop',
        f'        oifname "{interface}" drop',
        "    }",
        "}",
        "",
    ])

    return "\n".join(body)


def _write_temp(content: str, prefix: str, suffix: str) -> str:
    fd, tmp_name = tempfile.mkstemp(
        prefix=prefix,
        suffix=suffix,
        dir="/run",
        text=True,
    )
    os.fchmod(fd, 0o600)

    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)

    return tmp_name


def prepare_files(state: dict) -> tuple[str, str]:
    wg_content = render_wg_config(state)
    table_exists = (
        run(
            ["nft", "list", "table", "inet", "vpnhub"],
            check=False,
        ).returncode
        == 0
    )
    nft_content = render_nftables(state, table_exists)

    wg_tmp = _write_temp(
        wg_content,
        "vpnhub-wg-",
        ".conf",
    )
    nft_tmp = _write_temp(
        nft_content,
        "vpnhub-nft-",
        ".nft",
    )

    try:
        run(["nft", "-c", "-f", nft_tmp])
    except Exception:
        os.unlink(wg_tmp)
        os.unlink(nft_tmp)
        raise

    return wg_tmp, nft_tmp


def capture_runtime_state(state: dict) -> dict:
    interface = state["interface"]
    existed = interface_exists(interface)

    snapshot = {
        "interface_existed": existed,
        "wg_config": None,
        "addresses": [],
        "routes": [],
        "nft_table": None,
    }

    if existed:
        proc = run(
            ["wg", "showconf", interface],
            check=False,
        )
        if proc.returncode == 0:
            snapshot["wg_config"] = proc.stdout

        addr_proc = run([
            "ip",
            "-j",
            "address",
            "show",
            "dev",
            interface,
        ])
        for row in json.loads(addr_proc.stdout or "[]"):
            for info in row.get("addr_info", []):
                if info.get("family") == "inet":
                    snapshot["addresses"].append(
                        f"{info['local']}/{info['prefixlen']}"
                    )

    route_proc = run([
        "ip",
        "-j",
        "route",
        "show",
        "proto",
        str(state["route_protocol"]),
        "dev",
        interface,
    ], check=False)
    if route_proc.returncode == 0:
        snapshot["routes"] = json.loads(route_proc.stdout or "[]")

    nft_proc = run(
        ["nft", "list", "table", "inet", "vpnhub"],
        check=False,
    )
    if nft_proc.returncode == 0:
        snapshot["nft_table"] = nft_proc.stdout

    return snapshot


def apply_wireguard(state: dict, wg_tmp: str):
    run([
        "wg",
        "syncconf",
        state["interface"],
        wg_tmp,
    ])


def apply_routes(state: dict):
    interface = state["interface"]
    protocol = str(state["route_protocol"])

    run([
        "ip",
        "route",
        "flush",
        "proto",
        protocol,
        "dev",
        interface,
    ], check=False)

    for network in state["routes"]:
        run([
            "ip",
            "route",
            "replace",
            network,
            "dev",
            interface,
            "proto",
            protocol,
        ])


def apply_nftables(nft_tmp: str):
    run(["nft", "-f", nft_tmp])


def restore_runtime_state(state: dict, snapshot: dict):
    interface = state["interface"]
    protocol = str(state["route_protocol"])

    run(
        ["nft", "delete", "table", "inet", "vpnhub"],
        check=False,
    )

    if snapshot.get("nft_table"):
        nft_tmp = _write_temp(
            snapshot["nft_table"],
            "vpnhub-nft-rollback-",
            ".nft",
        )
        try:
            run(["nft", "-f", nft_tmp], check=False)
        finally:
            try:
                os.unlink(nft_tmp)
            except FileNotFoundError:
                pass

    if not snapshot.get("interface_existed"):
        if interface_exists(interface):
            run(["ip", "link", "delete", "dev", interface], check=False)
        return

    if not interface_exists(interface):
        run([
            "ip",
            "link",
            "add",
            "dev",
            interface,
            "type",
            "wireguard",
        ], check=False)

    run(["ip", "address", "flush", "dev", interface], check=False)
    for address in snapshot.get("addresses") or []:
        run([
            "ip",
            "address",
            "add",
            address,
            "dev",
            interface,
        ], check=False)

    if snapshot.get("wg_config"):
        wg_tmp = _write_temp(
            snapshot["wg_config"],
            "vpnhub-wg-rollback-",
            ".conf",
        )
        try:
            run(["wg", "syncconf", interface, wg_tmp], check=False)
        finally:
            try:
                os.unlink(wg_tmp)
            except FileNotFoundError:
                pass

    run(["ip", "link", "set", "up", "dev", interface], check=False)

    run([
        "ip",
        "route",
        "flush",
        "proto",
        protocol,
        "dev",
        interface,
    ], check=False)

    for route in snapshot.get("routes") or []:
        dst = route.get("dst")
        if not dst:
            continue
        run([
            "ip",
            "route",
            "replace",
            dst,
            "dev",
            interface,
            "proto",
            protocol,
        ], check=False)


def configure_firewalld(state: dict) -> list[str]:
    warnings = []

    if not shutil.which("firewall-cmd"):
        return warnings

    if (
        run(
            ["systemctl", "is-active", "--quiet", "firewalld"],
            check=False,
        ).returncode
        != 0
    ):
        return warnings

    default_zone = (
        run(["firewall-cmd", "--get-default-zone"]).stdout.strip()
        or "public"
    )

    changed = False

    port_query = run([
        "firewall-cmd",
        "--permanent",
        f"--zone={default_zone}",
        f"--query-port={state['listen_port']}/udp",
    ], check=False)

    if port_query.returncode != 0:
        proc = run([
            "firewall-cmd",
            "--permanent",
            f"--zone={default_zone}",
            f"--add-port={state['listen_port']}/udp",
        ], check=False)
        if proc.returncode == 0:
            changed = True
        else:
            warnings.append(
                "firewalld: não foi possível liberar a porta WireGuard."
            )

    interface_query = run([
        "firewall-cmd",
        "--permanent",
        "--zone=trusted",
        f"--query-interface={state['interface']}",
    ], check=False)

    if interface_query.returncode != 0:
        proc = run([
            "firewall-cmd",
            "--permanent",
            "--zone=trusted",
            f"--add-interface={state['interface']}",
        ], check=False)
        if proc.returncode == 0:
            changed = True
        else:
            warnings.append(
                "firewalld: não foi possível associar wg0 à zona trusted."
            )

    if changed:
        proc = run(["firewall-cmd", "--reload"], check=False)
        if proc.returncode != 0:
            warnings.append(
                "firewalld: configuração permanente foi alterada, "
                "mas o reload falhou."
            )

    return warnings


def perform_sync(payload: dict) -> dict:
    state = validate_state(payload)
    check_route_conflicts(state)

    wg_tmp, nft_tmp = prepare_files(state)

    try:
        if DRY_RUN:
            return {
                "ok": True,
                "dry_run": True,
                "message": (
                    "Estado, WireGuard e nftables validados; "
                    "nenhuma alteração aplicada."
                ),
                "peer_count": len(state["peers"]),
                "route_count": len(state["routes"]),
                "site_count": len(state["sites"]),
                "warnings": [],
            }

        snapshot = capture_runtime_state(state)

        try:
            ensure_kernel_state(state)
            apply_wireguard(state, wg_tmp)
            apply_routes(state)
            apply_nftables(nft_tmp)
        except Exception as exc:
            restore_runtime_state(state, snapshot)
            raise ControllerFailure(
                f"Sincronização falhou e o estado anterior foi restaurado: {exc}"
            ) from exc

        warnings = configure_firewalld(state)

        return {
            "ok": True,
            "dry_run": False,
            "message": (
                "WireGuard, rotas e isolamento sincronizados."
            ),
            "peer_count": len(state["peers"]),
            "route_count": len(state["routes"]),
            "site_count": len(state["sites"]),
            "warnings": warnings,
        }
    finally:
        for path in (wg_tmp, nft_tmp):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def wireguard_status() -> dict:
    interface = DEFAULT_INTERFACE

    if not interface_exists(interface):
        return {
            "ok": True,
            "dry_run": DRY_RUN,
            "interface": interface,
            "interface_up": False,
            "listen_port": None,
            "public_key": None,
            "peer_count": 0,
            "peers": {},
        }

    lines = [
        line.split("\t")
        for line in run([
            "wg",
            "show",
            interface,
            "dump",
        ]).stdout.splitlines()
        if line.strip()
    ]

    listen_port = None
    public_key = None

    if lines and len(lines[0]) >= 4:
        public_key = lines[0][1]
        listen_port = int(lines[0][2] or 0) or None

    peers = {}

    for fields in lines[1:]:
        if len(fields) < 8:
            continue

        public_peer_key = fields[0]
        peers[public_peer_key] = {
            "endpoint": (
                None
                if fields[2] in ("(none)", "")
                else fields[2]
            ),
            "allowed_ips": fields[3],
            "latest_handshake": int(fields[4] or 0),
            "rx_bytes": int(fields[5] or 0),
            "tx_bytes": int(fields[6] or 0),
            "persistent_keepalive": fields[7],
        }

    return {
        "ok": True,
        "dry_run": DRY_RUN,
        "interface": interface,
        "interface_up": True,
        "listen_port": listen_port,
        "public_key": public_key,
        "peer_count": len(peers),
        "peers": peers,
    }


def health() -> dict:
    status = wireguard_status()

    status["private_key_exists"] = Path(
        DEFAULT_PRIVATE_KEY
    ).exists()
    status["nft_table"] = (
        run(
            ["nft", "list", "table", "inet", "vpnhub"],
            check=False,
        ).returncode
        == 0
    )
    status["firewalld"] = (
        shutil.which("firewall-cmd") is not None
        and run(
            ["systemctl", "is-active", "--quiet", "firewalld"],
            check=False,
        ).returncode
        == 0
    )

    ip_forward = run([
        "sysctl",
        "-n",
        "net.ipv4.ip_forward",
    ], check=False)
    status["ip_forward"] = (
        ip_forward.returncode == 0
        and ip_forward.stdout.strip() == "1"
    )

    route_proc = run([
        "ip",
        "-j",
        "route",
        "show",
        "proto",
        str(DEFAULT_ROUTE_PROTOCOL),
        "dev",
        DEFAULT_INTERFACE,
    ], check=False)

    try:
        status["route_count"] = len(
            json.loads(route_proc.stdout or "[]")
        )
    except json.JSONDecodeError:
        status["route_count"] = 0

    return status


def handle(req: dict) -> dict:
    action = req.get("action")
    payload = req.get("payload") or {}

    if action == "health":
        return health()

    if action == "status":
        return wireguard_status()

    if action == "sync":
        return perform_sync(payload)

    return {
        "ok": False,
        "error": f"Ação não permitida: {action}",
    }


def _authorized_uids():
    allowed = {0}

    try:
        allowed.add(pwd.getpwnam(CONTROLLER_ALLOWED_USER).pw_uid)
    except KeyError as exc:
        raise ControllerFailure(
            f"Usuário autorizado do controller não existe: "
            f"{CONTROLLER_ALLOWED_USER}"
        ) from exc

    return allowed


def _peer_uid(conn: socket.socket) -> int:
    size = struct.calcsize("3i")
    credentials = conn.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        size,
    )
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid


def _handle_connection(conn: socket.socket, allowed_uids: set[int]):
    try:
        uid = _peer_uid(conn)
        if uid not in allowed_uids:
            raise ControllerFailure(
                f"UID {uid} não autorizado no controller."
            )

        data = b""

        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break

            data += chunk

            if len(data) > MAX_PAYLOAD_BYTES:
                raise ControllerFailure(
                    "Payload do controller excedeu o limite de 1 MiB."
                )

        if not data:
            raise ControllerFailure("Requisição vazia.")

        request = json.loads(data.decode("utf-8"))
        return handle(request)

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }


def main():
    path = Path(SOCKET_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        path.unlink()
    except FileNotFoundError:
        pass

    allowed_uids = _authorized_uids()
    service_user = pwd.getpwnam(CONTROLLER_ALLOWED_USER)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chown(SOCKET_PATH, 0, service_user.pw_gid)
    os.chmod(SOCKET_PATH, 0o660)
    server.listen(32)

    while True:
        conn, _ = server.accept()

        with conn:
            response = _handle_connection(conn, allowed_uids)
            conn.sendall(
                (json.dumps(response) + "\n").encode("utf-8")
            )


if __name__ == "__main__":
    main()
