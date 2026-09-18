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

from registry import (
    RegistryError,
    ensure_private_key,
    load_registry,
    next_interface,
    normalize_record,
    save_registry,
    validate_registry,
)

SOCKET_PATH = os.getenv(
    "CONTROLLER_SOCKET",
    "/run/vpnhub/controller.sock",
)
REGISTRY_PATH = os.getenv(
    "CONTROLLER_REGISTRY",
    "/etc/wireguard/vpnhub-instances.json",
)
DRY_RUN = os.getenv("WG_DRY_RUN", "true").lower() == "true"
CONTROLLER_ALLOWED_USER = os.getenv(
    "CONTROLLER_ALLOWED_USER",
    "vpnhub",
)
DEFAULT_ROUTE_PROTOCOL = int(
    os.getenv("WG_ROUTE_PROTOCOL", "186")
)
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
        raise ControllerFailure(
            f"{label} não é base64 válido."
        ) from exc

    if len(decoded) != 32:
        raise ControllerFailure(
            f"{label} deve representar 32 bytes."
        )


def _registry() -> dict:
    try:
        return validate_registry(
            load_registry(REGISTRY_PATH)
        )
    except RegistryError as exc:
        raise ControllerFailure(str(exc)) from exc


def _registered_record(
    registry: dict,
    interface: str,
) -> dict:
    raw = registry["instances"].get(interface)

    if raw is None:
        raise ControllerFailure(
            f"Interface {interface} não está autorizada "
            "na registry root-owned."
        )

    return normalize_record(raw)


def _require_equal(label, supplied, expected):
    if supplied != expected:
        raise ControllerFailure(
            f"{label} diverge da registry autorizada."
        )


def _normalize_peer(raw: dict) -> dict:
    public_key = str(raw.get("public_key") or "").strip()
    _validate_wg_key(public_key, "PublicKey")

    psk = str(raw.get("preshared_key") or "").strip() or None
    if psk:
        _validate_wg_key(psk, "PresharedKey")

    allowed_ips = []
    for item in raw.get("allowed_ips") or []:
        network = ipaddress.ip_network(
            str(item),
            strict=False,
        )
        if network.version != 4:
            raise ControllerFailure(
                "IPv6 ainda não é suportado."
            )
        allowed_ips.append(str(network))

    return {
        "kind": str(raw.get("kind") or "site"),
        "site_id": raw.get("site_id"),
        "name": str(raw.get("name") or ""),
        "public_key": public_key,
        "preshared_key": psk,
        "allowed_ips": allowed_ips,
    }


def _normalize_networks(values) -> list[str]:
    output = []

    for item in values or []:
        network = ipaddress.ip_network(
            str(item),
            strict=False,
        )

        if network.version != 4:
            raise ControllerFailure(
                "IPv6 ainda não é suportado."
            )

        output.append(str(network))

    return output


def _normalize_instance(raw: dict, registry: dict) -> dict:
    interface = str(raw.get("interface") or "").strip()
    authorized = _registered_record(
        registry,
        interface,
    )

    supplied = {
        "interface": interface,
        "listen_port": int(raw.get("listen_port") or 0),
        "vpn_pool": str(
            ipaddress.ip_network(
                str(raw.get("vpn_pool") or ""),
                strict=False,
            )
        ),
        "server_address": str(
            ipaddress.ip_interface(
                str(raw.get("server_address") or "")
            )
        ),
        "private_key_path": str(
            raw.get("private_key_path") or ""
        ),
        "route_protocol": int(
            raw.get("route_protocol") or 0
        ),
    }

    for key in (
        "listen_port",
        "vpn_pool",
        "server_address",
        "private_key_path",
        "route_protocol",
    ):
        _require_equal(
            f"{interface}.{key}",
            supplied[key],
            authorized[key],
        )

    peers = [
        _normalize_peer(peer)
        for peer in raw.get("peers") or []
    ]

    public_keys = set()
    prefix_owners = {}

    for peer in peers:
        if peer["public_key"] in public_keys:
            raise ControllerFailure(
                f"{interface}: PublicKey duplicada."
            )
        public_keys.add(peer["public_key"])

        for prefix in peer["allowed_ips"]:
            previous = prefix_owners.get(prefix)
            if (
                previous is not None
                and previous != peer["public_key"]
            ):
                raise ControllerFailure(
                    f"{interface}: AllowedIP {prefix} "
                    "está atribuída a mais de um Peer."
                )
            prefix_owners[prefix] = peer["public_key"]

    sites = []
    for site in raw.get("sites") or []:
        sites.append({
            "id": int(site["id"]),
            "name": str(site.get("name") or ""),
            "ranges": _normalize_networks(
                site.get("ranges")
            ),
        })

    return {
        "id": int(raw["id"]),
        "name": str(raw.get("name") or interface),
        "enabled": bool(raw.get("enabled", True)),
        **authorized,
        "peers": peers,
        "sites": sites,
        "admin_addresses": _normalize_networks(
            raw.get("admin_addresses")
        ),
        "routes": sorted(
            set(_normalize_networks(raw.get("routes")))
        ),
    }


def validate_state(payload: dict) -> dict:
    registry = _registry()
    raw_instances = payload.get("instances") or []

    if not isinstance(raw_instances, list):
        raise ControllerFailure(
            "Payload multi-instance inválido."
        )

    instances = [
        _normalize_instance(raw, registry)
        for raw in raw_instances
    ]

    supplied_names = {
        instance["interface"]
        for instance in instances
    }
    registered_names = set(registry["instances"])

    if supplied_names != registered_names:
        missing = sorted(
            registered_names - supplied_names
        )
        unknown = sorted(
            supplied_names - registered_names
        )
        details = []
        if missing:
            details.append(
                "ausentes=" + ",".join(missing)
            )
        if unknown:
            details.append(
                "não autorizadas=" + ",".join(unknown)
            )
        raise ControllerFailure(
            "Payload não representa toda a registry: "
            + "; ".join(details)
        )

    # Pools precisam permanecer independentes.
    pools = []
    for instance in instances:
        pool = ipaddress.ip_network(
            instance["vpn_pool"]
        )
        for previous_name, previous_pool in pools:
            if pool.overlaps(previous_pool):
                raise ControllerFailure(
                    f"VPN pools sobrepostos: "
                    f"{instance['interface']}={pool} e "
                    f"{previous_name}={previous_pool}"
                )
        pools.append((instance["interface"], pool))

    # Networks roteadas não podem se sobrepor entre trunks enquanto
    # não houver VRF/policy routing.
    routed = []
    for instance in instances:
        for route in instance["routes"]:
            network = ipaddress.ip_network(route)

            for owner, previous in routed:
                if network.overlaps(previous):
                    raise ControllerFailure(
                        "Networks sobrepostas ainda não são "
                        "suportadas entre trunks: "
                        f"{instance['interface']}={network} "
                        f"conflita com {owner}={previous}"
                    )

            for pool_owner, pool in pools:
                if network.overlaps(pool):
                    raise ControllerFailure(
                        f"Network {network} conflita com "
                        f"VPN pool {pool_owner}={pool}"
                    )

            routed.append(
                (instance["interface"], network)
            )

    return {
        "instances": sorted(
            instances,
            key=lambda row: row["id"],
        )
    }


def _host_routes():
    try:
        return json.loads(
            run(
                ["ip", "-j", "route", "show"]
            ).stdout
            or "[]"
        )
    except json.JSONDecodeError as exc:
        raise ControllerFailure(
            "Não foi possível interpretar a tabela de rotas."
        ) from exc


def check_route_conflicts(state: dict):
    registry_names = {
        instance["interface"]
        for instance in state["instances"]
    }
    protocols = {
        str(instance["route_protocol"])
        for instance in state["instances"]
    }

    protected = []

    for row in _host_routes():
        dst = row.get("dst")
        dev = row.get("dev")
        protocol = str(
            row.get("protocol")
            or row.get("proto")
            or ""
        )

        if not dst or dst == "default":
            continue

        if (
            dev in registry_names
            and protocol in protocols
        ):
            continue

        try:
            protected.append(
                (
                    ipaddress.ip_network(
                        dst,
                        strict=False,
                    ),
                    dev or "?",
                )
            )
        except ValueError:
            continue

    conflicts = []

    for instance in state["instances"]:
        if not instance["enabled"]:
            continue

        for desired in instance["routes"]:
            wanted = ipaddress.ip_network(desired)

            for existing, dev in protected:
                if wanted.overlaps(existing):
                    conflicts.append(
                        f"{instance['interface']}:{wanted} "
                        f"conflita com {existing} em {dev}"
                    )

    if conflicts:
        raise ControllerFailure(
            "Conflito de rota detectado: "
            + "; ".join(conflicts)
        )


def ensure_kernel_state(instance: dict):
    interface = instance["interface"]

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
        instance["server_address"],
        "dev",
        interface,
    ])
    run([
        "ip",
        "link",
        "set",
        "up",
        "dev",
        interface,
    ])


def render_wg_config(instance: dict) -> str:
    key_path = Path(instance["private_key_path"])

    if not key_path.exists():
        raise ControllerFailure(
            f"Chave privada de {instance['interface']} "
            f"não existe em {key_path}."
        )

    private_key = key_path.read_text(
        encoding="utf-8"
    ).strip()
    _validate_wg_key(
        private_key,
        f"PrivateKey {instance['interface']}",
    )

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"ListenPort = {instance['listen_port']}",
        "",
    ]

    for peer in instance["peers"]:
        lines.append("[Peer]")
        lines.append(
            f"PublicKey = {peer['public_key']}"
        )

        if peer["preshared_key"]:
            lines.append(
                f"PresharedKey = {peer['preshared_key']}"
            )

        if peer["allowed_ips"]:
            lines.append(
                "AllowedIPs = "
                + ", ".join(peer["allowed_ips"])
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
            "        elements = { "
            + ", ".join(values)
            + " }"
        )

    lines.append("    }")
    return "\n".join(lines)


def render_nftables(
    state: dict,
    table_exists: bool,
) -> str:
    enabled = [
        instance
        for instance in state["instances"]
        if instance["enabled"]
    ]

    body = []

    if table_exists:
        body.extend([
            "delete table inet vpnhub",
            "",
        ])

    body.append("table inet vpnhub {")

    for instance in enabled:
        iid = instance["id"]
        all_sites = sorted(
            set(
                item
                for site in instance["sites"]
                for item in site["ranges"]
            )
        )

        body.extend([
            nft_set(
                f"admin_{iid}",
                instance["admin_addresses"],
            ),
            "",
            nft_set(
                f"sites_{iid}",
                all_sites,
            ),
            "",
        ])

        for site in instance["sites"]:
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
    ])

    for instance in enabled:
        iid = instance["id"]
        interface = instance["interface"]
        body.append(
            f'        iifname "{interface}" '
            f"ip saddr @admin_{iid} accept"
        )
        body.append(
            f'        iifname "{interface}" drop'
        )

    body.extend([
        "    }",
        "",
        "    chain forward_guard {",
        "        type filter hook forward priority -20; policy accept;",
    ])

    for instance in enabled:
        iid = instance["id"]
        interface = instance["interface"]

        body.append(
            f'        iifname "{interface}" '
            f'oifname "{interface}" '
            f"ip saddr @admin_{iid} "
            f"ip daddr @sites_{iid} accept"
        )
        body.append(
            f'        iifname "{interface}" '
            f'oifname "{interface}" '
            f"ip saddr @sites_{iid} "
            f"ip daddr @admin_{iid} "
            "ct state established,related accept"
        )

        for site in instance["sites"]:
            set_name = f"site_{site['id']}"
            body.append(
                f'        iifname "{interface}" '
                f'oifname "{interface}" '
                f"ip saddr @{set_name} "
                f"ip daddr @{set_name} accept"
            )

        body.append(
            f'        iifname "{interface}" drop'
        )
        body.append(
            f'        oifname "{interface}" drop'
        )

    body.extend([
        "    }",
        "}",
        "",
    ])

    return "\n".join(body)


def _write_temp(
    content: str,
    prefix: str,
    suffix: str,
) -> str:
    fd, tmp_name = tempfile.mkstemp(
        prefix=prefix,
        suffix=suffix,
        dir="/run",
        text=True,
    )
    os.fchmod(fd, 0o600)

    with os.fdopen(
        fd,
        "w",
        encoding="utf-8",
    ) as handle:
        handle.write(content)

    return tmp_name


def prepare_files(state: dict) -> tuple[dict, str]:
    wg_files = {}

    for instance in state["instances"]:
        if not instance["enabled"]:
            continue

        wg_files[instance["interface"]] = _write_temp(
            render_wg_config(instance),
            f"vpnhub-{instance['interface']}-",
            ".conf",
        )

    table_exists = (
        run(
            [
                "nft",
                "list",
                "table",
                "inet",
                "vpnhub",
            ],
            check=False,
        ).returncode
        == 0
    )

    nft_tmp = _write_temp(
        render_nftables(
            state,
            table_exists,
        ),
        "vpnhub-nft-",
        ".nft",
    )

    try:
        run(["nft", "-c", "-f", nft_tmp])
    except Exception:
        for path in wg_files.values():
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        os.unlink(nft_tmp)
        raise

    return wg_files, nft_tmp


def capture_interface(instance: dict) -> dict:
    interface = instance["interface"]
    existed = interface_exists(interface)

    snapshot = {
        "interface_existed": existed,
        "wg_config": None,
        "addresses": [],
        "routes": [],
    }

    if existed:
        proc = run(
            ["wg", "showconf", interface],
            check=False,
        )
        if proc.returncode == 0:
            snapshot["wg_config"] = proc.stdout

        addr_proc = run(
            [
                "ip",
                "-j",
                "address",
                "show",
                "dev",
                interface,
            ],
            check=False,
        )
        if addr_proc.returncode == 0:
            try:
                rows = json.loads(
                    addr_proc.stdout or "[]"
                )
            except json.JSONDecodeError:
                rows = []

            for row in rows:
                for info in row.get(
                    "addr_info",
                    [],
                ):
                    if info.get("family") == "inet":
                        snapshot["addresses"].append(
                            f"{info['local']}/"
                            f"{info['prefixlen']}"
                        )

    route_proc = run(
        [
            "ip",
            "-j",
            "route",
            "show",
            "proto",
            str(instance["route_protocol"]),
            "dev",
            interface,
        ],
        check=False,
    )

    if route_proc.returncode == 0:
        try:
            snapshot["routes"] = json.loads(
                route_proc.stdout or "[]"
            )
        except json.JSONDecodeError:
            snapshot["routes"] = []

    return snapshot


def capture_runtime_state(state: dict) -> dict:
    nft_proc = run(
        [
            "nft",
            "list",
            "table",
            "inet",
            "vpnhub",
        ],
        check=False,
    )

    return {
        "interfaces": {
            instance["interface"]:
                capture_interface(instance)
            for instance in state["instances"]
        },
        "nft_table": (
            nft_proc.stdout
            if nft_proc.returncode == 0
            else None
        ),
    }


def apply_routes(instance: dict):
    interface = instance["interface"]
    protocol = str(instance["route_protocol"])

    run(
        [
            "ip",
            "route",
            "flush",
            "proto",
            protocol,
            "dev",
            interface,
        ],
        check=False,
    )

    for network in instance["routes"]:
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


def deactivate_instance(instance: dict):
    interface = instance["interface"]

    run(
        [
            "ip",
            "route",
            "flush",
            "proto",
            str(instance["route_protocol"]),
            "dev",
            interface,
        ],
        check=False,
    )

    if interface_exists(interface):
        run(
            [
                "ip",
                "link",
                "delete",
                "dev",
                interface,
            ],
            check=False,
        )


def restore_interface(
    instance: dict,
    snapshot: dict,
):
    interface = instance["interface"]
    protocol = str(instance["route_protocol"])

    if not snapshot.get("interface_existed"):
        if interface_exists(interface):
            run(
                [
                    "ip",
                    "link",
                    "delete",
                    "dev",
                    interface,
                ],
                check=False,
            )
        return

    if not interface_exists(interface):
        run(
            [
                "ip",
                "link",
                "add",
                "dev",
                interface,
                "type",
                "wireguard",
            ],
            check=False,
        )

    run(
        [
            "ip",
            "address",
            "flush",
            "dev",
            interface,
        ],
        check=False,
    )

    for address in snapshot.get("addresses") or []:
        run(
            [
                "ip",
                "address",
                "add",
                address,
                "dev",
                interface,
            ],
            check=False,
        )

    if snapshot.get("wg_config"):
        wg_tmp = _write_temp(
            snapshot["wg_config"],
            f"vpnhub-{interface}-rollback-",
            ".conf",
        )
        try:
            run(
                [
                    "wg",
                    "syncconf",
                    interface,
                    wg_tmp,
                ],
                check=False,
            )
        finally:
            try:
                os.unlink(wg_tmp)
            except FileNotFoundError:
                pass

    run(
        [
            "ip",
            "link",
            "set",
            "up",
            "dev",
            interface,
        ],
        check=False,
    )

    run(
        [
            "ip",
            "route",
            "flush",
            "proto",
            protocol,
            "dev",
            interface,
        ],
        check=False,
    )

    for route in snapshot.get("routes") or []:
        dst = route.get("dst")
        if not dst:
            continue

        run(
            [
                "ip",
                "route",
                "replace",
                dst,
                "dev",
                interface,
                "proto",
                protocol,
            ],
            check=False,
        )


def restore_runtime_state(
    state: dict,
    snapshot: dict,
):
    run(
        [
            "nft",
            "delete",
            "table",
            "inet",
            "vpnhub",
        ],
        check=False,
    )

    if snapshot.get("nft_table"):
        nft_tmp = _write_temp(
            snapshot["nft_table"],
            "vpnhub-nft-rollback-",
            ".nft",
        )
        try:
            run(
                ["nft", "-f", nft_tmp],
                check=False,
            )
        finally:
            try:
                os.unlink(nft_tmp)
            except FileNotFoundError:
                pass

    for instance in state["instances"]:
        restore_interface(
            instance,
            snapshot["interfaces"].get(
                instance["interface"],
                {},
            ),
        )


def configure_firewalld(
    instances: list[dict],
) -> list[str]:
    warnings = []

    if not shutil.which("firewall-cmd"):
        return warnings

    if (
        run(
            [
                "systemctl",
                "is-active",
                "--quiet",
                "firewalld",
            ],
            check=False,
        ).returncode
        != 0
    ):
        return warnings

    default_zone = (
        run([
            "firewall-cmd",
            "--get-default-zone",
        ]).stdout.strip()
        or "public"
    )

    changed = False

    for instance in instances:
        if not instance["enabled"]:
            continue

        port_query = run(
            [
                "firewall-cmd",
                "--permanent",
                f"--zone={default_zone}",
                f"--query-port="
                f"{instance['listen_port']}/udp",
            ],
            check=False,
        )

        if port_query.returncode != 0:
            proc = run(
                [
                    "firewall-cmd",
                    "--permanent",
                    f"--zone={default_zone}",
                    f"--add-port="
                    f"{instance['listen_port']}/udp",
                ],
                check=False,
            )
            if proc.returncode == 0:
                changed = True
            else:
                warnings.append(
                    f"firewalld: falha ao liberar "
                    f"UDP {instance['listen_port']}."
                )

        iface_query = run(
            [
                "firewall-cmd",
                "--permanent",
                "--zone=trusted",
                f"--query-interface="
                f"{instance['interface']}",
            ],
            check=False,
        )

        if iface_query.returncode != 0:
            proc = run(
                [
                    "firewall-cmd",
                    "--permanent",
                    "--zone=trusted",
                    f"--add-interface="
                    f"{instance['interface']}",
                ],
                check=False,
            )
            if proc.returncode == 0:
                changed = True
            else:
                warnings.append(
                    f"firewalld: falha ao associar "
                    f"{instance['interface']} à zona trusted."
                )

    if changed:
        proc = run(
            ["firewall-cmd", "--reload"],
            check=False,
        )
        if proc.returncode != 0:
            warnings.append(
                "firewalld: alterações permanentes feitas, "
                "mas o reload falhou."
            )

    return warnings


def perform_sync(payload: dict) -> dict:
    state = validate_state(payload)
    check_route_conflicts(state)

    wg_files, nft_tmp = prepare_files(state)

    try:
        if DRY_RUN:
            return {
                "ok": True,
                "dry_run": True,
                "message": (
                    "Todas as VPN Instances, WireGuard e "
                    "nftables foram validados; nenhuma "
                    "alteração aplicada."
                ),
                "instance_count": len(
                    state["instances"]
                ),
                "peer_count": sum(
                    len(instance["peers"])
                    for instance in state["instances"]
                ),
                "route_count": sum(
                    len(instance["routes"])
                    for instance in state["instances"]
                ),
                "site_count": sum(
                    len(instance["sites"])
                    for instance in state["instances"]
                ),
                "warnings": [],
            }

        snapshot = capture_runtime_state(state)

        try:
            run([
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=1",
            ])

            for instance in state["instances"]:
                if not instance["enabled"]:
                    deactivate_instance(instance)
                    continue

                ensure_kernel_state(instance)
                run([
                    "wg",
                    "syncconf",
                    instance["interface"],
                    wg_files[instance["interface"]],
                ])
                apply_routes(instance)

            run(["nft", "-f", nft_tmp])

        except Exception as exc:
            restore_runtime_state(
                state,
                snapshot,
            )
            raise ControllerFailure(
                "Sincronização multi-instance falhou e "
                f"o estado anterior foi restaurado: {exc}"
            ) from exc

        warnings = configure_firewalld(
            state["instances"]
        )

        return {
            "ok": True,
            "dry_run": False,
            "message": (
                "VPN Instances, WireGuard, rotas e "
                "isolamento sincronizados."
            ),
            "instance_count": len(
                state["instances"]
            ),
            "peer_count": sum(
                len(instance["peers"])
                for instance in state["instances"]
            ),
            "route_count": sum(
                len(instance["routes"])
                for instance in state["instances"]
            ),
            "site_count": sum(
                len(instance["sites"])
                for instance in state["instances"]
            ),
            "warnings": warnings,
        }
    finally:
        for path in wg_files.values():
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

        try:
            os.unlink(nft_tmp)
        except FileNotFoundError:
            pass


def wireguard_status(interface: str) -> dict:
    if not interface_exists(interface):
        return {
            "interface": interface,
            "interface_up": False,
            "listen_port": None,
            "public_key": None,
            "peer_count": 0,
            "peers": {},
        }

    lines = [
        line.split("\t")
        for line in run(
            [
                "wg",
                "show",
                interface,
                "dump",
            ]
        ).stdout.splitlines()
        if line.strip()
    ]

    listen_port = None
    public_key = None

    if lines and len(lines[0]) >= 4:
        public_key = lines[0][1]
        listen_port = (
            int(lines[0][2] or 0)
            or None
        )

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
            "latest_handshake": int(
                fields[4] or 0
            ),
            "rx_bytes": int(
                fields[5] or 0
            ),
            "tx_bytes": int(
                fields[6] or 0
            ),
            "persistent_keepalive": fields[7],
        }

    return {
        "interface": interface,
        "interface_up": True,
        "listen_port": listen_port,
        "public_key": public_key,
        "peer_count": len(peers),
        "peers": peers,
    }


def all_status() -> dict:
    registry = _registry()
    instances = {}

    for interface in sorted(
        registry["instances"]
    ):
        instances[interface] = wireguard_status(
            interface
        )

    return {
        "ok": True,
        "dry_run": DRY_RUN,
        "instances": instances,
    }


def health() -> dict:
    status = all_status()

    status["nft_table"] = (
        run(
            [
                "nft",
                "list",
                "table",
                "inet",
                "vpnhub",
            ],
            check=False,
        ).returncode
        == 0
    )

    status["firewalld"] = (
        shutil.which("firewall-cmd") is not None
        and run(
            [
                "systemctl",
                "is-active",
                "--quiet",
                "firewalld",
            ],
            check=False,
        ).returncode
        == 0
    )

    ip_forward = run(
        [
            "sysctl",
            "-n",
            "net.ipv4.ip_forward",
        ],
        check=False,
    )
    status["ip_forward"] = (
        ip_forward.returncode == 0
        and ip_forward.stdout.strip() == "1"
    )

    route_count = 0
    registry = _registry()

    for interface, raw in registry[
        "instances"
    ].items():
        record = normalize_record(raw)

        proc = run(
            [
                "ip",
                "-j",
                "route",
                "show",
                "proto",
                str(record["route_protocol"]),
                "dev",
                interface,
            ],
            check=False,
        )

        if proc.returncode != 0:
            continue

        try:
            route_count += len(
                json.loads(proc.stdout or "[]")
            )
        except json.JSONDecodeError:
            pass

    status["route_count"] = route_count
    return status


def _existing_matching_instance(
    registry: dict,
    requested: dict,
):
    for interface, raw in registry[
        "instances"
    ].items():
        record = normalize_record(raw)

        if (
            record["listen_port"]
            == requested["listen_port"]
            and record["vpn_pool"]
            == requested["vpn_pool"]
            and record["server_address"]
            == requested["server_address"]
        ):
            return record

    return None


def _validate_new_pool(
    registry: dict,
    requested: dict,
):
    new_pool = ipaddress.ip_network(
        requested["vpn_pool"]
    )

    for interface, raw in registry[
        "instances"
    ].items():
        record = normalize_record(raw)

        if (
            record["listen_port"]
            == requested["listen_port"]
        ):
            raise ControllerFailure(
                f"UDP {requested['listen_port']} "
                f"já pertence a {interface}."
            )

        existing_pool = ipaddress.ip_network(
            record["vpn_pool"]
        )

        if new_pool.overlaps(existing_pool):
            raise ControllerFailure(
                f"VPN pool {new_pool} conflita com "
                f"{interface}={existing_pool}."
            )

    for row in _host_routes():
        dst = row.get("dst")

        if not dst or dst == "default":
            continue

        try:
            existing = ipaddress.ip_network(
                dst,
                strict=False,
            )
        except ValueError:
            continue

        if new_pool.overlaps(existing):
            dev = row.get("dev") or "?"
            raise ControllerFailure(
                f"VPN pool {new_pool} conflita com "
                f"rota local {existing} em {dev}."
            )


def provision_instance(payload: dict) -> dict:
    registry = _registry()

    requested = normalize_record({
        "interface": "wg1",
        "listen_port": payload.get(
            "listen_port"
        ),
        "vpn_pool": payload.get("vpn_pool"),
        "server_address": payload.get(
            "server_address"
        ),
        "private_key_path": (
            "/etc/wireguard/"
            "vpnhub-placeholder.key"
        ),
        "route_protocol": DEFAULT_ROUTE_PROTOCOL,
    })

    existing = _existing_matching_instance(
        registry,
        requested,
    )

    if existing is not None:
        public_key = ensure_private_key(
            existing["private_key_path"]
        )
        return {
            "ok": True,
            "created": False,
            **existing,
            "public_key": public_key,
        }

    _validate_new_pool(
        registry,
        requested,
    )

    interface = next_interface(registry)
    key_path = (
        f"/etc/wireguard/vpnhub-{interface}.key"
    )

    record = normalize_record({
        **requested,
        "interface": interface,
        "private_key_path": key_path,
    })

    public_key = ensure_private_key(key_path)

    registry["instances"][interface] = record
    registry = validate_registry(registry)
    save_registry(
        REGISTRY_PATH,
        registry,
    )

    return {
        "ok": True,
        "created": True,
        **record,
        "public_key": public_key,
    }


def unprovision_instance(payload: dict) -> dict:
    interface = str(
        payload.get("interface") or ""
    ).strip()

    if interface == "wg0":
        raise ControllerFailure(
            "A Instance padrão wg0 não pode ser removida."
        )

    registry = _registry()
    raw = registry["instances"].get(interface)

    if raw is None:
        return {
            "ok": True,
            "removed": False,
        }

    if interface_exists(interface):
        peer_proc = run(
            ["wg", "show", interface, "peers"],
            check=False,
        )

        if (
            peer_proc.returncode == 0
            and peer_proc.stdout.strip()
        ):
            raise ControllerFailure(
                f"{interface} possui Peers ativos e "
                "não pode ser removida da registry."
            )

    record = normalize_record(raw)
    deactivate_instance(record)

    key_path = Path(record["private_key_path"])

    del registry["instances"][interface]
    save_registry(
        REGISTRY_PATH,
        validate_registry(registry),
    )

    try:
        key_path.unlink()
    except FileNotFoundError:
        pass

    return {
        "ok": True,
        "removed": True,
    }


def handle(req: dict) -> dict:
    action = req.get("action")
    payload = req.get("payload") or {}

    if action == "health":
        return health()

    if action == "status":
        return all_status()

    if action == "sync":
        return perform_sync(payload)

    if action == "provision_instance":
        return provision_instance(payload)

    if action == "unprovision_instance":
        return unprovision_instance(payload)

    return {
        "ok": False,
        "error": f"Ação não permitida: {action}",
    }


def _authorized_uids():
    allowed = {0}

    try:
        allowed.add(
            pwd.getpwnam(
                CONTROLLER_ALLOWED_USER
            ).pw_uid
        )
    except KeyError as exc:
        raise ControllerFailure(
            "Usuário autorizado do controller "
            f"não existe: {CONTROLLER_ALLOWED_USER}"
        ) from exc

    return allowed


def _peer_uid(conn: socket.socket) -> int:
    size = struct.calcsize("3i")
    credentials = conn.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        size,
    )
    _pid, uid, _gid = struct.unpack(
        "3i",
        credentials,
    )
    return uid


def _handle_connection(
    conn: socket.socket,
    allowed_uids: set[int],
):
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
                    "Payload do controller excedeu "
                    "o limite de 1 MiB."
                )

        if not data:
            raise ControllerFailure(
                "Requisição vazia."
            )

        request = json.loads(
            data.decode("utf-8")
        )
        return handle(request)

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }


def main():
    path = Path(SOCKET_PATH)
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Falha cedo se a registry root-owned não estiver pronta.
    _registry()

    try:
        path.unlink()
    except FileNotFoundError:
        pass

    allowed_uids = _authorized_uids()
    service_user = pwd.getpwnam(
        CONTROLLER_ALLOWED_USER
    )

    server = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    server.bind(SOCKET_PATH)
    os.chown(
        SOCKET_PATH,
        0,
        service_user.pw_gid,
    )
    os.chmod(SOCKET_PATH, 0o660)
    server.listen(32)

    while True:
        conn, _ = server.accept()

        with conn:
            response = _handle_connection(
                conn,
                allowed_uids,
            )
            conn.sendall(
                (
                    json.dumps(response)
                    + "\n"
                ).encode("utf-8")
            )


if __name__ == "__main__":
    main()
