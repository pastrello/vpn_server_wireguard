from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

REGISTRY_VERSION = 1
INTERFACE_RE = re.compile(r"^wg([0-9]+)$")


class RegistryError(RuntimeError):
    pass


def _empty_registry() -> dict:
    return {
        "version": REGISTRY_VERSION,
        "instances": {},
    }


def load_registry(path: str | Path) -> dict:
    registry_path = Path(path)

    if not registry_path.exists():
        raise RegistryError(
            f"Registry do controller não existe: {registry_path}"
        )

    try:
        data = json.loads(
            registry_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(
            f"Registry inválida: {registry_path}: {exc}"
        ) from exc

    if data.get("version") != REGISTRY_VERSION:
        raise RegistryError(
            "Versão da registry do controller não suportada."
        )

    if not isinstance(data.get("instances"), dict):
        raise RegistryError(
            "Registry não contém o mapa 'instances'."
        )

    return data


def save_registry(path: str | Path, data: dict):
    registry_path = Path(path)
    registry_path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    payload = json.dumps(
        data,
        indent=2,
        sort_keys=True,
    ) + "\n"

    fd, tmp_name = tempfile.mkstemp(
        prefix=".vpnhub-instances-",
        suffix=".json",
        dir=str(registry_path.parent),
        text=True,
    )
    os.fchmod(fd, 0o600)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_name, registry_path)
        os.chmod(registry_path, 0o600)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def normalize_record(raw: dict) -> dict:
    interface = str(raw.get("interface") or "").strip()

    if not INTERFACE_RE.fullmatch(interface):
        raise RegistryError(
            f"Interface WireGuard inválida: {interface!r}"
        )

    listen_port = int(raw.get("listen_port") or 0)
    if not 1 <= listen_port <= 65535:
        raise RegistryError("Porta WireGuard inválida.")

    vpn_pool = ipaddress.ip_network(
        str(raw.get("vpn_pool") or ""),
        strict=False,
    )
    server_address = ipaddress.ip_interface(
        str(raw.get("server_address") or "")
    )

    if vpn_pool.version != 4 or server_address.version != 4:
        raise RegistryError("A v0.6 suporta somente IPv4.")

    if vpn_pool.prefixlen > 24:
        raise RegistryError(
            "VPN pool precisa permitir sub-redes /24."
        )

    if server_address.ip not in vpn_pool:
        raise RegistryError(
            "Endereço do servidor não pertence ao VPN pool."
        )

    private_key_path = str(
        raw.get("private_key_path") or ""
    ).strip()
    key_path = Path(private_key_path)
    key_root = Path("/etc/wireguard")

    try:
        resolved = key_path.resolve(strict=False)
    except OSError as exc:
        raise RegistryError(
            "Caminho da PrivateKey inválido."
        ) from exc

    valid_name = (
        resolved.name == "vpnhub-server.key"
        or re.fullmatch(
            r"vpnhub-wg[0-9]+\.key",
            resolved.name,
        )
    )

    if (
        resolved.parent != key_root
        or not valid_name
    ):
        raise RegistryError(
            "PrivateKey precisa usar um nome VPNHub "
            "diretamente em /etc/wireguard."
        )

    private_key_path = str(resolved)

    route_protocol = int(raw.get("route_protocol") or 186)
    if not 1 <= route_protocol <= 255:
        raise RegistryError("Routing protocol inválido.")

    return {
        "interface": interface,
        "listen_port": listen_port,
        "vpn_pool": str(vpn_pool),
        "server_address": str(server_address),
        "private_key_path": private_key_path,
        "route_protocol": route_protocol,
    }


def validate_registry(data: dict) -> dict:
    normalized = _empty_registry()

    used_ports = set()
    used_pools = []

    for interface, raw in data.get("instances", {}).items():
        record = normalize_record({
            **raw,
            "interface": interface,
        })

        if record["listen_port"] in used_ports:
            raise RegistryError(
                f"Porta duplicada: {record['listen_port']}"
            )

        pool = ipaddress.ip_network(record["vpn_pool"])
        for previous in used_pools:
            if pool.overlaps(previous):
                raise RegistryError(
                    f"VPN pools sobrepostos: {pool} e {previous}"
                )

        used_ports.add(record["listen_port"])
        used_pools.append(pool)
        normalized["instances"][interface] = record

    return normalized


def next_interface(data: dict) -> str:
    numbers = []

    for name in data.get("instances", {}):
        match = INTERFACE_RE.fullmatch(name)
        if match:
            numbers.append(int(match.group(1)))

    candidate = 1
    used = set(numbers)

    while candidate in used:
        candidate += 1

    return f"wg{candidate}"


def ensure_private_key(
    key_path: str | Path,
    runner=subprocess.run,
) -> str:
    path = Path(key_path)

    if not path.exists():
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )

        generated = runner(
            ["wg", "genkey"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(generated + "\n")

    os.chmod(path, 0o600)

    private_key = path.read_text(
        encoding="utf-8"
    ).strip()

    public_key = runner(
        ["wg", "pubkey"],
        input=private_key + "\n",
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    return public_key
