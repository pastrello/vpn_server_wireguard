#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

CONTROLLER_DIR = PROJECT_ROOT / "controller"
if str(CONTROLLER_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROLLER_DIR))

from registry import (  # noqa: E402
    RegistryError,
    load_registry,
    save_registry,
    validate_registry,
)

REGISTRY_PATH = Path(
    os.getenv(
        "CONTROLLER_REGISTRY",
        "/etc/wireguard/vpnhub-instances.json",
    )
)


def main():
    interface = os.getenv("WG_INTERFACE", "wg0")
    record = {
        "interface": interface,
        "listen_port": int(
            os.getenv("WG_LISTEN_PORT", "51820")
        ),
        "vpn_pool": os.getenv(
            "VPN_ADDRESS_POOL",
            "10.250.0.0/16",
        ),
        "server_address": os.getenv(
            "WG_SERVER_ADDRESS",
            "10.250.0.1/16",
        ),
        "private_key_path": os.getenv(
            "WG_SERVER_PRIVATE_KEY_PATH",
            "/etc/wireguard/vpnhub-server.key",
        ),
        "route_protocol": int(
            os.getenv("WG_ROUTE_PROTOCOL", "186")
        ),
    }

    if REGISTRY_PATH.exists():
        registry = load_registry(REGISTRY_PATH)
    else:
        registry = {
            "version": 1,
            "instances": {},
        }

    current = registry["instances"].get(interface)

    if current:
        comparable = {
            key: current.get(key)
            for key in (
                "interface",
                "listen_port",
                "vpn_pool",
                "server_address",
                "private_key_path",
                "route_protocol",
            )
        }

        if comparable != record:
            raise RegistryError(
                "A Instance padrão existente na registry diverge "
                "do vpnhub.env. Revise antes de sobrescrever.\n"
                f"registry={json.dumps(comparable, sort_keys=True)}\n"
                f"env={json.dumps(record, sort_keys=True)}"
            )
    else:
        registry["instances"][interface] = record

    registry = validate_registry(registry)
    save_registry(REGISTRY_PATH, registry)

    print(
        "Registry do controller pronta: "
        f"{REGISTRY_PATH} ({len(registry['instances'])} Instance(s))"
    )


if __name__ == "__main__":
    main()
