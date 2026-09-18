from pathlib import Path
import sys

import pytest


CONTROLLER_DIR = (
    Path(__file__).resolve().parents[1]
    / "controller"
)
if str(CONTROLLER_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROLLER_DIR))

from registry import (  # noqa: E402
    RegistryError,
    next_interface,
    normalize_record,
    validate_registry,
)


def record(interface, port, pool):
    prefix = pool.split("/")[0].split(".")
    server = ".".join(
        prefix[:3] + ["1"]
    ) + "/" + pool.split("/")[1]

    return {
        "interface": interface,
        "listen_port": port,
        "vpn_pool": pool,
        "server_address": server,
        "private_key_path": (
            "/etc/wireguard/vpnhub-server.key"
            if interface == "wg0"
            else f"/etc/wireguard/vpnhub-{interface}.key"
        ),
        "route_protocol": 186,
    }


def test_next_interface_skips_existing_numbers():
    data = {
        "version": 1,
        "instances": {
            "wg0": record(
                "wg0",
                51820,
                "10.250.0.0/16",
            ),
            "wg1": record(
                "wg1",
                51821,
                "10.251.0.0/16",
            ),
        },
    }
    assert next_interface(data) == "wg2"


def test_registry_rejects_overlapping_pools():
    data = {
        "version": 1,
        "instances": {
            "wg0": record(
                "wg0",
                51820,
                "10.250.0.0/16",
            ),
            "wg1": record(
                "wg1",
                51821,
                "10.250.128.0/17",
            ),
        },
    }

    with pytest.raises(RegistryError):
        validate_registry(data)


def test_registry_rejects_path_escape():
    bad = record(
        "wg1",
        51821,
        "10.251.0.0/16",
    )
    bad["private_key_path"] = (
        "/etc/wireguard/../shadow"
    )

    with pytest.raises(RegistryError):
        normalize_record(bad)
