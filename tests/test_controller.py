import base64
import importlib.util
from pathlib import Path

import pytest


def load_controller():
    path = (
        Path(__file__).resolve().parents[1]
        / "controller"
        / "vpnhub-controller.py"
    )
    spec = importlib.util.spec_from_file_location(
        "vpnhub_controller",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode()


def base_state():
    return {
        "interface": "wg0",
        "listen_port": 51820,
        "server_address": "10.250.0.1/16",
        "vpn_pool": "10.250.0.0/16",
        "private_key_path": "/etc/wireguard/vpnhub-server.key",
        "route_protocol": 186,
        "peers": [{
            "kind": "site",
            "site_id": 1,
            "name": "gw-a",
            "public_key": key(1),
            "preshared_key": key(2),
            "allowed_ips": [
                "10.250.1.10/32",
                "192.168.10.0/24",
            ],
        }],
        "sites": [{
            "id": 1,
            "name": "Site A",
            "ranges": [
                "10.250.1.0/24",
                "192.168.10.0/24",
            ],
        }],
        "admin_addresses": ["10.250.0.10/32"],
        "routes": ["192.168.10.0/24"],
    }


def test_validate_state_accepts_authorized_runtime():
    controller = load_controller()
    state = controller.validate_state(base_state())
    assert state["interface"] == "wg0"
    assert state["listen_port"] == 51820


def test_validate_state_rejects_untrusted_interface():
    controller = load_controller()
    payload = base_state()
    payload["interface"] = "eth0"

    with pytest.raises(controller.ControllerFailure):
        controller.validate_state(payload)


def test_validate_state_rejects_untrusted_key_path():
    controller = load_controller()
    payload = base_state()
    payload["private_key_path"] = "/tmp/attacker.key"

    with pytest.raises(controller.ControllerFailure):
        controller.validate_state(payload)


def test_validate_state_rejects_duplicate_allowed_ip():
    controller = load_controller()
    payload = base_state()
    payload["peers"].append({
        "kind": "site",
        "site_id": 2,
        "name": "gw-b",
        "public_key": key(3),
        "preshared_key": key(4),
        "allowed_ips": ["192.168.10.0/24"],
    })

    with pytest.raises(controller.ControllerFailure):
        controller.validate_state(payload)


def test_nftables_has_admin_and_site_isolation_rules():
    controller = load_controller()
    state = controller.validate_state(base_state())
    rules = controller.render_nftables(
        state,
        table_exists=False,
    )

    assert "set admin_peers" in rules
    assert "set site_1" in rules
    assert "ip saddr @admin_peers ip daddr @all_sites accept" in rules
    assert 'iifname "wg0" drop' in rules
    assert 'oifname "wg0" drop' in rules
