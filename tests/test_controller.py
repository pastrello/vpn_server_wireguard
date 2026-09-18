import base64
import importlib.util
import json
import socket
import sys
import threading
from pathlib import Path

import pytest


CONTROLLER_DIR = (
    Path(__file__).resolve().parents[1]
    / "controller"
)
if str(CONTROLLER_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROLLER_DIR))


def load_controller():
    path = CONTROLLER_DIR / "vpnhub-controller.py"
    spec = importlib.util.spec_from_file_location(
        "vpnhub_controller",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def key(byte):
    return base64.b64encode(
        bytes([byte]) * 32
    ).decode()


def registry_data():
    return {
        "version": 1,
        "instances": {
            "wg0": {
                "interface": "wg0",
                "listen_port": 51820,
                "vpn_pool": "10.250.0.0/16",
                "server_address": "10.250.0.1/16",
                "private_key_path": (
                    "/etc/wireguard/"
                    "vpnhub-server.key"
                ),
                "route_protocol": 186,
            },
            "wg1": {
                "interface": "wg1",
                "listen_port": 51821,
                "vpn_pool": "10.251.0.0/16",
                "server_address": "10.251.0.1/16",
                "private_key_path": (
                    "/etc/wireguard/"
                    "vpnhub-wg1.key"
                ),
                "route_protocol": 186,
            },
        },
    }


def instance_state(
    interface,
    instance_id,
    site_id,
    peer_byte,
    psk_byte,
    route,
):
    registry = registry_data()["instances"][
        interface
    ]

    return {
        "id": instance_id,
        "name": f"Instance {interface}",
        "enabled": True,
        "interface": interface,
        "listen_port": registry["listen_port"],
        "server_address": registry[
            "server_address"
        ],
        "vpn_pool": registry["vpn_pool"],
        "private_key_path": registry[
            "private_key_path"
        ],
        "route_protocol": 186,
        "peers": [{
            "kind": "site",
            "site_id": site_id,
            "name": f"gw-{interface}",
            "public_key": key(peer_byte),
            "preshared_key": key(psk_byte),
            "allowed_ips": [
                (
                    "10.250.1.10/32"
                    if interface == "wg0"
                    else "10.251.1.10/32"
                ),
                route,
            ],
        }],
        "sites": [{
            "id": site_id,
            "name": f"Site {interface}",
            "ranges": [
                (
                    "10.250.1.0/24"
                    if interface == "wg0"
                    else "10.251.1.0/24"
                ),
                route,
            ],
        }],
        "admin_addresses": [
            (
                "10.250.0.10/32"
                if interface == "wg0"
                else "10.251.0.10/32"
            )
        ],
        "routes": [route],
    }


def base_state():
    return {
        "instances": [
            instance_state(
                "wg0",
                1,
                10,
                1,
                2,
                "192.168.10.0/24",
            ),
            instance_state(
                "wg1",
                2,
                20,
                3,
                4,
                "172.16.20.0/24",
            ),
        ]
    }


def configure_registry(
    controller,
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "instances.json"
    controller.save_registry(
        path,
        registry_data(),
    )
    monkeypatch.setattr(
        controller,
        "REGISTRY_PATH",
        str(path),
    )
    return path


def test_validate_state_accepts_two_instances(
    monkeypatch,
    tmp_path,
):
    controller = load_controller()
    configure_registry(
        controller,
        monkeypatch,
        tmp_path,
    )

    state = controller.validate_state(
        base_state()
    )

    assert len(state["instances"]) == 2
    assert state["instances"][0][
        "interface"
    ] == "wg0"
    assert state["instances"][1][
        "interface"
    ] == "wg1"


def test_validate_state_rejects_unregistered_interface(
    monkeypatch,
    tmp_path,
):
    controller = load_controller()
    configure_registry(
        controller,
        monkeypatch,
        tmp_path,
    )
    payload = base_state()
    payload["instances"][1][
        "interface"
    ] = "eth0"

    with pytest.raises(
        controller.ControllerFailure
    ):
        controller.validate_state(payload)


def test_validate_state_rejects_runtime_tampering(
    monkeypatch,
    tmp_path,
):
    controller = load_controller()
    configure_registry(
        controller,
        monkeypatch,
        tmp_path,
    )
    payload = base_state()
    payload["instances"][1][
        "private_key_path"
    ] = "/etc/wireguard/vpnhub-wg9.key"

    with pytest.raises(
        controller.ControllerFailure
    ):
        controller.validate_state(payload)


def test_validate_state_rejects_cross_trunk_overlap(
    monkeypatch,
    tmp_path,
):
    controller = load_controller()
    configure_registry(
        controller,
        monkeypatch,
        tmp_path,
    )
    payload = base_state()
    payload["instances"][1]["routes"] = [
        "192.168.10.128/25"
    ]

    with pytest.raises(
        controller.ControllerFailure
    ):
        controller.validate_state(payload)


def test_nftables_isolates_each_trunk(
    monkeypatch,
    tmp_path,
):
    controller = load_controller()
    configure_registry(
        controller,
        monkeypatch,
        tmp_path,
    )
    state = controller.validate_state(
        base_state()
    )
    rules = controller.render_nftables(
        state,
        table_exists=False,
    )

    assert "set admin_1" in rules
    assert "set admin_2" in rules
    assert "set site_10" in rules
    assert "set site_20" in rules
    assert 'iifname "wg0" drop' in rules
    assert 'iifname "wg1" drop' in rules
    assert 'oifname "wg0" drop' in rules
    assert 'oifname "wg1" drop' in rules


def test_provision_chooses_next_wg_interface(
    monkeypatch,
    tmp_path,
):
    controller = load_controller()
    registry = registry_data()
    del registry["instances"]["wg1"]

    path = tmp_path / "instances.json"
    controller.save_registry(path, registry)
    monkeypatch.setattr(
        controller,
        "REGISTRY_PATH",
        str(path),
    )
    monkeypatch.setattr(
        controller,
        "ensure_private_key",
        lambda _path: key(9),
    )
    monkeypatch.setattr(
        controller,
        "_host_routes",
        lambda: [],
    )

    result = controller.provision_instance({
        "listen_port": 51821,
        "vpn_pool": "10.251.0.0/16",
        "server_address": "10.251.0.1/16",
    })

    assert result["interface"] == "wg1"
    assert result["created"] is True

    stored = controller.load_registry(path)
    assert "wg1" in stored["instances"]


def test_socket_request_is_framed_by_real_newline(
    monkeypatch,
):
    controller = load_controller()
    server, client = socket.socketpair()
    result = {}

    monkeypatch.setattr(
        controller,
        "_peer_uid",
        lambda _conn: 0,
    )

    def worker():
        result["response"] = (
            controller._handle_connection(
                server,
                {0},
            )
        )

    thread = threading.Thread(target=worker)
    thread.start()

    client.sendall(
        (
            json.dumps({
                "action": "invalid"
            })
            + "\n"
        ).encode("utf-8")
    )
    thread.join(timeout=1.0)

    try:
        assert not thread.is_alive()
        assert result["response"]["ok"] is False
        assert (
            "Ação não permitida"
            in result["response"]["error"]
        )
    finally:
        client.close()
        server.close()
