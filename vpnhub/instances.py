from flask import current_app

from .models import VPNInstance


class InstanceConfigurationError(RuntimeError):
    pass


def default_instance() -> VPNInstance:
    instance = (
        VPNInstance.query
        .filter_by(is_default=True, enabled=True)
        .first()
    )

    if not instance:
        raise InstanceConfigurationError(
            "Nenhuma VPN Instance padrão está configurada. "
            "Execute scripts/sync-default-instance.py."
        )

    return instance


def enabled_instances():
    return (
        VPNInstance.query
        .filter_by(enabled=True)
        .order_by(VPNInstance.id)
        .all()
    )


def assert_single_runtime_instance(instance: VPNInstance):
    active = enabled_instances()

    if len(active) != 1 or active[0].id != instance.id:
        raise InstanceConfigurationError(
            "A v0.5 prepara o modelo multi-instance, mas o controller "
            "ainda opera uma única instância ativa. Mantenha somente a "
            "VPN Instance padrão habilitada."
        )


def assert_matches_runtime(instance: VPNInstance):
    expected = {
        "interface_name": current_app.config["WG_INTERFACE"],
        "endpoint": current_app.config["VPN_ENDPOINT"],
        "listen_port": current_app.config["WG_LISTEN_PORT"],
        "vpn_pool": current_app.config["VPN_ADDRESS_POOL"],
        "server_address": current_app.config["WG_SERVER_ADDRESS"],
        "server_public_key": current_app.config["VPN_SERVER_PUBLIC_KEY"],
        "private_key_path": current_app.config[
            "WG_SERVER_PRIVATE_KEY_PATH"
        ],
        "route_protocol": current_app.config["WG_ROUTE_PROTOCOL"],
    }

    mismatches = [
        key
        for key, value in expected.items()
        if getattr(instance, key) != value
    ]

    if mismatches:
        raise InstanceConfigurationError(
            "A VPN Instance padrão diverge de /etc/vpnhub/vpnhub.env "
            f"nos campos: {', '.join(mismatches)}. "
            "Execute scripts/sync-default-instance.py."
        )
