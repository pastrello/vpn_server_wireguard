from flask import session

from .models import VPNInstance


class InstanceConfigurationError(RuntimeError):
    pass


def default_instance() -> VPNInstance:
    instance = (
        VPNInstance.query
        .filter_by(is_default=True)
        .first()
    )

    if not instance:
        raise InstanceConfigurationError(
            "Nenhuma VPN Instance padrão está configurada."
        )

    return instance


def selected_instance() -> VPNInstance:
    selected_id = session.get("vpn_instance_id")

    if selected_id:
        instance = VPNInstance.query.get(selected_id)
        if instance is not None:
            return instance

    instance = default_instance()
    session["vpn_instance_id"] = instance.id
    return instance


def enabled_instances():
    return (
        VPNInstance.query
        .filter_by(enabled=True)
        .order_by(VPNInstance.id)
        .all()
    )


def all_instances():
    return (
        VPNInstance.query
        .order_by(VPNInstance.id)
        .all()
    )
