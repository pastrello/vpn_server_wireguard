#!/usr/bin/env python3
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vpnhub import create_app
from vpnhub.models import VPNInstance, db


app = create_app()

with app.app_context():
    instance = (
        VPNInstance.query
        .filter_by(is_default=True)
        .first()
    )

    if not instance:
        instance = VPNInstance(
            name="Principal",
            is_default=True,
            enabled=True,
        )
        db.session.add(instance)

    instance.name = instance.name or "Principal"
    instance.interface_name = app.config["WG_INTERFACE"]
    instance.endpoint = app.config["VPN_ENDPOINT"]
    instance.listen_port = app.config["WG_LISTEN_PORT"]
    instance.vpn_pool = app.config["VPN_ADDRESS_POOL"]
    instance.server_address = app.config["WG_SERVER_ADDRESS"]
    instance.server_public_key = app.config["VPN_SERVER_PUBLIC_KEY"]
    instance.private_key_path = app.config[
        "WG_SERVER_PRIVATE_KEY_PATH"
    ]
    instance.route_protocol = app.config["WG_ROUTE_PROTOCOL"]
    instance.enabled = True
    instance.is_default = True

    db.session.commit()

    print(
        "VPN Instance padrão sincronizada: "
        f"{instance.name} / {instance.interface_name} / "
        f"{instance.vpn_pool} / UDP {instance.listen_port}"
    )
