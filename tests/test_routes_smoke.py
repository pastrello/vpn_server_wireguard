from vpnhub import create_app
from vpnhub.models import User, VPNInstance, db
import vpnhub.sync as sync_module


def fake_controller(action, payload=None):
    if action == "status":
        return {
            "ok": True,
            "dry_run": True,
            "instances": {
                "wg0": {
                    "interface": "wg0",
                    "interface_up": False,
                    "listen_port": None,
                    "public_key": None,
                    "peer_count": 0,
                    "peers": {},
                }
            },
        }

    if action == "health":
        return {
            "ok": True,
            "dry_run": True,
            "instances": {
                "wg0": {
                    "interface": "wg0",
                    "interface_up": False,
                    "peer_count": 0,
                    "peers": {},
                }
            },
            "nft_table": False,
            "firewalld": False,
            "ip_forward": True,
            "route_count": 0,
        }

    raise AssertionError(
        f"unexpected controller action: {action}"
    )


def test_multi_trunk_pages_render(monkeypatch):
    app = create_app()
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite://",
        WTF_CSRF_ENABLED=False,
    )

    monkeypatch.setattr(
        sync_module,
        "controller_request",
        fake_controller,
    )

    with app.app_context():
        db.drop_all()
        db.create_all()

        user = User(
            username="admin",
            password_hash="x",
        )
        instance = VPNInstance(
            name="Principal",
            interface_name="wg0",
            endpoint="vpn.example.com:51820",
            listen_port=51820,
            vpn_pool="10.250.0.0/16",
            server_address="10.250.0.1/16",
            server_public_key=(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAA="
            ),
            private_key_path=(
                "/etc/wireguard/vpnhub-server.key"
            ),
            route_protocol=186,
            enabled=True,
            is_default=True,
        )
        db.session.add_all([user, instance])
        db.session.commit()
        user_id = user.id

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    for path in (
        "/",
        "/instances",
        "/instances/new",
        "/status",
        "/sites/new",
        "/admin-peers/new",
    ):
        response = client.get(path)
        assert response.status_code == 200, (
            path,
            response.status_code,
            response.get_data(as_text=True),
        )
