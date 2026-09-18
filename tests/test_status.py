from datetime import datetime, timedelta
from types import SimpleNamespace

from vpnhub import create_app
from vpnhub.sync import peer_state


def app():
    application = create_app()
    application.config.update(
        TESTING=True,
        WG_ONLINE_SECONDS=180,
        WG_IDLE_SECONDS=600,
    )
    return application


def test_peer_states():
    application = app()

    with application.app_context():
        assert peer_state(SimpleNamespace(latest_handshake=None)) == "never"

        recent = SimpleNamespace(
            latest_handshake=datetime.utcnow() - timedelta(seconds=30)
        )
        assert peer_state(recent) == "online"

        idle = SimpleNamespace(
            latest_handshake=datetime.utcnow() - timedelta(seconds=300)
        )
        assert peer_state(idle) == "idle"

        offline = SimpleNamespace(
            latest_handshake=datetime.utcnow() - timedelta(seconds=900)
        )
        assert peer_state(offline) == "offline"
