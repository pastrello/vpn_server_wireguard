import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")
    PSK_ENCRYPTION_KEY = os.getenv("PSK_ENCRYPTION_KEY", "")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://vpnhub:vpnhub@127.0.0.1:5432/vpnhub",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    VPN_ENDPOINT = os.getenv("VPN_ENDPOINT", "vpn.example.com:51820")
    VPN_SERVER_PUBLIC_KEY = os.getenv("VPN_SERVER_PUBLIC_KEY", "CHANGE_ME")
    VPN_ADDRESS_POOL = os.getenv("VPN_ADDRESS_POOL", "10.250.0.0/16")
    WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
    WG_LISTEN_PORT = int(os.getenv("WG_LISTEN_PORT", "51820"))
    WG_SERVER_ADDRESS = os.getenv("WG_SERVER_ADDRESS", "10.250.0.1/16")
    WG_SERVER_PRIVATE_KEY_PATH = os.getenv(
        "WG_SERVER_PRIVATE_KEY_PATH", "/etc/wireguard/vpnhub-server.key"
    )
    WG_ROUTE_PROTOCOL = int(os.getenv("WG_ROUTE_PROTOCOL", "186"))
    WG_ONLINE_SECONDS = int(os.getenv("WG_ONLINE_SECONDS", "180"))
    WG_DRY_RUN = os.getenv("WG_DRY_RUN", "true").lower() == "true"
    CONTROLLER_SOCKET = os.getenv("CONTROLLER_SOCKET", "/run/vpnhub/controller.sock")
    WTF_CSRF_TIME_LIMIT = None
