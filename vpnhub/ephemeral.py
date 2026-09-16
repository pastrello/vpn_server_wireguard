import secrets
import time
from pathlib import Path

SECRET_DIR = Path('/run/vpnhub/secrets')
TTL_SECONDS = 900


def _cleanup():
    now = time.time()
    if not SECRET_DIR.exists():
        return
    for path in SECRET_DIR.glob('*.conf'):
        try:
            if now - path.stat().st_mtime > TTL_SECONDS:
                path.unlink()
        except FileNotFoundError:
            pass


def store_config(config: str) -> str:
    SECRET_DIR.mkdir(parents=True, exist_ok=True)
    _cleanup()
    token = secrets.token_urlsafe(32)
    path = SECRET_DIR / f'{token}.conf'
    path.write_text(config, encoding='utf-8')
    path.chmod(0o600)
    return token


def read_config(token: str | None) -> str | None:
    if not token:
        return None
    _cleanup()
    path = SECRET_DIR / f'{token}.conf'
    try:
        return path.read_text(encoding='utf-8')
    except FileNotFoundError:
        return None
