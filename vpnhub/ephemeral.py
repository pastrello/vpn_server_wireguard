import os
import re
import secrets
import time
from pathlib import Path

SECRET_DIR = Path("/run/vpnhub/secrets")
TTL_SECONDS = 900
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{40,64}$")


def _cleanup():
    now = time.time()

    if not SECRET_DIR.exists():
        return

    for path in SECRET_DIR.glob("*.conf"):
        try:
            if now - path.stat().st_mtime > TTL_SECONDS:
                path.unlink()
        except FileNotFoundError:
            pass


def _path_for_token(token: str | None) -> Path | None:
    if not token or not TOKEN_RE.fullmatch(token):
        return None

    return SECRET_DIR / f"{token}.conf"


def store_config(config: str) -> str:
    SECRET_DIR.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )
    _cleanup()

    for _ in range(5):
        token = secrets.token_urlsafe(32)
        path = _path_for_token(token)

        try:
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            continue

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(config)

        return token

    raise RuntimeError(
        "Não foi possível reservar arquivo temporário de configuração."
    )


def read_config(token: str | None) -> str | None:
    _cleanup()
    path = _path_for_token(token)

    if path is None:
        return None

    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
