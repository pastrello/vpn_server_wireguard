from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _fernet() -> Fernet:
    key = current_app.config.get("PSK_ENCRYPTION_KEY", "")
    if not key or key == "troque-esta-chave-fernet":
        raise RuntimeError(
            "PSK_ENCRYPTION_KEY não configurada. "
            "Gere uma chave Fernet antes de criar peers."
        )

    try:
        return Fernet(key.encode("ascii"))
    except Exception as exc:
        raise RuntimeError(
            "PSK_ENCRYPTION_KEY inválida. "
            "Use uma chave Fernet gerada por scripts/generate-secrets.py."
        ) from exc


def encrypt_psk(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_psk(value: str | None) -> str | None:
    if not value:
        return None

    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "Não foi possível descriptografar a PSK. "
            "Verifique PSK_ENCRYPTION_KEY."
        ) from exc
