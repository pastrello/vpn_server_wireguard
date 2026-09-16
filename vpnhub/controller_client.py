import json
import socket
from flask import current_app


class ControllerError(RuntimeError):
    pass


def controller_request(action: str, payload: dict | None = None) -> dict:
    request = {"action": action, "payload": payload or {}}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect(current_app.config["CONTROLLER_SOCKET"])
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    except (OSError, TimeoutError) as exc:
        raise ControllerError(f"Controller indisponível: {exc}") from exc
    finally:
        sock.close()

    data = b"".join(chunks).strip()
    if not data:
        raise ControllerError("Controller não retornou resposta.")
    try:
        response = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ControllerError("Resposta inválida do controller.") from exc
    if not response.get("ok"):
        raise ControllerError(response.get("error", "Falha no controller."))
    return response
