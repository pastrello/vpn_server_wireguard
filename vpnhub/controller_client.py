import json
import socket

from flask import current_app

MAX_RESPONSE_BYTES = 1024 * 1024


class ControllerError(RuntimeError):
    pass


def controller_request(action: str, payload: dict | None = None) -> dict:
    request = {
        "action": action,
        "payload": payload or {},
    }

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        sock.connect(current_app.config["CONTROLLER_SOCKET"])
        sock.sendall(
            (json.dumps(request) + "\n").encode("utf-8")
        )

        data = b""

        while b"\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                break

            data += chunk

            if len(data) > MAX_RESPONSE_BYTES:
                raise ControllerError(
                    "Resposta do controller excedeu 1 MiB."
                )

    except (OSError, TimeoutError) as exc:
        raise ControllerError(
            f"Controller indisponível: {exc}"
        ) from exc
    finally:
        sock.close()

    if not data:
        raise ControllerError(
            "Controller não retornou resposta."
        )

    line = data.split(b"\n", 1)[0]

    try:
        response = json.loads(line.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ControllerError(
            "Resposta inválida do controller."
        ) from exc

    if not response.get("ok"):
        raise ControllerError(
            response.get("error", "Falha no controller.")
        )

    return response
