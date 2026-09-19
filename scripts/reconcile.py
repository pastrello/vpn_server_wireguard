#!/usr/bin/env python3
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vpnhub import create_app
from vpnhub.sync import reconcile


app = create_app()

with app.app_context():
    last_error = None

    for attempt in range(1, 11):
        try:
            result = reconcile()
            print(result["message"])
            print(f"dry_run: {result.get('dry_run')}")
            print(
                f"instances: "
                f"{result.get('instance_count', 1)}"
            )
            print(
                f"peers: "
                f"{result.get('peer_count', 0)}"
            )
            print(
                f"sites: "
                f"{result.get('site_count', 0)}"
            )
            print(
                f"routes: "
                f"{result.get('route_count', 0)}"
            )

            for warning in result.get(
                "warnings",
                [],
            ):
                print(f"WARNING: {warning}")

            raise SystemExit(0)

        except Exception as exc:
            last_error = exc

            if attempt == 10:
                break

            print(
                "Controller ainda não disponível "
                f"(tentativa {attempt}/10): {exc}",
                file=sys.stderr,
            )
            time.sleep(1)

    raise SystemExit(
        "Falha ao reconciliar após 10 tentativas: "
        f"{last_error}"
    )
