#!/usr/bin/env python3
from pathlib import Path
import sys

from sqlalchemy import inspect, text

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vpnhub import create_app
from vpnhub.models import db


def column_names(table):
    return {
        c["name"]
        for c in inspect(db.engine).get_columns(table)
    }


app = create_app()

with app.app_context():
    changes = []

    peers = column_names("peers")
    if "preshared_key_enc" not in peers:
        db.session.execute(
            text("ALTER TABLE peers ADD COLUMN preshared_key_enc TEXT")
        )
        changes.append("peers.preshared_key_enc")

    admins = column_names("admin_peers")
    if "preshared_key_enc" not in admins:
        db.session.execute(
            text("ALTER TABLE admin_peers ADD COLUMN preshared_key_enc TEXT")
        )
        changes.append("admin_peers.preshared_key_enc")

    db.session.commit()

    if changes:
        print("Migração v0.2 aplicada:")
        for item in changes:
            print(f"  + {item}")
    else:
        print("Schema já está compatível com v0.2.")
