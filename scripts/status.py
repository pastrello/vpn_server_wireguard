#!/usr/bin/env python3
from pathlib import Path
import json
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vpnhub import create_app
from vpnhub.sync import status_snapshot


app = create_app()

with app.app_context():
    snapshot = status_snapshot()
    print(json.dumps(snapshot, indent=2, ensure_ascii=False))
