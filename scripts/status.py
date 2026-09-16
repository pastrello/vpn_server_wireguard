#!/usr/bin/env python3
from pathlib import Path
import json, sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)) if str(ROOT) not in sys.path else None
from vpnhub import create_app
from vpnhub.sync import controller_health, refresh_status
app = create_app()
with app.app_context():
    print(json.dumps(controller_health(), indent=2))
    refresh_status()
