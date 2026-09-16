#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)) if str(ROOT) not in sys.path else None
from vpnhub import create_app
from vpnhub.sync import reconcile
app = create_app()
with app.app_context():
    result = reconcile()
    print(result["message"])
    print(f"dry_run: {result.get('dry_run')}")
    print(f"peers: {result.get('peer_count', 0)}")
    print(f"sites: {result.get('site_count', 0)}")
    print(f"routes: {result.get('route_count', 0)}")
    for warning in result.get("warnings", []):
        print(f"WARNING: {warning}")
