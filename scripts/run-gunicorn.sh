#!/usr/bin/env bash
set -Eeuo pipefail

BIND="${PORTAL_BIND:-0.0.0.0:8080}"

exec /opt/vpnhub/venv/bin/gunicorn \
    --workers "${GUNICORN_WORKERS:-2}" \
    --bind "${BIND}" \
    --access-logfile - \
    --error-logfile - \
    run:app
