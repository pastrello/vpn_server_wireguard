#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/vpnhub"
ENV_FILE="/etc/vpnhub/vpnhub.env"

[[ -f "${ENV_FILE}" ]] || { echo "Arquivo ${ENV_FILE} não existe."; exit 1; }

cd "${APP_DIR}"
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

exec "${APP_DIR}/venv/bin/flask" --app run:app db upgrade
