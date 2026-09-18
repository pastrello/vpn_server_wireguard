#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/vpnhub"
ENV_FILE="/etc/vpnhub/vpnhub.env"
VENV="${APP_DIR}/venv"
BASELINE_REV="20260917_0001"

[[ "${EUID}" -eq 0 ]] || { echo "Execute como root."; exit 1; }
[[ -f "${ENV_FILE}" ]] || { echo "Arquivo ${ENV_FILE} não existe."; exit 1; }

cd "${APP_DIR}"
"${VENV}/bin/pip" install -r requirements.txt

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

if ! "${VENV}/bin/python" - <<'PY'
import os
import psycopg

url = os.environ["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1)
with psycopg.connect(url) as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.alembic_version')")
        value = cur.fetchone()[0]
raise SystemExit(0 if value else 1)
PY
then
    echo "[INFO] Marcando banco v0.3 como baseline Alembic ${BASELINE_REV}..."
    "${VENV}/bin/flask" --app run:app db stamp "${BASELINE_REV}"
fi

"${VENV}/bin/flask" --app run:app db upgrade

cp systemd/vpnhub.service /etc/systemd/system/
cp systemd/vpnhub-controller.service /etc/systemd/system/
cp systemd/vpnhub-reconcile.service /etc/systemd/system/
cp tmpfiles/vpnhub.conf /etc/tmpfiles.d/vpnhub.conf
systemd-tmpfiles --create /etc/tmpfiles.d/vpnhub.conf
systemctl daemon-reload
systemctl enable vpnhub-controller vpnhub-reconcile vpnhub
systemctl restart vpnhub-controller
systemctl start vpnhub-reconcile
systemctl restart vpnhub

echo "[OK] VPNHub atualizado para v0.4."
