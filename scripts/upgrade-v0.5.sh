#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/vpnhub"
ENV_FILE="/etc/vpnhub/vpnhub.env"
VENV="${APP_DIR}/venv"

[[ "${EUID}" -eq 0 ]] || {
    echo "Execute como root."
    exit 1
}
[[ -f "${ENV_FILE}" ]] || {
    echo "Arquivo ${ENV_FILE} não existe."
    exit 1
}

cd "${APP_DIR}"

"${VENV}/bin/pip" install -r requirements.txt

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

"${VENV}/bin/flask" --app run:app db upgrade
"${VENV}/bin/python" scripts/sync-default-instance.py

cp systemd/vpnhub.service /etc/systemd/system/
cp systemd/vpnhub-controller.service /etc/systemd/system/
cp systemd/vpnhub-reconcile.service /etc/systemd/system/
cp tmpfiles/vpnhub.conf /etc/tmpfiles.d/vpnhub.conf

# Código executado pelo controller root nunca deve ser gravável pelo portal.
chown -R root:root "${APP_DIR}"
chmod -R go-w "${APP_DIR}"

chown root:vpnhub "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

systemd-tmpfiles --create /etc/tmpfiles.d/vpnhub.conf
systemctl daemon-reload
systemctl enable vpnhub-controller vpnhub-reconcile vpnhub

systemctl restart vpnhub-controller
systemctl start vpnhub-reconcile
systemctl restart vpnhub

echo "[OK] VPNHub atualizado para v0.5."
echo "[INFO] VPN Instance Principal preparada para futura expansão wgX."
