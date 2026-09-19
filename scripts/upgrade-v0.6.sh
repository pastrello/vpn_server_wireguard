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

if ! grep -q '^CONTROLLER_REGISTRY=' "${ENV_FILE}"; then
    printf '%s\n'         'CONTROLLER_REGISTRY=/etc/wireguard/vpnhub-instances.json'         >> "${ENV_FILE}"
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

"${VENV}/bin/flask" --app run:app db upgrade
"${VENV}/bin/python" scripts/sync-default-instance.py
"${VENV}/bin/python" scripts/bootstrap-controller-registry.py

cp systemd/vpnhub.service /etc/systemd/system/
cp systemd/vpnhub-controller.service /etc/systemd/system/
cp systemd/vpnhub-reconcile.service /etc/systemd/system/
cp tmpfiles/vpnhub.conf /etc/tmpfiles.d/vpnhub.conf

chown -R root:root "${APP_DIR}"
chmod -R go-w "${APP_DIR}"

chown root:vpnhub "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

chmod 700 /etc/wireguard
[[ ! -f "${CONTROLLER_REGISTRY}" ]] || {
    chown root:root "${CONTROLLER_REGISTRY}"
    chmod 600 "${CONTROLLER_REGISTRY}"
}

systemd-tmpfiles --create /etc/tmpfiles.d/vpnhub.conf
systemctl daemon-reload
systemctl enable vpnhub-controller vpnhub-reconcile vpnhub

systemctl restart vpnhub-controller
systemctl reset-failed vpnhub-reconcile || true
systemctl start vpnhub-reconcile
systemctl restart vpnhub

echo "[OK] VPNHub atualizado para v0.6."
echo "[INFO] Multi-trunk habilitado. wg0 preservado como Instance Principal."
