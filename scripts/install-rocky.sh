#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="/opt/vpnhub"
ETC_DIR="/etc/vpnhub"
VENV="${APP_DIR}/venv"
[[ "${EUID}" -eq 0 ]] || { echo "Execute como root."; exit 1; }

dnf install -y python3 python3-pip wireguard-tools nftables iproute postgresql postgresql-server
id vpnhub >/dev/null 2>&1 || useradd --system --home-dir "${APP_DIR}" --shell /sbin/nologin vpnhub
mkdir -p "${APP_DIR}" "${ETC_DIR}"
cp -a . "${APP_DIR}/"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --upgrade pip
"${VENV}/bin/pip" install -r "${APP_DIR}/requirements.txt"

if [[ ! -f "${ETC_DIR}/vpnhub.env" ]]; then
    cp "${APP_DIR}/.env.example" "${ETC_DIR}/vpnhub.env"
    SECRET_KEY="$("${VENV}/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
    PSK_KEY="$("${VENV}/bin/python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
    sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${SECRET_KEY}|" "${ETC_DIR}/vpnhub.env"
    sed -i "s|^PSK_ENCRYPTION_KEY=.*|PSK_ENCRYPTION_KEY=${PSK_KEY}|" "${ETC_DIR}/vpnhub.env"
    chmod 600 "${ETC_DIR}/vpnhub.env"
fi

chown -R vpnhub:vpnhub "${APP_DIR}"
chown root:vpnhub "${ETC_DIR}/vpnhub.env"
cp "${APP_DIR}/systemd/vpnhub.service" /etc/systemd/system/
cp "${APP_DIR}/systemd/vpnhub-controller.service" /etc/systemd/system/
cp "${APP_DIR}/tmpfiles/vpnhub.conf" /etc/tmpfiles.d/vpnhub.conf
systemd-tmpfiles --create /etc/tmpfiles.d/vpnhub.conf
systemctl daemon-reload

echo
echo "VPNHub v0.3 instalado."
echo "1. Configure PostgreSQL e ${ETC_DIR}/vpnhub.env"
echo "2. Rode: ${APP_DIR}/scripts/bootstrap-wireguard.sh"
echo "3. Valide em DRY-RUN com scripts/reconcile.py"
echo "4. Ative de verdade com: ${APP_DIR}/scripts/bootstrap-wireguard.sh --activate"
