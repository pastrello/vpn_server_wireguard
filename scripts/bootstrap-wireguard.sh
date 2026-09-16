#!/usr/bin/env bash
set -Eeuo pipefail
ENV_FILE="/etc/vpnhub/vpnhub.env"
KEY_FILE="/etc/wireguard/vpnhub-server.key"
ACTIVATE="false"
[[ "${1:-}" == "--activate" ]] && ACTIVATE="true"
[[ "${EUID}" -eq 0 ]] || { echo "Execute como root."; exit 1; }
[[ -f "${ENV_FILE}" ]] || { echo "Arquivo ${ENV_FILE} não existe."; exit 1; }

dnf install -y wireguard-tools nftables iproute
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
if [[ ! -f "${KEY_FILE}" ]]; then
    umask 077
    wg genkey > "${KEY_FILE}"
    chmod 600 "${KEY_FILE}"
    echo "[OK] Chave privada do servidor criada."
else
    echo "[OK] Chave privada do servidor já existe."
fi
PUBLIC_KEY="$(wg pubkey < "${KEY_FILE}")"
set_env() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "${ENV_FILE}"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "${ENV_FILE}"
    else
        printf '%s=%s\n' "${key}" "${value}" >> "${ENV_FILE}"
    fi
}
set_env "VPN_SERVER_PUBLIC_KEY" "${PUBLIC_KEY}"
set_env "WG_SERVER_PRIVATE_KEY_PATH" "${KEY_FILE}"
grep -q '^WG_SERVER_ADDRESS=' "${ENV_FILE}" || printf '%s\n' 'WG_SERVER_ADDRESS=10.250.0.1/16' >> "${ENV_FILE}"
grep -q '^WG_ROUTE_PROTOCOL=' "${ENV_FILE}" || printf '%s\n' 'WG_ROUTE_PROTOCOL=186' >> "${ENV_FILE}"
grep -q '^WG_ONLINE_SECONDS=' "${ENV_FILE}" || printf '%s\n' 'WG_ONLINE_SECONDS=180' >> "${ENV_FILE}"
if [[ "${ACTIVATE}" == "true" ]]; then
    set_env "WG_DRY_RUN" "false"
    echo "[OK] WG_DRY_RUN=false"
else
    echo "[INFO] WG_DRY_RUN não foi alterado; use --activate para aplicar a VPN real."
fi
chmod 600 "${ENV_FILE}"
chown root:vpnhub "${ENV_FILE}" 2>/dev/null || true
cat > /etc/sysctl.d/90-vpnhub.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
SYSCTL
sysctl --system >/dev/null
systemd-tmpfiles --create /etc/tmpfiles.d/vpnhub.conf 2>/dev/null || true
systemctl daemon-reload
systemctl restart vpnhub-controller vpnhub
printf '\nPublicKey do servidor:\n%s\n\n' "${PUBLIC_KEY}"
echo "Confirme VPN_ENDPOINT em ${ENV_FILE}."
