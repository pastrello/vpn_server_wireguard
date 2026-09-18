#!/usr/bin/env bash
set -Eeuo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"
ENV_FILE="/etc/vpnhub/vpnhub.env"
CADDYFILE="/etc/caddy/Caddyfile"

[[ "${EUID}" -eq 0 ]] || { echo "Execute como root."; exit 1; }
[[ -n "${DOMAIN}" ]] || { echo "Uso: $0 vpn.exemplo.com.br [email]"; exit 1; }
[[ -f "${ENV_FILE}" ]] || { echo "Arquivo ${ENV_FILE} não existe."; exit 1; }
command -v caddy >/dev/null 2>&1 || {
    echo "Caddy não está instalado. Instale o pacote caddy e execute novamente."
    exit 1
}

mkdir -p /etc/caddy
if [[ -f "${CADDYFILE}" ]]; then
    cp -a "${CADDYFILE}" "${CADDYFILE}.vpnhub-backup-$(date +%Y%m%d%H%M%S)"
fi

{
    if [[ -n "${EMAIL}" ]]; then
        printf '{\n\temail %s\n}\n\n' "${EMAIL}"
    fi
    cat <<CADDY
${DOMAIN} {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080

    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
}
CADDY
} > "${CADDYFILE}"

set_env() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "${ENV_FILE}"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "${ENV_FILE}"
    else
        printf '%s=%s\n' "${key}" "${value}" >> "${ENV_FILE}"
    fi
}

set_env "PORTAL_BIND" "127.0.0.1:8080"
set_env "SESSION_COOKIE_SECURE" "true"

caddy validate --config "${CADDYFILE}"
systemctl enable --now caddy
systemctl restart vpnhub caddy

echo "[OK] Portal configurado em https://${DOMAIN}"
