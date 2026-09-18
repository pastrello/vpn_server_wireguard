# VPNHub Portal v0.4

VPNHub é um portal simples para administrar WireGuard em um servidor central e acessar Sites/clientes remotos, inclusive atrás de NAT/CGNAT.

A v0.4 é a revisão de consolidação operacional do projeto.

## Destaques

- Dashboard com contadores `ONLINE`, `IDLE`, `OFFLINE` e `NEVER`.
- Página **Status** com visão de todos os Peers, endpoint, handshake, RX e TX.
- Atualização automática de status a cada 30 segundos.
- Health do servidor: `wg0`, porta UDP, nftables, firewalld, forwarding e rotas.
- Reconcile automático depois do boot.
- Um único Gateway ativo por Site.
- Regeneração/rekey de Peers e Admin Peers pelo portal.
- Admin Peer inclui `10.250.0.1/32` (ou o IP configurado em `WG_SERVER_ADDRESS`) em `AllowedIPs`.
- Sync com validação prévia de nftables e rollback de WireGuard/rotas/nftables em caso de falha.
- firewalld idempotente: reload somente quando uma configuração permanente realmente muda.
- Migrações de schema com Flask-Migrate/Alembic.
- Helper opcional para Caddy + HTTPS.
- Testes básicos do controller e classificação de status.

## Estados de Peer

Os limites são configuráveis:

```ini
WG_ONLINE_SECONDS=180
WG_IDLE_SECONDS=600
```

Classificação padrão:

```text
ONLINE   handshake <= 3 minutos
IDLE     > 3 minutos e <= 10 minutos
OFFLINE  > 10 minutos
NEVER    nunca houve handshake
```

## Arquitetura

```text
Portal Flask (vpnhub)
        |
        | Unix socket 0660
        v
vpnhub-controller (root)
        |
        +-- WireGuard / wg0
        +-- rotas proto 186
        +-- nftables inet vpnhub
        +-- firewalld (integração auxiliar)
```

O processo web não executa `wg`, `ip`, `nft` ou `firewall-cmd` como root.

## Política de rede

```text
Admin Peer -> Sites                    ALLOW
Site A -> Site A                       ALLOW
Site A -> Site B                       DROP
Site -> host VPNHub                    DROP
Admin Peer -> host VPNHub              ALLOW
tráfego externo não autorizado -> wg0  DROP
```

O isolamento é implementado diretamente em nftables. O firewalld é usado somente para integração com a política local do Rocky Linux.

## Instalação limpa em Rocky Linux 9/10

```bash
chmod +x scripts/install-rocky.sh
./scripts/install-rocky.sh
```

Configure PostgreSQL e `/etc/vpnhub/vpnhub.env` e então aplique as migrações:

```bash
/opt/vpnhub/scripts/db-upgrade.sh
```

Crie o administrador e inicialize WireGuard em DRY-RUN:

```bash
cd /opt/vpnhub
source venv/bin/activate
set -a
source /etc/vpnhub/vpnhub.env
set +a
python scripts/create-admin.py

./scripts/bootstrap-wireguard.sh
python scripts/reconcile.py
python scripts/status.py
```

Quando estiver correto:

```bash
./scripts/bootstrap-wireguard.sh --activate
```

## Upgrade da v0.3

Faça backup:

```bash
pg_dump -Fc vpnhub > /root/vpnhub-pre-v0.4.dump
cp -a /etc/vpnhub/vpnhub.env /root/vpnhub.env.pre-v0.4
```

Copie a v0.4 sobre `/opt/vpnhub`, preservando `/etc/vpnhub/vpnhub.env`, e execute:

```bash
cd /opt/vpnhub
./scripts/upgrade-v0.4.sh
```

O script detecta bancos v0.3 sem `alembic_version`, marca o schema atual como baseline e aplica a migração da v0.4.

A migração recusa prosseguir se encontrar mais de um Gateway ativo no mesmo Site.

## Reconcile no boot

A ordem de inicialização é:

```text
vpnhub-controller.service
   -> vpnhub-reconcile.service
      -> vpnhub.service
```

Assim `wg0`, Peers, rotas e nftables são reconstruídos automaticamente após reinicialização.

## Rekey / regeneração

Como o VPNHub não persiste a PrivateKey do cliente, **Regenerar** cria novo keypair + PSK, mantém o mesmo IP VPN e usa os `AllowedIPs` atuais. A configuração antiga deixa de funcionar.

Esse também é o método para atualizar um Admin Peer depois que novas Networks forem adicionadas.

## HTTPS com Caddy

Para laboratório:

```ini
PORTAL_BIND=0.0.0.0:8080
SESSION_COOKIE_SECURE=false
```

Com Caddy já instalado:

```bash
/opt/vpnhub/scripts/configure-caddy.sh vpn.exemplo.com.br admin@exemplo.com.br
```

O helper muda o portal para `127.0.0.1:8080`, ativa cookie `Secure` e configura reverse proxy HTTPS.

## Verificação operacional

```bash
systemctl status vpnhub-controller vpnhub-reconcile vpnhub
ip addr show wg0
wg show wg0
ip route show proto 186
nft list table inet vpnhub
ss -lunp | grep 51820
```

No portal, use `/status` para diagnóstico consolidado.

## Testes

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Limitação conhecida

Networks sobrepostas entre Sites ainda são recusadas. A estrutura `translated_cidr` permanece reservada para uma futura etapa de NAT/virtualização.
