# VPNHub Portal v0.3

A v0.3 conecta o portal ao plano de dados real do WireGuard.

## O que entrou

- controller privilegiado ativo;
- `wg0` criado/gerenciado pelo controller;
- peers sincronizados com `wg syncconf`;
- PresharedKey aplicada também no servidor;
- rotas de Networks gerenciadas com `proto 186`;
- prevenção de conflito com rotas locais do servidor;
- nftables com isolamento Site -> Site;
- Admin Peers com acesso aos Sites;
- leitura real de endpoint, handshake, RX e TX;
- status ONLINE/OFFLINE no portal;
- botão **Reconciliar**;
- integração básica com firewalld quando ele estiver ativo.

## Segurança

O processo web continua sem root. Ele fala com:

```text
/run/vpnhub/controller.sock
```

O controller aceita somente:

```text
health
status
sync
```

Não existe endpoint de shell ou execução arbitrária.

## Política de tráfego

```text
Admin Peer -> Site A/B/C         ALLOW
Site A -> Site A                 ALLOW
Site B -> Site B                 ALLOW
Site A -> Site B                 DROP
Site B -> Site A                 DROP
Site -> host VPNHub              DROP
Admin Peer -> host VPNHub        ALLOW
externo -> wg0                   DROP
```

## Padrões

```text
Interface:           wg0
Servidor VPN:        10.250.0.1/16
Porta:               UDP 51820
Chave privada:       /etc/wireguard/vpnhub-server.key
Rotas gerenciadas:   proto 186
ONLINE:              handshake <= 180s
```

## Upgrade da v0.2

Faça backup:

```bash
pg_dump -Fc vpnhub > /root/vpnhub-pre-v0.3.dump
cp -a /etc/vpnhub/vpnhub.env /root/vpnhub.env.pre-v0.3
```

Copie os arquivos novos para `/opt/vpnhub`, preservando `/etc/vpnhub/vpnhub.env`.

Depois:

```bash
cd /opt/vpnhub
source venv/bin/activate
pip install -r requirements.txt

cp systemd/vpnhub.service /etc/systemd/system/
cp systemd/vpnhub-controller.service /etc/systemd/system/
cp tmpfiles/vpnhub.conf /etc/tmpfiles.d/vpnhub.conf
systemd-tmpfiles --create /etc/tmpfiles.d/vpnhub.conf
systemctl daemon-reload
```

Inicialize a chave do servidor sem ativar alterações reais:

```bash
./scripts/bootstrap-wireguard.sh
```

Confirme no `/etc/vpnhub/vpnhub.env`:

```ini
VPN_ENDPOINT=SEU_DNS_OU_IP_PUBLICO:51820
VPN_SERVER_PUBLIC_KEY=...
WG_SERVER_ADDRESS=10.250.0.1/16
WG_DRY_RUN=true
```

Carregue o ambiente e teste:

```bash
set -a
source /etc/vpnhub/vpnhub.env
set +a

python scripts/reconcile.py
python scripts/status.py
```

Quando o DRY-RUN estiver correto:

```bash
./scripts/bootstrap-wireguard.sh --activate
```

Depois reconcilie:

```bash
set -a
source /etc/vpnhub/vpnhub.env
set +a
python scripts/reconcile.py
```

## Verificações no servidor

```bash
ip addr show wg0
wg show wg0
ip route show proto 186
nft list table inet vpnhub
ss -lunp | grep 51820
```

## firewalld

Quando `firewalld` está ativo, o controller tenta liberar a porta WireGuard no default zone e associar `wg0` à zona `trusted`. O isolamento entre Sites continua sendo feito na tabela nftables `inet vpnhub`.

## Conflitos de rota

O controller recusa uma Network remota que sobreponha uma rota local do servidor. Isso evita, por exemplo, que cadastrar `192.168.1.0/24` para um cliente substitua silenciosamente uma rede local já usada pelo próprio servidor.

## Observação sobre Admin Peers

O arquivo de um Admin Peer contém as Networks existentes no momento da criação. Quando novas Networks forem adicionadas depois, o servidor já será atualizado, mas o cliente administrativo poderá precisar de uma configuração atualizada para instalar as novas rotas. Regeneração controlada de configuração será tratada em uma próxima revisão.
