# VPNHub Portal v0.5

VPNHub centraliza conexões WireGuard para Sites remotos, inclusive redes atrás
de NAT/CGNAT, com portal operacional, isolamento nftables, status e geração de
configurações.

A v0.5 mantém o uso diário simples e prepara a arquitetura para futuras árvores
wg1, wg2, etc., sem habilitar essa complexidade antes da hora.

## Arquitetura atual

~~~text
VPNHub
└── VPN Instance "Principal"
    ├── interface: wg0
    ├── pool:      10.250.0.0/16
    ├── UDP:       51820
    │
    ├── Admin Peers
    └── Sites
        ├── Networks
        └── Peers
~~~

O modelo de dados agora é:

~~~text
VPNInstance
    │
    ├── AdminPeer
    │
    └── Site
         ├── Network
         └── Peer
~~~

Na v0.5 somente **uma VPN Instance pode estar ativa**. O portal não oferece
botão para criar wg1 ainda. Isso é intencional.

A futura etapa multi-instance poderá acrescentar uma lista root-owned de
interfaces autorizadas ao controller sem precisar remodelar Sites, Peers,
IPAM ou configurações de clientes novamente.

## Preparação para wgX

Cada VPN Instance já possui campos próprios para:

- nome;
- interface WireGuard;
- endpoint;
- porta UDP;
- VPN pool;
- endereço do servidor;
- PublicKey do servidor;
- caminho da PrivateKey;
- protocolo das rotas gerenciadas;
- estado enabled/default.

Sites e Admin Peers são vinculados à Instance. IPAM e geração de AllowedIPs
usam a configuração da Instance em vez de assumir globalmente wg0 e
10.250.0.0/16.

As unicidades também foram preparadas: CIDR/nome de Site e endereços de Peers
são limitados dentro de seu escopo, não globalmente entre futuras Instances.

## Limite deliberado

O controller v0.5 ainda é single-instance e fixa estes parâmetros à
configuração root-owned de /etc/vpnhub/vpnhub.env:

~~~text
WG_INTERFACE
WG_LISTEN_PORT
WG_SERVER_ADDRESS
VPN_ADDRESS_POOL
WG_SERVER_PRIVATE_KEY_PATH
WG_ROUTE_PROTOCOL
~~~

Se o banco divergir do arquivo root-owned, ou se mais de uma Instance estiver
habilitada, o reconcile é recusado.

Isso evita transformar a preparação de wgX em um canal para o portal escolher
arbitrariamente interfaces, caminhos de chave ou rotas do host.

## Dark mode

O portal possui alternância claro/escuro na barra lateral e também na tela de
login. A preferência fica no localStorage do navegador.

Sem preferência salva, o primeiro acesso acompanha prefers-color-scheme do
sistema.

## Status

A Dashboard e /status continuam exibindo:

~~~text
ONLINE   handshake <= WG_ONLINE_SECONDS
IDLE     <= WG_IDLE_SECONDS
OFFLINE  acima do limite
NEVER    nunca conectou
~~~

A tela de Status agora identifica explicitamente a VPN Instance ativa.

## Segurança da separação Portal / Controller

~~~text
Gunicorn / Flask
User=vpnhub
      │
      │ /run/vpnhub/controller.sock
      ▼
Controller
User=root
      │
      ├── wg
      ├── ip
      ├── nft
      └── firewall-cmd
~~~

Na v0.5:

- /opt/vpnhub fica root:root e não gravável por vpnhub;
- /run/vpnhub fica root:vpnhub 0750;
- somente /run/vpnhub/secrets fica vpnhub:vpnhub 0700;
- o socket verifica o UID chamador via SO_PEERCRED;
- payload e resposta são limitados a 1 MiB;
- interface, porta, pool, chave e route protocol não são aceitos livremente
  do payload do portal.

## Instalação limpa

~~~bash
chmod +x scripts/install-rocky.sh
./scripts/install-rocky.sh
~~~

Depois de configurar PostgreSQL e /etc/vpnhub/vpnhub.env:

~~~bash
/opt/vpnhub/scripts/db-upgrade.sh
/opt/vpnhub/scripts/bootstrap-wireguard.sh
~~~

Crie o administrador:

~~~bash
cd /opt/vpnhub
source venv/bin/activate
set -a
source /etc/vpnhub/vpnhub.env
set +a
python scripts/create-admin.py
~~~

Valide em DRY-RUN:

~~~bash
python scripts/reconcile.py
python scripts/status.py
~~~

Ative o plano de dados:

~~~bash
./scripts/bootstrap-wireguard.sh --activate
~~~

## Upgrade v0.4 -> v0.5

Faça backup:

~~~bash
pg_dump -Fc vpnhub > /root/vpnhub-pre-v0.5.dump
cp -a /etc/vpnhub/vpnhub.env /root/vpnhub.env.pre-v0.5
~~~

Copie a v0.5 sobre /opt/vpnhub, preservando
/etc/vpnhub/vpnhub.env, e execute:

~~~bash
cd /opt/vpnhub
./scripts/upgrade-v0.5.sh
~~~

A migração:

1. cria vpn_instances;
2. cria a Instance Principal;
3. associa Sites e Admin Peers existentes a ela;
4. converte unicidades globais em unicidades por Instance/Site;
5. sincroniza os dados da Instance com o .env real;
6. corrige ownership/permissões do código e runtime;
7. reinicia controller, reconcile e portal.

## Verificação

~~~bash
systemctl status vpnhub-controller vpnhub-reconcile vpnhub --no-pager

wg show wg0
ip route show proto 186
nft list table inet vpnhub

cd /opt/vpnhub
source venv/bin/activate
set -a
source /etc/vpnhub/vpnhub.env
set +a
python scripts/status.py
~~~

## Testes

~~~bash
pip install -r requirements-dev.txt
pytest -q
~~~

## Próxima camada de complexidade

Quando houver necessidade real de mais árvores, o passo seguinte será tornar o
controller multi-instance através de uma **registry root-owned** de interfaces
permitidas e então expor gerenciamento de VPN Instances no portal.

VRF/policy routing e Networks sobrepostas continuam fora da v0.5; serão
tratados somente quando houver caso real que justifique essa complexidade.
