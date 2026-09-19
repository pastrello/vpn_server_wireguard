# VPNHub Portal v0.6

VPNHub centraliza conexões WireGuard para Sites remotos, inclusive redes atrás
de NAT/CGNAT, com portal operacional, isolamento nftables, status e geração de
configurações.

A v0.6 ativa a arquitetura multi-trunk preparada na v0.5.

## Modelo multi-trunk

Cada trunk é uma VPN Instance independente:

~~~text
VPNHub
├── Principal / wg0
│   ├── UDP 51820
│   ├── 10.250.0.0/16
│   ├── chave WireGuard própria
│   ├── Admin Peers
│   └── Sites
│
├── Clientes ERP / wg1
│   ├── UDP 51821
│   ├── 10.251.0.0/16
│   ├── chave WireGuard própria
│   ├── Admin Peers
│   └── Sites
│
└── Infra / wg2
    ├── UDP 51822
    ├── 10.252.0.0/16
    ├── chave WireGuard própria
    ├── Admin Peers
    └── Sites
~~~

Sites e Admin Peers pertencem a uma única VPN Instance. Um Peer comum pertence
ao Site e, por consequência, ao trunk desse Site.

## Criação de trunk

No portal:

~~~text
Trunks WireGuard
    -> Novo trunk
~~~

O operador informa:

- nome;
- endpoint público;
- porta UDP local;
- VPN pool.

O portal **não escolhe** o nome da interface, caminho da chave ou PublicKey.

O controller root-owned:

1. valida porta e pool;
2. confere conflitos com a registry e rotas locais;
3. escolhe o próximo wgN;
4. cria /etc/wireguard/vpnhub-wgN.key;
5. deriva a PublicKey;
6. grava a Instance na registry root-owned;
7. devolve somente os metadados necessários ao portal;
8. o portal cria o registro correspondente no PostgreSQL;
9. um reconcile aplica WireGuard, rotas e nftables.

## Registry root-owned

As interfaces autorizadas ficam em:

~~~text
/etc/wireguard/vpnhub-instances.json
~~~

Permissões esperadas:

~~~text
root:root 0600
~~~

A registry guarda, para cada trunk:

- interface;
- listen port;
- VPN pool;
- server address;
- private-key path;
- PublicKey;
- route protocol.

Durante o sync, os valores enviados pelo portal precisam coincidir com a
registry. Portanto alterar somente o PostgreSQL não autoriza o portal a criar
uma interface arbitrária, trocar caminho de chave ou usar outra porta/pool.

A PublicKey também é validada contra a registry. No bootstrap da Instance
Principal, a PublicKey é derivada da PrivateKey real e comparada ao valor
configurado no ambiente.

## Isolamento

O nftables continua sendo a camada principal de política.

Existe uma única tabela:

~~~text
table inet vpnhub
~~~

mas sets e regras são separados por VPN Instance e por Site.

Conceitualmente:

~~~text
Admin wg0 -> Sites wg0     ALLOW
Site A wg0 -> Site A wg0   ALLOW
Site A wg0 -> Site B wg0   DROP

Admin wg1 -> Sites wg1     ALLOW
Site C wg1 -> Site C wg1   ALLOW
Site C wg1 -> Site D wg1   DROP

wg0 -> wg1                 DROP
wg1 -> wg0                 DROP
~~~

## Limite deliberado da v0.6

A v0.6 ainda usa a tabela principal de roteamento Linux. Portanto **Networks
LAN sobrepostas não são permitidas**, mesmo que estejam em trunks diferentes.

Exemplo recusado:

~~~text
wg0 / Cliente A -> 192.168.1.0/24
wg1 / Cliente B -> 192.168.1.0/24
~~~

Esse problema será tratado somente quando houver necessidade real de
VRF/policy routing.

Os VPN pools também não podem se sobrepor.

## IPAM

Cada Instance possui seu próprio pool.

Para um /16:

~~~text
10.251.0.0/24   Admin Peers
10.251.1.0/24   Site 1
10.251.2.0/24   Site 2
...
~~~

Isso é independente do IPAM de wg0.

## Dashboard e Status

O Dashboard trabalha com um trunk selecionado e possui seletor rápido entre as
Instances.

A tela:

~~~text
/status
~~~

mostra todos os trunks e todos os Peers, incluindo a coluna do trunk de origem.

Estados de Peer:

~~~text
ONLINE   handshake <= WG_ONLINE_SECONDS
IDLE     <= WG_IDLE_SECONDS
OFFLINE  acima do limite
NEVER    nunca conectou
~~~

## Dark mode

O modo claro/escuro continua disponível no portal e na tela de login. A
preferência é persistida no navegador.

## Segurança Portal / Controller

~~~text
Flask / Gunicorn
User=vpnhub
      |
      | Unix socket + SO_PEERCRED
      v
Controller root
      |
      +-- root registry
      +-- WireGuard wgX
      +-- ip route
      +-- nftables
      +-- firewalld
~~~

Proteções relevantes:

- /opt/vpnhub root-owned e não gravável pelo portal;
- /run/vpnhub root:vpnhub;
- somente /run/vpnhub/secrets é gravável por vpnhub;
- socket valida UID com SO_PEERCRED;
- request/response limitados a 1 MiB;
- PrivateKeys ficam sob /etc/wireguard;
- nomes de chave aceitos são limitados aos arquivos VPNHub;
- registry é root-owned;
- PublicKey da Instance é vinculada à chave/registry;
- interface/porta/pool/endereço/path/route protocol precisam coincidir com a
  registry para o sync.

## Upgrade v0.5 -> v0.6

Antes:

~~~bash
pg_dump -Fc vpnhub > /root/vpnhub-pre-v0.6.dump
cp -a /etc/vpnhub/vpnhub.env /root/vpnhub.env.pre-v0.6
cp -a /etc/wireguard /root/wireguard-pre-v0.6
~~~

Depois de atualizar os arquivos para a v0.6:

~~~bash
cd /opt/vpnhub
./scripts/upgrade-v0.6.sh
~~~

O upgrade:

1. aplica a migration marcador da v0.6;
2. sincroniza a Instance Principal no banco;
3. cria /etc/wireguard/vpnhub-instances.json a partir do wg0 existente;
4. preserva a chave atual de wg0;
5. instala os services;
6. executa reconcile;
7. reinicia o portal.

## Verificação após upgrade

~~~bash
systemctl status vpnhub-controller vpnhub-reconcile vpnhub --no-pager

cat /etc/wireguard/vpnhub-instances.json
wg show
ip -br addr show type wireguard
ip route show proto 186
nft list table inet vpnhub
~~~

Para a primeira validação, confirme que **wg0 continua funcionando exatamente
como antes** antes de criar wg1.

## Primeiro teste wg1

Sugestão para o laboratório:

~~~text
Nome:       Teste WG1
Endpoint:   mesmo hostname público, porta 51821
Listen UDP: 51821
VPN pool:   10.251.0.0/16
~~~

Depois confira:

~~~bash
wg show wg0
wg show wg1
ss -lunp | grep -E '51820|51821'
ip -br addr show wg0
ip -br addr show wg1
nft list table inet vpnhub
~~~

Crie então:

1. um Site em wg1;
2. um Gateway nesse Site;
3. um Admin Peer em wg1;
4. valide conexão;
5. confirme que o Admin Peer de wg0 não acessa Sites de wg1 e vice-versa.

## HTTPS

HTTPS continua opcional no laboratório fechado. O helper Caddy permanece no
projeto, mas não é requisito para o teste multi-trunk.

Antes de introduzir autenticação RADIUS/credenciais de usuário, HTTPS passará a
ser requisito operacional.

## Testes

~~~bash
pip install -r requirements-dev.txt
pytest -q
~~~

O CI também valida compilação Python e sintaxe dos scripts shell.

## Próximas camadas

Fora do escopo da v0.6:

- VRF/policy routing para LANs sobrepostas;
- HA/redundância de Gateway;
- autenticação RADIUS e authorization leases;
- accounting RADIUS;
- cliente VPNHub dedicado.
