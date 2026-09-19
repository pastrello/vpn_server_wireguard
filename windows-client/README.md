# VPNHub Client for Windows — v0.7 candidate

Primeiro cliente Windows do VPNHub.

## Objetivo

Adicionar uma camada local de senha sem alterar o protocolo WireGuard.

O WireGuard continua usando normalmente PrivateKey, PublicKey do servidor,
PresharedKey, Address, Endpoint e AllowedIPs.

A diferença é que o arquivo persistente do usuário não contém essas
credenciais em claro.

## Fluxo

~~~text
portal VPNHub
    |
    | gera .conf normal
    v
VPNHub Client
    |
    | usuário define senha local
    v
Argon2id
    |
    | chave AES-256
    v
perfil .vpnhub cifrado
~~~

Na conexão:

~~~text
senha
  |
  v
Argon2id
  |
  v
AES-256-GCM decrypt
  |
  v
config WireGuard temporária
  |
  v
wireguard.exe /installtunnelservice
  |
  v
serviço WireGuard Running
  |
  +--> arquivo temporário removido
~~~

O cliente oficial WireGuard continua sendo o motor do túnel.

## Criptografia do bundle

Formato: JSON .vpnhub, versão 1.

KDF padrão:

~~~text
Argon2id
memory:      64 MiB
iterations:  3
parallelism: 2
output:      256 bits
~~~

Cifra:

~~~text
AES-256-GCM
nonce: 96 bits
tag:   128 bits
~~~

O nome do perfil é associado à autenticação AES-GCM; alterar o nome no JSON
também invalida a autenticação.

A senha nunca é gravada no bundle.

## Proteções adicionais

O importador aceita somente as diretivas WireGuard necessárias ao VPNHub.

[Interface]:
- PrivateKey
- Address
- DNS
- MTU

[Peer]:
- PublicKey
- PresharedKey
- AllowedIPs
- Endpoint
- PersistentKeepalive

Diretivas como PreUp, PostUp, PreDown e PostDown são recusadas. O cliente roda
elevado para gerenciar o tunnel service e não deve executar comandos
arbitrários vindos de um .conf.

## Requisitos

- Windows 10/11 x64;
- .NET 8 Desktop Runtime ou publicação self-contained;
- WireGuard for Windows oficial instalado;
- execução elevada via UAC.

## Build

~~~powershell
cd windows-client
dotnet restore .\VPNHub.Client\VPNHub.Client.csproj
dotnet build .\VPNHub.Client\VPNHub.Client.csproj -c Release
dotnet test .\VPNHub.Client.Tests\VPNHub.Client.Tests.csproj -c Release
~~~

## Primeiro teste

1. Gere um Peer comum no portal VPNHub e baixe seu .conf.
2. Abra VPNHub Client.
3. Escolha Importar .conf.
4. Defina uma senha local.
5. O cliente grava %LOCALAPPDATA%\VPNHub\Profiles\<perfil>.vpnhub.
6. Opcionalmente exclua o .conf original.
7. Selecione o perfil, informe a senha e clique Conectar.
8. O cliente instala WireGuardTunnel$VPNHub_<perfil>.
9. Após o serviço ficar Running, a configuração temporária é removida.
10. Clique Desconectar para remover o tunnel service.

## Limitações da primeira candidata

- sem RADIUS;
- sem download direto do portal;
- sem auto-update;
- sem instalador MSI;
- sem tray icon;
- sem recuperação de senha;
- strings gerenciadas usadas durante o import podem permanecer na memória até
  o GC; o caminho de conexão trabalha com bytes e faz zeroização best-effort;
- se o tunnel service reiniciar sozinho após o arquivo temporário ter sido
  removido, o usuário deve reconectar pelo VPNHub Client.

Esses limites são intencionais. Primeiro queremos validar o modelo
senha -> identidade cifrada -> WireGuard oficial.

## Próxima etapa

Depois de validar o cliente local:
- entrega do bundle diretamente pelo portal;
- HTTPS obrigatório;
- identidade/usuário VPNHub;
- RADIUS;
- authorization lease;
- eventualmente TOTP/MFA.
