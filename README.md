# Trabalho 2 - Chat Seguro e Fluxo Kerberos (Educacional)

Este diretório contém uma implementação didática de dois cenários de segurança:

1. Chat seguro cliente-servidor com autenticação, abertura de canal e proteção de integridade.
2. Fluxo Kerberos simplificado (AS, TGS e serviço de chat) para estudo de autenticação distribuída.

## Objetivos do projeto

- Demonstrar autenticação com desafio-resposta.
- Estabelecer chave de sessão por canal entre participantes.
- Proteger mensagens com confidencialidade, integridade e autenticidade.
- Simular o fluxo Kerberos clássico: AS_REQ/AS_REP, TGS_REQ/TGS_REP e AP_REQ/AP_REP.

## Arquitetura Kerberos explicada passo a passo

Nesta implementação, o KDC (Key Distribution Center) é composto por dois serviços:

- AS (Authentication Server): autentica o usuário inicialmente.
- TGS (Ticket Granting Server): emite ticket para acesso ao serviço final.

Além disso, existe um "banco Kerberos" didático (estrutura de dados em memória) com os principals e chaves de longo prazo.

### Participantes e papéis

- Cliente (usuário): inicia autenticação e solicita tickets.
- AS: valida identidade e emite TGT.
- TGS: valida TGT e emite Service Ticket.
- Service Server (chat): valida Service Ticket e libera o acesso.

### Fluxo sequencial (visão do professor)

1. Usuário informa login e senha no cliente.
2. O cliente envia AS_REQ ao AS com: username, timestamp e nonce.
3. O AS consulta o "banco Kerberos" para validar o usuário.
4. Se válido, o AS responde com AS_REP contendo:
- TGT (Ticket Granting Ticket), cifrado com a chave do TGS.
- Chave de sessão cliente-TGS, cifrada com a chave de longo prazo do usuário.
5. O cliente decripta AS_REP com sua chave derivada da senha e guarda TGT + chave cliente-TGS.
6. Quando precisa acessar um serviço, o cliente envia TGS_REQ ao TGS com:
- TGT recebido do AS.
- Authenticator (username, timestamp, nonce) cifrado com a chave cliente-TGS.
- Nome do serviço desejado.
7. O TGS valida TGT, validade temporal e Authenticator (incluindo proteção contra replay).
8. Se tudo estiver correto, retorna TGS_REP contendo:
- Service Ticket cifrado com a chave do serviço.
- Chave de sessão cliente-serviço, cifrada com a chave cliente-TGS.
9. O cliente envia AP_REQ ao Service Server com:
- Service Ticket.
- Novo Authenticator cifrado com a chave cliente-serviço.
10. O servidor valida ticket e Authenticator; se válido, responde AP_REP (autenticação mútua).
11. Com a sessão estabelecida, as mensagens de chat seguem cifradas e com verificação de integridade/autenticidade.

### O que garante segurança neste fluxo

- Senha não é reenviada ao serviço final.
- Tickets são temporários (expiração por TTL).
- Authenticators usam timestamp + nonce para reduzir replay.
- Cada etapa usa chaves específicas (longo prazo, cliente-TGS, cliente-serviço).
- O serviço só aceita ticket emitido pelo TGS para aquele serviço.

Resumo: o usuário autentica uma vez no AS e, a partir disso, usa tickets temporários para acessar serviços sem reapresentar a senha.

## Estrutura

```text
Chat_Seguro_Fluxo_Kerberos/
  run.py
  test_integrity_demo.py
  src/
    authentication_server.py
    chat_server.py
    client.py
    common.py
    config.py
    secure_chat.py
    ticket_granting_server.py
    crypto/
      feistel.py
      kdf.py
      utils.py
  tests/
    test_crypto.py
    test_flow.py
```

## Requisitos

- Python 3.10+
- Dependências: somente biblioteca padrão do Python

## Como executar

No terminal, entre na pasta do trabalho:

```bash
cd Chat_Seguro_Fluxo_Kerberos
```

### Opção A: Menu interativo principal

```bash
python run.py
```

O menu oferece:

1. Servidor de chat seguro.
2. Cliente de chat seguro (usa os servidores da opcao 1).
3. Kerberos: fluxo completo + menu do cliente.

No modo 3, o terminal exibe o passo a passo das etapas Kerberos (AS_REQ/AS_REP, TGS_REQ/TGS_REP, AP_REQ/AP_REP) e, ao finalizar a autenticacao, abre um menu do cliente logado para continuar a interacao.
Nesse modo, AS/TGS/Chat Kerberos sobem em portas livres dinamicas mostradas no terminal para evitar conflito com instancias ja em execucao.
No modo 2, o cliente autentica no ecossistema Kerberos (AS_REQ/AS_REP, TGS_REQ/TGS_REP e AP_REQ/AP_REP) e, em seguida, abre o menu interativo de chat seguro com as opcoes de listar usuarios online, abrir canal seguro, enviar mensagem e sair.
No modo 1, sao iniciados AS (8888), TGS (8889), Servico Kerberos (9998) e o chat seguro interativo (9999).
As portas dinamicas sao exclusivas do modo 3.

### Opção B: Demonstração automática de integridade

Executa um cenário completo com dois clientes (alice e bob), incluindo envio íntegro e envio adulterado.

```bash
python test_integrity_demo.py
```

Resultado esperado:

- Mensagem íntegra: entregue com sucesso.
- Mensagem adulterada: detectada/rejeitada por validação de integridade.
- Autenticidade: validada no fluxo de comunicação.

## Execução em duas janelas (chat seguro)

1. Janela 1: iniciar servidor

```bash
python run.py
```

Escolha a opção 1.

2. Janela 2: iniciar cliente

```bash
python run.py
```

Escolha a opção 2 e autentique com um usuário de demonstração.

Usuários de demonstração:

- alice / alice123
- bob / bob123
- carol / carol123

## Testes automatizados

Pela raiz de Chat_Seguro_Fluxo_Kerberos:

```bash
python -m unittest discover -s tests -v
```

Cobertura principal:

- Criptografia básica (roundtrip) e derivação de chave PBKDF2: tests/test_crypto.py
- Fluxo Kerberos ponta a ponta: tests/test_flow.py

## Validação com Wireshark (para correção)

Para o professor validar confidencialidade no tráfego:

1. Inicie a captura no Wireshark na interface de loopback (Npcap Loopback Adapter, no Windows).
2. Aplique o filtro:

```text
tcp.port == 9999 || tcp.port == 8888 || tcp.port == 8889
```

Para o modo 3 (Kerberos completo), o AS/TGS/Chat usam portas dinamicas. Entao o filtro precisa usar as portas exibidas no terminal nessa execucao.

Exemplo (se o terminal mostrar AS=62612, TGS=62814, Chat Kerberos=62815):

```text
tcp.port == 62612 || tcp.port == 62814 || tcp.port == 62815
```

Se quiser ver tambem o chat seguro interativo no mesmo filtro, inclua a 9999:

```text
tcp.port == 9999 || tcp.port == 62612 || tcp.port == 62814 || tcp.port == 62815
```

3. Em paralelo, rode o projeto (por exemplo `python run.py`) e execute o fluxo de autenticação/chat.
4. No Wireshark, confirme que:

- Porta 8888 (AS): troca de mensagens AS_REQ/AS_REP sem conteúdo textual sensível em claro.
- Porta 8889 (TGS): troca TGS_REQ/TGS_REP sem credenciais/chaves em texto legível.
- Porta 9999 (Chat seguro interativo): mensagens de aplicacao trafegam em formato cifrado/serializado, sem o texto original em claro.
- Chat Kerberos no modo 3: AP_REQ/AP_REP e CHAT_MSG trafegam sem expor conteudo sensivel em texto plano na porta dinamica exibida no terminal.

Observação: como o projeto é didático, os campos de protocolo são legíveis, mas o conteúdo protegido (tickets, autenticadores e payload de chat) não deve aparecer em texto plano.

## Configurações importantes

Parâmetros globais ficam em src/config.py:

- Endereços e portas (AS, TGS, Chat)
- Porta dedicada do Chat Kerberos (`KERBEROS_CHAT_PORT`)
- TTL de tickets
- Tamanho de chave
- Iterações PBKDF2
- Principals de serviço

## Visão rápida dos módulos

- src/authentication_server.py: emite TGT no AS_REP.
- src/ticket_granting_server.py: valida TGT/autenticador e emite service ticket.
- src/chat_server.py: valida AP_REQ e processa mensagens protegidas.
- src/client.py: cliente Kerberos educacional (cache de tickets/chaves).
- src/secure_chat.py: servidor e cliente de chat interativo seguro.
- src/crypto/: utilitários criptográficos (KDF, Feistel, helpers).

## Observações

- Projeto com foco acadêmico/didático.
- Não deve ser usado como base direta para produção sem hardening, auditoria e revisão criptográfica formal.
