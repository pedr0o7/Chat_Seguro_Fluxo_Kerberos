# Trabalho 2 - Chat Seguro e Fluxo Kerberos (Educacional)

Este diretório contém uma implementação didática de dois cenários de segurança:

1. Chat seguro cliente-servidor com autenticação, abertura de canal e proteção de integridade.
2. Fluxo Kerberos simplificado (AS, TGS e serviço de chat) para estudo de autenticação distribuída.

## Objetivos do projeto

- Demonstrar autenticação com desafio-resposta.
- Estabelecer chave de sessão por canal entre participantes.
- Proteger mensagens com confidencialidade, integridade e autenticidade.
- Simular o fluxo Kerberos clássico: AS_REQ/AS_REP, TGS_REQ/TGS_REP e AP_REQ/AP_REP.

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
      dh.py
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
2. Cliente de chat seguro.
3. Demonstração Kerberos educacional.

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

## Configurações importantes

Parâmetros globais ficam em src/config.py:

- Endereços e portas (AS, TGS, Chat)
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
