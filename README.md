# Desafio de Auditoria de Segurança: Ataques de Força Bruta e Análise de Vulnerabilidades

## Objetivos do Desafio

Este projeto foi desenvolvido como parte de um bootcamp de cibersegurança com o objetivo de aplicar e documentar conhecimentos em auditoria de segurança e testes de penetração.

Os objetivos de aprendizagem propostos foram integralmente alcançados:

* Compreender ataques de força bruta em diferentes serviços (SSH) e explorar vulnerabilidades de autenticação (JWT).
* Utilizar ferramentas de segurança como Nmap, Metasploit, Hydra e Burp Suite em ambiente controlado.
* Documentar processos técnicos de forma clara e estruturada.
* Reconhecer vulnerabilidades comuns e propor medidas de mitigação.
* Utilizar o GitHub como portfólio técnico para compartilhar documentação e evidências.

## Ambiente de Auditoria

O ambiente de testes foi configurado para simular um cenário real de auditoria de segurança, utilizando máquinas virtuais em uma rede interna isolada, conforme as melhores práticas de laboratório.

### Máquina Atacante (Attacker)

| Detalhe                       | Configuração                                                                                                                                                  |
| :---------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Sistema Operacional** | Arch Linux (Distribuição de preferência do auditor)                                                                                                          |
| **Ferramentas**         | Nmap, Metasploit, Hydra, Burp Suite, e ferramentas nativas do Linux.                                                                                            |
| **Observação**        | O uso do Arch Linux substituiu o Kali Linux, demonstrando proficiência e flexibilidade no uso de ferramentas de cibersegurança em diferentes distribuições. |

**Instalação do Kali Linux (Referência):**

Para fins de referência, a instalação do Kali Linux em ambiente virtual (ex: VirtualBox) pode ser realizada seguindo os passos:

1. Acessar o site oficial do Kali Linux.
2. Selecionar a imagem para máquina virtual.
3. Após o download, extrair o arquivo e importar a imagem para o software de virtualização.

### Máquina Alvo (Target)

| Detalhe                    | Configuração                                              |
| :------------------------- | :---------------------------------------------------------- |
| **Cenário 1 (SSH)** | Metasploitable 3 (Ubuntu 14.04 LTS)                         |
| **Cenário 2 (JWT)** | Aplicação Web pública e vulnerável (brokencrystals.com) |
| **Rede**             | Isolada (ex:`vboxnet0` com faixa de IP `192.168.56.X`). |

**Instalação do Metasploitable 3 (Vagrant):**

A instalação do Metasploitable 3 requer o uso do Vagrant e pode ser feita seguindo os passos abaixo. O build é automático, subindo um ambiente Linux ou Windows conforme o sistema operacional do host.

```bash
# 1. Criar um diretório de trabalho
mkdir metasploitable3-workspace
cd metasploitable3-workspace

# 2. Baixar o Vagrantfile e iniciar o ambiente
curl -O https://raw.githubusercontent.com/rapid7/metasploitable3/master/Vagrantfile
vagrant up
```

Para subir as imagens específicas:

* **Linux (Ubuntu 14.04):** `vagrant up ub1404`
* **Windows (Server 2008):** `vagrant up win2k8`

---

## Documentação dos Ataques

Dois cenários de ataque distintos foram documentados em detalhes, cobrindo diferentes vetores de vulnerabilidade e técnicas de exploração.

### 1. Ataque de Força Bruta em Serviço SSH e Escalação de Privilégios

Este ataque focou na exploração de senhas fracas em um serviço SSH, seguido por uma escalação de privilégios devido a uma configuração insegura do `sudoers`.

* **Ferramentas Utilizadas:** Nmap (para enumeração), Metasploit (para enumeração de usuários), Hydra (para brute-force de senha) e técnicas de ofuscação (`proxychains`, `nmap -D`).
* **Vulnerabilidade Principal:** Credenciais padrão (`vagrant:vagrant`) e configuração `NOPASSWD: ALL` para o usuário `vagrant`.
* **Documentação Completa:** Consulte o arquivo [attack-ssh.md](./attack-ssh.md) para detalhes sobre a metodologia, comandos utilizados e evidências da exploração até o acesso root.
* **Evidências Visuais:** As capturas de tela e o passo a passo estão organizados na pasta `Img-SSH/`.

### 2. Exploração de Vulnerabilidade JWT: JWK Injection Attack

Este cenário abordou uma vulnerabilidade de alto nível em aplicações web que utilizam JSON Web Token (JWT) para autenticação, demonstrando como contornar a validação de assinatura.

* **Ferramentas Utilizadas:** Burp Suite (para interceptação e repetição de requisições), token.dev e mkjwk.org (para análise e geração de chaves).
* **Vulnerabilidade Principal:** **JWK Injection Attack**. A aplicação confiava no parâmetro `jwk` (JSON Web Key) presente no cabeçalho do token, permitindo que o atacante injetasse sua própria chave pública. Isso possibilitou a criação de um token auto-assinado, com o payload modificado para `{"user":"admin"}`, resultando em escalação de privilégios.
* **Documentação Completa:** Consulte o arquivo [attack-auth-jwt.md](./attack-auth-jwt.md) para a análise da vulnerabilidade, o processo detalhado de ataque e a validação do token de administrador.
* **Evidências Visuais:** As capturas de tela e o passo a passo estão organizados na pasta `Img-JWT/`.

---

## Vulnerabilidades e Mitigações Propostas

A documentação dos ataques permitiu o reconhecimento das seguintes vulnerabilidades e a proposição de medidas de mitigação:

### Vulnerabilidade 1: Senhas Fracas e Configuração Insegura (SSH)

| Vulnerabilidade                           | Descrição                                                                                                                                               | Mitigação Proposta                                                                                                                                                            |
| :---------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Credenciais Fracas/Padrão**      | A capacidade de quebrar credenciais via força bruta (Hydra) indica a presença de senhas fáceis de adivinhar ou credenciais padrão.                    | **Políticas de Senha Fortes:** Impor complexidade (tamanho mínimo, caracteres especiais) e proibir o uso de senhas padrão ou comuns.                                   |
| **Ausência de Bloqueio**           | O serviço SSH não implementou mecanismos de bloqueio após múltiplas tentativas falhas.                                                                | **Configuração de Fail2Ban/Limitadores de Taxa:** Implementar ferramentas como o Fail2Ban para bloquear IPs que tentarem múltiplos logins falhos em um curto período. |
| **Configuração Insegura de Sudo** | O usuário comprometido (`vagrant`) possuía permissão `NOPASSWD: ALL`, permitindo escalação de privilégios para root sem a necessidade de senha. | **Princípio do Menor Privilégio:** Remover `NOPASSWD: ALL`. Conceder permissões de `sudo` apenas para comandos essenciais e específicos, exigindo sempre a senha. |

### Vulnerabilidade 2: JWK Injection em Aplicações Web (JWT)

| Vulnerabilidade                       | Descrição                                                                                                                                                                                          | Mitigação Proposta                                                                                                                                                                                                                                                                |
| :------------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **JWK Injection Attack**        | A aplicação confiava no parâmetro `jwk` do cabeçalho do JWT para obter a chave pública de validação, permitindo que o atacante injetasse sua própria chave e assinasse um token malicioso. | **Validação Estrita da Chave:** O servidor deve ignorar o parâmetro `jwk` e validar o token apenas com chaves públicas pré-configuradas e conhecidas (ex: armazenadas em um JWKS endpoint seguro ou localmente). Nunca confiar na chave pública enviada pelo cliente. |
| **Escalação de Privilégio**  | A modificação do payload para `{"user":"admin"}` foi aceita, resultando em acesso indevido.                                                                                                      | **Validação de Payload:** Além da assinatura, o servidor deve validar se o usuário do token tem permissão para acessar o recurso solicitado, e não apenas confiar no valor do campo `user` dentro do token.                                                           |
| **Exposição de Informação** | O payload do JWT (ex:`{"user":"admin"}`) é facilmente decodificável (base64).                                                                                                                    | **Princípio de Não Confiança:** Nunca colocar informações sensíveis ou de controle de acesso (como permissões detalhadas) no payload, apenas identificadores. A autorização deve ser feita no backend após a validação do token.                                  |

---

## 📂 Estrutura do Repositório

O repositório está organizado da seguinte forma para facilitar a visualização e a auditoria do projeto:

```
.
├── Imagens/
│   ├── Img-SSH/            # Pasta com capturas de tela do ataque SSH.
│   └── Img-JWT/            # Pasta com capturas de tela do ataque JWT.
└── [OutrosArquivos]        # (Ex: wordlists utilizadas, scripts, etc.)
├── attack-auth-jwt.md      # Relatório detalhado do ataque de JWK Injection em JWT.
├── attack-ssh.md           # Relatório detalhado do ataque de força bruta SSH e escalação de privilégios.  
└── README.md               # Documentação principal do projeto.


```
