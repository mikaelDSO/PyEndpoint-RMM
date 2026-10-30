# 🛰️ PyEndpoint-RMM

**Remote Monitoring & Agent Framework** — um framework leve, auditável e 100% Python para monitorar e administrar estações de trabalho de uma rede que **você administra**, usando apenas uma pasta compartilhada como "fila de mensagens".

![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)
![Plataformas](https://img.shields.io/badge/plataformas-Windows%20%7C%20Linux-informational)
![Licença](https://img.shields.io/badge/licença-MIT-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Assinatura](https://img.shields.io/badge/comandos-assinados%20Ed25519-success)
![Sem dependência de servidor](https://img.shields.io/badge/infra-sem%20servidor%20dedicado-lightgrey)
![Testes](https://github.com/mikaelDSO/PyEndpoint-RMM/actions/workflows/tests.yml/badge.svg)

---

## 📑 Sumário

1. [Visão geral](#-visão-geral)
2. [Arquitetura](#-arquitetura)
3. [Estrutura do repositório](#-estrutura-do-repositório)
4. [Instalação](#-instalação)
5. [Configuração](#-configuração)
6. [Exemplos de uso](#-exemplos-de-uso)
7. [Guia de segurança](#-guia-de-segurança)
8. [Privacidade e conformidade](#-privacidade-e-conformidade)
9. [Testes](#-testes)
10. [Roadmap](#-roadmap)
11. [Contribuindo](#-contribuindo) · [Licença](#-licença) · [Aviso legal](#-aviso-legal)

---

## 🔎 Visão geral

| Componente | Arquivo | Função |
|---|---|---|
| **Agente** | `agent.py` / `agent.bat` | Roda em segundo plano, publica *heartbeat*, lê comandos **assinados** do diretório compartilhado e os executa de forma restrita. |
| **Painel ADM** | `dashboard.py` / `dashboard.bat` | CLI com autenticação por senha e sessão com timeout. Assina e envia comandos (reiniciar, rodar scripts, atualizar executáveis). |
| **Notificador** | `ticket_notifier.py` / `notifier.bat` | Roda na sessão do usuário: exibe avisos da TI e facilita a abertura de chamados. |
| **Núcleo** | `rmm_common.py` | Logging, assinatura, keystore cifrado, escrita atômica e validações. |

**Por que usar uma pasta compartilhada como fila?** Zero infraestrutura extra: funciona com um compartilhamento SMB, NFS ou uma pasta sincronizada. Como todo comando é **assinado**, o diretório compartilhado é tratado como *não confiável* — quem consegue escrever nele não consegue mandar o agente executar nada.

### Princípios de projeto

- **Transparência** — o usuário é avisado antes de reinícios; o agente não se oculta nem coleta telas, teclas ou conteúdo de arquivos.
- **Autorização explícita** — nada executa sem assinatura válida do ADM.
- **Menor privilégio** — tipos de comando fechados; sem `shell=True`; atualizações só em pastas permitidas.
- **Auditável** — log rotativo no agente, `audit.jsonl` no painel, resultado de cada comando gravado.
- **Fail-safe** — rede fora do ar nunca derruba o agente; comando repetido nunca é reexecutado.

---

## 🏗️ Arquitetura

### Visão de componentes

```
   MÁQUINA DO ADMINISTRADOR                 SERVIDOR DE ARQUIVOS               ESTAÇÕES (N)
 ┌───────────────────────────┐        ┌─────────────────────────┐     ┌──────────────────────────────┐
 │  dashboard.py             │        │   \\SERVIDOR\rmm_share  │     │  agent.py  (SYSTEM / root)   │
 │  ─ login (senha)          │ grava  │                         │ lê  │  ─ verifica assinatura       │
 │  ─ chave PRIVADA cifrada  ├───────►│  commands/<agent>/*.json├────►│  ─ valida alvo/validade      │
 │  ─ assina (Ed25519)       │        │  commands/_all/*.json   │     │  ─ anti-replay               │
 │  ─ audit.jsonl            │        │  payloads/  (scripts)   │     │  ─ executa (lista fechada)   │
 │                           │  lê    │                         │grava│                              │
 │  agents / results /       │◄───────┤  heartbeats/<agent>.json│◄────┤  ─ heartbeat + resultados    │
 │  tickets                  │        │  results/<agent>/*.json │     │                              │
 └───────────────────────────┘        │  tickets/<agent>/*.json │     │            │ spool local     │
                                      └────────────▲────────────┘     │            ▼ (somente texto) │
                                                   │ grava chamado    │  ticket_notifier.py (usuário)│
                                                   └──────────────────┤  ─ janela de aviso           │
                                                                      │  ─ "Abrir chamado"           │
                                                                      └──────────────────────────────┘
```

### Ciclo de vida de um comando

```
 ADM                       Compartilhamento                 Agente
  │  1. login (senha)             │                            │
  │  2. monta comando + TTL       │                            │
  │  3. assina com chave privada  │                            │
  │ ────── grava .json ─────────► │                            │
  │                               │ ◄──── poll (5 s) ───────── │
  │                               │ ──── envia .json ────────► │
  │                               │          4. verifica assinatura (chave pública)
  │                               │          5. alvo == este agente?  não expirou?  id inédito?
  │                               │          6. registra id (anti-replay) ANTES de executar
  │                               │          7. executa handler da lista fechada
  │                               │ ◄── results/<id>.json ──── │
  │ ◄─── dashboard results ─────  │                            │
```

### Layout do compartilhamento

```
rmm_share/
├── commands/
│   ├── PC-FINANCEIRO-01/     ← comandos para um agente específico
│   └── _all/                 ← broadcast (alvo "*")
├── payloads/                 ← scripts/executáveis publicados pelo ADM
├── heartbeats/               ← PC-FINANCEIRO-01.json (estado, 1 arquivo por agente)
├── results/PC-FINANCEIRO-01/ ← <id-do-comando>.json
└── tickets/PC-FINANCEIRO-01/ ← chamados abertos pelo usuário
```

---

## 📁 Estrutura do repositório

```
PyEndpoint-RMM/
├── agent.py                  # agente (serviço)
├── agent.bat                 # launcher Windows com auto-restart
├── dashboard.py              # painel ADM (CLI)
├── dashboard.bat
├── ticket_notifier.py        # notificador/abertura de chamados (usuário)
├── notifier.bat
├── rmm_common.py             # núcleo compartilhado
├── requirements.txt
├── config/
│   ├── agent.example.json
│   └── dashboard.example.json
├── scripts/
│   ├── install_windows.bat   # instala agente + notificador
│   └── uninstall_windows.bat
├── tests/test_end_to_end.py
├── .gitignore  .gitattributes  LICENSE
└── README.md
```

---

## ⚙️ Instalação

**Requisitos:** Python 3.9+, um compartilhamento de rede acessível por ADM e estações. No Linux, para a GUI: `sudo apt install python3-tk`.

### 1. Máquina do administrador

```bash
git clone https://github.com/mikaelDSO/PyEndpoint-RMM.git
cd PyEndpoint-RMM
python -m venv venv && venv\Scripts\activate        # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt

# Cria o par de chaves (privada cifrada por senha) e as pastas do compartilhamento
python dashboard.py init --shared-dir \\SERVIDOR\rmm_share
```

O `init` pede uma senha (mínimo de 12 caracteres) e gera, em `%APPDATA%\PyEndpointRMM-Admin\`:

| Arquivo | Destino |
|---|---|
| `admin_key.json` | **Fica só com o administrador.** Chave privada cifrada (scrypt + AES-GCM). |
| `admin_pub.pem` | Distribuído aos agentes. É público. |
| `dashboard.json` | Configuração do painel. |

### 2. Estações Windows (agente + notificador)

Em um prompt **como Administrador**, na pasta do repositório:

```bat
scripts\install_windows.bat
```

O script copia o projeto para `%ProgramFiles%\PyEndpointRMM` (pasta que usuários comuns não alteram), cria o venv, restringe as permissões de `%ProgramData%\PyEndpointRMM` e registra as tarefas agendadas `PyEndpointRMM-Agent` (SYSTEM, na inicialização) e `PyEndpointRMM-Notifier` (no logon do usuário). **Nada é iniciado automaticamente.** Depois:

```bat
copy admin_pub.pem "%ProgramData%\PyEndpointRMM\admin_pub.pem"
notepad "%ProgramData%\PyEndpointRMM\agent.json"      :: ajuste shared_dir e allowed_update_dirs
schtasks /run /tn "PyEndpointRMM-Agent"
type "%ProgramData%\PyEndpointRMM\logs\agent.log"
```

> 💡 **Comece com `"dry_run": true`.** O agente valida e registra tudo, mas não executa nada. Confirme que o fluxo funciona e só então mude para `false`.

Para implantação em massa, use GPO/Intune/SCCM executando `scripts\install_windows.bat /silent`.

Desinstalar: `scripts\uninstall_windows.bat` (acrescente `/purge` para apagar configuração e logs).

### 3. Estações Linux (manual)

```bash
sudo mkdir -p /opt/pyendpoint-rmm && sudo cp -r . /opt/pyendpoint-rmm
cd /opt/pyendpoint-rmm && sudo python3 -m venv venv && sudo venv/bin/pip install -r requirements.txt
sudo mkdir -p /var/lib/pyendpoint-rmm && sudo cp config/agent.example.json /var/lib/pyendpoint-rmm/agent.json
sudo cp admin_pub.pem /var/lib/pyendpoint-rmm/
sudo chown -R root:root /opt/pyendpoint-rmm /var/lib/pyendpoint-rmm && sudo chmod -R go-w /opt/pyendpoint-rmm
```

Exemplo de unidade `systemd` (`/etc/systemd/system/pyendpoint-agent.service`):

```ini
[Unit]
Description=PyEndpoint-RMM Agent
After=network-online.target

[Service]
ExecStart=/opt/pyendpoint-rmm/venv/bin/python /opt/pyendpoint-rmm/agent.py --config /var/lib/pyendpoint-rmm/agent.json
Restart=on-failure
RestartPreventExitStatus=2

[Install]
WantedBy=multi-user.target
```

### Permissões do compartilhamento (recomendado)

| Pasta | Contas das estações | Administrador |
|---|---|---|
| `commands/`, `payloads/` | **Leitura** | Modificar |
| `heartbeats/`, `results/` | Modificar | Leitura |
| `tickets/` | Modificar (usuários criam arquivos) | Leitura |

Mesmo que essas permissões sejam mais frouxas do que o recomendado, a assinatura e o hash dos payloads continuam protegendo a execução.

---

## 🧩 Configuração

`agent.json` (também lido pelo `ticket_notifier.py`). Chaves iniciadas por `_` são comentários.

| Chave | Padrão | Descrição |
|---|---|---|
| `agent_id` | hostname | Identificador único (`A-Z a-z 0-9 . _ -`, até 64). |
| `shared_dir` | — | **Obrigatório.** Pasta/UNC compartilhada. |
| `admin_public_key` | `<data_dir>/admin_pub.pem` | Chave pública do ADM. |
| `data_dir` | `%ProgramData%\PyEndpointRMM` | Config, logs, estado, spool. |
| `poll_interval_sec` | `5` | Intervalo de leitura de comandos. |
| `heartbeat_interval_sec` | `30` | Intervalo do heartbeat. |
| `max_command_ttl_sec` | `900` | Validade máxima aceita (comandos com TTL maior são rejeitados). |
| `reboot_delay_sec` | `60` | Atraso padrão do reinício (mínimo imposto: 30 s). |
| `script_timeout_sec` | `300` | Tempo máximo de um script. |
| `allowed_script_exts` | `.bat .cmd .ps1 .py .sh` | Extensões que `run_script` aceita. |
| `allowed_update_dirs` | `[]` | Pastas onde `update` pode gravar. **Vazio = atualização desativada.** |
| `monitored_processes` | `[]` | Processos cujo estado (rodando/parado) vai no heartbeat. |
| `report_logged_users` | `true` | Inclui os nomes dos usuários logados no heartbeat. |
| `dry_run` | `false` | Valida tudo, executa nada. |
| `helpdesk_url` | `""` | (Notificador) URL aberta após criar um chamado. |

---

## 🚀 Exemplos de uso

Tudo é feito a partir do painel. Cada comando pede a senha do ADM (ou usa a sessão aberta).

```bash
# Interativo: autentica uma vez; a sessão expira após 15 min de inatividade
python dashboard.py shell
rmm> agents
rmm> ping --target PC-FINANCEIRO-01
rmm> results -n 5
```

**Ver o parque**

```text
$ python dashboard.py agents
AGENTE                STATUS   VISTO     CPU%   MEM%   DISCO%  SO
PC-FINANCEIRO-01      ONLINE   12s       7.1    48.3   61.0    Windows-11-10.0.22631-SP0
PC-RECEPCAO-02        OFFLINE  3h        -      -      -       Windows-10-10.0.19045-SP0
```

**Testar comunicação e forçar coleta de status**

```bash
python dashboard.py ping   --target PC-FINANCEIRO-01
python dashboard.py status --target PC-FINANCEIRO-01
python dashboard.py results -n 5
```

**Avisar o usuário** (aparece como janela via `ticket_notifier`)

```bash
python dashboard.py notify --target PC-FINANCEIRO-01 --priority warning \
    --title "Manutenção hoje às 18h" --message "Salve seus arquivos antes das 17h50." --ticket CH-2041
```

**Reiniciar** (o usuário é avisado e há atraso mínimo de 30 s; dá para cancelar)

```bash
python dashboard.py reboot --target PC-FINANCEIRO-01 --delay 120 --message "Atualização de segurança"
python dashboard.py cancel-reboot --target PC-FINANCEIRO-01
```

**Rodar um script** — publique primeiro; o painel calcula o SHA-256 e o assina junto do comando

```bash
python dashboard.py payload-add .\limpar_temp.bat
python dashboard.py run-script limpar_temp.bat --target PC-FINANCEIRO-01 --timeout 120
python dashboard.py results -v        # -v mostra a saída do script
```

**Atualizar um executável local** (destino precisa estar em `allowed_update_dirs`; é feito backup `.bak` e troca atômica)

```bash
python dashboard.py payload-add .\app_v2.exe --name app.exe
python dashboard.py update app.exe --target PC-FINANCEIRO-01 --dest "C:\Program Files\MinhaEmpresa\Apps\app.exe"
```

**Todos os agentes** — exige `--all` e confirmação digitando `SIM` (ou `--yes` em automações)

```bash
python dashboard.py reboot --all --delay 300 --message "Reinício mensal"
```

**Lado do usuário**

```bat
notifier.bat --new-ticket    :: abre o formulário de chamado (bom para um atalho na área de trabalho)
notifier.bat --list          :: chamados abertos nesta máquina
```

Chamados chegam ao ADM com `python dashboard.py tickets`.

---

## 🔐 Guia de segurança

> Uma ferramenta que executa ações remotas é, por definição, um alvo valioso. O projeto foi desenhado assumindo que **o compartilhamento e as estações podem ser comprometidos**.

### Autenticação do administrador

1. **Senha → chave.** A chave privada Ed25519 só existe em disco cifrada (**scrypt** `n=2¹⁵` + **AES-256-GCM**). Sem a senha, o arquivo não serve para nada.
2. **Porta única de autenticação.** Todo subcomando (exceto `init`) exige destravar a chave. O `shell` mantém uma **sessão com timeout** (`session_timeout_sec`, 15 min) e pede a senha de novo depois disso.
3. **Atraso crescente** entre tentativas (2 s, 4 s, 8 s) e limite de 3 tentativas; falhas vão para `audit.jsonl`.
4. **Auditoria.** Logins, comandos emitidos (com parâmetros), payloads publicados e logouts são registrados em `audit.jsonl`.

### Integridade dos comandos

| Proteção | Como funciona |
|---|---|
| **Assinatura Ed25519** | O agente só tem a chave **pública**; ele verifica, mas não consegue forjar comandos. |
| **Alvo** | O alvo assinado precisa bater com a pasta (`agent_id` ou `*`). Mover um comando entre pastas não funciona. |
| **Validade (TTL)** | `expires_at` obrigatório; TTL acima de `max_command_ttl_sec` é rejeitado; tolerância de relógio de 120 s. |
| **Anti-replay** | O `id` é gravado em `state.json` **antes** da execução — nem crash nem reboot repetem um comando. |
| **Hash do payload** | `run_script`/`update` carregam o SHA-256 assinado. O agente copia para uma área local protegida, confere o hash e executa **a cópia verificada** (sem janela de TOCTOU). |
| **Lista fechada** | Só existem os tipos `ping status notify reboot cancel_reboot run_script update`. Não há "executar comando arbitrário". |
| **Sem shell** | Todo `subprocess` usa lista de argumentos, sem `shell=True`; argumentos aceitam apenas `A-Za-z0-9_-.:=/\`. |
| **Path traversal** | Nomes e IDs passam por `rmm_common.safe_id`; destinos de `update` são resolvidos e conferidos contra `allowed_update_dirs`. |

### Checklist de hardening


- [ ] **Use senha longa** (frase-senha) e guarde `admin_key.json` apenas na estação do administrador (com backup cifrado).
- [ ] **Instale em pasta não gravável por usuários** (`%ProgramFiles%`). O agente roda como SYSTEM: se um usuário puder editar o código ou o `agent.json`, ele escala privilégios. O instalador já aplica as ACLs corretas.
- [ ] **Deixe `allowed_update_dirs` vazio** onde não precisar de atualização remota.
- [ ] **Restrinja `allowed_script_exts`** ao mínimo (ex.: só `.ps1`).
- [ ] **Permissões do compartilhamento** conforme a tabela da instalação (estações com *leitura* em `commands/` e `payloads/`).
- [ ] **Sincronize os relógios** (NTP/AD) — a validade dos comandos depende disso.
- [ ] **Teste com `dry_run: true`** e com um grupo piloto antes de usar `--all`.
- [ ] **Envie `audit.jsonl` e os logs dos agentes** para o seu SIEM/syslog.
- [ ] **Rotação de chave:** `dashboard.py init --force` gera novo par; redistribua o novo `admin_pub.pem`. Comandos antigos deixam de ser válidos.
- [ ] **Perda ou suspeita de vazamento da senha/chave?** Faça a rotação imediatamente.

### O que o projeto *não* protege (limitações conhecidas)

- Quem tem a **senha do ADM e o `admin_key.json`** pode emitir qualquer comando suportado.
- O notificador consome uma fila local em que usuários têm permissão de escrita (para ele poder remover os avisos). Um usuário local pode, no máximo, exibir um **aviso falso** para si mesmo — nunca executar algo.
- Chamados são dados não autenticados: trate-os como entrada de usuário.
- A comunicação em SMB deve ser protegida por **SMB 3 com criptografia** quando o tráfego atravessar redes não confiáveis; a assinatura protege a integridade, não o sigilo.
- Ainda não há revogação de chave por agente nem *pinning* de versão (veja o roadmap).

---

## 🛡️ Privacidade e conformidade

- O heartbeat contém: hostname, SO, CPU/memória/disco, uptime, estado dos `monitored_processes` e (opcionalmente) os **nomes** dos usuários logados.
- O projeto **não** captura tela, teclado, área de transferência, navegação nem conteúdo de arquivos, e **não** inclui mecanismos de ocultação.
- Implante apenas em equipamentos sob sua responsabilidade, **informe os usuários** (política de uso aceitável / termo de ciência) e, no Brasil, observe a **LGPD** (finalidade, necessidade e transparência). Defina `"report_logged_users": false` se não precisar desse dado.

---

## 🧪 Testes

```bash
python -m unittest discover -s tests -v
```

A suíte cobre: comandos adulterados, assinante desconhecido, replay, expiração, TTL excessivo, alvo trocado, hash divergente, *path traversal*, metacaracteres em argumentos, extensão proibida, `update` fora da lista permitida, troca real de arquivo com backup, heartbeat e keystore.

---

## 🗺️ Roadmap

- [ ] Painel GUI (Tkinter/Textual) além da CLI
- [ ] Revogação de chave e *key IDs* (múltiplos administradores)
- [ ] Transporte alternativo (SQLite/Redis/MQTT) sem trocar o protocolo de assinatura
- [ ] Limpeza automática de `commands/` e `results/` antigos (`dashboard.py purge`)
- [ ] Empacotamento (`pip install`, MSI/NSSM) e serviço Windows nativo
- [ ] Status de chamados de volta ao usuário (ida e volta no notificador)

---

## 🤝 Contribuindo

1. *Fork* → branch (`feat/minha-ideia`) → *pull request*.
2. Rode `python -m unittest discover -s tests` antes de abrir o PR.
3. Mudanças que **ampliem o poder do agente** (novos tipos de comando) precisam de testes de rejeição e de uma seção no guia de segurança.
4. Vulnerabilidades: não abra *issue* pública; contate os mantenedores em privado.

## 📄 Licença

[MIT](LICENSE) © 2026 PyEndpoint-RMM Contributors.

## ⚠️ Aviso legal

Este software destina-se **exclusivamente à administração autorizada** de dispositivos de propriedade da organização ou com consentimento informado de seus usuários. O uso para acessar, monitorar ou controlar sistemas sem autorização é ilegal e contrário aos objetivos do projeto. Os autores não se responsabilizam por uso indevido. O software é fornecido "como está", sem garantias.
