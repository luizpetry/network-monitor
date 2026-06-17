# Network Monitor

Monitor de rede em tempo real com verificação de IPs maliciosos via AbuseIPDB.

---

## Pré-requisitos

**1. Npcap** (obrigatório no Windows)
- Baixe em: https://npcap.com/
- Durante a instalação, marque **"Install Npcap in WinPcap API-compatible Mode"**

**2. Python 3.8+**
- Baixe em: https://python.org

---

## Instalação

Abra o **PowerShell como Administrador** na pasta `Network_Monitor` e rode:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Se o PowerShell bloquear o `Activate.ps1`, rode antes (uma vez só):
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

---

## Configuração da chave AbuseIPDB

A verificação de IPs maliciosos usa a API do [AbuseIPDB](https://www.abuseipdb.com/account/api), que exige uma chave (gratuita). A chave é lida da variável de ambiente `ABUSEIPDB_KEY`.

A forma recomendada é via arquivo `.env` na pasta do projeto. Há um modelo pronto — copie e preencha:

```powershell
Copy-Item .env.example .env
```

Depois edite o `.env` e coloque a sua chave:

```
ABUSEIPDB_KEY=sua_chave_aqui
```

O programa carrega esse `.env` automaticamente ao iniciar — não é preciso exportar nada.

> **Alternativas:** você também pode definir a variável de ambiente manualmente
> (`$env:ABUSEIPDB_KEY = "..."`) ou passar a chave direto na linha de comando
> (`--abuseipdb-key sua_chave`). Sem nenhuma chave configurada, o monitor roda
> normalmente, apenas com a verificação de reputação desativada.

> ⚠️ **Nunca** versione o arquivo `.env` — ele contém a sua chave. Adicione-o ao `.gitignore`. O `.env.example` (sem a chave real) é que deve ir para o repositório.

---

## Como iniciar

O PowerShell **precisa estar aberto como Administrador** — captura de pacotes exige privilégios elevados.

**Monitorar tudo (interface padrão):**
```powershell
python network_monitor.py
```

**Ver interfaces disponíveis primeiro:**
```powershell
python network_monitor.py --list-ifaces
```

**Escolher uma interface específica:**
```powershell
python network_monitor.py --iface "Wi-Fi"
```

**Filtrar por protocolo:**
```powershell
python network_monitor.py --protocol tcp
python network_monitor.py --protocol udp
python network_monitor.py --protocol icmp
```

**Filtro avançado (BPF):**
```powershell
python network_monitor.py --filter "port 53"
python network_monitor.py --filter "host 8.8.8.8"
```

**Salvar log em CSV:**
```powershell
python network_monitor.py --log traffic.csv
```

**Desativar verificação de IPs maliciosos (modo offline):**
```powershell
python network_monitor.py --no-abuse-check
```

**Combinando opções:**
```powershell
python network_monitor.py --iface "Wi-Fi" --protocol tcp --log captura.csv
```

Pressione **Ctrl+C** para parar. Um resumo final será exibido no terminal.

---

## O que aparece na tela

| Coluna   | Descrição                              |
|----------|----------------------------------------|
| Time     | Horário do pacote                      |
| Proto    | Protocolo (TCP, UDP, ICMP, etc.)       |
| Source   | IP de origem                           |
| S.Port   | Porta de origem                        |
| Dest     | IP de destino                          |
| D.Port   | Porta de destino                       |
| Bytes    | Tamanho do pacote                      |
| Abuse%   | Score de reputação do IP (0–100)       |

**Score de reputação (AbuseIPDB):**
- `0` — IP limpo
- `1–24` — baixo risco
- `25–74` — risco médio
- `75–100` — IP malicioso (vermelho)
