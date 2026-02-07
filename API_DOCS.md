# Greenbone Adapter — Documentacao da API

Base URL: `http://<host>:<port>` (default: `http://localhost:8080`)

---

## Endpoints

| Metodo | Endpoint | Descricao |
|--------|----------|-----------|
| POST | `/scans` | Submeter novo scan |
| GET | `/scans` | Listar todos os scans (persistido em SQLite) |
| GET | `/scans/{scan_id}` | Status de um scan |
| GET | `/scans/{scan_id}/report` | Report XML completo (so quando Done) |
| GET | `/probes` | Listar probes e scans ativos |
| GET | `/targets` | Listar targets sincronizados da API externa |
| GET | `/targets/{external_id}` | Detalhes de um target |
| GET | `/health` | Health check (testa todos os probes) |
| GET | `/metrics` | Metricas Prometheus |

---

## POST /scans

Submete um novo scan. O adapter seleciona automaticamente o probe menos ocupado (least-busy), ou voce pode forcar um probe especifico.

### Request Body

| Campo | Tipo | Obrigatorio | Descricao |
|-------|------|-------------|-----------|
| `target` | string | Sim | IP, hostname ou CIDR (ex: `192.168.1.10`, `10.0.0.0/24`, `server.local`) |
| `scan_type` | string | Nao | `full` (default) ou `directed` |
| `ports` | list[int] | Condicional | Obrigatorio se `scan_type` = `directed`. Portas 1-65535 |
| `probe_name` | string | Nao | Nome do probe. Se omitido, seleciona automaticamente |

### Exemplos

**Full scan (automatico):**

```bash
curl -X POST http://192.168.15.249:8088/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.15.20",
    "scan_type": "full"
  }'
```

**Directed scan (portas especificas):**

```bash
curl -X POST http://192.168.15.249:8088/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.15.20",
    "scan_type": "directed",
    "ports": [22, 80, 443, 3306, 8080]
  }'
```

**Scan em probe especifico:**

```bash
curl -X POST http://192.168.15.249:8088/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "10.0.0.0/24",
    "scan_type": "full",
    "probe_name": "gvm-2"
  }'
```

### Response (201)

```json
{
  "scan_id": "cbae3d52-2e59-4255-92a5-4985906a4bf8",
  "probe_name": "gvm-1",
  "message": "Scan submitted"
}
```

### Erros

| Status | Causa |
|--------|-------|
| 422 | Target invalido, porta fora do range, probe nao encontrado, directed sem ports |

---

## GET /scans

Lista todos os scans (ativos e finalizados). Dados lidos do **SQLite**.

### Origem dos dados

| Campo | Origem | Descricao |
|-------|--------|----------|
| `scan_id` | SQLite | UUID gerado pelo adapter |
| `probe_name` | SQLite | Probe selecionado pelo adapter |
| `target` | SQLite | IP/host informado na criacao |
| `scan_type` | SQLite | Tipo do scan (full/directed) |
| `gvm_status` | GVM Probe → SQLite | Ultimo status coletado do GVM via polling |
| `gvm_progress` | GVM Probe → SQLite | Ultimo percentual coletado do GVM via polling |
| `created_at` | SQLite | Timestamp de criacao no adapter |

> `gvm_status` e `gvm_progress` sao atualizados no SQLite a cada ciclo de polling (default: 30s).
> Entre polls, o valor pode estar ligeiramente defasado em relacao ao GVM real.

### Exemplo

```bash
curl http://192.168.15.249:8088/scans
```

### Response

```json
{
  "total": 3,
  "scans": [
    {
      "scan_id": "cbae3d52-...",          // SQLite
      "probe_name": "gvm-1",              // SQLite
      "target": "192.168.15.20",          // SQLite
      "scan_type": "full",                // SQLite
      "gvm_status": "Running",            // GVM Probe (via polling)
      "gvm_progress": 42,                 // GVM Probe (via polling)
      "created_at": "2026-02-07T00:22:10Z" // SQLite
    },
    {
      "scan_id": "a5bc2f6f-...",
      "probe_name": "gvm-1",
      "target": "192.168.15.20",
      "scan_type": "full",
      "gvm_status": "Done",
      "gvm_progress": 100,
      "created_at": "2026-02-07T00:18:17Z"
    }
  ]
}
```

---

## GET /scans/{scan_id}

Status detalhado de um scan. Dados lidos do **SQLite**, que e atualizado a cada ciclo de polling com dados do **GVM Probe**.

### Origem dos dados

| Campo | Origem | Descricao |
|-------|--------|----------|
| `scan_id` | SQLite | UUID gerado pelo adapter |
| `probe_name` | SQLite | Probe que esta executando o scan |
| `gvm_status` | GVM Probe → SQLite | Status real do task no GVM (atualizado a cada poll) |
| `gvm_progress` | GVM Probe → SQLite | Progresso real do task no GVM 0-100 (atualizado a cada poll) |
| `target` | SQLite | IP/host informado na criacao |
| `scan_type` | SQLite | Tipo do scan |
| `created_at` | SQLite | Quando o scan foi criado no adapter |
| `started_at` | SQLite | Quando o task foi iniciado no GVM |
| `completed_at` | SQLite | Quando o task chegou a estado terminal |
| `error` | SQLite | Mensagem de erro (conexao, timeout, GVM error) |

### Exemplo

```bash
curl http://192.168.15.249:8088/scans/cbae3d52-2e59-4255-92a5-4985906a4bf8
```

### Response

```json
{
  "scan_id": "cbae3d52-...",               // SQLite
  "probe_name": "gvm-1",                   // SQLite
  "gvm_status": "Running",                 // GVM Probe (via polling)
  "gvm_progress": 42,                      // GVM Probe (via polling)
  "target": "192.168.15.20",               // SQLite
  "scan_type": "full",                     // SQLite
  "created_at": "2026-02-07T00:22:10Z",    // SQLite
  "started_at": "2026-02-07T00:22:11Z",    // SQLite (momento do start_task no GVM)
  "completed_at": null,                    // SQLite (preenchido quando terminal)
  "error": null                            // SQLite
}
```

### Status possiveis (do GVM)

| Status | Descricao |
|--------|-----------|
| `New` | Scan criado, aguardando inicio |
| `Requested` | Inicio solicitado ao GVM |
| `Queued` | Na fila do GVM |
| `Running` | Em execucao (gvm_progress = 0-100) |
| `Done` | Completo com sucesso |
| `Stopped` | Parado manualmente |
| `Interrupted` | Interrompido por erro |
| `Stop Requested` | Parada solicitada |

### Erros

| Status | Causa |
|--------|-------|
| 404 | scan_id nao encontrado |

---

## GET /scans/{scan_id}/report

Report XML completo. Os dados vem de **duas fontes**:

| Campo | Origem | Descricao |
|-------|--------|----------|
| `scan_id` | SQLite | UUID do scan |
| `probe_name` | SQLite | Probe que executou o scan |
| `gvm_status` | GVM Probe → SQLite | Status final |
| `target` | SQLite | IP/host escaneado |
| `completed_at` | SQLite | Quando finalizou |
| `report_xml` | GVM Probe → SQLite | XML completo baixado do GVM quando status = Done |
| `summary` | Adapter (parseado do XML) | Contagem de vulns extraida do report_xml |
| `error` | SQLite | Erro se houver |

> O `report_xml` e baixado **uma unica vez** do GVM quando o scan atinge status `Done`, e armazenado no SQLite. Consultas subsequentes leem do SQLite (nao consulta o GVM novamente).

So disponivel quando `gvm_status` = `Done`.

### Exemplo

```bash
curl http://192.168.15.249:8088/scans/cbae3d52-2e59-4255-92a5-4985906a4bf8/report
```

**Salvar XML em arquivo:**

```bash
curl -s http://192.168.15.249:8088/scans/{scan_id}/report | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['report_xml'])" > report.xml
```

### Response

```json
{
  "scan_id": "cbae3d52-2e59-4255-92a5-4985906a4bf8",
  "probe_name": "gvm-1",
  "gvm_status": "Done",
  "target": "192.168.15.20",
  "completed_at": "2026-02-07T01:15:30.456789Z",
  "report_xml": "<?xml version=\"1.0\"?><report>...</report>",
  "summary": {
    "hosts_scanned": 1,
    "vulns_high": 2,
    "vulns_medium": 5,
    "vulns_low": 12,
    "vulns_log": 45
  },
  "error": null
}
```

### Erros

| Status | Causa |
|--------|-------|
| 404 | scan_id nao encontrado |
| 409 | Report nao disponivel (scan ainda nao terminou) |

---

## GET /probes

Lista todos os probes configurados e quantos scans ativos cada um tem.

### Origem dos dados

| Campo | Origem | Descricao |
|-------|--------|----------|
| `name` | config.yaml | Nome do probe configurado |
| `host` | config.yaml | Host GVM configurado |
| `port` | config.yaml | Porta GVM configurada |
| `active_scans` | SQLite (query) | `COUNT(*) FROM scans WHERE completed_at IS NULL AND probe_name = ?` |

### Exemplo

```bash
curl http://192.168.15.249:8088/probes
```

### Response

```json
{
  "probes": [
    {
      "name": "gvm-1",
      "host": "192.168.15.20",
      "port": 9390,
      "active_scans": 2
    },
    {
      "name": "gvm-2",
      "host": "192.168.15.30",
      "port": 9390,
      "active_scans": 0
    }
  ]
}
```

---

## GET /targets

Lista todos os targets sincronizados da API externa. Todos os dados vem do **SQLite** (sincronizado periodicamente da API externa via Target Sync).

### Origem dos dados

| Campo | Origem | Descricao |
|-------|--------|----------|
| `external_id` | API externa → SQLite | ID do ativo na API externa |
| `host` | API externa → SQLite | IP/hostname/CIDR |
| `ports` | API externa → SQLite | Portas (JSON) |
| `scan_type` | API externa → SQLite | full ou directed |
| `criticality` | API externa → SQLite | critical, high, medium, low |
| `criticality_weight` | Adapter (calculado) | Peso numerico (4=critical, 3=high, 2=medium, 1=low) |
| `scan_frequency_hours` | API externa → SQLite | Frequencia de scan em horas |
| `enabled` | API externa → SQLite | 1=ativo, 0=desativado |
| `tags` | API externa → SQLite | Metadados livres (JSON) |
| `last_scan_at` | SQLite | Quando o ultimo scan foi disparado |
| `next_scan_at` | SQLite | Quando o proximo scan sera disparado |
| `last_scan_id` | SQLite | scan_id do ultimo scan disparado |
| `synced_at` | SQLite | Quando este target foi sincronizado pela ultima vez |
| `created_at` | SQLite | Quando este target apareceu pela primeira vez |

> Targets sao sincronizados a cada `sync_interval` segundos (default: 5min).
> Se um target desaparece da API externa, ele e **desativado** (enabled=0), nao deletado.

So retorna dados se `source.url` estiver configurado e o sync tiver rodado pelo menos uma vez.

### Exemplo

```bash
curl http://192.168.15.249:8088/targets
```

### Response

```json
{
  "total": 2,
  "targets": [
    {
      "external_id": "asset-001",
      "host": "192.168.15.20",
      "ports": null,
      "scan_type": "full",
      "criticality": "high",
      "criticality_weight": 3,
      "scan_frequency_hours": 24,
      "enabled": 1,
      "tags": "{\"department\": \"TI\"}",
      "last_scan_at": "2026-02-07T01:00:00Z",
      "next_scan_at": "2026-02-08T01:00:00Z",
      "last_scan_id": "cbae3d52-2e59-4255-92a5-4985906a4bf8",
      "synced_at": "2026-02-07T00:55:00Z",
      "created_at": "2026-02-06T22:00:00Z"
    },
    {
      "external_id": "asset-002",
      "host": "10.0.1.0/24",
      "ports": "[22, 80, 443]",
      "scan_type": "directed",
      "criticality": "critical",
      "criticality_weight": 4,
      "scan_frequency_hours": 12,
      "enabled": 1,
      "tags": null,
      "last_scan_at": null,
      "next_scan_at": "2026-02-07T00:55:00Z",
      "last_scan_id": null,
      "synced_at": "2026-02-07T00:55:00Z",
      "created_at": "2026-02-07T00:55:00Z"
    }
  ]
}
```

---

## GET /targets/{external_id}

Detalhes de um target especifico pelo ID da API externa.

### Exemplo

```bash
curl http://192.168.15.249:8088/targets/asset-001
```

### Response

Mesmo formato de um item da lista acima.

### Erros

| Status | Causa |
|--------|-------|
| 404 | Target nao encontrado |

---

## GET /health

Testa a conectividade com todos os probes GVM. Dados vem **diretamente do GVM Probe** em tempo real (nao usa SQLite).

> Este endpoint faz uma conexao real ao GVM e executa `get_scanners()` para validar. Pode demorar alguns segundos se houver probes lentos ou offline.

Retorna 200 se todos estao conectados, 503 se algum falhou.

### Exemplo

```bash
curl http://192.168.15.249:8088/health
```

### Response (200 — todos saudaveis)

```json
{
  "status": "healthy",
  "probes": {
    "gvm-1": "connected",
    "gvm-2": "connected"
  }
}
```

### Response (503 — algum probe com problema)

```json
{
  "detail": {
    "status": "degraded",
    "probes": {
      "gvm-1": "connected",
      "gvm-2": "Failed to connect to GVM at 192.168.15.30:9390 after 3 attempts: ..."
    }
  }
}
```

---

## GET /metrics

Metricas Prometheus em formato texto. Usado pelo Prometheus para scraping.

### Exemplo

```bash
curl http://192.168.15.249:8088/metrics
```

### Metricas expostas

**Globais:**

| Metrica | Tipo | Descricao |
|---------|------|-----------|
| `greenbone_scans_submitted_total` | Counter | Total de scans submetidos (label: `scan_type`) |
| `greenbone_scans_completed_total` | Counter | Total de scans finalizados (label: `gvm_status`) |
| `greenbone_scans_failed_total` | Counter | Total de falhas do adapter |
| `greenbone_scans_active` | Gauge | Scans em execucao agora |
| `greenbone_scan_duration_seconds` | Histogram | Duracao dos scans (p50, p90, p99) |

**Por probe:**

| Metrica | Tipo | Descricao |
|---------|------|-----------|
| `greenbone_probe_scans_active` | Gauge | Scans ativos por probe (label: `probe`) |
| `greenbone_probe_scans_routed_total` | Counter | Total de scans roteados por probe (label: `probe`) |
| `greenbone_gvm_connection_errors_total` | Counter | Erros de conexao por probe (label: `probe`) |

---

## Fluxo tipico de uso

```
1. Submeter scan
   POST /scans  →  { scan_id, probe_name }

2. Acompanhar status (polling)
   GET /scans/{scan_id}  →  { gvm_status: "Running", gvm_progress: 42 }
   GET /scans/{scan_id}  →  { gvm_status: "Running", gvm_progress: 78 }
   GET /scans/{scan_id}  →  { gvm_status: "Done", gvm_progress: 100 }

3. Coletar report
   GET /scans/{scan_id}/report  →  { report_xml, summary }
```

---

## Distribuicao multi-probe

Quando ha multiplos probes configurados:

1. O adapter seleciona o **probe menos ocupado** (fewest active scans)
2. O mesmo probe nao pode ser selecionado mais que `max_consecutive_same_probe` vezes consecutivas (default: 3) — **anti-starvation**
3. Voce pode forcar um probe especifico passando `probe_name` no POST

```
Scan 1 → gvm-1 (0 ativos)
Scan 2 → gvm-2 (0 ativos, gvm-1 ja tem 1)
Scan 3 → gvm-1 (1 ativo, gvm-2 ja tem 1, gvm-1 terminou 1)
Scan 4 → gvm-2 (anti-starvation: gvm-1 selecionado 3x seguidas)
```

### Monitoramento

- **API**: `GET /probes` — scans ativos por probe
- **Grafana**: Dashboard "Greenbone Adapter" com paineis por probe
- **Prometheus**: `greenbone_probe_scans_active{probe="gvm-1"}`

---

## Target Sync (API externa)

Quando `source.url` esta configurado no `config.yaml`, o adapter sincroniza targets automaticamente:

```yaml
source:
  url: "https://cmdb.empresa.com/api/v1/targets"
  auth_token: "Bearer <token>"
  sync_interval: 300        # puxa targets a cada 5 min
  callback_url: "https://cmdb.empresa.com/api/v1/scan-results"  # opcional
  scheduler_interval: 60    # verifica targets due a cada 60s
```

### Fluxo

```
1. Target Sync (a cada sync_interval):
   GET source.url → upsert targets no SQLite

2. Scheduler (a cada scheduler_interval):
   SELECT targets WHERE next_scan_at <= now() ORDER BY criticality_weight DESC
   → cria scan automaticamente para cada target due

3. Callback (quando scan termina):
   POST callback_url com { scan_id, summary, gvm_status }
```

### Consultar targets sincronizados

```bash
# Listar todos
curl http://192.168.15.249:8088/targets

# Detalhes de um target
curl http://192.168.15.249:8088/targets/asset-001
```

### Sem source.url

Se `source.url` nao estiver configurado, o sync e o scheduler ficam **desativados**. O adapter funciona normalmente so via `POST /scans` manual. Os endpoints `/targets` retornam lista vazia.

---

## Configuracao completa

```yaml
probes:
  - name: "gvm-1"
    host: "192.168.15.20"
    port: 9390
    username: "admin"
    password: "admin"

api:
  host: "0.0.0.0"
  port: 8088

scan:
  poll_interval: 30
  max_duration: 86400
  cleanup_after_report: true
  default_port_list: "All IANA assigned TCP"
  max_consecutive_same_probe: 3
  gvm_scan_config: "Full and fast"
  gvm_scanner: "OpenVAS Default"
  db_path: "scans.db"

# source:
#   url: "https://cmdb.empresa.com/api/v1/targets"
#   auth_token: "Bearer <token>"
#   sync_interval: 300
#   callback_url: ""
#   timeout: 30
#   scheduler_interval: 60

logging:
  level: "INFO"
  format: "console"
```
