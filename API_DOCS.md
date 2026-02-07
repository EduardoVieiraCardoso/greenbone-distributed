# Greenbone Adapter — Documentacao da API

Base URL: `http://<host>:<port>` (default: `http://localhost:8080`)

---

## Endpoints

| Metodo | Endpoint | Descricao |
|--------|----------|-----------|
| POST | `/scans` | Submeter novo scan |
| GET | `/scans` | Listar todos os scans |
| GET | `/scans/{scan_id}` | Status de um scan |
| GET | `/scans/{scan_id}/report` | Report XML completo (so quando Done) |
| GET | `/probes` | Listar probes e scans ativos |
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

Lista todos os scans (ativos e finalizados). Persistido em SQLite.

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
      "scan_id": "cbae3d52-2e59-4255-92a5-4985906a4bf8",
      "probe_name": "gvm-1",
      "target": "192.168.15.20",
      "scan_type": "full",
      "gvm_status": "Running",
      "gvm_progress": 42,
      "created_at": "2026-02-07T00:22:10.790306Z"
    },
    {
      "scan_id": "a5bc2f6f-9948-4a92-824e-2c40e0cc583a",
      "probe_name": "gvm-1",
      "target": "192.168.15.20",
      "scan_type": "full",
      "gvm_status": "Done",
      "gvm_progress": 100,
      "created_at": "2026-02-07T00:18:17.503252Z"
    }
  ]
}
```

---

## GET /scans/{scan_id}

Status detalhado de um scan. Todos os campos `gvm_status` e `gvm_progress` vem direto do GVM.

### Exemplo

```bash
curl http://192.168.15.249:8088/scans/cbae3d52-2e59-4255-92a5-4985906a4bf8
```

### Response

```json
{
  "scan_id": "cbae3d52-2e59-4255-92a5-4985906a4bf8",
  "probe_name": "gvm-1",
  "gvm_status": "Running",
  "gvm_progress": 42,
  "target": "192.168.15.20",
  "scan_type": "full",
  "created_at": "2026-02-07T00:22:10.790306Z",
  "started_at": "2026-02-07T00:22:11.123456Z",
  "completed_at": null,
  "error": null
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

Report XML completo do GVM. So disponivel quando `gvm_status` = `Done`.

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

## GET /health

Testa a conectividade com todos os probes GVM. Retorna 200 se todos estao conectados, 503 se algum falhou.

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
