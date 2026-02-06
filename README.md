# Greenbone Adapter

Serviço bridge entre uma API externa e o Greenbone/OpenVAS via protocolo GMP.

Recebe pedidos de scan, executa no GVM, reporta status real (Queued, Running, %, Done) e entrega o XML completo do relatório.

## Arquitetura

```
API Externa           Greenbone Adapter              GVM (OpenVAS)
    │                       │                             │
    │  POST /scans          │                             │
    │──────────────────────▶│  create target + task       │
    │                       │────────────────────────────▶│
    │                       │         (GMP/TLS)           │
    │                       │                             │
    │  GET /scans/{id}      │  get_task status/progress   │
    │──────────────────────▶│◀───────────────────────────▶│
    │  { gvm_status,        │         (GMP/TLS)           │
    │    gvm_progress }     │                             │
    │◀──────────────────────│                             │
    │                       │                             │
    │  GET /scans/{id}/report                             │
    │──────────────────────▶│  get_report (XML)           │
    │  { report_xml }       │◀────────────────────────────│
    │◀──────────────────────│                             │
```

- O adapter **não modifica** a instalação do Greenbone
- Todos os status e percentuais vêm **direto do GVM** via GMP
- A conexão com o GVM é via TLS (porta 9390), pode ser local ou remota

## Estrutura

```
greenbone/
├── config.yaml.example    # Template de configuração
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── src/
    ├── main.py            # Entry point
    ├── config.py          # Loader de configuração (YAML + env vars)
    ├── gvm_client.py      # Interface GMP com o Greenbone
    ├── scan_manager.py    # Ciclo de vida do scan
    ├── api.py             # Endpoints HTTP (FastAPI)
    └── models.py          # Modelos de dados
```

## Quick Start

```bash
# 1. Copiar e editar configuração
cp config.yaml.example config.yaml
# Editar config.yaml com host/porta/credenciais do GVM

# 2. Criar e ativar ambiente virtual
python -m venv venv
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. Instalar dependências
pip install -r requirements.txt

# 4. Rodar
python -m src.main
```

Ou via Docker:

```bash
docker-compose up -d
```

## Configuração

Via `config.yaml`:

```yaml
gvm:
  host: "10.0.0.5"       # IP do Greenbone
  port: 9390              # Porta GMP
  username: "admin"
  password: "sua_senha"
  timeout: 300
  retry_attempts: 3
  retry_delay: 5

api:
  host: "0.0.0.0"
  port: 8080

scan:
  poll_interval: 30       # Segundos entre cada poll de status no GVM
  max_duration: 86400     # Timeout máximo do scan em segundos (24h)
  cleanup_after_report: true  # Deletar recursos GVM após coletar report

logging:
  level: "INFO"
  format: "console"       # console ou json
```

Environment variables sobrescrevem o YAML: `GVM_HOST`, `GVM_PORT`, `GVM_USERNAME`, `GVM_PASSWORD`, `GVM_TIMEOUT`, `GVM_RETRY_ATTEMPTS`, `GVM_RETRY_DELAY`, `API_HOST`, `API_PORT`, `SCAN_POLL_INTERVAL`, `LOG_LEVEL`, `LOG_FORMAT`.

## API Endpoints

| Metodo | Endpoint | Descricao |
|--------|----------|-----------|
| GET | `/health` | Health check |
| POST | `/scans` | Submeter novo scan |
| GET | `/scans` | Listar todos os scans |
| GET | `/scans/{id}` | Status atual do scan (status + % do GVM) |
| GET | `/scans/{id}/report` | XML completo do relatorio (so quando Done) |
| GET | `/metrics` | Metricas Prometheus |

### Submeter scan (full)

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.0/24",
    "scan_type": "full"
  }'
```

### Submeter scan (portas especificas)

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "10.0.0.5",
    "scan_type": "directed",
    "ports": [22, 80, 443, 3389]
  }'
```

### Consultar status

```bash
curl http://localhost:8080/scans/{scan_id}
```

Resposta:

```json
{
  "scan_id": "uuid",
  "gvm_status": "Running",
  "gvm_progress": 45,
  "target": "192.168.1.0/24",
  "scan_type": "full",
  "created_at": "2025-01-01T00:00:00",
  "started_at": "2025-01-01T00:00:05"
}
```

### Buscar relatorio

```bash
curl http://localhost:8080/scans/{scan_id}/report
```

Retorna o XML completo do GVM quando `gvm_status` = `Done`.

## Status do GVM

Os status reportados sao os reais do Greenbone, sem modificacao:

| Status | Significado |
|--------|-------------|
| `New` | Task criada |
| `Requested` | Execucao solicitada |
| `Queued` | Na fila do scanner |
| `Running` | Em execucao (com % de progresso) |
| `Done` | Concluido |
| `Stopped` | Parado manualmente |
| `Interrupted` | Interrompido |

## Métricas Prometheus

Endpoint `/metrics` expõe métricas no formato Prometheus:

| Métrica | Tipo | Descrição |
|---------|------|-----------|
| `greenbone_scans_submitted_total` | Counter | Total de scans submetidos (label: `scan_type`) |
| `greenbone_scans_completed_total` | Counter | Scans que chegaram a estado terminal (label: `gvm_status`) |
| `greenbone_scans_failed_total` | Counter | Scans que falharam por erro do adapter/conexão |
| `greenbone_scans_active` | Gauge | Scans em execução agora |
| `greenbone_scan_duration_seconds` | Histogram | Duração do scan (start → terminal) |
| `greenbone_gvm_connection_errors_total` | Counter | Falhas de conexão com o GVM |

## Stack

| Componente | Tecnologia |
|------------|------------|
| API | Python / FastAPI |
| GVM Client | python-gvm (protocolo GMP) |
| Config | YAML + env vars |
| Container | Docker |
