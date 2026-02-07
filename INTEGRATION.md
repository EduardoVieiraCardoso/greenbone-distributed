# Integracao com API Externa de Ativos

Este documento define o **contrato** que a API externa deve implementar para que o Scan Hub consuma os targets automaticamente.

O adapter faz polling periodico na API externa, sincroniza os targets no SQLite local, e dispara scans automaticamente baseado na frequencia configurada por target.

---

## Arquitetura

```
API Externa (CMDB/Assets)           Scan Hub                      GVM Probes
        |                               |                              |
        |  GET /api/v1/targets          |                              |
        |<------------------------------|  sync (a cada X min)         |
        |  { targets: [...] }           |                              |
        |                               |                              |
        |                               |  SQLite                      |
        |                               |  targets -> scheduler        |
        |                               |                              |
        |                               |  "next_scan <= now?"         |
        |  POST /api/v1/scan-results    |                              |
        |<------------------------------|  callback (quando Done)      |
        |  { scan_id, summary, ... }    |                              |
        |                               |------------------------------>|
        |                               |  distribui entre probes      |
```

---

## Endpoints que a API externa DEVE implementar

### 1. GET /api/v1/targets

Retorna a lista de targets que devem ser escaneados.

**Headers:**

```
Authorization: Bearer <token>
Content-Type: application/json
```

**Response (200):**

```json
{
  "targets": [
    {
      "id": "asset-001",
      "host": "192.168.15.20",
      "ports": null,
      "scan_type": "full",
      "criticality": "high",
      "scan_frequency_hours": 24,
      "enabled": true,
      "tags": {
        "department": "TI",
        "environment": "production"
      }
    },
    {
      "id": "asset-002",
      "host": "10.0.1.0/24",
      "ports": [22, 80, 443, 3306],
      "scan_type": "directed",
      "criticality": "critical",
      "scan_frequency_hours": 12,
      "enabled": true,
      "tags": {
        "department": "Financeiro",
        "environment": "production"
      }
    },
    {
      "id": "asset-003",
      "host": "dev-server.local",
      "ports": null,
      "scan_type": "full",
      "criticality": "low",
      "scan_frequency_hours": 720,
      "enabled": false,
      "tags": {
        "department": "Dev",
        "environment": "development"
      }
    }
  ]
}
```

#### Campos obrigatorios

| Campo | Tipo | Descricao |
|-------|------|-----------|
| `id` | string | Identificador unico do ativo na API externa. Usado para sincronizar (upsert) |
| `host` | string | IP, hostname ou CIDR range |
| `scan_type` | string | `full` ou `directed` |
| `criticality` | string | `critical`, `high`, `medium` ou `low` |
| `scan_frequency_hours` | int | Frequencia de scan em horas. Ex: 24 = a cada 24h |
| `enabled` | bool | Se `false`, o adapter ignora este target |

#### Campos opcionais

| Campo | Tipo | Descricao |
|-------|------|-----------|
| `ports` | list[int] ou null | Obrigatorio se `scan_type` = `directed`. Portas a escanear |
| `tags` | object ou null | Metadados livres. O adapter armazena mas nao usa internamente |

#### Regras

- O adapter faz `GET` periodicamente (default: a cada 5 minutos)
- Targets com `enabled: false` sao ignorados (e removidos do schedule se ja existiam)
- Se um target **desaparece** da lista, ele e **desativado** localmente (nao deletado)
- O campo `id` e a chave de sincronizacao — se mudar, o adapter trata como upsert

---

### 2. POST /api/v1/scan-results (opcional — callback)

Quando um scan termina (`Done`), o adapter pode enviar o resultado de volta.

**Request Body:**

```json
{
  "external_target_id": "asset-001",
  "scan_id": "cbae3d52-2e59-4255-92a5-4985906a4bf8",
  "probe_name": "gvm-1",
  "host": "192.168.15.20",
  "gvm_status": "Done",
  "completed_at": "2026-02-07T01:15:30.456789Z",
  "summary": {
    "hosts_scanned": 1,
    "vulns_high": 2,
    "vulns_medium": 5,
    "vulns_low": 12,
    "vulns_log": 45
  },
  "duration_seconds": 3420
}
```

**Response esperada:** `200` ou `201` (qualquer 2xx)

> Se este endpoint nao estiver implementado, o adapter simplesmente nao envia o callback. Configuravel via `source.callback_url` no config.yaml.

---

## Configuracao no Adapter

No `config.yaml`:

```yaml
source:
  url: "https://cmdb.empresa.com/api/v1/targets"
  auth_token: "Bearer eyJhbGciOiJIUzI1NiIs..."
  sync_interval: 300        # segundos entre cada sync (default: 5min)
  callback_url: "https://cmdb.empresa.com/api/v1/scan-results"  # opcional
  timeout: 30               # timeout HTTP em segundos
```

Ou via environment variables:

```bash
SOURCE_URL=https://cmdb.empresa.com/api/v1/targets
SOURCE_AUTH_TOKEN=Bearer eyJhbGciOiJIUzI1NiIs...
SOURCE_SYNC_INTERVAL=300
SOURCE_CALLBACK_URL=https://cmdb.empresa.com/api/v1/scan-results
```

---

## Criticidade e Prioridade

Quando multiplos targets precisam de scan ao mesmo tempo, o scheduler prioriza por criticidade:

| Criticidade | Peso | Frequencia sugerida | Descricao |
|-------------|------|--------------------|-----------| 
| `critical` | 4 | 12h | Sistemas criticos (DC, firewall, AD) |
| `high` | 3 | 24h | Servidores de producao |
| `medium` | 2 | 168h (7 dias) | Infra interna geral |
| `low` | 1 | 720h (30 dias) | Desenvolvimento, staging |

---

## Fluxo de Sincronizacao

```
1. Adapter faz GET na API externa
2. Para cada target recebido:
   a. Se nao existe no SQLite → insere com next_scan = now (scan imediato)
   b. Se ja existe → atualiza host/ports/freq/criticidade
   c. Se enabled=false → desativa (nao agenda mais scans)
3. Targets que estavam no SQLite mas NAO vieram na API → desativa
```

## Fluxo do Scheduler

```
1. A cada 60 segundos, o scheduler verifica:
   SELECT * FROM targets WHERE enabled=1 AND next_scan <= now()
   ORDER BY criticality_weight DESC

2. Para cada target encontrado:
   a. Cria scan via ScanManager (auto-seleciona probe)
   b. Atualiza last_scan = now()
   c. Atualiza next_scan = now() + scan_frequency_hours
```

---

## Autenticacao

O adapter envia o token configurado no header `Authorization`:

```
GET /api/v1/targets HTTP/1.1
Host: cmdb.empresa.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json
```

Formatos aceitos:
- `Bearer <jwt_token>`
- `ApiKey <api_key>`
- Qualquer string — o adapter envia exatamente o que estiver em `auth_token`

---

## Erros

Se a API externa retornar erro, o adapter loga e tenta novamente no proximo ciclo de sync:

| Status | Comportamento do adapter |
|--------|-------------------------|
| 200 | Sincroniza normalmente |
| 401/403 | Log de erro, tenta novamente no proximo ciclo |
| 404 | Log de erro, tenta novamente no proximo ciclo |
| 500+ | Log de erro, tenta novamente no proximo ciclo |
| Timeout | Log de erro, tenta novamente no proximo ciclo |

O adapter **nunca para** por causa de erro na API externa. Ele continua operando com os targets que ja tem no SQLite.
