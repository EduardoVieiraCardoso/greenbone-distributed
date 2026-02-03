# Greenbone Distributed Scanning Platform

Plataforma distribuída para execução de vulnerability assessments usando OpenVAS/Greenbone, com probes geograficamente dispersos e orquestração centralizada.

## 🎯 Visão Geral

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              VPS CENTRAL                                 │
│   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐         │
│   │   API/Web    │─────▶│ Orquestrador │─────▶│   VoidProbe  │         │
│   └──────────────┘      └──────┬───────┘      └───────┬──────┘         │
│          ▲                     ▼                      │                 │
│   ┌──────┴───────┐      ┌──────────────┐             │                 │
│   │   Webhook    │◀─────│    NATS      │             │                 │
│   └──────────────┘      └──────────────┘             │                 │
└──────────────────────────────────────────────────────┼─────────────────┘
                                                       │ gRPC tunnel
           ┌───────────────────┬───────────────────────┤
           ▼                   ▼                       ▼
   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
   │   PROBE 1     │   │   PROBE 2     │   │   PROBE 3     │
   │ ┌───────────┐ │   │ ┌───────────┐ │   │ ┌───────────┐ │
   │ │ VoidProbe │ │   │ │ VoidProbe │ │   │ │ VoidProbe │ │
   │ │ Satellite │ │   │ │ Satellite │ │   │ │ Satellite │ │
   │ │ OpenVAS   │ │   │ │ OpenVAS   │ │   │ │ OpenVAS   │ │
   │ └───────────┘ │   │ └───────────┘ │   │ └───────────┘ │
   └───────────────┘   └───────────────┘   └───────────────┘
```

## 🏗 Estrutura do Projeto

```
greenbone/
├── central/                    # Stack VPS Central
│   ├── docker-compose.yml
│   ├── orchestrator/           # Distribuição de scans
│   ├── webhook/                # Receptor de resultados
│   ├── api/                    # REST API
│   └── nats/                   # Config NATS
│
├── probe/                      # Stack Probe Remoto
│   ├── docker-compose.yml
│   └── satellite/              # Controlador GVM
│
└── docs/                       # Documentação
```

## 🚀 Quick Start

### Central (VPS)

```bash
cd central
cp .env.example .env
# Editar .env com suas configurações
docker-compose up -d
```

### Probe (Remoto)

```bash
cd probe
cp .env.example .env
# Configurar PROBE_TOKEN e CENTRAL_URL
docker-compose up -d
```

## 📡 API Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/v1/scans` | Submeter novo scan |
| GET | `/api/v1/scans/{id}` | Status do scan |
| GET | `/api/v1/probes` | Listar probes |

### Exemplo: Submeter Scan

```bash
curl -X POST http://central:8080/api/v1/scans \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "full",
    "target": "192.168.1.0/24"
  }'
```

### Scan Direcionado (portas específicas)

```bash
curl -X POST http://central:8080/api/v1/scans \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{
    "type": "directed",
    "target": "10.0.0.5",
    "ports": [22, 80, 443, 3389]
  }'
```

## 🔧 Componentes

| Componente | Tecnologia | Descrição |
|------------|------------|-----------|
| **Scanner** | immauss/openvas | Vulnerability assessment |
| **Queue** | NATS | Mensageria leve |
| **Tunnel** | VoidProbe | Conexão probe→central |
| **Orchestrator** | Go | Distribuição de jobs |
| **Satellite** | Python | Interface com GVM |

## 📋 Princípios de Design

- ✅ **Probes efêmeros** - Sem persistência local, sem IP fixo
- ✅ **Zero customização GVM** - Imagens oficiais/comunitárias apenas
- ✅ **Comunicação iniciada pelo probe** - Probe conecta no central
- ✅ **Single-tenant** - Uso interno único

## 📊 Recursos Necessários

### Central (VPS)
- 2 vCPU
- 4 GB RAM
- 20 GB SSD

### Probe (por instância)
- 2+ vCPU
- 4+ GB RAM (OpenVAS é pesado)
- 10 GB SSD

## 📖 Documentação

- [Arquitetura Detalhada](docs/architecture.md)
- [Setup do Probe](docs/probe-setup.md)
- [API Reference](docs/api.md)

## 📝 License

MIT License - Uso interno
