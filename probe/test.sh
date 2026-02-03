#!/bin/bash
#
# Testa conexões do Probe (GVM e NATS)
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🧪 Testando conexões do Probe..."
echo ""

# Carregar variáveis
if [ -f ".env" ]; then
    source .env
fi

# Ativar venv
cd satellite
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "❌ Virtual environment não encontrado. Execute ./setup.sh primeiro."
    exit 1
fi

# Exportar variáveis
export GVM_HOST GVM_PORT GVM_USERNAME GVM_PASSWORD
export NATS_URL NATS_TOKEN PROBE_ID PROBE_LOCATION

echo "1️⃣  Testando conexão com GVM (OpenVAS)..."
echo "-------------------------------------------"
python -m src.test_gvm

echo ""
echo "2️⃣  Testando conexão com NATS..."
echo "-------------------------------------------"
python -m src.test_nats
