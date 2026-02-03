#!/bin/bash
#
# Inicia todos os serviços do Probe
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🚀 Iniciando Probe..."

# Verificar .env
if [ ! -f ".env" ]; then
    echo "❌ Arquivo .env não encontrado. Execute ./setup.sh primeiro."
    exit 1
fi

# Carregar variáveis
source .env

# Subir OpenVAS
echo "📦 Iniciando OpenVAS..."
docker-compose up -d openvas

# Aguardar OpenVAS ficar pronto
echo "⏳ Aguardando OpenVAS inicializar..."
echo "   (Isso pode levar alguns minutos na primeira vez)"

MAX_WAIT=300
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -k -s https://localhost:9392/login > /dev/null 2>&1; then
        echo "   ✓ OpenVAS pronto!"
        break
    fi
    sleep 5
    WAITED=$((WAITED + 5))
    echo "   Aguardando... ($WAITED s)"
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "⚠️  Timeout aguardando OpenVAS. Verifique os logs:"
    echo "   docker logs greenbone-openvas"
fi

# Iniciar Satellite
echo ""
echo "🛰️  Iniciando Satellite Controller..."
cd satellite
source venv/bin/activate

# Exportar variáveis
export PROBE_ID GVM_HOST GVM_PORT GVM_USERNAME GVM_PASSWORD
export NATS_URL NATS_TOKEN CENTRAL_WEBHOOK PROBE_TOKEN
export PROBE_LOCATION LOG_LEVEL LOG_FORMAT

# Rodar em background
nohup python -m src.main > ../satellite.log 2>&1 &
SATELLITE_PID=$!
echo $SATELLITE_PID > ../satellite.pid

echo "   ✓ Satellite iniciado (PID: $SATELLITE_PID)"
echo ""
echo "✅ Probe iniciado!"
echo ""
echo "Logs:"
echo "   OpenVAS:   docker logs -f greenbone-openvas"
echo "   Satellite: tail -f satellite.log"
echo ""
echo "Para parar: ./stop.sh"
