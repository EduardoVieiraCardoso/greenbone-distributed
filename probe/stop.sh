#!/bin/bash
#
# Para todos os serviços do Probe
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🛑 Parando Probe..."

# Parar Satellite
if [ -f "satellite.pid" ]; then
    PID=$(cat satellite.pid)
    if kill -0 $PID 2>/dev/null; then
        echo "   Parando Satellite (PID: $PID)..."
        kill $PID
        rm satellite.pid
    fi
fi

# Parar containers
echo "   Parando containers..."
docker-compose down

echo "✅ Probe parado!"
