#!/bin/bash
#
# Run Probe Satellite API
#

cd "$(dirname "$0")/satellite"

# Load env
if [ -f "../.env" ]; then
    export $(grep -v '^#' ../.env | xargs)
fi

# Create venv if needed
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Run
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
uvicorn src.api:app --host 0.0.0.0 --port ${PORT:-8000} --reload
