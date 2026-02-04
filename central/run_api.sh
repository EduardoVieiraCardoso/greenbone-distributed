#!/bin/bash
#
# Run Central API
#

cd "$(dirname "$0")"

# Load env
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Create venv if needed
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r api/requirements.txt
else
    source venv/bin/activate
fi

# Create data dir
mkdir -p data

# Run
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
cd api
uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080} --reload
