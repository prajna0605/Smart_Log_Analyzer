#!/bin/bash
set -e

# Synthesize initial dataset if data/logs.csv does not exist
if [ ! -f "data/logs.csv" ]; then
    echo "Generating initial synthetic dataset..."
    python backend/synthesizer.py
fi

# Use PORT assigned by Render/Cloud environment, fallback to 8501
PORT="${PORT:-8501}"

echo "Starting FastAPI Backend Server on port 8000..."
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 &

echo "Waiting for backend startup..."
sleep 3

echo "Starting Streamlit Frontend Dashboard on port $PORT..."
exec streamlit run frontend/app.py \
    --server.port "$PORT" \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.enableCORS false \
    --server.enableXsrfProtection false
