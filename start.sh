#!/bin/bash
set -e

# Synthesize initial dataset if data/logs.csv does not exist
if [ ! -f "data/logs.csv" ]; then
    echo "Generating initial synthetic dataset..."
    python backend/synthesizer.py
fi

# Use PORT assigned by Render/Cloud environment, fallback to 8000
PORT="${PORT:-8000}"

echo "Starting Unified Smart Log Analyzer Web Application on port $PORT..."
exec python -m uvicorn backend.main:app --host 0.0.0.0 --port "$PORT"

